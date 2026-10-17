import copy
import json
import ipaddress
import re
from pathlib import Path

from .common import PRESETS, UserError, identifier, label
from .dns import bootstrap_address, dns_server
from .xray import uses_xray, socks_outbound

RULE_TYPES = {"domain", "domain_suffix", "ip_cidr", "list", "process_name", "process_path", "port"}
LIST_FIELDS = {"domain", "domain_suffix", "ip_cidr"}


def rule(raw):
    kind = raw.get("type", "domain_suffix")
    action = raw.get("action", "proxy")
    if kind not in RULE_TYPES or action not in {"proxy", "direct", "block"}:
        raise UserError("Неподдерживаемое условие или действие правила.")
    values = raw.get("values", [])
    if not isinstance(values, list) or not 1 <= len(values) <= 10000:
        raise UserError("Укажите значения правила, каждое с новой строки.")
    cleaned = []
    for v in values:
        v = str(v).strip()
        if kind == "ip_cidr":
            try:
                v = str(ipaddress.ip_network(v, strict=False))
            except ValueError:
                raise UserError("Некорректный IP/CIDR.") from None
        elif kind in {"domain", "domain_suffix"}:
            try:
                v = v.lstrip(".").encode("idna").decode().lower()
                if not re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*", v) or len(v) > 253:
                    raise ValueError()
            except (ValueError, UnicodeError):
                raise UserError("Нужен домен без URL, звёздочек и пути.") from None
        elif kind == "port":
            try:
                v = int(v)
                if not 1 <= v <= 65535:
                    raise ValueError()
            except ValueError:
                raise UserError("Порт: 1–65535.") from None
        elif kind == "list":
            if not re.fullmatch(r"[a-f0-9]{32}|ru-(blocked|ip-blocked|domains|ips)", v):
                raise UserError("Выберите существующий список.")
        elif not v or len(v) > 4096 or "\n" in v or "\x00" in v:
            raise UserError("Некорректное имя процесса или путь.")
        cleaned.append(v)
    return {"id": raw.get("id") or identifier(), "name": label(raw.get("name", "Правило")), "type": kind, "values": cleaned, "action": action, "enabled": bool(raw.get("enabled", True))}


def source_list(obj):
    if not isinstance(obj, dict) or obj.get("version") not in {1, 2, 3, 4} or not isinstance(obj.get("rules"), list) or not obj["rules"]:
        raise UserError("Список: нужен sing-box source JSON version/rules.")
    for r in obj["rules"]:
        if not isinstance(r, dict) or not r or set(r) - LIST_FIELDS:
            raise UserError("Списки могут содержать только domain, domain_suffix и ip_cidr.")
        for k, values in r.items():
            values = values if isinstance(values, list) else [values]
            if not values or len(values) > 1000000:
                raise UserError("Пустой или слишком большой список.")
            normalized = []
            for start in range(0, len(values), 10000):
                normalized.extend(rule({"type": k, "values": values[start:start + 10000]})["values"])
            r[k] = normalized
    return obj


def text_list(text):
    domains, ips = [], []
    for line in text.splitlines():
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            ips.append(str(ipaddress.ip_network(value, strict=False)))
        except ValueError:
            domains.append(rule({"type": "domain_suffix", "values": [value]})["values"][0])
    rules = []
    if domains:
        rules.append({"domain_suffix": domains})
    if ips:
        rules.append({"ip_cidr": ips})
    return source_list({"version": 3, "rules": rules})


def compile_config(state, profile, runtime, engine_uid, tun=True, xray_proxy=None):
    if state["preset"] not in PRESETS:
        raise UserError("Неизвестный сценарий.")
    s = state["settings"]
    outbound = socks_outbound(xray_proxy) if uses_xray(profile) else copy.deepcopy(profile["outbound"])
    outbound["tag"] = "proxy"
    endpoint = outbound["type"] in {"wireguard", "openvpn-client"}
    if outbound["type"] == "openvpn-client":
        outbound["system"] = False
        outbound["route_no_pull"] = True
    if outbound["type"] == "wireguard":
        outbound["system"] = False
    settings = {"log": {"disabled": True}, "inbounds": [],
                "outbounds": [{"type": "direct", "tag": "direct"}] + ([] if endpoint else [outbound]),
                "endpoints": [outbound] if endpoint else [],
                "dns": {"servers": [
                    {"type": "udp", "tag": "bootstrap", "server": bootstrap_address(s.get("dns_bootstrap", "9.9.9.9"))},
                    dns_server(s["dns_direct"], "dns-direct"),
                    dns_server(s["dns_proxy"], "dns-proxy", proxy=True),
                    {"type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"}],
                    "rules": [], "final": "dns-proxy", "strategy": "prefer_ipv4" if s["ipv6"] else "ipv4_only", "reverse_mapping": True},
                "route": {"auto_detect_interface": True, "default_domain_resolver": {"server": "bootstrap", "strategy": "prefer_ipv4"}, "rules": [], "rule_set": [], "final": "proxy"},
                "experimental": {"cache_file": {"enabled": True, "path": str(Path(runtime) / "cache.db"), "store_fakeip": True}}}
    if profile.get("dns"):
        settings["dns"]["servers"][2] = {"type": "udp", "tag": "dns-proxy", "server": profile["dns"], "detour": "proxy"}
    if tun:
        settings["inbounds"] = [{"type": "tun", "tag": "tun", "interface_name": "helmsman0", "address": ["172.31.255.1/30", "fdfe:dcba:9876::1/126"], "mtu": s["mtu"], "auto_route": True, "auto_redirect": False, "strict_route": True, "stack": "mixed", "iproute2_table_index": 31800, "iproute2_rule_index": 31800, "exclude_uid": [engine_uid]}]
        if outbound["type"] in {"wireguard", "openvpn-client"}:
            settings["inbounds"][0]["mtu"] = min(s["mtu"], outbound.get("mtu", 1280 if outbound["type"] == "wireguard" else 1500))
    r = settings["route"]["rules"]
    if s["lan"]:
        # mDNS/LLMNR use DNS wire format too. Preserve local discovery before
        # protocol sniffing, otherwise hijack-dns can swallow Remote Play LAN.
        multicast = ["224.0.0.0/4", "255.255.255.255/32"] + (["ff00::/8"] if s["ipv6"] else [])
        r.extend([{"ip_cidr": multicast, "outbound": "direct"},
                  {"ip_is_private": True, "port": [5353, 5355], **({} if s["ipv6"] else {"ip_version": 4}), "outbound": "direct"}])
    r.extend([{"action": "sniff", "timeout": "200ms"}, {"protocol": "dns", "action": "hijack-dns"}, {"port": 53, "action": "hijack-dns"}])
    if not s["ipv6"]:
        r.append({"ip_version": 6, "action": "reject"})
    if s["lan"]:
        r.append({"ip_is_private": True, "outbound": "direct"})
        settings["dns"]["rules"].append({"domain_suffix": ["local", "lan", "home.arpa"], "server": "bootstrap"})
    rules = [rule(x) for x in state["rules"] if x.get("enabled", True)]
    preset = state["preset"]
    if preset == "ru-selective":
        rules += [rule({"type": "list", "values": ["ru-blocked", "ru-ip-blocked"], "action": "proxy"})]
    elif preset == "ru-except":
        rules += [rule({"type": "list", "values": ["ru-domains", "ru-ips"], "action": "direct"})]
    requested_final = "direct" if preset == "ru-selective" else s["default_action"] if preset == "manual" else "proxy"
    resolver = "dns-direct" if requested_final == "direct" else "dns-proxy"
    used = set()
    lists = {x["id"]: x for x in state["lists"]}
    resolved = False
    for item in rules:
        key = "rule_set" if item["type"] == "list" else item["type"]
        cond = {key: item["values"]}
        if key == "rule_set":
            used.update(item["values"])
        if item["type"] in {"ip_cidr", "list"} and not resolved:
            # FakeIP restores the hostname, not its real IP. Resolve explicitly
            # before IP/set matching so CIDR rules really apply to DNS traffic.
            r.append({"action": "resolve", "server": resolver})
            resolved = True
        r.append({**cond, **({"action": "reject"} if item["action"] == "block" else {"outbound": item["action"]})})
        if item["type"] in {"domain", "domain_suffix", "list"}:
            dns_cond = cond
            if item["type"] == "list":
                # 1.14 rejects legacy destination-IP filters in DNS rule sets.
                # DNS decisions use only the domain projection; real-IP rules
                # are evaluated by routing after the explicit resolve action.
                domains = {"domain": [], "domain_suffix": []}
                for tag in item["values"]:
                    if tag not in lists or not lists[tag].get("path") or not Path(lists[tag]["path"]).is_file():
                        raise UserError("Сначала загрузите список: " + tag)
                    for entry in json.loads(Path(lists[tag]["path"]).read_text())["rules"]:
                        for k in domains:
                            value = entry.get(k, [])
                            domains[k].extend(value if isinstance(value, list) else [value])
                choices = [{k: list(dict.fromkeys(v))} for k, v in domains.items() if v]
                if not choices:
                    continue
                dns_cond = choices[0] if len(choices) == 1 else {"type": "logical", "mode": "or", "rules": choices}
            if item["action"] == "block":
                settings["dns"]["rules"].append({**dns_cond, "action": "reject"})
            elif item["action"] == "direct":
                settings["dns"]["rules"].append({**dns_cond, "server": "dns-direct"})
            else:
                if dns_cond.get("type") == "logical":
                    settings["dns"]["rules"].append({"type": "logical", "mode": "and", "rules": [dns_cond, {"query_type": ["A", "AAAA"]}], "server": "fakeip"})
                else:
                    settings["dns"]["rules"].append({**dns_cond, "query_type": ["A", "AAAA"], "server": "fakeip"})
    final = requested_final
    if final == "block":
        r.append({"action": "reject"})
        final = "direct"  # Unreachable after unconditional rejection.
    settings["route"]["final"] = final
    settings["dns"]["final"] = "dns-direct" if final == "direct" else "dns-proxy"
    settings["dns"]["rules"].append({"action": "reject"} if requested_final == "block" else {"query_type": ["A", "AAAA"], "server": "fakeip"})
    for tag in sorted(used):
        if tag not in lists or not lists[tag].get("path") or not Path(lists[tag]["path"]).is_file():
            raise UserError("Сначала загрузите список: " + tag)
        settings["route"]["rule_set"].append({"type": "local", "tag": tag, "format": "source", "path": lists[tag]["path"]})
    return settings
