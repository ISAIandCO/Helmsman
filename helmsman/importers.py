"""Import connection data, never a provider's system policy or executable hooks."""
import base64
import copy
import ipaddress
import json
import re
import shlex
import struct
import uuid
import zlib
from urllib.parse import parse_qs, unquote, urlsplit

from .common import MAX_BYTES, UserError, identifier, label

PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2", "tuic", "anytls", "socks", "http", "wireguard", "openvpn-client"}
AWG_KEYS = {k.lower(): k for k in ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts"]}
AWG_JSON = {k: re.sub(r"(?<!^)(?=[A-Z])", "_", v).lower() for k, v in AWG_KEYS.items()}
AWG_JSON.update({k: k for k in AWG_KEYS if len(k) <= 4})
COMMON_FIELDS = {"type", "tag", "server", "server_port", "tls", "transport", "multiplex", "network", "connect_timeout", "tcp_fast_open", "udp_fragment"}
FIELDS = {
    "vless": {"uuid", "flow", "packet_encoding"},
    "vmess": {"uuid", "security", "alter_id", "global_padding", "authenticated_length", "packet_encoding"},
    "trojan": {"password"}, "shadowsocks": {"method", "password", "udp_over_tcp"},
    "hysteria": {"up_mbps", "down_mbps", "obfs", "auth", "auth_str", "recv_window_conn", "recv_window", "disable_mtu_discovery"},
    "hysteria2": {"password", "up_mbps", "down_mbps", "obfs", "server_ports", "hop_interval"},
    "tuic": {"uuid", "password", "congestion_control", "udp_relay_mode", "zero_rtt_handshake", "heartbeat"},
    "anytls": {"password", "idle_session_check_interval", "idle_session_timeout", "min_idle_session"},
    "socks": {"version", "username", "password", "udp_over_tcp"}, "http": {"username", "password"},
    "wireguard": {"system", "name", "mtu", "address", "private_key", "peers", "workers", "amnezia_wg"},
    "openvpn-client": {"mode", "servers", "remote_random", "address", "topology", "username", "password", "auth_retry", "key_direction", "cipher", "data_ciphers", "data_ciphers_fallback", "auth", "mss_fix", "ping_interval", "ping_restart", "renegotiate_interval", "explicit_exit_notify", "system", "name", "mtu", "route_no_pull"},
}


def b64(s):
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        raise UserError("Некорректный Base64.") from None


def _no_files(value, parent=""):
    if isinstance(value, dict):
        for k, v in value.items():
            if k.endswith("_path") or k in {"plugin", "plugin_opts", "detour", "bind_interface", "routing_mark", "netns", "certificate_provider", "ech", "client_certificate_provider"}:
                raise UserError("Импорт не допускает файлы, плагины и системные параметры: " + k)
            if k == "path" and parent != "transport":
                raise UserError("Путь к файлу не разрешён.")
            _no_files(v, k)
    elif isinstance(value, list):
        for v in value:
            _no_files(v, parent)


def outbound(raw):
    if not isinstance(raw, dict) or raw.get("type") not in PROTOCOLS:
        raise UserError("Неподдерживаемый тип соединения.")
    o = copy.deepcopy(raw)
    t = o["type"]
    unknown = set(o) - COMMON_FIELDS - FIELDS[t]
    if unknown:
        raise UserError("Неподдерживаемые поля профиля: " + ", ".join(sorted(unknown)))
    _no_files(o)
    tls = o.get("tls", {})
    if tls.get("insecure") or tls.get("disable_sni"):
        raise UserError("Отключение проверки TLS/SNI не допускается.")
    if tls.get("reality") and tls["reality"].get("private_key"):
        raise UserError("Нужен клиентский профиль REALITY с публичным ключом.")
    if t == "wireguard":
        if not o.get("private_key") or not o.get("address") or not o.get("peers"):
            raise UserError("WireGuard: нужны PrivateKey, Address и Peer.")
        if o.get("system") or o.get("name"):
            raise UserError("Helmsman использует WireGuard без отдельного системного интерфейса.")
        for peer in o["peers"]:
            if set(peer) - {"address", "port", "public_key", "pre_shared_key", "allowed_ips", "persistent_keepalive_interval", "reserved"}:
                raise UserError("Неподдерживаемые поля Peer.")
            if not peer.get("address") or not peer.get("public_key") or not peer.get("allowed_ips"):
                raise UserError("WireGuard: неполный Peer.")
            _port(peer.get("port"))
        if "amnezia_wg" in o and set(o["amnezia_wg"]) - set(AWG_JSON.values()):
            raise UserError("Неизвестные параметры AmneziaWG.")
    elif t == "openvpn-client":
        if o.get("mode", "tls") != "tls" or o.get("system") or o.get("name"):
            raise UserError("Поддерживается OpenVPN TLS в userspace-режиме.")
        if not o.get("server") and not o.get("servers"):
            raise UserError("OpenVPN: не задан сервер.")
        if not o.get("tls", {}).get("certificate") and not o.get("tls", {}).get("peer_fingerprint"):
            raise UserError("OpenVPN: нужен встроенный CA или SHA-256 отпечаток сервера.")
        if o.get("tls", {}).get("remote_certificate_tls", "server") != "server":
            raise UserError("OpenVPN: требуется проверка назначения сертификата сервера.")
    else:
        if not isinstance(o.get("server"), str) or not o["server"] or any(c.isspace() for c in o["server"]):
            raise UserError("Не задан адрес сервера.")
        _port(o.get("server_port"))
    o.pop("tag", None)
    return o


def _port(p):
    if not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535:
        raise UserError("Порт должен быть от 1 до 65535.")


def profile(o, name=""):
    o = outbound(o)
    return {"id": identifier(), "name": label(name or o.get("server") or o["type"]), "kind": "sing-box", "outbound": o}


def _tls(q, required=False):
    security = q.get("security", "tls" if required else "none")
    if security not in {"tls", "reality", "none", ""}:
        raise UserError("Неизвестный режим TLS.")
    if required or security in {"tls", "reality"}:
        t = {"enabled": True}
        if q.get("sni") or q.get("peer"):
            t["server_name"] = q.get("sni") or q["peer"]
        if q.get("alpn"):
            t["alpn"] = q["alpn"].split(",")
        if q.get("fp") or security == "reality":
            t["utls"] = {"enabled": True, "fingerprint": q.get("fp", "chrome")}
        if security == "reality":
            if not q.get("pbk"):
                raise UserError("REALITY: не задан публичный ключ.")
            t["reality"] = {"enabled": True, "public_key": q["pbk"], "short_id": q.get("sid", "")}
        if q.get("insecure", q.get("allowInsecure", "0")) in {"1", "true"}:
            raise UserError("Профиль отключает проверку TLS. Исправьте сертификат сервера.")
        return t
    return None


def uri(s):
    u = urlsplit(s)
    if u.scheme == "ss" and "@" not in u.netloc:
        decoded = b64(u.netloc).decode()
        return uri("ss://" + decoded + ("#" + u.fragment if u.fragment else ""))
    if u.scheme == "zerotier":
        network = u.netloc or u.path
        if not re.fullmatch(r"[0-9a-fA-F]{16}", network):
            raise UserError("ZeroTier Network ID: 16 шестнадцатеричных символов.")
        return {"id": identifier(), "name": label(unquote(u.fragment) or "ZeroTier"), "kind": "zerotier", "network_id": network.lower()}
    if u.scheme == "vmess":
        v = json.loads(b64(s[8:]).decode())
        if v.get("net", "tcp") not in {"tcp", "ws", "grpc", "http", "httpupgrade"}:
            raise UserError("VMess: неподдерживаемый транспорт.")
        q = {"type": v.get("net", "tcp"), "path": v.get("path", ""), "host": v.get("host", ""), "security": v.get("tls", "none"), "sni": v.get("sni", "")}
        o = {"type": "vmess", "server": v["add"], "server_port": int(v["port"]), "uuid": v["id"], "security": v.get("scy", "auto"), "alter_id": int(v.get("aid", 0))}
        _transport(o, q)
        if t := _tls(q):
            o["tls"] = t
        return profile(o, v.get("ps", ""))
    q = {k: v[-1] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
    known = {"security", "type", "sni", "peer", "alpn", "fp", "pbk", "sid", "spx", "flow", "encryption", "path", "host", "serviceName", "mode", "insecure", "allowInsecure", "obfs", "obfs-password", "upmbps", "downmbps", "auth", "protocol", "mport", "ports", "username", "password", "congestion_control", "udp_relay_mode"}
    if set(q) - known:
        raise UserError("Параметры ссылки требуют отдельной поддержки: " + ", ".join(sorted(set(q) - known)))
    t = {"hy2": "hysteria2", "ss": "shadowsocks", "socks5": "socks", "https": "http"}.get(u.scheme, u.scheme)
    if t not in PROTOCOLS - {"wireguard", "openvpn-client"}:
        raise UserError("Неподдерживаемая ссылка: " + u.scheme)
    o = {"type": t, "server": u.hostname, "server_port": u.port or (443 if t in {"hysteria2", "tuic", "trojan", "anytls", "http"} else 1080)}
    if t in {"vless", "vmess", "tuic"}:
        o["uuid"] = str(uuid.UUID(unquote(u.username or "")))
    if t == "vless":
        if q.get("encryption", "none") != "none":
            raise UserError("VLESS encryption не поддерживается основным движком.")
        if q.get("flow"):
            o["flow"] = q["flow"]
        _transport(o, q)
    elif t == "shadowsocks":
        auth = unquote(u.username or "") + (":" + unquote(u.password) if u.password is not None else "")
        if ":" not in auth:
            auth = b64(auth).decode()
        o["method"], o["password"] = auth.split(":", 1)
    elif t == "hysteria":
        if q.get("protocol", "udp") != "udp":
            raise UserError("Hysteria1 поддерживается только поверх UDP.")
        o.update(auth_str=q.get("auth", unquote(u.username or "")), up_mbps=int(q.get("upmbps", 20)), down_mbps=int(q.get("downmbps", 100)))
        if q.get("obfs"):
            o["obfs"] = q["obfs"]
    elif t in {"trojan", "hysteria2", "anytls", "tuic"}:
        o["password"] = unquote(u.password or "") if t == "tuic" else unquote(u.netloc.rsplit("@", 1)[0])
        if t == "hysteria2":
            if q.get("obfs"):
                o["obfs"] = {"type": q["obfs"], "password": q.get("obfs-password", "")}
            if q.get("mport") or q.get("ports"):
                o["server_ports"] = (q.get("mport") or q["ports"]).split(",")
        if t == "tuic":
            for k in ("congestion_control", "udp_relay_mode"):
                if k in q:
                    o[k] = q[k]
    elif t in {"socks", "http"}:
        if u.username is not None:
            o.update(username=unquote(u.username), password=unquote(u.password or ""))
        if t == "socks":
            o["version"] = "5"
    if tls := _tls(q, t in {"hysteria", "hysteria2", "trojan", "tuic", "anytls"} or u.scheme == "https"):
        o["tls"] = tls
    return profile(o, unquote(u.fragment))


def _transport(o, q):
    t = q.get("type", "tcp")
    if t == "tcp":
        return
    if t not in {"ws", "grpc", "http", "httpupgrade", "quic"}:
        raise UserError("Транспорт " + t + " пока не поддерживается; используйте TCP/WS/gRPC/HTTPUpgrade.")
    v = {"type": t}
    if t == "grpc":
        v["service_name"] = q.get("serviceName", q.get("path", ""))
    elif t in {"ws", "http", "httpupgrade"}:
        v["path"] = q.get("path", "/")
        if q.get("host"):
            if t == "ws":
                v["headers"] = {"Host": q["host"]}
            else:
                v["host"] = q["host"].split(",") if t == "http" else q["host"]
    o["transport"] = v


def wireguard(text, name="WireGuard"):
    interface, peers, current = {}, [], None
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if line == "[Interface]":
            if interface:
                raise UserError("Повторная секция Interface.")
            current = interface
        elif line == "[Peer]":
            current = {}
            peers.append(current)
        elif current is not None and "=" in line:
            k, v = line.split("=", 1)
            k = k.strip().lower()
            if k in current:
                raise UserError("Повторный параметр WireGuard: " + k)
            current[k] = v.strip()
        else:
            raise UserError("Некорректная строка WireGuard.")
    if set(interface) - {"privatekey", "address", "dns", "mtu", "listenport"} - AWG_KEYS.keys():
        raise UserError("WireGuard: скрипты PostUp/PostDown, Table и неизвестные параметры не поддерживаются.")
    o = {"type": "wireguard", "private_key": interface.get("privatekey", ""), "address": [str(ipaddress.ip_interface(x.strip())) for x in interface.get("address", "").split(",") if x.strip()], "peers": [], "mtu": int(interface.get("mtu", 1280)), "workers": 2}
    for p in peers:
        if set(p) - {"endpoint", "publickey", "presharedkey", "persistentkeepalive", "allowedips"}:
            raise UserError("WireGuard: неизвестные параметры Peer.")
        u = urlsplit("udp://" + p.get("endpoint", ""))
        peer = {"address": u.hostname, "port": u.port, "public_key": p.get("publickey", ""), "allowed_ips": [str(ipaddress.ip_network(x.strip(), strict=False)) for x in p.get("allowedips", "").split(",") if x.strip()]}
        if p.get("presharedkey"):
            peer["pre_shared_key"] = p["presharedkey"]
        if p.get("persistentkeepalive"):
            peer["persistent_keepalive_interval"] = int(p["persistentkeepalive"])
        o["peers"].append(peer)
    awg = {}
    for k, v in interface.items():
        if k in AWG_KEYS:
            awg[AWG_JSON[k]] = int(v) if k in {"jc", "jmin", "jmax", "s1", "s2", "s3", "s4"} else v
    if awg:
        o["amnezia_wg"] = awg
        name = name.replace("WireGuard", "AmneziaWG")
    result = profile(o, name)
    if interface.get("dns"):
        # A profile DNS can be private, e.g. split corporate DNS. Use first IP, reject search domains.
        result["dns"] = str(ipaddress.ip_address(interface["dns"].split(",")[0].strip()))
    return result


def openvpn(text, name="OpenVPN"):
    """Deliberately bounded .ovpn dialect. Unknown directives fail, never execute."""
    o = {"type": "openvpn-client", "mode": "tls", "tls": {"remote_certificate_tls": "server"}, "route_no_pull": True}
    blocks = {}
    def take(m):
        blocks[m[1]] = m[2].strip()
        return ""
    rest = re.sub(r"<([a-z-]+)>\s*([\s\S]*?)</\1>", take, text)
    if set(blocks) - {"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "auth-user-pass"}:
        raise UserError("OpenVPN: неподдерживаемый inline-блок.")
    ignored = {"client", "tls-client", "nobind", "persist-key", "persist-tun", "resolv-retry", "verb", "mute", "route", "route-ipv6", "redirect-gateway", "dhcp-option", "pull", "route-nopull", "auth-nocache", "explicit-exit-notify"}
    remotes, proto, direction, legacy_cipher = [], "udp", "", ""
    for line in rest.splitlines():
        tokens = shlex.split(line, comments=True)
        if not tokens or tokens[0].startswith(";"):
            continue
        k, *v = tokens
        if k in ignored:
            continue
        if k == "remote" and 1 <= len(v) <= 3:
            remotes.append({"server": v[0], "server_port": int(v[1]) if len(v) > 1 else 1194, "network": v[2].replace("-client", "") if len(v) > 2 else ""})
        elif k == "proto" and len(v) == 1:
            proto = v[0].replace("-client", "")
        elif k == "dev" and len(v) == 1 and v[0].startswith("tun"):
            continue
        elif k in {"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"} and v and v[0] == "[inline]":
            if len(v) > 1:
                direction = v[1]
        elif k == "remote-cert-tls" and v == ["server"]:
            continue
        elif k == "key-direction" and len(v) == 1:
            direction = v[0]
        elif k == "verify-x509-name" and 1 <= len(v) <= 2:
            o["tls"].update(server_name=v[0], server_name_type=v[1] if len(v) > 1 else "subject")
        elif k == "auth-user-pass" and not v:
            if "auth-user-pass" not in blocks:
                raise UserError("OpenVPN: добавьте inline-блок <auth-user-pass> с логином и паролем или импортируйте JSON-профиль.")
        elif k == "cipher" and len(v) == 1:
            legacy_cipher = v[0]
        elif k in {"auth", "data-ciphers-fallback"} and len(v) == 1:
            o[k.replace("-", "_")] = v[0]
        elif k == "data-ciphers" and len(v) == 1:
            o["data_ciphers"] = v[0].split(":")
        elif k in {"tun-mtu", "mssfix"} and len(v) == 1:
            o["mtu" if k == "tun-mtu" else "mss_fix"] = int(v[0])
        elif k in {"ping", "ping-restart", "reneg-sec"} and len(v) == 1:
            o[{"ping": "ping_interval", "ping-restart": "ping_restart", "reneg-sec": "renegotiate_interval"}[k]] = str(int(v[0])) + "s"
        elif k == "tls-version-min" and len(v) == 1:
            o["tls"]["version_min"] = v[0]
        else:
            raise UserError("OpenVPN: директива не поддерживается: " + k + ". Нужен автономный TLS .ovpn без скриптов и внешних файлов.")
    if not remotes or proto not in {"udp", "udp4", "udp6", "tcp", "tcp4", "tcp6"}:
        raise UserError("OpenVPN: нужен remote и UDP/TCP.")
    for r in remotes:
        r["network"] = r["network"] or proto
    o["servers"] = remotes
    o["network"] = proto
    if legacy_cipher:
        o.setdefault("data_ciphers_fallback", legacy_cipher)
    for a, b in {"ca": "certificate", "cert": "client_certificate", "key": "client_key"}.items():
        if a in blocks:
            o["tls"][b] = [blocks[a]]
    for key in ("tls-auth", "tls-crypt", "tls-crypt-v2"):
        if key in blocks:
            o["tls"]["control_wrap"] = {"type": key.replace("-", "_"), "key": [blocks[key]]}
            if key == "tls-auth" and direction:
                o["tls"]["control_wrap"]["direction"] = {"0": "server", "1": "client"}.get(direction, direction)
    if "auth-user-pass" in blocks:
        credentials = blocks["auth-user-pass"].splitlines()
        if len(credentials) != 2:
            raise UserError("OpenVPN: в auth-user-pass нужны две строки.")
        o.update(username=credentials[0], password=credentials[1])
    return profile(o, name)


def _amnezia(obj):
    # Self-hosted client exports only. API/Gateway/admin keys are different contracts.
    results = []
    for container in obj.get("containers", []):
        for t in ("awg", "wireguard", "openvpn"):
            if t not in container:
                continue
            last = container[t].get("last_config", {})
            if isinstance(last, str):
                last = json.loads(last)
            if isinstance(last, dict) and last.get("config"):
                results.extend(parse(last["config"]))
            elif t in {"awg", "wireguard"} and isinstance(last, dict) and last.get("client_priv_key"):
                ips = last.get("allowed_ips", ["0.0.0.0/0", "::/0"])
                if isinstance(ips, str):
                    ips = ips.split(",")
                host = obj.get("hostName", obj.get("host_name", ""))
                port = container[t].get("port", 51820)
                conf = f"[Interface]\nPrivateKey={last['client_priv_key']}\nAddress={last['client_ip']}\nMTU={last.get('mtu',1280)}\n"
                for key in AWG_KEYS.values():
                    if key in last:
                        conf += f"{key}={last[key]}\n"
                endpoint = f"[{host}]" if ":" in host else host
                conf += f"[Peer]\nPublicKey={last['server_pub_key']}\nEndpoint={endpoint}:{port}\nAllowedIPs={','.join(ips)}\n"
                if last.get("psk_key"):
                    conf += "PresharedKey=" + last["psk_key"] + "\n"
                results.append(wireguard(conf, obj.get("description", "Amnezia")))
            else:
                raise UserError("Этот экспорт Amnezia не содержит готовой клиентской конфигурации. Экспортируйте WireGuard/AmneziaWG .conf или OpenVPN .ovpn.")
    if not results:
        raise UserError("Ключ Amnezia API/Gateway/администратора или неподдерживаемый контейнер. Экспортируйте готовую конфигурацию нужного протокола.")
    return results


def parse(text, depth=0):
    if depth > 3 or not isinstance(text, str) or len(text.encode()) > MAX_BYTES:
        raise UserError("Слишком большой или вложенный импорт (лимит 8 МиБ).")
    text = text.strip().lstrip("\ufeff")
    if not text:
        raise UserError("Пустой импорт.")
    try:
        if text.startswith("vpn://"):
            data = b64(text[6:])
            if len(data) < 6 or struct.unpack(">I", data[:4])[0] > MAX_BYTES:
                raise UserError("Некорректный размер экспорта Amnezia.")
            decompressor = zlib.decompressobj()
            decoded = decompressor.decompress(data[4:], MAX_BYTES + 1)
            if len(decoded) > MAX_BYTES or not decompressor.eof:
                raise UserError("Экспорт Amnezia повреждён или слишком велик.")
            return _amnezia(json.loads(decoded))
        if text.startswith("[Interface]"):
            return [wireguard(text)]
        if re.search(r"(?m)^\s*(client|remote|dev tun)\b", text):
            return [openvpn(text)]
        if text.startswith(("{", "[")):
            obj = json.loads(text)
            if isinstance(obj, dict) and "containers" in obj:
                return _amnezia(obj)
            items = obj if isinstance(obj, list) else obj.get("outbounds", obj.get("endpoints", [obj]))
            if isinstance(obj, dict) and "outbounds" in obj and "endpoints" in obj:
                items = items + obj["endpoints"]
            results = [profile(x, x.get("tag", "")) for x in items if x.get("type") not in {"direct", "block", "dns", "selector", "urltest"}]
            if not results:
                raise UserError("В JSON нет поддерживаемых соединений.")
            return results
        lines = [x.strip() for x in text.splitlines() if x.strip() and not x.strip().startswith("#")]
        if all("://" in line for line in lines):
            return [uri(line) for line in lines]
        return parse(b64("".join(lines)).decode(), depth + 1)
    except UserError:
        raise
    except (ValueError, KeyError, TypeError, UnicodeError, zlib.error, AttributeError, OverflowError):
        raise UserError("Не удалось разобрать конфигурацию. Проверьте формат и обязательные параметры; исходные данные не изменены.") from None
