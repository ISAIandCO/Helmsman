"""Dynamic membership and stable selection; probes use the existing Runtime."""
import re

from .common import UserError, defaults as state_defaults

GROUP_ID = "vpn-auto"
PROTOCOLS = ("vless", "hysteria2", "hysteria", "trojan", "vmess", "shadowsocks",
             "tuic", "anytls", "socks", "http", "wireguard", "amneziawg", "openvpn-client")


def defaults():
    return state_defaults()["fastest"]


def validate(raw, previous):
    if not isinstance(raw, dict) or set(raw) - (defaults().keys() - {"active"}):
        raise UserError("VPN: неизвестный параметр группы.")
    value = {**previous, **raw}
    pattern = value["regex"]
    if not isinstance(pattern, str) or not pattern.strip() or len(pattern) > 512:
        raise UserError("VPN: regex должен содержать от 1 до 512 символов.")
    try:
        re.compile(pattern)
    except re.error:
        raise UserError("VPN: некорректное регулярное выражение.") from None
    protocols = value["protocols"]
    if not isinstance(protocols, list) or any(p not in PROTOCOLS for p in protocols):
        raise UserError("VPN: неизвестный протокол.")
    value["protocols"] = list(dict.fromkeys(protocols))
    for key, low, high in (("interval_seconds", 60, 3600), ("tolerance_ms", 0, 2000), ("switch_seconds", 60, 3600)):
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise UserError("VPN: интервал и пауза 60–3600 с, порог 0–2000 мс.")
    return value


def protocol(profile):
    outbound = profile.get("outbound", {})
    return "amneziawg" if outbound.get("amnezia_wg") else outbound.get("type", "zerotier")


def candidates(state):
    group = state["fastest"]
    pattern = re.compile(group["regex"])
    return [p for p in state["profiles"] if p["kind"] == "sing-box"
            and (not group["protocols"] or protocol(p) in group["protocols"])
            and pattern.search(p["name"])]


def choose(results, current, group, elapsed):
    """Only successful end-to-end results qualify; failure bypasses hysteresis."""
    working = {key: r["duration_ms"] for key, r in results.items() if r.get("ok")}
    if not working:
        return ""
    best = min(working, key=working.get)
    if current in working and (elapsed < group["switch_seconds"] or working[current] - working[best] <= group["tolerance_ms"]):
        return current
    return best
