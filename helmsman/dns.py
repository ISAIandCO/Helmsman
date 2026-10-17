"""Encrypted resolvers shared by the service and desktop picker."""
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from .common import UserError

# Official endpoint references are recorded in README; no availability promise.
DNS_PRESETS = (
    ("Cloudflare · DoH · без фильтра", "https://cloudflare-dns.com/dns-query"),
    ("Cloudflare · DoT · без фильтра", "tls://one.one.one.one"),
    ("Quad9 · DoH · защита от вредоносных доменов", "https://dns.quad9.net/dns-query"),
    ("Quad9 · DoT · защита от вредоносных доменов", "tls://dns.quad9.net"),
    ("Google · DoH · без фильтра", "https://dns.google/dns-query"),
    ("Google · DoT · без фильтра", "tls://dns.google"),
    ("AdGuard · DoH · блокировка рекламы и трекеров", "https://dns.adguard-dns.com/dns-query"),
    ("AdGuard · DoT · блокировка рекламы и трекеров", "tls://dns.adguard-dns.com"),
)


def bootstrap_address(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        raise UserError("Начальный DNS: укажите IPv4 или IPv6 адрес.") from None


def resolver_url(value):
    """Validate without looking up names; never include private URLs in errors."""
    try:
        if not isinstance(value, str) or not 1 <= len(value) <= 4096:
            raise ValueError()
        value = value.strip()
        if any(c.isspace() or ord(c) < 32 for c in value) or "\\" in value:
            raise ValueError()
        # Compatibility with pre-release settings which stored only a DoH IP.
        try:
            address = ipaddress.ip_address(value)
            value = "https://" + ("[" + str(address) + "]" if address.version == 6 else str(address)) + "/dns-query"
        except ValueError:
            pass
        u = urlsplit(value)
        scheme = "tls" if u.scheme == "dot" else u.scheme
        if scheme not in {"https", "tls"} or not u.hostname or u.username is not None or u.password is not None or u.fragment:
            raise ValueError()
        host = u.hostname
        try:
            ip = ipaddress.ip_address(host)
            host = "[" + str(ip) + "]" if ip.version == 6 else str(ip)
        except ValueError:
            host = host.encode("idna").decode().lower().rstrip(".")
            if len(host) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) or any(not x or len(x) > 63 or x.startswith("-") or x.endswith("-") for x in host.split(".")):
                raise ValueError()
        port = u.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError()
        if u.netloc.endswith(":") or "%" in host:
            raise ValueError()
        if scheme == "tls" and (u.path not in {"", "/"} or u.query):
            raise ValueError()
        return urlunsplit((scheme, host + (":" + str(port) if port else ""), (u.path or "/dns-query") if scheme == "https" else "", u.query, ""))
    except (ValueError, UnicodeError):
        raise UserError("DNS: нужен DoH URL https://сервер/dns-query или DoT tls://сервер[:порт]. Логин и фрагмент URL не поддерживаются.") from None


def dns_server(value, tag, proxy=False):
    u = urlsplit(resolver_url(value))
    host = u.hostname
    # Quad9 certificates use the hostname, including for old numeric settings.
    name = "dns.quad9.net" if host in {"9.9.9.9", "149.112.112.112"} else host
    result = {"type": "https" if u.scheme == "https" else "tls", "tag": tag,
              "server": host, "server_port": u.port or (443 if u.scheme == "https" else 853),
              "tls": {"enabled": True, "server_name": name},
              "domain_resolver": {"server": "bootstrap", "strategy": "prefer_ipv4"}}
    if u.scheme == "https":
        result["path"] = u.path + ("?" + u.query if u.query else "")
    if proxy:
        result["detour"] = "proxy"
    return result
