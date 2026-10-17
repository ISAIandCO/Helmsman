"""Bounded Xray XHTTP/mux connection data; system policy belongs to sing-box."""
import copy
from .common import UserError

EXTRA_FIELDS = set("headers xPaddingBytes xPaddingObfsMode xPaddingKey xPaddingHeader xPaddingPlacement xPaddingMethod uplinkHTTPMethod sessionIDPlacement sessionIDKey sessionIDTable sessionIDLength seqPlacement seqKey uplinkDataPlacement uplinkDataKey uplinkChunkSize noGRPCHeader noSSEHeader scMaxEachPostBytes scMinPostsIntervalMs scMaxBufferedPosts scStreamUpServerSecs serverMaxHeaderBytes xmux downloadSettings".split())
XMUX_FIELDS = set("maxConcurrency maxConnections cMaxReuseTimes hMaxRequestTimes hMaxReusableSecs hKeepAlivePeriod".split())


def is_xhttp(profile):
    return profile.get("outbound", {}).get("transport", {}).get("type") in {"xhttp", "splithttp"}


def uses_xray(profile):
    o = profile.get("outbound", {})
    return is_xhttp(profile) or "xray_mux" in o


def mux_settings(value):
    only(value, {"enabled", "concurrency", "xudpConcurrency", "xudpProxyUDP443"}, "Xray mux")
    if "enabled" in value and type(value["enabled"]) is not bool:
        raise UserError("Xray mux enabled должен быть логическим.")
    for key in ("concurrency", "xudpConcurrency"):
        if key in value and (type(value[key]) is not int or not -32768 <= value[key] <= 32767):
            raise UserError("Xray mux: concurrency/xudpConcurrency должны быть целыми int16.")
    if value.get("xudpProxyUDP443", "reject") not in {"reject", "allow", "skip"}:
        raise UserError("Xray mux xudpProxyUDP443: reject, allow или skip.")
    return copy.deepcopy(value)


def only(value, fields, name):
    if not isinstance(value, dict) or set(value) - set(fields):
        raise UserError(name + ": неизвестные или небезопасные параметры.")


def native_tls(value, reality=False):
    allowed = {"fingerprint", "serverName", "alpn", "useSystemCA", "allowInsecure"} if not reality else {"fingerprint", "serverName", "publicKey", "password", "shortId", "spiderX", "mldsa65Verify", "show"}
    only(value, allowed, "TLS/REALITY")
    if value.get("allowInsecure"):
        raise UserError("Отключение проверки TLS не допускается.")
    return copy.deepcopy(value)


def xhttp_settings(value, depth=0):
    only(value, EXTRA_FIELDS | {"host", "path", "mode", "extra"}, "XHTTP")
    if depth > 2:
        raise UserError("Слишком много вложенных downloadSettings XHTTP.")
    result = copy.deepcopy(value)
    if result.get("mode", "auto") not in {"auto", "packet-up", "stream-up", "stream-one"}:
        raise UserError("XHTTP mode: auto, packet-up, stream-up или stream-one.")
    if "extra" in result:
        only(result["extra"], EXTRA_FIELDS, "XHTTP extra")
        result["extra"] = xhttp_settings(result["extra"], depth + 1)
    if "xmux" in result:
        only(result["xmux"], XMUX_FIELDS, "XHTTP xmux")
    if "downloadSettings" in result:
        d = result["downloadSettings"]
        only(d, {"address", "port", "network", "security", "tlsSettings", "realitySettings", "xhttpSettings", "splithttpSettings"}, "XHTTP downloadSettings")
        if d.get("network", "xhttp") not in {"xhttp", "splithttp"} or d.get("security", "none") not in {"none", "tls", "reality"}:
            raise UserError("downloadSettings: нужен XHTTP с TLS/REALITY или без TLS.")
        for k in ("xhttpSettings", "splithttpSettings"):
            if k in d:
                d[k] = xhttp_settings(d[k], depth + 1)
        for k in ("tlsSettings", "realitySettings"):
            if k in d:
                d[k] = native_tls(d[k], k == "realitySettings")
    return result


def stream_settings(outbound):
    t = outbound.get("transport", {})
    network = t.get("type", "tcp")
    if network in {"xhttp", "splithttp"}:
        only(t, {"type", "host", "path", "mode", "extra"} | EXTRA_FIELDS, "Транспорт XHTTP")
        stream = {"network": "xhttp", "security": "none", "xhttpSettings": xhttp_settings({k: v for k, v in t.items() if k != "type"})}
    else:
        stream = {"network": network, "security": "none"}
        if network == "tcp":
            only(t, {"type"}, "Транспорт TCP Xray")
        elif network == "ws":
            only(t, {"type", "path", "headers", "max_early_data", "early_data_header_name"}, "Транспорт WS Xray")
            stream["wsSettings"] = {"path": t.get("path", "/"), "headers": t.get("headers", {})}
            for source, target in (("max_early_data", "maxEarlyData"), ("early_data_header_name", "earlyDataHeaderName")):
                if source in t:
                    stream["wsSettings"][target] = t[source]
        elif network == "grpc":
            only(t, {"type", "service_name"}, "Транспорт gRPC Xray")
            stream["grpcSettings"] = {"serviceName": t.get("service_name", "")}
        elif network in {"http", "httpupgrade"}:
            only(t, {"type", "path", "host"}, "Транспорт HTTP Xray")
            stream["httpSettings" if network == "http" else "httpupgradeSettings"] = {"path": t.get("path", "/"), "host": t.get("host", [] if network == "http" else "")}
        else:
            raise UserError("Транспорт профиля Xray mux пока не поддерживается.")
    tls = outbound.get("tls", {})
    only(tls, {"enabled", "server_name", "alpn", "utls", "reality"}, "TLS Xray")
    only(tls.get("utls", {}), {"enabled", "fingerprint"}, "uTLS Xray")
    if tls.get("enabled"):
        reality = tls.get("reality", {})
        if reality.get("enabled"):
            only(reality, {"enabled", "public_key", "short_id", "spider_x", "mldsa65_verify"}, "REALITY Xray")
            stream["security"] = "reality"
            stream["realitySettings"] = {"serverName": tls.get("server_name", outbound["server"]), "fingerprint": tls.get("utls", {}).get("fingerprint", "chrome"), "publicKey": reality["public_key"], "shortId": reality.get("short_id", ""), "spiderX": reality.get("spider_x", "")}
            if reality.get("mldsa65_verify"):
                stream["realitySettings"]["mldsa65Verify"] = reality["mldsa65_verify"]
        else:
            stream["security"] = "tls"
            stream["tlsSettings"] = {"serverName": tls.get("server_name", outbound["server"]), "useSystemCA": True}
            if tls.get("alpn"):
                stream["tlsSettings"]["alpn"] = tls["alpn"]
            if tls.get("utls", {}).get("enabled"):
                stream["tlsSettings"]["fingerprint"] = tls["utls"]["fingerprint"]
    return stream


def socks_outbound(proxy=None):
    port, password = proxy or (1081, "check-only")
    return {"type": "socks", "server": "127.0.0.1", "server_port": port, "version": "5", "username": "helmsman", "password": password}


def compile_xray(profile, proxy=None, bootstrap="9.9.9.9", ipv6=True):
    o = profile["outbound"]
    if o["type"] not in {"vless", "vmess", "trojan"}:
        raise UserError("Xray поддерживается для VLESS, VMess и Trojan.")
    if any(k in o for k in ("multiplex", "network", "connect_timeout", "tcp_fast_open", "udp_fragment")) or o.get("packet_encoding", "xudp") != "xudp":
        raise UserError("Xray: параметры multiplex/network/socket sing-box не переносятся; используйте Xray mux или XHTTP extra/xmux.")
    mux = mux_settings(o['xray_mux']) if 'xray_mux' in o else None
    if mux and mux.get('enabled') and mux.get('concurrency', 0) >= 0 and (is_xhttp(profile) or o.get('flow', '').startswith('xtls-rprx-vision')):
        raise UserError('Xray: TCP Mux.Cool несовместим с XHTTP/Vision. В конфигурации провайдера нужен mux.concurrency=-1 или mux.enabled=false; XUDP можно сохранить. Параметры не изменены автоматически.')
    port, password = proxy or (1081, "check-only")
    if o["type"] == "trojan":
        settings = {"servers": [{"address": o["server"], "port": o["server_port"], "password": o["password"]}]}
    else:
        user = {"id": o["uuid"]}
        if o["type"] == "vless":
            user["encryption"] = "none"
            if o.get("flow"):
                user["flow"] = o["flow"]
        else:
            user.update(security=o.get("security", "auto"), alterId=o.get("alter_id", 0))
            if o.get("global_padding") or o.get("authenticated_length"):
                raise UserError("VMess XHTTP: global_padding/authenticated_length не переносятся в Xray.")
        settings = {"vnext": [{"address": o["server"], "port": o["server_port"], "users": [user]}]}
    stream = stream_settings(o)
    stream["sockopt"] = {"domainStrategy": "UseIP" if ipv6 else "UseIPv4", "penetrate": True}
    outbound = {"tag": "proxy", "protocol": o["type"], "settings": settings, "streamSettings": stream}
    if mux is not None:
        outbound["mux"] = mux
    return {"log": {"loglevel": "none", "access": "none", "error": "none"},
            "dns": {"servers": [bootstrap], "queryStrategy": "UseIP" if ipv6 else "UseIPv4"},
            "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"auth": "password", "accounts": [{"user": "helmsman", "pass": password}], "udp": True, "ip": "127.0.0.1"}}],
            "outbounds": [outbound]}


def import_outbound(raw):
    """Import one native Xray outbound, excluding routing, APIs and file paths."""
    only(raw, {"protocol", "tag", "settings", "streamSettings", "mux"}, "Xray outbound")
    mux = mux_settings(raw["mux"]) if "mux" in raw else None
    t = raw["protocol"]
    if t not in {"vless", "vmess", "trojan"}:
        raise UserError("Нативный Xray JSON: нужен VLESS, VMess, Trojan или WireGuard.")
    s = raw.get("streamSettings", {})
    only(s, {"network", "security", "xhttpSettings", "splithttpSettings", "tlsSettings", "realitySettings", "tcpSettings", "rawSettings", "wsSettings", "grpcSettings", "httpSettings", "httpupgradeSettings"}, "Xray streamSettings")
    network = s.get("network", "tcp")
    if network not in {"tcp", "raw", "ws", "grpc", "http", "h2", "httpupgrade", "xhttp", "splithttp"}:
        raise UserError("Неподдерживаемый транспорт Xray JSON.")
    settings = raw["settings"]
    only(settings, {"servers"} if t == "trojan" else {"vnext"}, "Xray settings")
    servers = settings["servers" if t == "trojan" else "vnext"]
    if len(servers) != 1:
        raise UserError("Xray: в одном профиле нужен один сервер.")
    server = servers[0]
    only(server, {"address", "port", "password"} if t == "trojan" else {"address", "port", "users"}, "Xray server")
    o = {"type": t, "server": server["address"], "server_port": server["port"]}
    if network in {"xhttp", "splithttp"}:
        o["transport"] = {"type": "xhttp", **xhttp_settings(s.get("xhttpSettings", s.get("splithttpSettings", {})))}
    elif network in {"tcp", "raw"}:
        tcp = s.get("tcpSettings", s.get("rawSettings", {}))
        only(tcp, {"header"}, "Xray TCP")
        if tcp.get("header", {"type": "none"}) != {"type": "none"}:
            raise UserError("TCP header: поддерживается только none.")
    else:
        field = {"ws": "wsSettings", "grpc": "grpcSettings", "http": "httpSettings", "h2": "httpSettings", "httpupgrade": "httpupgradeSettings"}[network]
        settings_transport = s.get(field, {})
        transport = {"type": "http" if network == "h2" else network}
        if network == "grpc":
            only(settings_transport, {"serviceName", "multiMode"}, "Xray gRPC")
            if settings_transport.get("multiMode"):
                raise UserError("gRPC multiMode пока не поддерживается.")
            transport["service_name"] = settings_transport.get("serviceName", "")
        elif network == "ws":
            only(settings_transport, {"path", "headers", "maxEarlyData", "earlyDataHeaderName"}, "Xray WebSocket")
            transport.update(path=settings_transport.get("path", "/"), headers=settings_transport.get("headers", {}))
            for source, target in (("maxEarlyData", "max_early_data"), ("earlyDataHeaderName", "early_data_header_name")):
                if source in settings_transport:
                    transport[target] = settings_transport[source]
        else:
            only(settings_transport, {"path", "host"}, "Xray HTTP")
            transport.update(path=settings_transport.get("path", "/"), host=settings_transport.get("host", [] if network in {"http", "h2"} else ""))
        o["transport"] = transport
    if t == "trojan":
        o["password"] = server["password"]
    else:
        if len(server["users"]) != 1:
            raise UserError("Xray: нужен один пользователь сервера.")
        u = server["users"][0]
        only(u, {"id", "encryption", "flow", "security", "alterId", "email", "level"}, "Xray user")
        if u.get("encryption", "none") != "none":
            raise UserError("VLESS Encryption: этот формат пока не поддерживается.")
        o["uuid"] = u["id"]
        if u.get("flow"):
            o["flow"] = u["flow"]
        if t == "vmess":
            o.update(security=u.get("security", "auto"), alter_id=u.get("alterId", 0))
    security = s.get("security", "none")
    if security not in {"none", "tls", "reality"}:
        raise UserError("Xray: неизвестный режим безопасности.")
    if security != "none":
        nt = native_tls(s.get("realitySettings" if security == "reality" else "tlsSettings", {}), security == "reality")
        tls = {"enabled": True, "server_name": nt.get("serverName", server["address"])}
        if nt.get("alpn"):
            tls["alpn"] = nt["alpn"]
        if nt.get("fingerprint") or security == "reality":
            tls["utls"] = {"enabled": True, "fingerprint": nt.get("fingerprint", "chrome")}
        if security == "reality":
            tls["reality"] = {"enabled": True, "public_key": nt.get("publicKey", nt.get("password", "")), "short_id": nt.get("shortId", "")}
            if network in {"xhttp", "splithttp"} or mux is not None:
                tls["reality"]["spider_x"] = nt.get("spiderX", "")
            if nt.get("mldsa65Verify"):
                tls["reality"]["mldsa65_verify"] = nt["mldsa65Verify"]
        o["tls"] = tls
    if mux is not None and (mux.get("enabled") or set(mux) - {"enabled"}):
        o["xray_mux"] = mux
    return o
