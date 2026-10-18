"""Bounded Xray client data; system policy belongs to sing-box."""
import copy
from .common import UserError

EXTRA_FIELDS = set("headers xPaddingBytes xPaddingObfsMode xPaddingKey xPaddingHeader xPaddingPlacement xPaddingMethod uplinkHTTPMethod sessionIDPlacement sessionIDKey sessionIDTable sessionIDLength seqPlacement seqKey uplinkDataPlacement uplinkDataKey uplinkChunkSize noGRPCHeader noSSEHeader scMaxEachPostBytes scMinPostsIntervalMs scMaxBufferedPosts scStreamUpServerSecs serverMaxHeaderBytes xmux downloadSettings".split())
XMUX_FIELDS = set("maxConcurrency maxConnections cMaxReuseTimes hMaxRequestTimes hMaxReusableSecs hKeepAlivePeriod".split())
CLIENT_PROTOCOLS = {'vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http'}
STREAM_FIELDS = set('network method security xhttpSettings splithttpSettings tlsSettings realitySettings tcpSettings rawSettings wsSettings grpcSettings httpSettings httpupgradeSettings hysteriaSettings sockopt'.split())
EMPTY_STREAM_FIELDS = set('address port finalmask kcpSettings quicSettings dsSettings gunSettings masqueSettings xdriveSettings xtlsSettings'.split())
SOCKET_DEFAULTS = {'mark': (0,), 'interface': ('',), 'dialerProxy': ('',), 'tproxy': ('', 'off'), 'acceptProxyProtocol': (False,), 'trustedXForwardedFor': ([],), 'v6only': (False,), 'tcpMptcp': (False,), 'customSockopt': ([],), 'addressPortStrategy': ('', 'none'), 'penetrate': (False, True)}
SOCKET_INTS = {'tcpFastOpen': (-2147483648, 2147483647), 'tcpKeepAliveIdle': (-2147483648, 2147483647), 'tcpKeepAliveInterval': (-2147483648, 2147483647), 'tcpUserTimeout': (0, 2147483647), 'tcpMaxSeg': (0, 65535), 'tcpWindowClamp': (0, 2147483647)}
SOCKET_FIELDS = set(SOCKET_DEFAULTS) | set(SOCKET_INTS) | {'domainStrategy', 'tcpCongestion', 'happyEyeballs'}


def protocol_label(value):
    # Never echo arbitrary provider text: this field can contain a private token.
    return value if isinstance(value, str) and value in CLIENT_PROTOCOLS | {'hysteria', 'wireguard', 'loopback', 'freedom', 'blackhole', 'dns', 'shadowsocksr', 'dokodemo-door'} else 'неизвестный'


def is_xhttp(profile):
    return profile.get("outbound", {}).get("transport", {}).get("type") in {"xhttp", "splithttp"}


def uses_xray(profile):
    o = profile.get("outbound", {})
    return is_xhttp(profile) or "xray_mux" in o or bool(o.get('xray_sockopt')) or (o.get('type') in {'shadowsocks', 'socks'} and bool(o.get('transport') or o.get('tls', {}).get('enabled')))


def mux_settings(value):
    only(value, {"enabled", "concurrency", "xudpConcurrency", "xudpProxyUDP443"}, "Xray mux")
    if "enabled" in value and type(value["enabled"]) is not bool:
        raise UserError("Xray mux enabled должен быть логическим.")
    for key in ("concurrency", "xudpConcurrency"):
        if key in value and (type(value[key]) is not int or not -32768 <= value[key] <= 32767):
            raise UserError("Xray mux: concurrency/xudpConcurrency должны быть целыми int16.")
    if value.get("xudpProxyUDP443", "reject") not in {"", "reject", "allow", "skip"}:
        raise UserError("Xray mux xudpProxyUDP443: reject, allow или skip.")
    return copy.deepcopy(value)


def only(value, fields, name, known=()):
    if not isinstance(value, dict):
        raise UserError(name + ': нужен JSON-объект.')
    unknown = set(value) - set(fields)
    if unknown:
        # Show schema names, never arbitrary provider keys or their values.
        names = sorted(unknown & set(known))
        if unknown - set(known): names.append('нераспознанных полей: ' + str(len(unknown - set(known))))
        raise UserError(name + ': неподдерживаемые параметры' + (' — ' + ', '.join(names) if names else '') + '.')


def socket_settings(value):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise UserError('Xray sockopt: нужен JSON-объект.')
    aliases = {f.lower(): f for f in SOCKET_FIELDS}
    normalized = {}
    for key, item in value.items():
        field = aliases.get(key.lower())
        if field is None:
            raise UserError('Xray sockopt: нераспознанный параметр; имя и значение скрыты.')
        if field in normalized:
            raise UserError('Xray sockopt: повторяющийся параметр ' + field + '.')
        normalized[field] = item
    result = {}
    for key, item in normalized.items():
        if item is None:
            continue  # Optional Go JSON fields accept null as their default.
        if key in SOCKET_DEFAULTS:
            defaults = SOCKET_DEFAULTS[key]
            if type(item) is not type(defaults[0]) or item not in defaults:
                reason = 'цепочки через другой outbound пока не поддерживаются' if key == 'dialerProxy' else 'этим системным параметром управляет Helmsman; допускается только выключенное/пустое значение'
                raise UserError('Xray sockopt.' + key + ': ' + reason + '.')
        elif key in SOCKET_INTS:
            low, high = SOCKET_INTS[key]
            if not (key == 'tcpFastOpen' and type(item) is bool) and (type(item) is not int or not low <= item <= high):
                raise UserError('Xray sockopt.' + key + ': некорректное целое значение.')
            result[key] = item
        elif key == 'domainStrategy':
            strategies = ('AsIs', 'UseIP', 'UseIPv4', 'UseIPv6', 'UseIPv4v6', 'UseIPv6v4', 'ForceIP', 'ForceIPv4', 'ForceIPv6', 'ForceIPv4v6', 'ForceIPv6v4')
            strategy = next((s for s in strategies if isinstance(item, str) and s.lower() == item.lower()), None)
            if strategy is None and item != '':
                raise UserError('Xray sockopt.domainStrategy: неизвестная стратегия DNS.')
            if strategy not in (None, 'AsIs'):
                result[key] = strategy
        elif key == 'tcpCongestion':
            if item not in ('', 'bbr', 'cubic', 'reno'):
                raise UserError('Xray sockopt.tcpCongestion: поддерживаются bbr, cubic и reno; алгоритм должен быть доступен в ядре.')
            if item: result[key] = item
        elif key == 'happyEyeballs':
            only(item, {'tryDelayMs', 'prioritizeIPv6', 'interleave', 'maxConcurrentTry'}, 'Xray sockopt.happyEyeballs')
            for field, setting in item.items():
                maximum = {'tryDelayMs': 60000, 'interleave': 16, 'maxConcurrentTry': 64}.get(field)
                valid = type(setting) is bool if field == 'prioritizeIPv6' else type(setting) is int and 0 <= setting <= maximum
                if not valid:
                    raise UserError('Xray sockopt.happyEyeballs.' + field + ': некорректное значение.')
            if item: result[key] = copy.deepcopy(item)
    return result


def import_stream(value):
    if value is None:
        return {}
    only(value, STREAM_FIELDS | EMPTY_STREAM_FIELDS, 'Xray streamSettings', known={'xtlsSettings', 'udpSettings', 'securitySettings'})
    stream = {}
    for key, item in value.items():
        if key in EMPTY_STREAM_FIELDS:
            default = 0 if key == 'port' else '' if key == 'address' else {}
            if item is not None and (type(item) is not type(default) or item != default):
                raise UserError('Xray streamSettings.' + key + ': непустой параметр пока не поддерживается; прежняя подписка сохранена.')
        elif item is not None:
            stream[key] = copy.deepcopy(item)
    return stream


def native_tls(value, reality=False):
    if value is None: value = {}
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
    if o["type"] not in CLIENT_PROTOCOLS:
        raise UserError("Xray: неподдерживаемый тип соединения «" + protocol_label(o['type']) + "».")
    if any(k in o for k in ("multiplex", "network", "connect_timeout", "tcp_fast_open", "udp_fragment", "udp_over_tcp")) or o.get("packet_encoding", "xudp") != "xudp":
        raise UserError("Xray: параметры multiplex/network/socket sing-box не переносятся; используйте Xray mux или XHTTP extra/xmux.")
    if o['type'] == 'socks' and o.get('version', '5') != '5':
        raise UserError('Xray: поддерживается SOCKS5.')
    mux = mux_settings(o['xray_mux']) if 'xray_mux' in o else None
    if mux and mux.get('enabled') and mux.get('concurrency', 0) >= 0 and (is_xhttp(profile) or o.get('flow', '').startswith('xtls-rprx-vision')):
        raise UserError('Xray: TCP Mux.Cool несовместим с XHTTP/Vision. В конфигурации провайдера нужен mux.concurrency=-1 или mux.enabled=false; XUDP можно сохранить. Параметры не изменены автоматически.')
    port, password = proxy or (1081, "check-only")
    if o['type'] in {'shadowsocks', 'socks', 'http'}:
        server = {'address': o['server'], 'port': o['server_port']}
        if o['type'] == 'shadowsocks':
            server.update(method=o['method'], password=o['password'])
        elif o.get('username'):
            server['users'] = [{'user': o['username'], 'pass': o.get('password', '')}]
        settings = {'servers': [server]}
        if o['type'] == 'http' and o.get('headers'):
            settings['headers'] = o['headers']
    elif o["type"] == "trojan":
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
    sockopt = socket_settings(o.get('xray_sockopt'))
    # The app owns bootstrap DNS, IPv6 policy and route-loop prevention.
    sockopt.update(domainStrategy=sockopt.get('domainStrategy', 'UseIP') if ipv6 else 'UseIPv4', penetrate=True)
    stream["sockopt"] = sockopt
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
    mux = mux_settings(raw["mux"]) if raw.get('mux') is not None else None
    t = raw["protocol"]
    if not isinstance(t, str) or t not in CLIENT_PROTOCOLS | {'hysteria'}:
        raise UserError('Нативный Xray JSON: протокол «' + protocol_label(t) + '» пока не поддерживается. Выберите URI/Base64 или sing-box JSON; прежние профили сохранены.')
    s = import_stream(raw.get('streamSettings'))
    sockopt = socket_settings(s.pop('sockopt', None))
    network = s.get('method', s.get('network', 'tcp')).lower()
    network = {'websocket': 'ws'}.get(network, network)
    if network not in {"tcp", "raw", "ws", "grpc", "http", "h2", "httpupgrade", "xhttp", "splithttp", "hysteria"}:
        raise UserError("Неподдерживаемый транспорт Xray JSON.")
    if t == 'http' and network not in {'tcp', 'raw'}:
        raise UserError('Xray HTTP CONNECT: поддерживаются TCP и TLS, без дополнительных транспортов.')
    settings = raw["settings"]
    if t == 'hysteria':
        if sockopt:
            raise UserError('Xray Hysteria2: дополнительные sockopt не переносятся; выберите hysteria2 URI или sing-box JSON.')
        only(settings, {'version', 'address', 'port'}, 'Xray Hysteria settings')
        only(s, {'network', 'method', 'security', 'tlsSettings', 'hysteriaSettings'}, 'Xray Hysteria streamSettings')
        ht = s.get('hysteriaSettings', {})
        only(ht, {'version', 'auth', 'udpIdleTimeout'}, 'Xray Hysteria transport')
        if settings.get('version') != 2 or ht.get('version') != 2 or network != 'hysteria' or s.get('security') != 'tls':
            raise UserError('Xray Hysteria: нужен version=2, транспорт Hysteria2 и TLS; Hysteria1 импортируется отдельной ссылкой.')
        if ht.get('udpIdleTimeout', 60) not in (0, 60) or (mux and (mux.get('enabled') or set(mux) - {'enabled'})):
            raise UserError('Xray Hysteria2: нестандартный UDP idle timeout или mux не переносятся; выберите hysteria2 URI или sing-box JSON.')
        servers = [settings]
    elif t in {'shadowsocks', 'socks', 'http'}:
        connection_fields = {'address', 'port', 'level', 'email'} | ({'method', 'password'} if t == 'shadowsocks' else {'user', 'pass'})
        only(settings, connection_fields | {'servers'} | ({'headers'} if t == 'http' else set()), 'Xray settings')
        servers = [{k: v for k, v in settings.items() if k in connection_fields}] if settings.get('address') is not None else settings['servers']
    else:
        only(settings, {"servers"} if t == "trojan" else {"vnext"}, "Xray settings")
        servers = settings["servers" if t == "trojan" else "vnext"]
    if not isinstance(servers, list) or len(servers) != 1:
        raise UserError("Xray: в одном профиле нужен один сервер.")
    server = servers[0]
    server_fields = {'address', 'port'}
    if t in {'vless', 'vmess'}: server_fields |= {'users'}
    elif t == 'hysteria': server_fields |= {'version'}
    elif t == 'trojan': server_fields |= {'password'}
    elif t == 'shadowsocks': server_fields |= {'method', 'password', 'level', 'email'}
    else: server_fields |= {'users', 'user', 'pass', 'level', 'email'}
    only(server, server_fields, 'Xray server')
    o = {"type": t, "server": server["address"], "server_port": server["port"]}
    if sockopt:
        o['xray_sockopt'] = sockopt
    if t == 'hysteria':
        o.update(type='hysteria2', password=ht.get('auth', ''))
    elif network in {"xhttp", "splithttp"}:
        o["transport"] = {"type": "xhttp", **xhttp_settings(s.get("xhttpSettings", s.get("splithttpSettings", {})))}
    elif network in {"tcp", "raw"}:
        tcp = s.get("rawSettings", s.get("tcpSettings", {}))
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
    if t == 'hysteria':
        pass  # Authentication belongs to hysteriaSettings, not the proxy user.
    elif t == 'shadowsocks':
        o.update(method={'chacha20-poly1305': 'chacha20-ietf-poly1305', 'xchacha20-poly1305': 'xchacha20-ietf-poly1305', 'aead_aes_128_gcm': 'aes-128-gcm', 'aead_aes_256_gcm': 'aes-256-gcm', 'aead_chacha20_poly1305': 'chacha20-ietf-poly1305', 'aead_xchacha20_poly1305': 'xchacha20-ietf-poly1305'}.get(server['method'], server['method']), password=server['password'])
    elif t in {'socks', 'http'}:
        users = server.get('users') if server.get('users') is not None else []
        if not isinstance(users, list) or len(users) > 1:
            raise UserError('Xray: нужен не более чем один пользователь сервера.')
        user = server if settings.get('address') is not None else users[0] if users else {}
        only(user, server_fields if user is server else {'user', 'pass', 'level', 'email'}, 'Xray proxy user')
        if user.get('user'):
            o.update(username=user['user'], password=user.get('pass', ''))
        if t == 'socks': o['version'] = '5'
        elif settings.get('headers') is not None: o['headers'] = copy.deepcopy(settings['headers'])
    elif t == "trojan":
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
