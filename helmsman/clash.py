"""Import Clash/Mihomo connection data, keeping Helmsman's system policy."""
import re
import yaml

from .common import UserError
from .xray import xhttp_settings, XMUX_FIELDS


COMMON = set('name type server port udp tls sni servername alpn client-fingerprint skip-cert-verify certificate tfo mptcp ip-version interface-name routing-mark dialer-proxy smux'.split())
FIELDS = {
    'vless': set('uuid flow packet-encoding encryption network ws-opts grpc-opts h2-opts http-opts httpupgrade-opts xhttp-opts reality-opts'.split()),
    'vmess': set('uuid alterId cipher packet-encoding network ws-opts grpc-opts h2-opts http-opts httpupgrade-opts'.split()),
    'trojan': set('password network ws-opts grpc-opts httpupgrade-opts'.split()),
    'hysteria2': set('password ports hop-interval obfs obfs-password up down'.split()),
    'ss': {'cipher', 'password'}, 'socks5': {'username', 'password'}, 'http': {'username', 'password'},
}


def only(value, fields, context):
    if not isinstance(value, dict):
        raise UserError(context + ': нужен объект.')
    if set(value) - fields:
        # Never include provider-defined keys or values in ordinary errors.
        raise UserError(context + ': неподдерживаемых полей: ' + str(len(set(value) - fields)) + '.')


def load(text):
    try:
        depth = 0
        for count, event in enumerate(yaml.parse(text)):
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)): depth += 1
            if isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)): depth -= 1
            if depth > 40 or count > 250000:
                raise UserError('Clash YAML: превышен предел вложенности или размера структуры.')
        data = yaml.safe_load(text)
        pending, count = [(data, frozenset())], 0
        while pending:
            value, ancestors = pending.pop(); count += 1
            if count > 250000:
                raise UserError('Clash YAML: слишком большое раскрытие aliases.')
            if isinstance(value, (dict, list)):
                if id(value) in ancestors:
                    raise UserError('Clash YAML: циклические aliases не поддерживаются.')
                lineage = ancestors | {id(value)}
                pending.extend((item, lineage) for item in (value.values() if isinstance(value, dict) else value))
        return data
    except (yaml.YAMLError, ValueError, TypeError, RecursionError):
        raise UserError('Clash YAML: некорректный документ; содержимое скрыто, прежняя подписка сохранена.') from None


def parse(text):
    from .importers import profile
    data = load(text)
    if not isinstance(data, dict) or not isinstance(data.get('proxies'), list) or not 1 <= len(data['proxies']) <= 2000:
        raise UserError('Clash: нужен список proxies из 1–2000 подключений; proxy-providers автоматически не загружаются.')
    result = []
    for index, raw in enumerate(data['proxies']):
        try:
            if isinstance(raw, dict) and raw.get('type') == 'hysteria2': raw = {k.replace('_', '-'): v for k, v in raw.items()}
            only(raw, COMMON | set().union(*FIELDS.values()), 'Clash proxy')
            kind = raw.get('type')
            if kind not in FIELDS:
                raise UserError('Clash: неподдерживаемый тип подключения.')
            only(raw, COMMON | FIELDS[kind], 'Clash proxy')
            raw = dict(raw)
            for field in ('udp', 'tls', 'tfo', 'mptcp', 'skip-cert-verify'):
                if raw.get(field) is not None and type(raw[field]) is not bool:
                    if raw[field] not in ('true', 'false'): raise UserError('Clash.' + field + ': нужно логическое значение.')
                    raw[field] = raw[field] == 'true'
            for field, default in (('mptcp', False), ('interface-name', ''), ('routing-mark', 0), ('dialer-proxy', ''), ('ip-version', '')):
                if raw.get(field) not in (None, default) and not (field == 'ip-version' and raw[field] == 'dual'):
                    raise UserError('Clash.' + field + ': системным подключением управляет Helmsman.')
            port = raw.get('port')
            if port is None and raw.get('ports'): port = str(raw['ports']).split(',')[0].split('-')[0]
            if isinstance(port, str) and port.isdecimal(): port = int(port)
            out = {'type': {'ss': 'shadowsocks', 'socks5': 'socks'}.get(kind, kind), 'server': raw.get('server'), 'server_port': port}
            if raw.get('udp') is False: out['network'] = 'tcp'
            if kind in {'vless', 'vmess'}:
                out['uuid'] = raw['uuid']
                if kind == 'vless':
                    if raw.get('encryption') not in (None, '', 'none'):
                        raise UserError('Clash VLESS: encryption пока не поддерживается.')
                    if raw.get('flow'): out['flow'] = raw['flow']
                    out['packet_encoding'] = raw.get('packet-encoding') or 'xudp'
                else:
                    out.update(security=raw.get('cipher') or 'auto', alter_id=int(raw.get('alterId') or 0))
            if kind in {'hysteria2', 'trojan', 'ss'}: out['password'] = str(raw['password'])
            if kind == 'ss': out['method'] = raw['cipher']
            if kind in {'socks5', 'http'}:
                for field in ('username', 'password'):
                    if raw.get(field) is not None: out[field] = str(raw[field])
                if kind == 'socks5': out['version'] = '5'
            if raw.get('skip-cert-verify') not in (None, False):
                raise UserError('Clash.skip-cert-verify: отключение проверки TLS не допускается.')
            reality = raw.get('reality-opts')
            if raw.get('tls') or reality or kind in {'trojan', 'hysteria2'}:
                tls = {'enabled': True, 'server_name': raw.get('servername') or raw.get('sni') or raw.get('server')}
                if raw.get('alpn'): tls['alpn'] = raw['alpn']
                if kind == 'hysteria2': tls.setdefault('alpn', ['h3'])
                if raw.get('certificate'):
                    if not isinstance(raw['certificate'], str) or '-----BEGIN CERTIFICATE-----' not in raw['certificate']:
                        raise UserError('Clash.certificate: нужен встроенный PEM; пути к файлам не импортируются.')
                    tls['certificate'] = [raw['certificate']]
                fp = raw.get('client-fingerprint') or data.get('global-client-fingerprint')
                if kind != 'hysteria2' and (fp or reality): tls['utls'] = {'enabled': True, 'fingerprint': fp or 'chrome'}
                if reality:
                    only(reality, {'public-key', 'short-id'}, 'Clash reality-opts')
                    tls['reality'] = {'enabled': True, 'public_key': reality['public-key'], 'short_id': str(reality.get('short-id') or '')}
                out['tls'] = tls
            network = raw.get('network') or 'tcp'
            if network in ('ws', 'grpc', 'h2', 'http', 'httpupgrade'):
                field = {'ws': 'ws-opts', 'grpc': 'grpc-opts', 'h2': 'h2-opts', 'http': 'http-opts', 'httpupgrade': 'httpupgrade-opts'}[network]
                options = raw.get(field) or {}
                if network == 'grpc':
                    only(options, {'grpc-service-name'}, 'Clash grpc-opts')
                    transport = {'type': 'grpc', 'service_name': options.get('grpc-service-name') or ''}
                elif network == 'ws':
                    only(options, {'path', 'headers', 'max-early-data', 'early-data-header-name', 'v2ray-http-upgrade'}, 'Clash ws-opts')
                    transport = {'type': 'ws', 'path': options.get('path') or '/', 'headers': options.get('headers') or {}}
                    for source, target in (('max-early-data', 'max_early_data'), ('early-data-header-name', 'early_data_header_name')):
                        if source in options: transport[target] = options[source]
                    if options.get('v2ray-http-upgrade'):
                        transport = {'type': 'httpupgrade', 'path': transport['path'], 'host': transport['headers'].get('Host', '')}
                else:
                    only(options, {'path', 'host'} | ({'method', 'headers'} if network == 'http' else set()), 'Clash ' + field)
                    path = options.get('path') or '/'
                    if isinstance(path, list):
                        if len(path) != 1: raise UserError('Clash HTTP: нужен один path.')
                        path = path[0]
                    headers = options.get('headers') or {}
                    if not isinstance(headers, dict): raise UserError('Clash HTTP headers: нужен объект.')
                    host = next((value for key, value in headers.items() if key.lower() == 'host'), None)
                    transport = {'type': 'httpupgrade' if network == 'httpupgrade' else 'http', 'path': path, 'host': options.get('host') or host or ([] if network != 'httpupgrade' else '')}
                    if network == 'http':
                        if options.get('method'): transport['method'] = options['method']
                        if headers: transport['headers'] = headers
                out['transport'] = transport
            elif network == 'xhttp' and kind == 'vless':
                options = raw.get('xhttp-opts') or {}
                mapping = dict(zip('host path mode headers no-grpc-header x-padding-bytes x-padding-obfs-mode x-padding-key x-padding-header x-padding-placement x-padding-method uplink-http-method session-placement session-key session-table session-length seq-placement seq-key uplink-data-placement uplink-data-key uplink-chunk-size sc-max-each-post-bytes sc-min-posts-interval-ms'.split(), 'host path mode headers noGRPCHeader xPaddingBytes xPaddingObfsMode xPaddingKey xPaddingHeader xPaddingPlacement xPaddingMethod uplinkHTTPMethod sessionIDPlacement sessionIDKey sessionIDTable sessionIDLength seqPlacement seqKey uplinkDataPlacement uplinkDataKey uplinkChunkSize scMaxEachPostBytes scMinPostsIntervalMs'.split()))
                only(options, set(mapping) | {'reuse-settings'}, 'Clash xhttp-opts')
                settings = {mapping[k]: v for k, v in options.items() if k in mapping}
                if options.get('reuse-settings'):
                    reuse_map = {re.sub(r'([A-Z])', lambda m: '-' + m[1].lower(), k): k for k in XMUX_FIELDS}
                    only(options['reuse-settings'], set(reuse_map), 'Clash XHTTP reuse-settings')
                    settings['xmux'] = {reuse_map[k]: v for k, v in options['reuse-settings'].items()}
                out['transport'] = {'type': 'xhttp', **xhttp_settings(settings)}
            elif network != 'tcp':
                raise UserError('Clash.network: неподдерживаемый транспорт.')
            if raw.get('tfo') is True:
                if network == 'xhttp': out['xray_sockopt'] = {'tcpFastOpen': True}
                else: out['tcp_fast_open'] = True
            mux = raw.get('smux')
            if mux:
                only(mux, {'enabled', 'protocol', 'max-connections', 'min-streams', 'max-streams', 'padding'}, 'Clash smux')
                if 'enabled' in mux and type(mux['enabled']) is not bool: raise UserError('Clash smux.enabled: нужно логическое значение.')
                if mux.get('enabled'):
                    out['multiplex'] = {key.replace('-', '_'): value for key, value in mux.items()}
            if kind == 'hysteria2':
                if raw.get('obfs') not in (None, '', 'salamander'):
                    raise UserError('Clash Hysteria2: поддерживается obfs salamander.')
                if raw.get('obfs-password'): out['obfs'] = {'type': 'salamander', 'password': str(raw['obfs-password'])}
                if raw.get('ports'): out['server_ports'] = str(raw['ports']).replace('-', ':').split(',')
                if raw.get('hop-interval') is not None:
                    duration = str(raw['hop-interval'])
                    out['hop_interval'] = duration + 's' if duration.replace('.', '', 1).isdecimal() else duration
                for source, target in (('up', 'up_mbps'), ('down', 'down_mbps')):
                    if raw.get(source) is not None:
                        rate = str(raw[source]).split()[0]
                        if not re.fullmatch(r'\d+(?:\.\d+)?', rate): raise UserError('Clash Hysteria2: скорость задаётся в Mbps.')
                        if not float(rate).is_integer(): raise UserError('Clash Hysteria2: нужны целые Mbps.')
                        out[target] = int(float(rate))
            result.append(profile(out, raw.get('name') or ''))
        except UserError as error:
            raise UserError(f'Clash.proxies[{index}]: ' + str(error)) from None
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
            raise UserError(f'Clash.proxies[{index}]: некорректные поля подключения; значения скрыты.') from None
    return result
