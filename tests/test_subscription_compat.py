"""NekoBox_SF HWID semantics and common provider subscription representations."""
import base64
import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from helmsman.common import Store, UserError, defaults
from helmsman.importers import parse
from helmsman.routing import compile_config
from helmsman.subscriptions import SUBSCRIPTION_AGENT, hwid_parameters, request_data, update, validate_subscription
from helmsman.xray import compile_xray, uses_xray

LINK = 'vless://00000000-0000-0000-0000-000000000001@127.0.0.1:12345?type=tcp&security=none&headerType=none&packetEncoding=xudp#Provider'
PARAMS = 'hwid=0123456789abcdef,os=Android,osVersion=16,model=Test Device'


def xray_config(network='tcp'):
    stream = {'network': network, 'security': 'none'}
    if network == 'tcp':
        stream['tcpSettings'] = {'header': {'type': 'none'}}
    if network == 'ws':
        stream['wsSettings'] = {'path': '/websocket', 'headers': {'Host': 'example.test'}}
    if network == 'grpc':
        stream['grpcSettings'] = {'serviceName': 'rpc', 'multiMode': False}
    if network == 'xhttp':
        stream['xhttpSettings'] = {'path': '/', 'mode': 'packet-up'}
    return {'remarks': 'Provider ' + network, 'inbounds': [{'listen': '0.0.0.0'}],
            'routing': {'rules': [{'outboundTag': 'direct'}]}, 'outbounds': [
                {'protocol': 'vless', 'tag': 'proxy', 'settings': {'vnext': [{'address': '127.0.0.1', 'port': 12345, 'users': [{'id': '00000000-0000-0000-0000-000000000001', 'encryption': 'none'}]}]}, 'streamSettings': stream},
                {'protocol': 'freedom', 'tag': 'direct'}]}


def xray_proxy(kind, modern=True):
    server = {'address': '127.0.0.1', 'port': 12345}
    if kind == 'shadowsocks':
        server.update(method='aes-128-gcm', password='fixture-password')
    elif modern:
        server.update(user='fixture-user', **{'pass': 'fixture-password'})
    else:
        server['users'] = [{'user': 'fixture-user', 'pass': 'fixture-password', 'level': 0}]
    settings = server if modern else {'servers': [server]}
    if kind == 'http': settings['headers'] = {'X-Fixture': 'header-value'}
    return {'protocol': kind, 'tag': kind, 'settings': settings, 'streamSettings': None, 'mux': None}


def xray_hysteria():
    return {'protocol': 'hysteria', 'tag': 'Hysteria2', 'settings': {'version': 2, 'address': '127.0.0.1', 'port': 443},
            'streamSettings': {'network': 'hysteria', 'security': 'tls', 'tlsSettings': {'serverName': 'localhost'}, 'hysteriaSettings': {'version': 2, 'auth': 'fixture-password'}}}


class SubscriptionCompatibilityTests(unittest.TestCase):
    def test_stream_socket_options_and_nullable_export_blocks(self):
        for network in ('tcp', 'ws', 'grpc', 'xhttp'):
            source = xray_config(network)
            stream = source['outbounds'][0]['streamSettings']
            stream.update(sockopt={'mark': 0, 'tproxy': 'off', 'interface': '', 'dialerProxy': '', 'customSockopt': [], 'domainStrategy': 'AsIs', 'penetrate': False}, kcpSettings=None, quicSettings={}, finalmask=None, xdriveSettings=None, address=None, port=0)
            p = parse(json.dumps(source))[0]
            self.assertNotIn('xray_sockopt', p['outbound'])
            options = {'tcpFastOpen': False, 'tcpKeepAliveIdle': 30, 'tcpKeepAliveInterval': 15, 'tcpMaxSeg': 1280, 'tcpUserTimeout': 10000, 'tcpWindowClamp': 65536, 'tcpCongestion': 'cubic', 'domainStrategy': 'ForceIPv4', 'happyEyeballs': {'tryDelayMs': 250, 'interleave': 1, 'maxConcurrentTry': 4, 'prioritizeIPv6': False}}
            stream['sockopt'].update(options)
            p = parse(json.dumps(source))[0]
            self.assertTrue(uses_xray(p))
            self.assertEqual(p['outbound']['xray_sockopt'], options)
            compiled = compile_xray(p)['outbounds'][0]['streamSettings']['sockopt']
            self.assertEqual(compiled, {**options, 'penetrate': True})
            self.assertEqual(compile_xray(p, ipv6=False)['outbounds'][0]['streamSettings']['sockopt']['domainStrategy'], 'UseIPv4')
            self.assertNotIn('xray_sockopt', json.dumps(compile_config(defaults(), p, '/tmp', os.getuid())))
        source = xray_config('ws')
        stream = source['outbounds'][0]['streamSettings']
        stream.update(method='websocket', sockopt={'tcpcongestion': 'cubic', 'V6Only': False})
        p = parse(json.dumps(source))[0]
        self.assertEqual(p['outbound']['transport']['type'], 'ws')
        self.assertEqual(p['outbound']['xray_sockopt'], {'tcpCongestion': 'cubic'})
        stream.update(method=None, network=None, security=None, wsSettings=None, tcpSettings=None)
        stream['sockopt'] = None
        self.assertNotIn('transport', parse(json.dumps(source))[0]['outbound'])

    def test_stream_socket_errors_name_schema_field_without_private_values(self):
        invalid = [({'sockopt': {'dialerProxy': 'private-token'}}, 'sockopt.dialerProxy'), ({'sockopt': {'interface': 'private-token'}}, 'sockopt.interface'), ({'sockopt': {'mark': 42}}, 'sockopt.mark'), ({'sockopt': {'mark': False}}, 'sockopt.mark'), ({'sockopt': {'tcpFastOpen': 'private-token'}}, 'sockopt.tcpFastOpen'), ({'sockopt': {'customSockopt': [{'value': 'private-token'}]}}, 'sockopt.customSockopt'), ({'sockopt': {'happyEyeballs': {'maxConcurrentTry': -1}}}, 'happyEyeballs.maxConcurrentTry'), ({'sockopt': {'tcpcongestion': 'private-token'}}, 'sockopt.tcpCongestion'), ({'finalmask': {'password': 'private-token'}}, 'streamSettings.finalmask'), ({'kcpSettings': {'seed': 'private-token'}}, 'streamSettings.kcpSettings'), ({'xtlsSettings': {'password': 'private-token'}}, 'xtlsSettings'), ({'private-token': None}, 'нераспознанных полей'), ({'sockopt': {'private-token': None}}, 'нераспознанный параметр')]
        for extra, field in invalid:
            with self.subTest(field=field):
                source = [xray_config() for _ in range(14)]
                source[13]['outbounds'][0]['streamSettings'].update(extra)
                with self.assertRaises(UserError) as error:
                    parse(json.dumps(source))
                message = str(error.exception)
                self.assertIn('JSON[13].outbounds[0]', message)
                self.assertIn(field, message)
                self.assertNotIn('private-token', message)

    def test_native_extra_protocols_and_loopback_in_mixed_subscription(self):
        for modern in (True, False):
            source = xray_config()
            source['outbounds'] += [xray_proxy(t, modern) for t in ('shadowsocks', 'socks', 'http')]
            source['outbounds'] += [xray_hysteria(), {'protocol': 'loopback', 'tag': 'internal', 'settings': {'inboundTag': 'internal-only'}}, {'protocol': 'dns'}, {'protocol': 'blackhole'}]
            profiles = parse(json.dumps([source]))
            self.assertEqual([p['outbound']['type'] for p in profiles], ['vless', 'shadowsocks', 'socks', 'http', 'hysteria2'])
            self.assertEqual(profiles[1]['outbound']['password'], 'fixture-password')
            self.assertEqual(profiles[2]['outbound']['username'], 'fixture-user')
            self.assertEqual(profiles[2]['outbound']['version'], '5')
            self.assertEqual(profiles[3]['outbound']['headers'], {'X-Fixture': 'header-value'})
            self.assertEqual(profiles[4]['outbound']['password'], 'fixture-password')
            self.assertNotIn('transport', profiles[4]['outbound'])
        with self.assertRaisesRegex(UserError, 'нет поддерживаемых'):
            parse(json.dumps({'outbounds': [{'protocol': 'loopback'}]}))

    def test_native_failure_has_safe_location_and_preserves_entire_subscription(self):
        state = defaults()
        sub = validate_subscription({'url': 'https://private.example/token-secret', 'hwid': 'secret-hwid'})
        state['subscriptions'] = [sub]
        source = xray_config()
        result = update(state, sub['id'], lambda _: None, lambda *_: json.dumps([source]).encode())
        for protocol in ('shadowsocksr', 'private-token-must-not-be-logged'):
            bad = {'protocol': protocol, 'tag': 'private-tag', 'settings': {'password': 'private-password', 'address': 'private-host'}}
            before = copy.deepcopy(result)
            with self.assertRaises(UserError) as error:
                update(result, sub['id'], lambda _: None, lambda *_: json.dumps([source, {'outbounds': [bad]}]).encode())
            message = str(error.exception)
            self.assertIn('JSON[1].outbounds[0]', message)
            if protocol == 'shadowsocksr': self.assertIn('shadowsocksr', message)
            for secret in ('private-token-must-not-be-logged', 'private-tag', 'private-password', 'private-host', 'token-secret', 'secret-hwid'):
                self.assertNotIn(secret, message)
            self.assertEqual(before, result)
        for value, path in (({'outbounds': {}}, 'JSON.outbounds'), ([17], 'JSON[0]'), ({'outbounds': [xray_proxy('socks'), {'protocol': 'socks'}]}, 'JSON.outbounds[1]')):
            with self.subTest(value=value), self.assertRaisesRegex(UserError, path.replace('[', r'\[').replace(']', r'\]')):
                parse(json.dumps(value))

    @unittest.skipUnless(os.environ.get('HELMSMAN_ENGINES'), 'Real engine checks run in CI')
    def test_native_extra_protocols_pass_actual_engines(self):
        with tempfile.TemporaryDirectory() as root:
            for raw in [xray_proxy(t, modern) for t in ('shadowsocks', 'socks', 'http') for modern in (True, False)] + [xray_hysteria()]:
                p = parse(json.dumps({'outbounds': [raw]}))[0]
                path = Path(root) / 'config.json'
                path.write_text(json.dumps(compile_config(defaults(), p, root, os.getuid())))
                checked = subprocess.run([str(Path(os.environ['HELMSMAN_ENGINES']) / 'sing-box'), 'check', '-c', str(path)], capture_output=True, text=True)
                self.assertEqual(checked.returncode, 0, checked.stderr)
            for raw in [xray_proxy(t) for t in ('shadowsocks', 'socks', 'http')]:
                raw['mux'] = {'enabled': True, 'concurrency': 8}
                p = parse(json.dumps(raw))[0]
                path.write_text(json.dumps(compile_xray(p)))
                checked = subprocess.run([str(Path(os.environ['HELMSMAN_ENGINES']) / 'xray'), 'run', '-test', '-config', str(path)], capture_output=True, text=True)
                self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)

    def test_neko_parameters_only_listed_fields_and_manual_override(self):
        s = validate_subscription({'name': 'Test', 'url': 'https://example.test/sub', 'hwid_mode': 'remnawave', 'hwid_params': PARAMS})
        _, headers = request_data(s, 'global-is-not-used')
        self.assertEqual({k: headers[k] for k in ['x-hwid', 'x-device-os', 'x-ver-os', 'x-device-model']},
                         {'x-hwid': '0123456789abcdef', 'x-device-os': 'Android', 'x-ver-os': '16', 'x-device-model': 'Test Device'})
        self.assertEqual(headers['user-agent'], SUBSCRIPTION_AGENT)
        s['hwid_params'] = 'hwid=0123456789abcdef'
        _, headers = request_data(s, 'not-used')
        self.assertNotIn('x-device-os', headers)
        self.assertNotIn('x-device-model', headers)
        self.assertEqual(hwid_parameters('hwid=abcdef====\nosVersion=16\nmodel=Test Device')['x-hwid'], 'abcdef====')
        s = validate_subscription({**s, 'hwid_params': '', 'hwid': PARAMS})
        self.assertEqual(s['hwid'], '')
        self.assertEqual(request_data(s, 'ignored')[1]['x-device-model'], 'Test Device')
        for text in ('hwid=one,hwid=two', 'unknown=value', 'hwid=value\rInjected: yes', 'model='):
            with self.subTest(text=text), self.assertRaises(UserError):
                hwid_parameters(text)

    def test_case_insensitive_headers_and_explicit_precedence(self):
        s = validate_subscription({'url': 'https://example.test/sub', 'hwid_mode': 'remnawave', 'headers': {'X-HWID': 'abcdef0123456789', 'User-Agent': 'Custom/1', 'X-Device-Os': 'Custom'}})
        _, headers = request_data(s, '0123456789abcdef')
        self.assertEqual(headers['x-hwid'], 'abcdef0123456789')
        self.assertEqual(headers['user-agent'], 'Custom/1')
        self.assertEqual(headers['x-device-os'], 'Custom')
        self.assertFalse(any(k != k.lower() for k in headers))
        with self.assertRaises(UserError):
            validate_subscription({'url': 'https://example.test/sub', 'headers': {'User-Agent': 'a', 'user-agent': 'b'}})
        with self.assertRaises(UserError):
            validate_subscription({'url': 'https://example.test/sub', 'user_agent': 'a\r\nX: bad'})

    def test_provider_uri_and_config_arrays_preserve_policy(self):
        self.assertEqual(parse(LINK)[0]['outbound']['packet_encoding'], 'xudp')
        with self.assertRaises(UserError):
            parse(LINK.replace('headerType=none', 'headerType=http'))
        profiles = parse(json.dumps([xray_config(n) for n in ('tcp', 'ws', 'grpc', 'xhttp')]))
        self.assertEqual(len(profiles), 4)
        self.assertEqual(profiles[0]['name'], 'Provider tcp')
        self.assertNotIn('transport', profiles[0]['outbound'])
        self.assertEqual(profiles[1]['outbound']['transport']['headers'], {'Host': 'example.test'})
        self.assertEqual(profiles[2]['outbound']['transport']['service_name'], 'rpc')
        self.assertEqual(profiles[3]['outbound']['transport']['type'], 'xhttp')
        self.assertFalse(any('routing' in p or 'inbounds' in p for p in profiles))
        unsafe = xray_config()
        unsafe['outbounds'][0]['streamSettings'].update(security='tls', tlsSettings={'allowInsecure': True})
        with self.assertRaises(UserError):
            parse(json.dumps(unsafe))
        unsafe['outbounds'][0]['streamSettings']['tlsSettings'] = {'certificateFile': '/etc/shadow'}
        with self.assertRaises(UserError):
            parse(json.dumps(unsafe))

    def test_base64_config_arrays_and_saved_options_survive_failure_and_restart(self):
        state = defaults()
        sub = validate_subscription({'url': 'https://example.test/sub', 'hwid_mode': 'remnawave', 'hwid_params': PARAMS, 'user_agent': 'Chosen/1'})
        state['subscriptions'] = [sub]
        source = xray_config()
        source['outbounds'][0]['mux'] = {'enabled': True, 'concurrency': 8, 'xudpConcurrency': 16, 'xudpProxyUDP443': 'skip'}
        payload = base64.b64encode(json.dumps([source]).encode())
        result = update(state, sub['id'], lambda _: None, lambda *_: payload)
        self.assertEqual(result['profiles'][0]['outbound']['xray_mux'], source['outbounds'][0]['mux'])
        for payload in (b'', b'<html>account page</html>', b'proxies:\n - name: a', b'{"error":"private-token-must-not-be-logged"}'):
            before = copy.deepcopy(result)
            with self.assertRaises(UserError) as error:
                update(result, sub['id'], lambda _: None, lambda *_: payload)
            self.assertNotIn('private-token-must-not-be-logged', str(error.exception))
            self.assertEqual(before, result)
        with tempfile.TemporaryDirectory() as root:
            store = Store(root); store.data = result; store.save()
            restored = Store(root).data
            self.assertEqual(restored['hwid'], result['hwid'])
            self.assertEqual(restored['subscriptions'][0]['hwid_params'], PARAMS)
            self.assertEqual(restored['subscriptions'][0]['user_agent'], 'Chosen/1')
            self.assertEqual(restored['profiles'], result['profiles'])

    def test_mux_import_preserves_native_parameters_and_shared_policy(self):
        for mux in ({'enabled': True}, {'enabled': True, 'xudpProxyUDP443': ''}, {'enabled': True, 'concurrency': -1, 'xudpConcurrency': 16, 'xudpProxyUDP443': 'allow'}, {'enabled': False, 'xudpProxyUDP443': 'skip'}):
            for network in ('tcp', 'ws', 'grpc', 'xhttp'):
                with self.subTest(network=network, mux=mux):
                    source = xray_config(network)
                    if network == 'xhttp':
                        mux = {**mux, 'concurrency': -1}
                    source['outbounds'][0]['mux'] = mux
                    p = parse(json.dumps([source]))[0]
                    self.assertTrue(uses_xray(p))
                    self.assertEqual(compile_xray(p)['outbounds'][0]['mux'], mux)
                    compiled = compile_config(defaults(), p, '/tmp', os.getuid())
                    self.assertEqual(next(o for o in compiled['outbounds'] if o['tag'] == 'proxy')['type'], 'socks')
                    self.assertNotIn('xray_mux', json.dumps(compiled))
        for mux in (True, {'enabled': 'true'}, {'concurrency': True}, {'concurrency': 32768}, {'xudpConcurrency': -32769}, {'xudpProxyUDP443': 'anything'}, {'enabled': True, 'file': '/etc/shadow'}):
            source = xray_config()
            source['outbounds'][0]['mux'] = mux
            with self.subTest(invalid=mux), self.assertRaises(UserError):
                parse(json.dumps(source))
        source['outbounds'][0]['mux'] = {'enabled': False}
        self.assertFalse(uses_xray(parse(json.dumps(source))[0]))
        for mode in ('xhttp', 'vision'):
            source = xray_config('xhttp' if mode == 'xhttp' else 'tcp')
            source['outbounds'][0]['mux'] = {'enabled': True, 'concurrency': 8}
            if mode == 'vision':
                source['outbounds'][0]['settings']['vnext'][0]['users'][0]['flow'] = 'xtls-rprx-vision'
            with self.subTest(incompatible=mode), self.assertRaisesRegex(UserError, 'concurrency=-1'):
                parse(json.dumps(source))

    @unittest.skipUnless(os.environ.get('HELMSMAN_ENGINES'), 'Real engine checks run in CI')
    def test_native_provider_json_validates_with_real_engine(self):
        with tempfile.TemporaryDirectory() as root:
            for network in ('tcp', 'ws', 'grpc', 'xhttp'):
                source = xray_config(network)
                source['outbounds'][0]['mux'] = {'enabled': True, 'concurrency': 8, 'xudpProxyUDP443': 'skip'}
                if network == 'xhttp':
                    source['outbounds'][0]['mux']['concurrency'] = -1
                p = parse(json.dumps([source]))[0]
                path = Path(root) / 'config.json'
                path.write_text(json.dumps(compile_xray(p)))
                checked = subprocess.run([str(Path(os.environ['HELMSMAN_ENGINES']) / 'xray'), 'run', '-test', '-config', str(path)], capture_output=True, text=True)
                self.assertEqual(checked.returncode, 0, checked.stderr + checked.stdout)
                path.write_text(json.dumps(compile_config(defaults(), p, root, os.getuid())))
                checked = subprocess.run([str(Path(os.environ['HELMSMAN_ENGINES']) / 'sing-box'), 'check', '-c', str(path)], capture_output=True, text=True)
                self.assertEqual(checked.returncode, 0, checked.stderr)


if __name__ == '__main__':
    unittest.main()
