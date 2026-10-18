"""NekoBox-style format negotiation and connection-only Clash import."""
import base64
import copy
import json
import unittest
import os
import tempfile
from pathlib import Path

from helmsman.common import UserError, defaults
from helmsman.importers import parse
from helmsman.subscriptions import SUBSCRIPTION_AGENT, request_data, update, validate_subscription
from helmsman.xray import compile_xray, native_tls, uses_xray
from test_subscription_compat import xray_config

CLASH = '''global-client-fingerprint: chrome
port: 7890
rules: [MATCH,DIRECT]
proxies:
  - name: VLESS Reality
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    tls: true
    servername: example.com
    flow: xtls-rprx-vision
    reality-opts:
      public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      short-id: "1234"
  - name: Hysteria2
    type: hysteria2
    server: example.com
    port: 443
    password: fixture-password
    sni: example.com
    obfs: salamander
    obfs-password: fixture-obfs
    ports: 443,8443-8445
    hop-interval: 15
    up: 50 Mbps
    down: 100
'''


class ClashTests(unittest.TestCase):
    def test_mixed_clash_yaml_json_base64_and_policy(self):
        import yaml
        expected = None
        for text in (CLASH, json.dumps(yaml.safe_load(CLASH)), base64.b64encode(CLASH.encode()).decode()):
            nodes = parse(text)
            out = [p['outbound'] for p in nodes]
            self.assertEqual([o['type'] for o in out], ['vless', 'hysteria2'])
            self.assertEqual(out[0]['tls']['reality']['short_id'], '1234')
            self.assertEqual(out[0]['packet_encoding'], 'xudp')
            self.assertFalse(uses_xray(nodes[0]))
            self.assertEqual(out[1]['obfs'], {'type': 'salamander', 'password': 'fixture-obfs'})
            self.assertEqual(out[1]['server_ports'], ['443:443', '8443:8445'])
            self.assertEqual(out[1]['hop_interval'], '15s')
            self.assertEqual(out[1]['up_mbps'], 50)
            self.assertEqual(out[1]['down_mbps'], 100)
            self.assertEqual(out[1]['tls']['alpn'], ['h3'])
            self.assertNotIn('utls', out[1]['tls'])
            if expected: self.assertEqual(expected, out)
            expected = out

    @unittest.skipUnless(os.environ.get('HELMSMAN_ENGINES'), 'Pinned engines required')
    def test_mixed_clash_is_accepted_by_actual_sing_box(self):
        from helmsman.system import Runtime
        with tempfile.TemporaryDirectory() as root:
            Runtime(Path(os.environ['HELMSMAN_ENGINES']).resolve(), root, engine_uid=os.getuid()).validate_profiles(parse(CLASH))
        out = parse('hysteria2://fixture-password@example.com:443?ports=443,8443-8445')[0]['outbound']
        self.assertEqual(out['server_ports'], ['443:443', '8443:8445'])

    def test_clash_transports_and_anchors(self):
        root = {'proxies': []}
        for net, opts in [('ws', {'path': '/ws', 'headers': {'Host': 'example.com'}}), ('grpc', {'grpc-service-name': 'service'}), ('h2', {'path': '/', 'host': ['example.com']}), ('httpupgrade', {'path': '/', 'host': 'example.com'}), ('xhttp', {'path': '/x', 'mode': 'packet-up', 'x-padding-bytes': '100-200', 'reuse-settings': {'max-concurrency': '8-16'}})]:
            root['proxies'].append({'name': net, 'type': 'vless', 'server': 'example.com', 'port': '443', 'uuid': '00000000-0000-0000-0000-000000000001', 'tls': True, 'network': net, net + '-opts': opts})
        nodes = parse(json.dumps(root))
        self.assertEqual([p['outbound']['transport']['type'] for p in nodes], ['ws', 'grpc', 'http', 'httpupgrade', 'xhttp'])
        settings = compile_xray(nodes[-1])['outbounds'][0]['streamSettings']['xhttpSettings']
        self.assertEqual(settings['xmux']['maxConcurrency'], '8-16')
        self.assertEqual(settings['xPaddingBytes'], '100-200')
        anchored = 'template: &node {type: vless, server: example.com, port: 443, uuid: 00000000-0000-0000-0000-000000000001}\nproxies: [*node, *node]'
        self.assertEqual(len(parse(anchored)), 2)

    def test_invalid_yaml_and_partial_refresh_are_transactional(self):
        state = defaults(); sub = validate_subscription({'url': 'https://example.test/sub'})
        state['subscriptions'] = [sub]
        state = update(state, sub['id'], lambda _: None, lambda *_: CLASH.encode())
        for text in ('proxies: [!unsafe private-token]', 'proxies: &a [*a]', CLASH + '    private-token: private-token\n', CLASH.replace('sni: example.com', 'skip-cert-verify: true'), CLASH.replace('type: hysteria2', 'type: private-token')):
            before = copy.deepcopy(state)
            with self.assertRaises(UserError) as error:
                update(state, sub['id'], lambda _: None, lambda *_: text.encode())
            self.assertNotIn('private-token', str(error.exception))
            self.assertEqual(before, state)

    def test_default_agent_migration_and_explicit_override(self):
        for agent in (None, '', 'v2rayNG/1.10.5 Helmsman/0.1.0-alpha.10'):
            sub = validate_subscription({'url': 'https://example.test/sub'})
            sub['user_agent'] = agent
            self.assertEqual(request_data(sub, 'test')[1]['user-agent'], SUBSCRIPTION_AGENT)
        sub = validate_subscription({'url': 'https://example.test/sub', 'user_agent': 'sing-box/1.14.3', 'headers': {'User-Agent': 'custom-provider'}})
        self.assertEqual(sub['user_agent'], 'sing-box/1.14.3')
        self.assertEqual(request_data(sub, 'test')[1]['user-agent'], 'custom-provider')

    def test_native_tls_defaults_and_client_extensions(self):
        raw = xray_config(); stream = raw['outbounds'][0]['streamSettings']
        stream.update(security='tls', tlsSettings={'serverName': 'example.com'})
        stream['tlsSettings'].update(enableSessionResumption=True, minVersion='1.2', maxVersion='1.3', curvePreferences=['X25519'], pinnedPeerCertSha256='aa' * 32, verifyPeerCertByName='example.com', certificates=[], masterKeyLog='', echConfigList='', rejectUnknownSni=False, verifyPeerCertInNames=[], allowInsecureIfPinnedPeerCertificate=False)
        p = parse(json.dumps(raw))[0]
        self.assertTrue(uses_xray(p))
        compiled = compile_xray(p)['outbounds'][0]['streamSettings']['tlsSettings']
        for key in ('enableSessionResumption', 'minVersion', 'maxVersion', 'curvePreferences', 'pinnedPeerCertSha256', 'verifyPeerCertByName'):
            self.assertEqual(compiled[key], stream['tlsSettings'][key])
        self.assertNotIn('masterKeyLog', compiled)
        self.assertEqual(native_tls({'publicKey': 'old', 'password': 'new', 'show': False, 'serverNames': [], 'shortIds': [], 'spiderY': None}, True)['password'], 'new')
        for value in ({'allowInsecure': True}, {'masterKeyLog': '/tmp/private-token'}, {'certificates': [{'usage': 'verify', 'certificateFile': '/tmp/private-token'}]}, {'minVersion': '1.0'}):
            with self.assertRaises(UserError) as error: native_tls(value)
            self.assertNotIn('private-token', str(error.exception))
