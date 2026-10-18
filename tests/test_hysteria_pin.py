"""Synthetic Hysteria certificate pins; never contains a private subscription."""
import base64
import copy
import json
import unittest
from urllib.parse import urlencode

from helmsman.common import UserError, defaults
from helmsman.importers import parse
from helmsman.subscriptions import update, validate_subscription
from helmsman.xray import compile_xray, uses_xray

LINK = 'hysteria2://fixture-password@example.com:443?'
PIN = 'ab' * 32
FM = {'quicParams': {'congestion': 'bbr', 'debug': False}}


class HysteriaPinTests(unittest.TestCase):
    def test_pin_and_native_quic_settings_are_applied(self):
        for pin in (PIN, PIN.upper(), ':'.join(['AB'] * 32)):
            text = LINK + urlencode({'pinSHA256': pin, 'sni': 'example.com', 'fm': json.dumps(FM)})
            for body in (text, base64.b64encode(text.encode()).decode()):
                p = parse(body)[0]
                self.assertTrue(uses_xray(p))
                stream = compile_xray(p)['outbounds'][0]['streamSettings']
                self.assertEqual(stream['tlsSettings']['pinnedPeerCertSha256'], PIN)
                self.assertEqual(stream['finalmask'], FM)
                self.assertEqual(stream['hysteriaSettings']['auth'], 'fixture-password')
                self.assertNotIn('allowInsecure', stream['tlsSettings'])

    def test_empty_pin_retains_normal_tls_and_conflicting_pins_fail(self):
        p = parse(LINK + 'pinSHA256=')[0]
        self.assertFalse(uses_xray(p))
        self.assertTrue(p['outbound']['tls']['enabled'])
        for query in ({'pinSHA256': PIN, 'pcs': 'cd' * 32}, {'pinSHA256': 'private-token'}, {'pinSHA256': 'a' * 63}, {'pinSHA256': 'zz' * 32}):
            with self.assertRaises(UserError) as error: parse(LINK + urlencode(query))
            self.assertNotIn('private-token', str(error.exception))
        with self.assertRaisesRegex(UserError, 'несколько раз'): parse(LINK + 'pinSHA256=' + PIN + '&pinSHA256=' + PIN)
        with self.assertRaises(UserError): parse('vless://00000000-0000-0000-0000-000000000001@example.com:443?' + urlencode({'pinSHA256': PIN}))

    def test_atomic_mixed_subscription_refresh_keeps_last_good_state(self):
        state = defaults(); sub = validate_subscription({'url': 'https://example.test/sub', 'hwid_mode': 'remnawave', 'hwid_params': 'hwid=fixture-device,os=Android,osVersion=13,model=Test Device'})
        state['subscriptions'] = [sub]
        lines = ['vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls', LINK + urlencode({'sni': 'example.com', 'fm': json.dumps(FM)}), LINK + urlencode({'pinSHA256': PIN, 'fm': json.dumps(FM)})]
        state = update(state, sub['id'], lambda _: None, lambda *_: base64.b64encode('\n'.join(lines).encode()))
        before = copy.deepcopy(state)
        with self.assertRaises(UserError): update(state, sub['id'], lambda _: None, lambda *_: ('\n'.join(lines) + '\n' + LINK + 'pinSHA256=private-token').encode())
        self.assertEqual(state, before)
        self.assertEqual(len(state['profiles']), 3)
