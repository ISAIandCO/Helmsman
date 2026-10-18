"""Native FinalMask data contracts; Xray owns the actual network transforms."""
import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from helmsman.common import UserError, defaults
from helmsman.importers import parse
from helmsman.routing import compile_config
from helmsman.subscriptions import update, validate_subscription
from helmsman.xray import compile_xray, finalmask_settings, uses_xray
from test_subscription_compat import xray_config, xray_hysteria


MASKS = [
    {'tcp': [{'type': 'fragment', 'settings': {'packets': 'tlshello', 'lengths': ['40-80'], 'delays': ['0'], 'maxSplit': '4'}}]},
    {'tcp': [{'type': 'sudoku', 'settings': {'password': 'fixture-password'}}]},
    {'tcp': [{'type': 'header-custom', 'settings': {'clients': [[{'type': 'str', 'packet': 'HELMSMAN', 'capture': 'prefix'}, {'transform': {'op': 'concat', 'args': [{'reuse': 'prefix'}, {'type': 'str', 'bytes': '!'}]}}]], 'servers': [[{'type': 'str', 'packet': 'READY'}]]}}]},
    {'udp': [{'type': 'mkcp-legacy', 'settings': {'header': 'dtls'}}]},
    {'udp': [{'type': 'salamander', 'settings': {'password': 'fixture-password'}}]},
    {'udp': [{'type': 'sudoku', 'settings': {'password': 'fixture-password'}}]},
    {'udp': [{'type': 'noise', 'settings': {'reset': '30-60', 'noise': [{'type': 'str', 'packet': 'HELMSMAN', 'delay': '0'}]}}]},
    {'udp': [{'type': 'header-custom', 'settings': {'client': [{'type': 'str', 'packet': 'HELMSMAN'}], 'server': [{'type': 'str', 'packet': 'READY'}]}}]},
    {'quicParams': {'congestion': 'bbr', 'maxIdleTimeout': 30, 'keepAlivePeriod': 10, 'debug': False}},
]


class FinalMaskTests(unittest.TestCase):
    def test_empty_export_is_noop_and_active_masks_keep_order(self):
        for masks in (None, {}, {'tcp': [], 'udp': [], 'quicParams': None}):
            source = xray_config()
            source['outbounds'][0]['streamSettings']['finalmask'] = masks
            p = parse(json.dumps(source))[0]
            self.assertNotIn('xray_finalmask', p['outbound'])
            self.assertFalse(uses_xray(p))
        combined = {'tcp': MASKS[0]['tcp'] + MASKS[1]['tcp'], 'udp': MASKS[3]['udp'] + MASKS[4]['udp'], **MASKS[-1]}
        for network in ('tcp', 'ws', 'grpc', 'xhttp'):
            source = xray_config(network)
            source['outbounds'][0]['streamSettings']['finalmask'] = copy.deepcopy(combined)
            before = copy.deepcopy(source)
            p = parse(json.dumps(source))[0]
            self.assertTrue(uses_xray(p))
            self.assertEqual(p['outbound']['xray_finalmask'], combined)
            self.assertEqual(compile_xray(p)['outbounds'][0]['streamSettings']['finalmask'], combined)
            self.assertNotIn('finalmask', json.dumps(compile_config(defaults(), p, '/tmp', os.getuid())))
            self.assertEqual(source, before)

    def test_hysteria2_masks_use_native_xray_and_keep_authentication(self):
        source = xray_hysteria()
        source['streamSettings']['finalmask'] = {**MASKS[4], **MASKS[-1]}
        p = parse(json.dumps(source))[0]
        self.assertEqual(p['outbound']['type'], 'hysteria2')
        compiled = compile_xray(p)['outbounds'][0]
        self.assertEqual(compiled['protocol'], 'hysteria')
        self.assertEqual(compiled['streamSettings']['network'], 'hysteria')
        self.assertEqual(compiled['streamSettings']['hysteriaSettings']['auth'], 'fixture-password')
        self.assertEqual(compiled['streamSettings']['finalmask'], source['streamSettings']['finalmask'])

    def test_xhttp_download_settings_keep_their_own_finalmask(self):
        source = xray_config('xhttp')
        extra = {'downloadSettings': {'address': '127.0.0.1', 'port': 12345, 'network': 'xhttp', 'finalmask': MASKS[0], 'xhttpSettings': {'path': '/download'}}}
        source['outbounds'][0]['streamSettings']['xhttpSettings']['extra'] = extra
        compiled = compile_xray(parse(json.dumps(source))[0])
        self.assertEqual(compiled['outbounds'][0]['streamSettings']['xhttpSettings']['extra'], extra)

    def test_unsupported_masks_and_scripts_preserve_previous_subscription(self):
        state = defaults()
        sub = validate_subscription({'url': 'https://example.test/sub'})
        state['subscriptions'] = [sub]
        state = update(state, sub['id'], lambda _: None, lambda *_: json.dumps([xray_config()]).encode())
        invalid = [
            {'udp': [{'type': 'noise', 'settings': {'script': 'private-token'}}]},
            {'tcp': [{'type': 'header-custom', 'settings': {'clients': [[{'script': 'private-token'}]]}}]},
            {'tcp': [{'type': 'private-token', 'settings': {'password': 'private-token'}}]},
            {'udp': [{'type': 'realm', 'settings': {'url': 'private-token'}}]},
            {'udp': [{'type': 'xicmp', 'settings': {}}]},
            {'quicParams': {'debug': True}},
            {'quicParams': {'udpHop': {'ports': 'private-token'}}},
            {'tcp': {}},
        ]
        for masks in invalid:
            with self.subTest(masks=masks):
                source = [xray_config() for _ in range(14)]
                source[13]['outbounds'][0]['streamSettings']['finalmask'] = masks
                before = copy.deepcopy(state)
                with self.assertRaises(UserError) as error:
                    update(state, sub['id'], lambda _: None, lambda *_: json.dumps(source).encode())
                self.assertIn('JSON[13].outbounds[0]', str(error.exception))
                self.assertIn('finalmask', str(error.exception))
                self.assertNotIn('private-token', str(error.exception))
                self.assertEqual(state, before)
        self.assertEqual(finalmask_settings({'udp': [{'type': 'noise', 'settings': {'script': '', 'noise': []}}]}), {'udp': [{'type': 'noise', 'settings': {'noise': []}}]})

    @unittest.skipUnless(os.environ.get('HELMSMAN_ENGINES'), 'Real Xray validation runs in CI')
    def test_mask_schemas_validate_with_pinned_xray(self):
        with tempfile.TemporaryDirectory() as root:
            binary = str(Path(os.environ['HELMSMAN_ENGINES']) / 'xray')
            path = Path(root) / 'xray.json'
            for masks in MASKS:
                with self.subTest(masks=masks):
                    source = xray_config()
                    source['outbounds'][0]['streamSettings']['finalmask'] = masks
                    path.write_text(json.dumps(compile_xray(parse(json.dumps(source))[0])))
                    checked = subprocess.run([binary, 'run', '-test', '-config', str(path)], capture_output=True, text=True)
                    self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
