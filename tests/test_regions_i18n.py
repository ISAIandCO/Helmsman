import ast
import copy
import json
import io
import struct
from types import SimpleNamespace
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from helmsman.common import Store, UserError, defaults
from helmsman.daemon import Controller, Handler
from helmsman.i18n import EN, localize_response, translate_message
from helmsman.importers import parse
from helmsman.regions import BUILTIN_LISTS, COUNTRIES, PRESETS, SUFFIXES, available_presets, preset_description, required_lists
from helmsman.routing import compile_config, rule, source_list
from test_core import MemoryRuntime, LINK

ROOT = Path(__file__).resolve().parents[1]


class RegionTests(unittest.TestCase):
    def test_migrate_and_independent_preferences_without_restart(self):
        for preset in ('full', 'ru-selective', 'ru-except', 'manual'):
            with self.subTest(preset=preset), tempfile.TemporaryDirectory() as d:
                old = defaults()
                old['settings'].pop('language'); old['settings'].pop('country')
                old['preset'] = preset
                old['profiles'] = parse(LINK)
                old['selected'] = old['profiles'][0]['id']
                old['rules'] = [rule({'name': 'Правило', 'values': ['example.com']})]
                old['lists'] = [{'id': 'a' * 32, 'name': 'Мой список', 'url': 'https://example.com/list'}]
                old['desired'] = True
                Path(d, 'state.json').write_text(json.dumps(old))
                store = Store(d); runtime = MemoryRuntime(d)
                controller = Controller(store, runtime)
                runtime.start = unittest.mock.Mock()
                controller.call('preferences', {'language': 'en'})
                self.assertEqual(store.data['settings']['country'], 'ru')
                self.assertIn('ru-selective', controller.status()['presets'])
                controller.call('preferences', {'country': 'cn'})
                self.assertEqual(store.data['settings']['language'], 'en')
                self.assertEqual(store.data['preset'], preset)
                self.assertEqual(store.data['selected'], old['selected'])
                self.assertEqual(store.data['rules'], old['rules'])
                self.assertEqual(store.data['lists'][0], old['lists'][0])
                for key in ('profiles', 'subscriptions', 'hwid', 'desired'):
                    self.assertEqual(store.data[key], old[key])
                for key, value in old['settings'].items():
                    self.assertEqual(store.data['settings'][key], value)
                runtime.start.assert_not_called()
                reopened = Store(d)
                self.assertEqual(reopened.data, store.data)
                self.assertNotIn('ru-selective', controller.status()['presets'])
                with self.assertRaises(UserError):
                    controller.call('preset', {'preset': 'ru-selective'})
                controller.call('preferences', {'language': 'ru'})
                self.assertEqual(controller.status()['country'], 'cn')

    def test_apply_failure_is_atomic_and_user_rules_survive(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(d); runtime = MemoryRuntime(d); controller = Controller(store, runtime)
            store.data['rules'] = [rule({'values': ['keep.example'], 'action': 'proxy'})]
            controller.call('preferences', {'country': 'ir'})
            before = copy.deepcopy(store.data)
            with patch.object(controller, 'load_list', side_effect=UserError('offline')):
                with self.assertRaises(UserError): controller.apply_preset('ir-except')
            self.assertEqual(store.data, before)
            def loaded(item):
                path = Path(d, item['id'] + '.json')
                path.write_text(json.dumps({'version': 3, 'rules': [{'domain_suffix': ['iran.example']}]}))
                return {**item, 'path': str(path)}
            with patch.object(controller, 'load_list', side_effect=loaded):
                controller.apply_preset('ir-except')
            self.assertEqual(store.data['preset'], 'ir-except')
            self.assertEqual(store.data['rules'], before['rules'])
            self.assertEqual(Store(d).data['preset'], 'ir-except')

    def test_all_presets_compile_with_language_country_independent_of_active_route(self):
        with tempfile.TemporaryDirectory() as d:
            state = defaults()
            for tag in BUILTIN_LISTS:
                path = Path(d, tag + '.json')
                value = {'ip_cidr': ['203.0.113.0/24']} if 'ip' in tag else {'domain_suffix': [tag + '.example']}
                path.write_text(json.dumps({'version': 3, 'rules': [value]}))
                state['lists'].append({'id': tag, 'path': str(path)})
            state['rules'] = [rule({'values': ['custom.example'], 'action': 'block'})]
            p = parse(LINK)[0]
            for preset in PRESETS:
                for lan in (True, False):
                    with self.subTest(preset=preset, lan=lan):
                        state['preset'] = preset; state['settings']['lan'] = lan
                        a = compile_config(state, p, d, 999)
                        state['settings'].update(language='en', country='other')
                        self.assertEqual(a, compile_config(state, p, d, 999))
                        rules = a['route']['rules']
                        custom = next(i for i, x in enumerate(rules) if x.get('domain_suffix') == ['custom.example'])
                        regional = next((i for i, x in enumerate(rules) if x.get('rule_set')), len(rules))
                        self.assertLess(custom, regional)
                        self.assertEqual(any(x.get('ip_is_private') and x.get('outbound') == 'direct' for x in rules), lan)
                        self.assertEqual(a['dns']['rules'][0].get('server') == 'bootstrap', lan)
                        self.assertEqual({x['tag'] for x in a['route']['rule_set']}, set(required_lists(preset)))
                        self.assertEqual(a['route']['final'], 'direct' if preset == 'ru-selective' else 'proxy')
                        self.assertEqual(a['dns']['final'], 'dns-direct' if preset == 'ru-selective' else 'dns-proxy')
                        # IP-only rule sets must never enter modern DNS rule sets.
                        self.assertNotIn('rule_set', json.dumps(a['dns']['rules']))
            for country in SUFFIXES:
                state['preset'] = country + '-domains-only'
                a = compile_config(state, p, d, 999)
                self.assertIn({'domain_suffix': SUFFIXES[country], 'outbound': 'direct'}, a['route']['rules'])
                self.assertIn({'domain_suffix': SUFFIXES[country], 'server': 'dns-direct'}, a['dns']['rules'])
            for country in COUNTRIES:
                for key in available_presets(country):
                    self.assertTrue(key in {'full', 'manual'} or key.startswith(country + '-'))
                    self.assertFalse(re.search('[А-Яа-яЁё]', translate_message(PRESETS[key], 'en')))
                    self.assertFalse(re.search('[А-Яа-яЁё]', translate_message(preset_description(key), 'en')))

    def test_source_regex_preserved_in_routing_and_dns(self):
        expression = r'^cdn[0-9]+\.example\.com$'
        obj = source_list({'version': 3, 'rules': [{'domain_regex': [expression]}]})
        with tempfile.TemporaryDirectory() as d:
            path = Path(d, 'cn.json'); path.write_text(json.dumps(obj))
            state = defaults(); state['preset'] = 'cn-domains-only'
            state['lists'] = [{'id': 'cn-domains', 'path': str(path)}]
            config = compile_config(state, parse(LINK)[0], d, 999)
            self.assertIn({'domain_regex': [expression], 'server': 'dns-direct'}, config['dns']['rules'])
            self.assertEqual(json.loads(path.read_text())['rules'][0]['domain_regex'][0], expression)
        for bad in ('', 'x' * 4097, 'bad\nregex', 42):
            with self.assertRaises(UserError): source_list({'version': 3, 'rules': [{'domain_regex': [bad]}]})

    def test_rpc_localizes_only_own_messages_and_validates_preferences(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(d); controller = Controller(store, MemoryRuntime(d))
            store.data['profiles'] = parse(LINK)
            store.data['profiles'][0]['name'] = 'Ошибка'
            controller.last_error = 'Сначала загрузите список: cn-domains'
            # Exercise the actual wire handler without binding a socket: some
            # development sandboxes prohibit AF_UNIX (test_core covers real IPC).
            def rpc(method, params=None):
                handler = Handler.__new__(Handler)
                handler.server = SimpleNamespace(controller=controller, owner_uid=os.getuid())
                handler.request = SimpleNamespace(settimeout=lambda _: None, getsockopt=lambda *_: struct.pack('3i', 1, os.getuid(), os.getgid()))
                handler.rfile = io.BytesIO(json.dumps({'method': method, 'params': params or {}}).encode() + b'\n')
                handler.wfile = io.BytesIO()
                handler.handle()
                result = json.loads(handler.wfile.getvalue())
                if not result['ok']:
                    raise UserError(result['error'])
                return result['result']
            value = rpc('preferences', {'language': 'en'})
            self.assertEqual(value['profiles'][0]['name'], 'Ошибка')
            self.assertEqual(value['error'], 'Download the list first: cn-domains')
            self.assertEqual(value['country'], 'ru')
            self.assertEqual(rpc('configuration')['profiles'][0]['name'], 'Ошибка')
            with self.assertRaisesRegex(UserError, 'Unknown command'):
                rpc('unknown')
            before = copy.deepcopy(store.data)
            for params in ({'country': 'zz'}, {'language': 'zz'}, {'country': 'ir', 'language': 'zz'}, {'preset': 'full'}):
                with self.assertRaises(UserError): rpc('preferences', params)
                self.assertEqual(store.data, before)
            rpc('preferences', {'language': 'ru'})
            self.assertIn('Сначала загрузите', rpc('status')['error'])

    def test_catalogue_covers_every_own_russian_literal(self):
        for path in [*ROOT.joinpath('helmsman').glob('*.py'), ROOT / 'decky/main.py']:
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and re.search('[А-Яа-яЁё]', node.value) and node.value != 'Русский':
                    with self.subTest(path=path.name, text=node.value):
                        self.assertIn(node.value, EN)
                        self.assertFalse(re.search('[А-Яа-яЁё]', EN[node.value]))
        for text in re.findall(r'"((?:[^"\\]|\\.)*)"', ROOT.joinpath('decky/src/index.tsx').read_text()):
            if re.search('[А-Яа-яЁё]', text) and text != 'Русский':
                self.assertIn(json.loads('"' + text + '"'), EN)
        self.assertEqual(translate_message('Ошибка системного компонента: sing-box (код 1).', 'en'), 'System component error: sing-box (code 1).')
        self.assertEqual(localize_response({'name': 'Ошибка', 'outbound': {'message': 'Ошибка'}}, 'en'), {'name': 'Ошибка', 'outbound': {'message': 'Ошибка'}})
