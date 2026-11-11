import copy
import json
import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from helmsman.boot_guard import policy
from helmsman.common import Store, UserError, defaults
from helmsman.daemon import Controller
from helmsman.fastest import GROUP_ID, candidates, choose, validate
from helmsman.importers import parse
from helmsman.dns import bootstrap_address
from helmsman.routing import compile_config, dns_inbounds
from helmsman.system import Runtime, dns_redirect_script
from test_core import LINK, MemoryRuntime


class TrialRuntime(MemoryRuntime):
    def __init__(self, directory):
        super().__init__(directory)
        self.profile = None
        self.delays = {}
        self.waiting = None
        self.probe_port, self.probe_password = 1234, 'test'

    def install_guard(self, lan):
        self.guard = True

    def start(self, state, profile):
        super().start(state, profile)
        self.profile = profile

    def stop(self):
        super().stop()
        self.profile = None

    def measure_profile(self, state, profile):
        if self.waiting:
            self.waiting.wait(3)
        delay = self.delays.get(profile['id'])
        return {'ok': False} if delay is None else {'ok': True, 'duration_ms': delay}


class FastestTests(unittest.TestCase):
    def fixture(self, directory):
        store = Store(directory)
        store.data['profiles'] = parse(LINK.replace('#One', '#VPN One') + '\n' + LINK.replace(':12345', ':12346').replace('#One', '#VPN Two'))
        store.data['selected'] = GROUP_ID
        runtime = TrialRuntime(directory)
        controller = Controller(store, runtime)
        return controller, runtime, store.data['profiles']

    def finish(self, controller, health=False):
        thread = controller.health_thread if health else controller.scan_thread
        thread.join(5)
        self.assertFalse(thread.is_alive())

    def test_regex_protocol_union_awg_and_empty(self):
        state = defaults()
        state['profiles'] = parse(LINK.replace('#One', '#VPN One') + '\nhy2://secret@127.0.0.1:443#VPN Two\nzerotier://0123456789abcdef')
        state['profiles'].append({'id': 'wg', 'kind': 'sing-box', 'name': 'VPN WG', 'outbound': {'type': 'wireguard', 'amnezia_wg': {}}})
        # Real AWG options are nonempty; distinguish them from plain WG.
        state['profiles'][-1]['outbound']['amnezia_wg'] = {'jc': 3}
        self.assertEqual(len(candidates(state)), 3)
        state['fastest'] = validate({'protocols': ['hysteria2', 'amneziawg']}, state['fastest'])
        self.assertEqual([p['name'] for p in candidates(state)], ['VPN Two', 'VPN WG'])
        state['fastest']['regex'] = '(?i)vpn two$'
        self.assertEqual(len(candidates(state)), 1)
        state['fastest']['regex'] = '^missing$'
        self.assertEqual(candidates(state), [])
        for invalid in ({'regex': '['}, {'regex': ''}, {'protocols': ['zerotier']}, {'protocols': 'vless'}, {'active': 'override'}, {'interval_seconds': True}, {'tolerance_ms': -1}):
            with self.subTest(invalid=invalid), self.assertRaises(UserError):
                validate(invalid, defaults()['fastest'])

    def test_only_working_hysteresis_and_failure(self):
        group = defaults()['fastest']
        r = {'a': {'ok': True, 'duration_ms': 100}, 'b': {'ok': True, 'duration_ms': 10}, 'bad': {'ok': False, 'duration_ms': 1}}
        self.assertEqual(choose(r, '', group, 0), 'b')
        self.assertEqual(choose(r, 'a', group, 20), 'a')
        self.assertEqual(choose(r, 'a', group, 400), 'b')
        r['a']['duration_ms'] = 40
        self.assertEqual(choose(r, 'a', group, 400), 'a')
        r['a']['ok'] = False
        self.assertEqual(choose(r, 'a', group, 0), 'b')
        self.assertEqual(choose({'a': {'ok': False}}, 'a', group, 400), '')

    def test_async_selection_persistence_health_failover_and_cancellation(self):
        with tempfile.TemporaryDirectory() as directory:
            controller, runtime, profiles = self.fixture(directory)
            first, second = [p['id'] for p in profiles]
            runtime.delays = {first: 20, second: 50}
            controller.call('connect', {})
            self.finish(controller)
            self.assertEqual(runtime.profile['id'], first)
            self.assertEqual(Store(directory).data['selected'], GROUP_ID)
            self.assertEqual(Store(directory).data['fastest']['active'], first)
            with patch('helmsman.daemon.probe_connection', return_value={'ok': False}):
                controller.scan_group(full=False)
                self.finish(controller, health=True)
                self.assertEqual(controller.scan_due, 0)
                controller.scan_group()
                self.finish(controller)
            self.assertEqual(runtime.profile['id'], second)
            # Stale successful work must never reconnect after disconnect.
            runtime.waiting = threading.Event()
            controller.scan_group()
            controller.call('disconnect', {})
            runtime.waiting.set()
            self.finish(controller)
            self.assertIsNone(runtime.profile)
            self.assertFalse(Store(directory).data['desired'])
            self.assertFalse(runtime.guard)

    def test_membership_changes_and_settings_are_persistent(self):
        with tempfile.TemporaryDirectory() as directory:
            controller, runtime, profiles = self.fixture(directory)
            controller.call('fastest_save', {'regex': 'Two$', 'protocols': ['vless'], 'interval_seconds': 120})
            runtime.delays = {p['id']: i + 1 for i, p in enumerate(profiles)}
            controller.call('connect', {})
            self.finish(controller)
            self.assertEqual(runtime.profile['id'], profiles[1]['id'])
            self.assertEqual(Store(directory).data['fastest']['regex'], 'Two$')
            controller.call('fastest_save', {'regex': 'One$'})
            self.finish(controller)
            self.assertEqual(runtime.profile['id'], profiles[0]['id'])
            before = copy.deepcopy(controller.data)
            with self.assertRaises(UserError):
                controller.call('fastest_save', {'regex': '['})
            self.assertEqual(controller.data, before)
            controller.call('disconnect', {})
            controller.call('fastest_save', {'regex': '^none$'})
            with self.assertRaises(UserError):
                controller.call('connect', {})
            self.assertFalse(controller.data['desired'])

    def test_legacy_state_and_boot_guard_for_virtual_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            old = defaults(); old.pop('fastest')
            Path(directory, 'state.json').write_text(json.dumps(old))
            store = Store(directory)
            self.assertEqual(store.data['fastest']['regex'], 'VPN')
            store.data.update(selected=GROUP_ID, desired=True, boot_id='boot-a')
            store.data['settings']['auto_connect'] = True
            store.save()
            store.prepare_boot('boot-b')
            self.assertTrue(store.data['desired'])
            with patch('helmsman.boot_guard.boot_id', return_value='boot-b'):
                self.assertEqual(policy(directory), (True, True))

    def test_crashed_only_candidate_is_retested_using_a_fresh_client(self):
        with tempfile.TemporaryDirectory() as directory:
            controller, runtime, profiles = self.fixture(directory)
            controller.data['profiles'] = profiles[:1]
            controller.data['desired'] = True
            runtime.start(controller.data, profiles[0])
            runtime.delays = {profiles[0]['id']: 15}
            with patch.object(runtime, 'status', return_value={'state': 'error'}), \
                 patch.object(runtime, 'start', wraps=runtime.start) as restart, \
                 patch('helmsman.daemon.probe_connection', side_effect=AssertionError('dead inbound must not be reused')):
                controller.scan_group()
                self.finish(controller)
                restart.assert_called_once()
            self.assertEqual(controller.data['fastest']['active'], profiles[0]['id'])


class DNSLifecycleTests(unittest.TestCase):
    def test_bootstrap_cannot_recurse_through_a_local_stub(self):
        for address in ('127.0.0.53', '127.0.0.1', '::1', '0.0.0.0', '::'):
            with self.subTest(address=address), self.assertRaises(UserError):
                bootstrap_address(address)
        self.assertEqual(bootstrap_address('192.168.1.1'), '192.168.1.1')

    def test_redirect_install_failure_stops_client_and_keeps_crash_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Runtime(directory, Path(directory, 'runtime'), engine_uid=os.getuid())
            state = defaults(); profile = parse(LINK)[0]
            def arm(_):
                runtime.guard = True
            with patch.object(runtime, 'check'), patch.object(runtime, 'binary', return_value=Path('/fixture/sing-box')), \
                 patch.object(runtime, 'install_guard', side_effect=arm), patch.object(runtime, 'clear_dns_redirect') as cleanup, \
                 patch.object(runtime, 'cleanup_routes'), patch.object(runtime, 'stop_process') as stop, \
                 patch('helmsman.system.socket.create_connection'), patch('helmsman.system.subprocess.Popen') as process, \
                 patch.object(runtime, 'install_dns_redirect', side_effect=UserError('fixture nft failure')):
                process.return_value.poll.return_value = None
                with self.assertRaisesRegex(UserError, 'fixture nft failure'):
                    runtime.start(state, profile)
                self.assertIsNone(runtime.process)
                self.assertTrue(runtime.guard)
                self.assertGreaterEqual(cleanup.call_count, 2)
                self.assertTrue(any(c.args[0] is process.return_value for c in stop.call_args_list))

    @unittest.skipUnless(os.environ.get('HELMSMAN_ENGINES'), 'set HELMSMAN_ENGINES for pinned engine schema checks')
    def test_native_dns_listener_config_both_engines_and_ip_stacks(self):
        with tempfile.TemporaryDirectory() as directory:
            state = defaults()
            profile = parse(LINK)[0]
            for engine in ('sing-box', 'sing-box-awg'):
                for ipv6 in (True, False):
                    state['settings']['ipv6'] = ipv6
                    config = compile_config(state, profile, directory, os.getuid())
                    dns_inbounds(config, 15353, ipv6)
                    addresses = [i['listen'] for i in config['inbounds'] if i['type'] == 'direct']
                    self.assertEqual(addresses, ['127.0.0.1', '::1'] if ipv6 else ['127.0.0.1'])
                    self.assertEqual(config['route']['rules'][0]['action'], 'hijack-dns')
                    self.assertEqual(config['dns']['servers'][2]['detour'], 'proxy')
                    path = Path(directory, 'config.json'); path.write_text(json.dumps(config))
                    with self.subTest(engine=engine, ipv6=ipv6):
                        subprocess.run([str(Path(os.environ['HELMSMAN_ENGINES'], engine)), 'check', '-c', str(path)], check=True, capture_output=True)

    def test_redirect_dual_stack_loop_exclusion_and_owned_cleanup(self):
        script = dns_redirect_script(1234, 4567)
        self.assertIn('table inet helmsman_dns', script)
        self.assertIn('type nat hook output priority -100', script)
        self.assertIn('{ tcp, udp } th dport 53 redirect to :4567', script)
        self.assertLess(script.index('skuid 1234 return'), script.index('redirect to'))
        self.assertNotIn('flush ruleset', script)
        with tempfile.TemporaryDirectory() as directory:
            import os
            runtime = Runtime(directory, Path(directory, 'runtime'), engine_uid=os.getuid())
            calls = []
            def run(args, **kwargs):
                calls.append((list(map(str, args)), kwargs))
                return type('Result', (), {'returncode': 0})()
            with patch('helmsman.system.run', side_effect=run):
                runtime.install_dns_redirect(4567)
                runtime.stop()
            deletes = [c for c, _ in calls if c == ['nft', 'delete', 'table', 'inet', 'helmsman_dns']]
            self.assertEqual(len(deletes), 2)
            calls.clear()
            runtime.tun = False
            with patch('helmsman.system.run', side_effect=run):
                runtime.stop()
            self.assertEqual(calls, [])  # Probe cleanup cannot touch serving host rules.
