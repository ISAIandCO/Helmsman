"""Actual HTTPS subscription requests, with a private test CA and local server."""
import copy
import base64
import gzip
import http.server
import json
import os
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.request
from unittest.mock import patch
from pathlib import Path

from helmsman.common import Store, UserError, defaults
from helmsman.daemon import Controller
from test_core import MemoryRuntime
from helmsman.subscriptions import SafeRedirect, download, update, validate_subscription
from test_subscription_compat import xray_config, xray_hysteria, xray_proxy

LINK = "vless://00000000-0000-0000-0000-000000000001@127.0.0.1:12345#HTTPS-test"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.seen.append(dict(self.headers))
        if self.path in ('/hwid-required', '/limit'):
            self.send_response(200 if self.path == '/limit' else 404)
            self.send_header('x-hwid-max-devices-reached' if self.path == '/limit' else 'x-hwid-not-supported', 'true')
            self.end_headers()
            return
        if self.path in ('/neko', '/mixed-xray', '/mixed-xray-bad'):
            expected = {'x-hwid': '0123456789abcdef', 'x-device-os': 'Android', 'x-ver-os': '16', 'x-device-model': 'Test Device'}
            if any(self.headers.get(k) != v for k, v in expected.items()) or not self.headers.get('user-agent', '').startswith('v2rayNG/'):
                self.send_response(403); self.end_headers(); return
            content = LINK.encode()
            if self.path.startswith('/mixed-xray'):
                source = xray_config()
                source['outbounds'] += [xray_proxy(t) for t in ('shadowsocks', 'socks', 'http')] + [xray_hysteria(), {'protocol': 'loopback'}]
                if self.path.endswith('-bad'):
                    source['outbounds'].append({'protocol': 'shadowsocksr', 'tag': 'private-name', 'settings': {'password': 'private-password'}})
                content = json.dumps([source]).encode()
            payload = gzip.compress(base64.b64encode(content))
            self.send_response(200)
            self.send_header('Content-Encoding', 'gzip')
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == '/gzip-overflow':
            self.send_response(200)
            self.send_header('Content-Encoding', 'gzip')
            self.end_headers()
            self.wfile.write(gzip.compress(b'x' * (8 * 1024 * 1024 + 1)))
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/sub")
            self.end_headers()
            return
        if self.path == "/cross-origin":
            self.send_response(302)
            self.send_header("Location", "https://elsewhere.invalid/sub")
            self.end_headers()
            return
        self.send_response(500 if self.path == "/error" else 200)
        self.end_headers()
        self.wfile.write(b"<html>error</html>" if self.path == "/html" else LINK.encode())

    def log_message(self, *_):
        # Test fixture never logs headers or keys.
        return


class HTTPSSubscriptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "key"), "-out", str(root / "cert"), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        except PermissionError:
            cls.tmp.cleanup()
            if os.environ.get("HELMSMAN_CI"):
                raise
            raise unittest.SkipTest("Sandbox forbids local HTTPS server")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(root / "cert", root / "key")
        cls.server.socket = ctx.wrap_socket(cls.server.socket, server_side=True)
        cls.server.seen = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        trusted = ssl.create_default_context(cafile=str(root / "cert"))
        cls.opener = urllib.request.build_opener(SafeRedirect(), urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trusted))
        cls.url = "https://localhost:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.tmp.cleanup()

    def test_hwid_over_verified_https_and_transactional_failure(self):
        state = defaults()
        s = validate_subscription({"name": "Test", "url": self.url + "/redirect", "hwid_mode": "remnawave"})
        state["subscriptions"] = [s]
        fetch = lambda url, headers: download(url, headers, self.opener)
        result = update(state, s["id"], lambda profiles: None, fetch)
        self.assertEqual(len(result["profiles"]), 1)
        seen = {k.lower(): v for k, v in self.server.seen[-1].items()}
        self.assertEqual(seen["x-hwid"], state["hwid"])
        self.assertEqual(seen["x-device-model"], "Steam Deck")
        for path in ("/error", "/html", "/cross-origin"):
            result["subscriptions"][0]["url"] = self.url + path
            before = copy.deepcopy(result)
            with self.assertRaises(UserError):
                update(result, s["id"], lambda profiles: None, fetch)
            self.assertEqual(before, result)

    def test_neko_hwid_user_agent_gzip_and_provider_denials_over_tls(self):
        state = defaults()
        s = validate_subscription({'url': self.url + '/neko', 'hwid_mode': 'remnawave', 'hwid_params': 'hwid=0123456789abcdef,os=Android,osVersion=16,model=Test Device'})
        state['subscriptions'] = [s]
        fetch = lambda url, headers: download(url, headers, self.opener)
        result = update(state, s['id'], lambda _: None, fetch)
        self.assertEqual(len(result['profiles']), 1)
        for path, message in [('/hwid-required', 'не принял HWID'), ('/limit', 'лимит устройств'), ('/gzip-overflow', 'больше 8 МиБ')]:
            result['subscriptions'][0]['url'] = self.url + path
            before = copy.deepcopy(result)
            with self.assertRaisesRegex(UserError, message):
                update(result, s['id'], lambda _: None, fetch)
            self.assertEqual(result, before)

    def test_service_manual_and_scheduled_refresh_use_saved_hwid_and_agent(self):
        with tempfile.TemporaryDirectory() as root, patch('helmsman.subscriptions.urllib.request.build_opener', return_value=self.opener):
            c = Controller(Store(root), MemoryRuntime(root))
            c.call('hwid', {'value': '0123456789abcdef'})
            saved = c.call('subscription_save', {'url': self.url + '/neko', 'hwid_mode': 'remnawave', 'hwid_params': 'hwid=0123456789abcdef,os=Android,osVersion=16,model=Test Device', 'interval_hours': 1})
            c.call('subscriptions_update', saved)
            self.assertEqual(len(c.data['profiles']), 1)
            before = copy.deepcopy(c.data['profiles'])
            c.data['subscriptions'][0]['last_attempt'] = 0
            c.tick()
            self.assertEqual(c.data['profiles'], before)
            self.assertEqual(c.data['subscriptions'][0]['error'], '')
            c.data['subscriptions'][0]['url'] = self.url + '/limit'
            with self.assertRaisesRegex(UserError, 'лимит устройств'):
                c.call('subscriptions_update', saved)
            self.assertEqual(c.data['profiles'], before)
            self.assertEqual(c.data['hwid'], '0123456789abcdef')
            self.assertIn('лимит устройств', c.data['subscriptions'][0]['error'])

    def test_mixed_xray_json_over_verified_https_keeps_previous_profiles_on_failure(self):
        state = defaults()
        sub = validate_subscription({'url': self.url + '/mixed-xray', 'hwid_mode': 'remnawave', 'hwid_params': 'hwid=0123456789abcdef,os=Android,osVersion=16,model=Test Device'})
        state['subscriptions'] = [sub]
        fetch = lambda url, headers: download(url, headers, self.opener)
        result = update(state, sub['id'], lambda _: None, fetch)
        self.assertEqual([p['outbound']['type'] for p in result['profiles']], ['vless', 'shadowsocks', 'socks', 'http', 'hysteria2'])
        result['subscriptions'][0]['url'] = self.url + '/mixed-xray-bad'
        before = copy.deepcopy(result)
        with self.assertRaisesRegex(UserError, r'JSON\[0\].outbounds\[7\].*shadowsocksr') as error:
            update(result, sub['id'], lambda _: None, fetch)
        self.assertNotIn('private-password', str(error.exception))
        self.assertNotIn('private-name', str(error.exception))
        self.assertEqual(before, result)


if __name__ == "__main__":
    unittest.main()
