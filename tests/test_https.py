"""Actual HTTPS subscription requests, with a private test CA and local server."""
import copy
import http.server
import json
import os
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from helmsman.common import UserError, defaults
from helmsman.subscriptions import SafeRedirect, download, update, validate_subscription

LINK = "vless://00000000-0000-0000-0000-000000000001@127.0.0.1:12345#HTTPS-test"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.seen.append(dict(self.headers))
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


if __name__ == "__main__":
    unittest.main()
