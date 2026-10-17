"""Real DoH/DoT queries through direct and SOCKS-detoured native DNS transports."""
import http.server
import json
import os
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from helmsman.common import defaults
from helmsman.routing import compile_config
from helmsman.system import receive, socks_connect
from test_transports import Echo, port


def answer(data):
    end = 12
    while data[end]:
        end += data[end] + 1
    end += 5
    is_a = data[end - 4:end - 2] == b"\x00\x01"
    result = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01" if is_a else b""
    return data[:2] + b"\x81\x80\x00\x01" + (b"\x00\x01" if is_a else b"\x00\x00") + b"\x00\x00\x00\x00" + data[12:end] + result


class DoH(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        self.server.seen.append(self.path)
        data = answer(self.rfile.read(int(self.headers["Content-Length"])))
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


class DoT(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            while True:
                size = struct.unpack("!H", receive(self.request, 2))[0]
                data = answer(receive(self.request, size))
                self.server.seen.append("tls")
                self.request.sendall(struct.pack("!H", len(data)) + data)
        except (OSError, Exception):
            return


@unittest.skipUnless(os.environ.get("HELMSMAN_ENGINES"), "set HELMSMAN_ENGINES for native encrypted DNS tests")
class EncryptedDNSTests(unittest.TestCase):
    def test_doh_dot_direct_and_proxy_actual_queries(self):
        try:
            with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE):
                pass
        except PermissionError:
            if os.environ.get("HELMSMAN_CI"):
                raise
            self.skipTest("Sandbox forbids netlink; native DNS test required in CI")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "key"), "-out", str(root / "cert"), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(root / "cert", root / "key")
            echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
            doh = http.server.ThreadingHTTPServer(("127.0.0.1", 0), DoH)
            dot = socketserver.ThreadingTCPServer(("127.0.0.1", 0), DoT)
            for s in (doh, dot):
                s.socket = ctx.wrap_socket(s.socket, server_side=True)
                s.seen = []
            for s in (echo, doh, dot):
                s.daemon_threads = True
                threading.Thread(target=s.serve_forever, daemon=True).start()
            procs = []
            try:
                for name in ("sing-box", "sing-box-awg"):
                    proxy_port = port()
                    binary = str(Path(os.environ["HELMSMAN_ENGINES"]) / name)
                    server = {"log": {"disabled": True}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": proxy_port}], "outbounds": [{"type": "direct"}]}
                    server_file = root / "socks.json"
                    server_file.write_text(json.dumps(server))
                    proxy = subprocess.Popen([binary, "run", "-c", str(server_file)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    procs.append(proxy)
                    for scheme, dns in (("https", doh), ("tls", dot)):
                        for direction in ("direct", "proxy"):
                            with self.subTest(engine=name, scheme=scheme, direction=direction):
                                before = len(dns.seen)
                                listen = port()
                                state = defaults()
                                value = scheme + "://127.0.0.1:" + str(dns.server_address[1]) + ("/custom/token?device=test" if scheme == "https" else "")
                                state["settings"].update(dns_direct=value, dns_proxy=value)
                                p = {"outbound": {"type": "socks", "server": "127.0.0.1", "server_port": proxy_port}}
                                config = compile_config(state, p, root, os.getuid(), tun=False)
                                for s in config["dns"]["servers"][1:3]:
                                    s["tls"].update(server_name="localhost", certificate=[(root / "cert").read_text()])
                                config["inbounds"] = [{"type": "socks", "listen": "127.0.0.1", "listen_port": listen, "users": [{"username": "test", "password": "test"}]}]
                                config["route"].update(auto_detect_interface=False, rules=[{"action": "resolve", "server": "dns-" + direction}], final="direct")
                                file = root / "client.json"
                                file.write_text(json.dumps(config))
                                client = subprocess.Popen([binary, "run", "-c", str(file)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                procs.append(client)
                                try:
                                    for attempt in range(40):
                                        try:
                                            with socks_connect(listen, "test", "test", "game.fixture", echo.server_address[1]) as sock:
                                                sock.sendall(b"encrypted-dns")
                                                self.assertEqual(receive(sock, 13), b"encrypted-dns")
                                            break
                                        except OSError:
                                            if client.poll() is not None or attempt == 39:
                                                raise
                                            time.sleep(0.05)
                                    self.assertGreater(len(dns.seen), before)
                                    if scheme == "https":
                                        self.assertIn("/custom/token?device=test", dns.seen)
                                finally:
                                    client.terminate()
                                    client.wait(timeout=5)
                    proxy.terminate()
                    proxy.wait(timeout=5)
            finally:
                for p in procs:
                    if p.poll() is None:
                        p.kill()
                    p.wait(timeout=5)
                for s in (echo, doh, dot):
                    s.shutdown()
                    s.server_close()
