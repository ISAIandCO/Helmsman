"""Actual Xray client/server TCP and UDP over XHTTP, no provider account."""
import json
import os
import re
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from helmsman.common import UserError
from helmsman.importers import profile
from helmsman.system import receive, socks_connect
from helmsman.xray import compile_xray

ENGINES = os.environ.get("HELMSMAN_ENGINES")
UUID = "00000000-0000-0000-0000-000000000001"


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(self.request.recv(256))


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


def udp_echo(socks_port, target_port):
    with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as control:
        control.sendall(b"\x05\x01\x02")
        assert receive(control, 2) == b"\x05\x02"
        control.sendall(b"\x01\x08helmsman\x04test")
        assert receive(control, 2) == b"\x01\x00"
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        header = receive(control, 4)
        assert header[1] == 0
        length = {1: 4, 4: 16}[header[3]]
        receive(control, length)
        udp_port = int.from_bytes(receive(control, 2), "big")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.sendto(b"\x00\x00\x00\x01\x7f\x00\x00\x01" + target_port.to_bytes(2, "big") + b"xhttp-game-udp", ("127.0.0.1", udp_port))
            assert s.recv(256).endswith(b"xhttp-game-udp")


@unittest.skipUnless(ENGINES, "set HELMSMAN_ENGINES for actual XHTTP traffic")
class XhttpTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.tcp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), TCP)
        cls.udp = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UDP)
        for s in (cls.tcp, cls.udp):
            s.daemon_threads = True
            threading.Thread(target=s.serve_forever, daemon=True).start()
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cls.root / "key"), "-out", str(cls.root / "cert"), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "extendedKeyUsage=serverAuth"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        for s in (cls.tcp, cls.udp):
            s.shutdown()
            s.server_close()
        cls.tmp.cleanup()

    def exercise(self, mode, kind="vless", download=False, reality=False):
        server_port, client_port = port(), port()
        binary = str(Path(ENGINES) / "xray")
        settings = {"clients": [{"id": UUID}], "decryption": "none"}
        o = {"type": kind, "server": "127.0.0.1", "server_port": server_port, "uuid": UUID, "tls": {"enabled": True, "server_name": "localhost", "alpn": ["h2"]}, "transport": {"type": "xhttp", "path": "/helmsman", "mode": mode}}
        if kind == "vmess":
            settings = {"clients": [{"id": UUID}]}
        if kind == "trojan":
            settings = {"clients": [{"password": "test-password"}]}
            o.pop("uuid")
            o["password"] = "test-password"
        if download:
            o["transport"]["extra"] = {"downloadSettings": {"address": "download.fixture", "port": server_port, "network": "xhttp", "security": "tls", "tlsSettings": {"serverName": "localhost", "alpn": ["h2"], "useSystemCA": True}, "xhttpSettings": {"path": "/helmsman", "mode": mode}}}
        server = {"log": {"loglevel": "debug"}, "inbounds": [{"listen": "127.0.0.1", "port": server_port, "protocol": kind, "settings": settings, "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/helmsman", "mode": mode}, "security": "tls", "tlsSettings": {"alpn": ["h2", "http/1.1"], "certificates": [{"certificateFile": str(self.root / "cert"), "keyFile": str(self.root / "key")}]}}}], "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]}}]}
        if reality:
            keys = subprocess.check_output([binary, "x25519"], text=True)
            private = re.search(r"PrivateKey: (\S+)", keys).group(1)
            public = re.search(r"Password \(PublicKey\): (\S+)", keys).group(1)
            target_port = port()
            # Local TLS 1.3 target for REALITY, no external website involved.
            target = json.loads(json.dumps(server["inbounds"][0]))
            target["port"] = target_port
            target["streamSettings"]["network"] = "raw"
            target["streamSettings"].pop("xhttpSettings")
            server["inbounds"].append(target)
            stream = server["inbounds"][0]["streamSettings"]
            stream.pop("tlsSettings")
            stream["security"] = "reality"
            stream["realitySettings"] = {"target": "127.0.0.1:" + str(target_port), "serverNames": ["localhost"], "privateKey": private, "shortIds": ["1234"]}
            o["tls"] = {"enabled": True, "server_name": "localhost", "utls": {"enabled": True, "fingerprint": "chrome"}, "reality": {"enabled": True, "public_key": public, "short_id": "1234"}}
        client = compile_xray(profile(o), (client_port, "test"))
        client["log"] = {"loglevel": "debug"}
        if download:
            client["dns"]["hosts"] = {"download.fixture": "127.0.0.1"}
        procs, logs = [], []
        try:
            for name, config in (("server", server), ("client", client)):
                path = self.root / (name + ".json")
                path.write_text(json.dumps(config))
                log = open(self.root / (name + ".log"), "w+")
                logs.append(log)
                procs.append(subprocess.Popen([binary, "run", "-config", str(path)], stdout=log, stderr=log, env={**os.environ, "SSL_CERT_FILE": str(self.root / "cert")}))
            error = None
            for _ in range(10):
                if any(p.poll() is not None for p in procs):
                    break
                try:
                    with socks_connect(client_port, "helmsman", "test", "127.0.0.1", self.tcp.server_address[1]) as s:
                        s.sendall(b"xhttp-real-tcp")
                        self.assertEqual(receive(s, 14), b"xhttp-real-tcp")
                    udp_echo(client_port, self.udp.server_address[1])
                    # The sidecar's TCP listener requires credentials.
                    with self.assertRaises(UserError):
                        socks_connect(client_port, "helmsman", "wrong", "127.0.0.1", self.tcp.server_address[1])
                    return
                except (OSError, UserError) as e:
                    error = e
                    time.sleep(0.1)
            content = []
            for log in logs:
                log.flush()
                log.seek(0)
                content.append(log.read())
            self.fail(f"{kind}/{mode}/download={download}: {error}; " + " ".join(content))
        finally:
            for p in procs:
                if p.poll() is None:
                    p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
            for log in logs:
                log.close()

    def test_vless_xhttp_tls_modes_tcp_and_udp(self):
        for mode in ("auto", "packet-up", "stream-up", "stream-one"):
            with self.subTest(mode=mode):
                self.exercise(mode)

    def test_vless_xhttp_reality_tcp_and_udp(self):
        self.exercise("packet-up", reality=True)

    def test_xhttp_separate_download_settings(self):
        self.exercise("packet-up", download=True)

    def test_vmess_trojan_xhttp(self):
        for kind in ("vmess", "trojan"):
            with self.subTest(kind=kind):
                self.exercise("packet-up", kind)
