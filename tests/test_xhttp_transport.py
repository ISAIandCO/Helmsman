"""Actual Xray client/server TCP and UDP over XHTTP and mux, no provider account."""
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
from helmsman.importers import parse, profile
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

    def exercise(self, mode, kind="vless", download=False, reality=False, network="xhttp", mux=None, native=False, method='aes-128-gcm', sockopt=None):
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
        if kind in {'shadowsocks', 'socks', 'http'}:
            o.pop('uuid')
            if kind == 'shadowsocks':
                password = 'AAECAwQFBgcICQoLDA0ODw==' if method.startswith('2022-') else 'test-password'
                settings = {'method': method, 'password': password, 'network': 'tcp,udp'}
                o.update(method=method, password=password)
            else:
                settings = {'accounts': [{'user': 'fixture-user', 'pass': 'fixture-password'}]}
                o.update(username='fixture-user', password='fixture-password')
                if kind == 'socks':
                    settings.update(auth='password', udp=True, ip='127.0.0.1')
                    o['version'] = '5'
        if download:
            o["transport"]["extra"] = {"downloadSettings": {"address": "download.fixture", "port": server_port, "network": "xhttp", "security": "tls", "tlsSettings": {"serverName": "localhost", "alpn": ["h2"], "useSystemCA": True}, "xhttpSettings": {"path": "/helmsman", "mode": mode}}}
        server = {"log": {"loglevel": "debug"}, "inbounds": [{"listen": "127.0.0.1", "port": server_port, "protocol": kind, "settings": settings, "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/helmsman", "mode": mode}, "security": "tls", "tlsSettings": {"alpn": ["h2", "http/1.1"], "certificates": [{"certificateFile": str(self.root / "cert"), "keyFile": str(self.root / "key")}]}}}], "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]}}]}
        if network != 'xhttp':
            stream = server['inbounds'][0]['streamSettings']
            stream.pop('xhttpSettings')
            stream['network'] = network
            o.pop('transport')
            if network == 'ws':
                stream['wsSettings'] = {'path': '/helmsman'}
                o['transport'] = {'type': 'ws', 'path': '/helmsman'}
                o['tls']['alpn'] = ['http/1.1']
            if network == 'grpc':
                stream['grpcSettings'] = {'serviceName': 'helmsman'}
                o['transport'] = {'type': 'grpc', 'service_name': 'helmsman'}
            if network == 'httpupgrade':
                stream['httpupgradeSettings'] = {'path': '/helmsman'}
                o['transport'] = {'type': 'httpupgrade', 'path': '/helmsman'}
                o['tls']['alpn'] = ['http/1.1']
        if kind == 'http':
            # Xray's HTTP inbound parses HTTP/1.1; do not advertise h2 in this fixture.
            server['inbounds'][0]['streamSettings']['tlsSettings']['alpn'] = ['http/1.1']
            o['tls']['alpn'] = ['http/1.1']
        if mux is not None:
            o['xray_mux'] = mux
        if reality:
            keys = subprocess.check_output([binary, "x25519"], text=True)
            private = re.search(r"PrivateKey: (\S+)", keys).group(1)
            public = re.search(r"Password \(PublicKey\): (\S+)", keys).group(1)
            target_port = port()
            # Local TLS 1.3 target for REALITY, no external website involved.
            target = json.loads(json.dumps(server["inbounds"][0]))
            target["port"] = target_port
            target["streamSettings"]["network"] = "raw"
            target["streamSettings"].pop("xhttpSettings", None)
            server["inbounds"].append(target)
            stream = server["inbounds"][0]["streamSettings"]
            stream.pop("tlsSettings")
            stream["security"] = "reality"
            stream["realitySettings"] = {"target": "127.0.0.1:" + str(target_port), "serverNames": ["localhost"], "privateKey": private, "shortIds": ["1234"]}
            o["tls"] = {"enabled": True, "server_name": "localhost", "utls": {"enabled": True, "fingerprint": "chrome"}, "reality": {"enabled": True, "public_key": public, "short_id": "1234"}}
        client = compile_xray(profile(o), (client_port, "test"))
        if native:
            raw = client['outbounds'][0]
            raw['streamSettings']['sockopt'].update(sockopt or {})
            raw['streamSettings'].update(kcpSettings=None, quicSettings={}, finalmask=None)
            imported = parse(json.dumps({'outbounds': [raw, {'protocol': 'loopback', 'settings': {'inboundTag': 'internal'}}]}))[0]
            client = compile_xray(imported, (client_port, 'test'))
            for key, value in (sockopt or {}).items():
                self.assertEqual(client['outbounds'][0]['streamSettings']['sockopt'][key], value)
        if mux is not None:
            self.assertEqual(client['outbounds'][0]['mux'], mux)
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
                    if kind != 'http': udp_echo(client_port, self.udp.server_address[1])
                    if mux is not None:
                        streams = []
                        try:
                            for i in range(3):
                                streams.append(socks_connect(client_port, 'helmsman', 'test', '127.0.0.1', self.tcp.server_address[1]))
                                streams[-1].sendall(b'parallel-mux')
                            for stream in streams:
                                self.assertEqual(receive(stream, 12), b'parallel-mux')
                        finally:
                            for stream in streams:
                                stream.close()
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

    def test_native_mux_tcp_ws_grpc_httpupgrade_tcp_and_udp(self):
        for kind in ('vless', 'vmess', 'trojan'):
            for network in ('tcp', 'ws', 'grpc', 'httpupgrade'):
                with self.subTest(kind=kind, network=network):
                    self.exercise('auto', kind, network=network, mux={'enabled': True, 'concurrency': 8, 'xudpConcurrency': 8, 'xudpProxyUDP443': 'skip'})

    def test_native_mux_reality_and_xhttp(self):
        self.exercise('auto', network='tcp', reality=True, mux={'enabled': True, 'concurrency': 8})
        self.exercise('packet-up', mux={'enabled': True, 'concurrency': -1, 'xudpConcurrency': 8})

    def test_native_xudp_without_tcp_mux(self):
        self.exercise('auto', network='tcp', mux={'enabled': True, 'concurrency': -1, 'xudpConcurrency': 8, 'xudpProxyUDP443': 'allow'})

    def test_native_json_shadowsocks_socks_http_actual_tls_connections(self):
        for kind in ('shadowsocks', 'socks', 'http'):
            with self.subTest(kind=kind):
                self.exercise('auto', kind=kind, network='tcp', native=True)
        self.exercise('auto', kind='shadowsocks', network='tcp', native=True, method='2022-blake3-aes-128-gcm')

    def test_native_json_sockopt_actual_tcp_and_udp_connections(self):
        for network in ('tcp', 'ws', 'grpc', 'xhttp'):
            with self.subTest(network=network):
                self.exercise('packet-up', network=network, native=True, sockopt={'tcpFastOpen': False, 'tcpKeepAliveIdle': 30, 'tcpKeepAliveInterval': 15, 'tcpUserTimeout': 10000, 'tcpMaxSeg': 1280, 'tcpWindowClamp': 65536, 'tcpCongestion': 'cubic', 'happyEyeballs': {'tryDelayMs': 250, 'maxConcurrentTry': 4}})

    def test_native_json_shadowsocks_socks_mux(self):
        for kind in ('shadowsocks', 'socks', 'http'):
            with self.subTest(kind=kind):
                self.exercise('auto', kind=kind, network='tcp', native=True, mux={'enabled': True, 'concurrency': 8, 'xudpProxyUDP443': 'skip'})
