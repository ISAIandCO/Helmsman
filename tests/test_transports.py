"""Real local engine-to-engine traffic. Does not assert third-party interoperability."""
import base64
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

from helmsman.common import defaults
from helmsman.importers import profile
from helmsman.routing import compile_config
from helmsman.system import receive, socks_connect

ENGINE_DIR = os.environ.get("HELMSMAN_ENGINES", "")
UUID = "00000000-0000-0000-0000-000000000001"


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(100)
        self.request.sendall(data)


@unittest.skipUnless(ENGINE_DIR, "set HELMSMAN_ENGINES for actual transport tests")
class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE):
                pass
            cls.echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
        except PermissionError:
            if os.environ.get("HELMSMAN_CI"):
                raise
            raise unittest.SkipTest("Sandbox forbids netlink/local sockets; required in GitHub CI")
        cls.echo.daemon_threads = True
        cls.thread = threading.Thread(target=cls.echo.serve_forever, daemon=True)
        cls.thread.start()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cls.root / "key"), "-out", str(cls.root / "cert"), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "extendedKeyUsage=serverAuth"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.cert = (cls.root / "cert").read_text()
        cls.key = (cls.root / "key").read_text()

    @classmethod
    def tearDownClass(cls):
        cls.echo.shutdown()
        cls.echo.server_close()
        cls.thread.join()
        cls.tmp.cleanup()

    def exercise(self, kind, transport=None):
        server_port, socks_port = port(), port()
        binary = Path(ENGINE_DIR) / ("sing-box-awg" if kind == "amneziawg" else "sing-box")
        t = "wireguard" if kind == "amneziawg" else kind
        server = {"type": t, "listen": "127.0.0.1", "listen_port": server_port}
        out = {"type": t, "server": "127.0.0.1", "server_port": server_port}
        if t in {"vless", "vmess", "tuic"}:
            out["uuid"] = UUID
            server["users"] = [{"uuid": UUID}]
        if t in {"trojan", "hysteria2", "anytls", "tuic"}:
            out["password"] = "test-password"
            if t == "tuic":
                server["users"][0]["password"] = "test-password"
            else:
                server["users"] = [{"password": "test-password"}]
        if t == "shadowsocks":
            server.update(method="aes-128-gcm", password="test-password")
            out.update(method="aes-128-gcm", password="test-password")
        if t == "vmess":
            out["security"] = "auto"
        if t == "hysteria":
            server.update(up_mbps=100, down_mbps=100, users=[{"auth_str": "test-password"}])
            out.update(up_mbps=100, down_mbps=100, auth_str="test-password")
        if t in {"trojan", "hysteria", "hysteria2", "tuic", "anytls", "openvpn-client"}:
            server["tls"] = {"enabled": True, "certificate": [self.cert], "key": [self.key]}
            out["tls"] = {"enabled": True, "server_name": "localhost", "certificate": [self.cert]}
        if transport:
            server["transport"] = out["transport"] = transport
        endpoints = []
        if t == "openvpn-client":
            server = {"type": "openvpn-server", "listen": "127.0.0.1", "listen_port": server_port, "network": "udp", "mode": "tls", "address": ["10.211.0.1/24"], "topology": "subnet", "users": [{"username": "test", "password": "test-password"}], "tls": {"certificate": [self.cert], "key": [self.key], "verify_client_certificate": "none"}}
            out.update(network="udp", username="test", password="test-password")
            out["tls"].pop("enabled")
            out["tls"].update(remote_certificate_tls="server", server_name_type="name")
            endpoints = [server]
        if t == "wireguard":
            def keypair():
                output = subprocess.check_output([str(binary), "generate", "wg-keypair"], text=True)
                keys = re.findall(r"[A-Za-z0-9+/]{43}=", output)
                self.assertEqual(len(keys), 2)
                return keys
            spriv, spub = keypair()
            cpriv, cpub = keypair()
            server = {"type": "wireguard", "tag": "server", "listen_port": server_port, "address": ["10.211.0.1/24"], "private_key": spriv, "peers": [{"public_key": cpub, "allowed_ips": ["10.211.0.2/32"]}], "workers": 2}
            out = {"type": "wireguard", "address": ["10.211.0.2/32"], "private_key": cpriv, "peers": [{"address": "127.0.0.1", "port": server_port, "public_key": spub, "allowed_ips": ["0.0.0.0/0"]}], "workers": 2}
            if kind == "amneziawg":
                obfs = {"jc": 2, "jmin": 40, "jmax": 80, "s1": 16, "s2": 16, "s3": 8, "s4": 4, "h1": "123", "h2": "456", "h3": "789", "h4": "987"}
                server["amnezia_wg"] = out["amnezia_wg"] = obfs
            endpoints = [server]
        server_config = {"log": {"level": "debug"}, "inbounds": [] if endpoints else [server], "endpoints": endpoints, "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}
        p = profile(out, "test")
        state = defaults()
        state["settings"]["lan"] = False
        client_config = compile_config(state, p, self.root, os.getuid(), tun=False)
        client_config["log"] = {"level": "debug"}
        # This test has no TUN: binding UDP to the physical interface would
        # intentionally make the loopback-only server unreachable. The separate
        # namespace test exercises the application's real auto-detection/TUN.
        client_config["route"]["auto_detect_interface"] = False
        client_config["inbounds"] = [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port, "users": [{"username": "test", "password": "test"}]}]
        procs, logs = [], []
        try:
            for name, config in (("server", server_config), ("client", client_config)):
                file = self.root / (name + ".json")
                file.write_text(json.dumps(config))
                log = open(self.root / (name + ".log"), "w+")
                logs.append(log)
                procs.append(subprocess.Popen([str(binary), "run", "-c", str(file)], stdout=log, stderr=log))
            last = None
            deadline = time.monotonic() + 25
            for _ in range(250):
                if time.monotonic() > deadline:
                    break
                if any(p.poll() is not None for p in procs):
                    break
                try:
                    target = "10.211.0.1" if endpoints else "127.0.0.1"
                    with socks_connect(socks_port, "test", "test", target, self.echo.server_address[1]) as sock:
                        sock.sendall(b"helmsman-real-transport")
                        self.assertEqual(receive(sock, 23), b"helmsman-real-transport")
                    return
                except (OSError, Exception) as e:
                    last = e
                    time.sleep(0.1)
            for log in logs:
                log.flush()
                log.seek(0)
            self.fail(kind + " failed: " + str(last) + " " + " ".join(log.read()[-2000:] for log in logs))
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

    def test_vless_tcp(self): self.exercise("vless")
    def test_vless_websocket(self): self.exercise("vless", {"type": "ws", "path": "/helmsman"})
    def test_vmess(self): self.exercise("vmess")
    def test_shadowsocks(self): self.exercise("shadowsocks")
    def test_trojan(self): self.exercise("trojan")
    def test_hysteria1(self): self.exercise("hysteria")
    def test_hysteria2(self): self.exercise("hysteria2")
    def test_tuic(self): self.exercise("tuic")
    def test_anytls(self): self.exercise("anytls")
    def test_wireguard(self): self.exercise("wireguard")
    def test_amneziawg(self): self.exercise("amneziawg")
    def test_openvpn(self): self.exercise("openvpn-client")


if __name__ == "__main__":
    unittest.main()
