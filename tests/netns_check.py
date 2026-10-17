"""Isolated real TUN/DNS/UDP/fail-closed lifecycle, executed by test-netns.sh."""
import json
import os
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from helmsman.common import Store, defaults
from helmsman.importers import parse
from helmsman.routing import rule
from helmsman.system import Runtime

ROOT = Path("/tmp/helmsman-netns-test")
UUID = "00000000-0000-0000-0000-000000000001"


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(self.request.recv(256))


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        end = 12
        while data[end]:
            end += data[end] + 1
        end += 5
        question = data[12:end]
        is_a = data[end - 4:end - 2] == b"\x00\x01"
        answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton("198.51.100.2") if is_a else b""
        sock.sendto(data[:2] + b"\x81\x80\x00\x01" + (b"\x00\x01" if is_a else b"\x00\x00") + b"\x00\x00\x00\x00" + question + answer, self.client_address)


def server():
    ROOT.mkdir(mode=0o711, exist_ok=True)
    os.chmod(ROOT, 0o711)
    servers = [socketserver.ThreadingTCPServer(("0.0.0.0", 19002), TCP), socketserver.ThreadingUDPServer(("0.0.0.0", 19003), UDP), socketserver.ThreadingUDPServer(("0.0.0.0", 53), DNS)]
    for s in servers:
        s.daemon_threads = True
        threading.Thread(target=s.serve_forever, daemon=True).start()
    config = {"log": {"level": "error"}, "inbounds": [{"type": "vless", "listen": "0.0.0.0", "listen_port": 19001, "users": [{"uuid": UUID}]}], "outbounds": [{"type": "direct", "tag": "direct"}], "dns": {"servers": [{"type": "udp", "tag": "local-dns", "server": "127.0.0.1"}]}, "route": {"default_domain_resolver": "local-dns", "final": "direct"}}
    file = ROOT / "server.json"
    file.write_text(json.dumps(config))
    p = subprocess.Popen([str(Path(os.environ["HELMSMAN_ENGINES"]) / "sing-box"), "run", "-c", str(file)])
    def stop(*_):
        p.terminate()
        for s in servers:
            s.shutdown()
        sys.exit(0)
    signal.signal(signal.SIGTERM, stop)
    (ROOT / "ready").touch()
    while True:
        if p.poll() is not None:
            raise RuntimeError("Test server engine exited")
        time.sleep(0.2)


def echo(host="198.51.100.2", timeout=5):
    with socket.create_connection((host, 19002), timeout=timeout) as s:
        s.sendall(b"helmsman-netns")
        assert s.recv(100) == b"helmsman-netns"


def client():
    for _ in range(100):
        if (ROOT / "ready").exists():
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("Test server did not start")
    echo()  # Proves a real direct route exists; a later failure isn't no route.
    store = Store(ROOT / "state")
    os.chmod(store.directory, 0o711)
    runtime = Runtime(os.environ["HELMSMAN_ENGINES"], store.directory / "runtime")
    state = store.data
    p = parse(f"vless://{UUID}@10.90.0.1:19001")[0]
    p["dns"] = "198.51.100.2"
    state.update(profiles=[p], selected=p["id"], desired=True)
    state["settings"].update(lan=False, dns_direct="198.51.100.2")
    store.save()
    saved_hwid = state["hwid"]
    try:
        runtime.start(state, p)
        for _ in range(100):
            if runtime.status()["state"] == "running":
                break
            time.sleep(0.1)
        else:
            raise AssertionError(runtime.status())
        echo()
        print("PASS real TUN TCP", flush=True)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.sendto(b"game-udp", ("198.51.100.2", 19003))
            assert s.recv(100) == b"game-udp"
        print("PASS real UDP through VLESS/TUN", flush=True)
        echo("game.example")
        print("PASS DNS interception + FakeIP + remote resolution", flush=True)
        state["rules"] = [rule({"type": "domain_suffix", "values": ["blocked.example"], "action": "block"}), rule({"type": "ip_cidr", "values": ["198.51.100.3/32"], "action": "block"})]
        runtime.start(state, p)
        time.sleep(0.5)
        for target in ("blocked.example", "198.51.100.3"):
            try:
                echo(target, 2)
            except OSError:
                pass
            else:
                raise AssertionError("Blocked route leaked: " + target)
        echo()
        print("PASS domain/DNS block and IP block; other traffic still works", flush=True)
        runtime.process.kill()
        runtime.process.wait(timeout=5)
        try:
            echo(timeout=2)
        except OSError:
            pass
        else:
            raise AssertionError("FAIL OPEN: traffic escaped after SIGKILL")
        assert runtime.guard
        print("PASS fail-closed after SIGKILL, including pre-existing direct underlay", flush=True)
        runtime.start(state, p)
        time.sleep(0.8)
        echo()
        assert Store(store.directory).data["hwid"] == saved_hwid
        print("PASS recovery + saved configuration/HWID", flush=True)
    finally:
        runtime.stop()
        runtime.clear_guard()
    assert not Path("/sys/class/net/helmsman0").exists()
    assert subprocess.run(["nft", "list", "table", "inet", "helmsman_guard"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0
    assert "31800" not in subprocess.check_output(["ip", "rule", "show"], text=True)
    echo()
    print("PASS disconnect cleanup and normal direct access", flush=True)
    before_routes = subprocess.check_output(["ip", "route", "show", "default"], text=True)
    zt = parse("zerotier://0123456789abcdef")[0]
    try:
        runtime.start(state, zt)
        status = None
        for _ in range(30):
            status = runtime.status()
            if status.get("node_id") and status["state"] == "authorizing":
                break
            if status["state"] == "error":
                raise AssertionError(status)
            time.sleep(0.2)
        else:
            raise AssertionError("ZeroTier did not expose pending join and Node ID: " + str(status))
        policy = (runtime.zt_home / "networks.d/0123456789abcdef.local.conf").read_text()
        for entry in ("allowDefault=0", "allowGlobal=0", "allowDNS=0"):
            assert entry in policy, policy
        assert subprocess.check_output(["ip", "route", "show", "default"], text=True) == before_routes
        print("PASS real ZeroTier Agent start, join pending, Node ID and route/DNS policy", flush=True)
    finally:
        runtime.stop()
        runtime.clear_guard()
    assert not list((runtime.zt_home / "networks.d").glob("*"))
    print("PASS ZeroTier disconnect and membership cleanup", flush=True)


if __name__ == "__main__":
    {"server": server, "client": client}[sys.argv[1]]()
