"""Only this module touches host networking. No shell and no imported scripts."""
import json
import os
import pwd
import secrets
import socket
import ssl
import subprocess
import time
from pathlib import Path

from .common import UserError, atomic_json
from .routing import compile_config


def run(args, *, input=None, check=True, timeout=15):
    try:
        p = subprocess.run([str(x) for x in args], input=input, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
    except (OSError, subprocess.TimeoutExpired):
        raise UserError("Системный компонент недоступен или не ответил: " + Path(str(args[0])).name) from None
    if check and p.returncode:
        raise UserError("Ошибка системного компонента: " + Path(str(args[0])).name + f" (код {p.returncode}).")
    return p


def firewall_script(engine_uid, lan):
    # Never accept established physical connections before the guard: existing
    # Steam sockets must also stop when the engine dies. Engine UID is reserved.
    rules = [f"meta skuid {int(engine_uid)} accept", 'oifname "lo" accept', 'oifname "helmsman0" accept',
             "udp sport 68 udp dport 67 accept", "udp sport 546 udp dport 547 accept",
             "icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept",
             "meta l4proto { tcp, udp } th dport 53 reject"]
    if lan:
        rules += ["ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4 } accept", "ip6 daddr { fc00::/7, fe80::/10, ff00::/8 } accept"]
    rules.append("reject with icmpx type admin-prohibited")
    return "add table inet helmsman_guard\nadd chain inet helmsman_guard output { type filter hook output priority 10; policy accept; }\n" + "\n".join("add rule inet helmsman_guard output " + r for r in rules) + "\n"


class Runtime:
    def __init__(self, binaries, directory, engine_uid=None):
        self.binaries = Path(binaries)
        self.directory = Path(directory)
        self.uid = engine_uid if engine_uid is not None else pwd.getpwnam("helmsman-engine").pw_uid
        self.gid = pwd.getpwuid(self.uid).pw_gid
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chown(self.directory, self.uid, self.gid)
        self.process = None
        self.profile = None
        self.guard = False
        self.started = 0
        self.probe_port = 0
        self.probe_password = ""
        self.last_probe = None
        self.zt_home = self.directory.parent / "zerotier"

    def binary(self, p):
        name = "sing-box-awg" if p.get("outbound", {}).get("amnezia_wg") else "sing-box"
        b = self.binaries / name
        if not os.access(b, os.X_OK):
            raise UserError("Не установлен движок " + name + ". Переустановите полный пакет Helmsman.")
        return b

    def check(self, config, profile):
        path = self.directory / "check.json"
        atomic_json(path, config)
        try:
            run([self.binary(profile), "check", "-c", path], timeout=20)
        except UserError:
            raise UserError("Движок отклонил конфигурацию. Проверьте параметры протокола, ключи и сертификаты; действующее подключение сохранено.") from None
        finally:
            path.unlink(missing_ok=True)

    def validate_profiles(self, profiles):
        for p in profiles:
            if p["kind"] == "sing-box":
                o = dict(p["outbound"], tag="proxy")
                key = "endpoints" if o["type"] in {"wireguard", "openvpn-client"} else "outbounds"
                self.check({"log": {"disabled": True}, key: [o], "route": {"default_domain_resolver": "local"}, "dns": {"servers": [{"type": "local", "tag": "local"}]}}, p)
            elif not os.access(self.binaries / "zerotier-one", os.X_OK):
                raise UserError("В пакете отсутствует ZeroTier Agent.")

    def install_guard(self, lan):
        # Replace the owned table in one nft transaction: never flush all rules.
        exists = run(["nft", "list", "table", "inet", "helmsman_guard"], check=False).returncode == 0
        script = ("delete table inet helmsman_guard\n" if exists else "") + firewall_script(self.uid, lan)
        run(["nft", "-f", "-"], input=script)
        self.guard = True

    def clear_guard(self):
        exists = run(["nft", "list", "table", "inet", "helmsman_guard"], check=False).returncode == 0
        if exists:
            run(["nft", "delete", "table", "inet", "helmsman_guard"])
        self.guard = False

    def cleanup_routes(self):
        # Reserved exclusively by this application, documented for recovery.
        for family in ("-4", "-6"):
            for pref in range(31800, 31812):
                run(["ip", family, "rule", "del", "pref", str(pref)], check=False)
            run(["ip", family, "route", "flush", "table", "31800"], check=False)
        run(["ip", "link", "del", "helmsman0"], check=False)

    def stop(self):
        if self.process:
            self.process.terminate() if self.process.poll() is None else None
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
            self.process = None
        if self.profile and self.profile["kind"] == "zerotier":
            # Process is gone; membership file removed so future starts don't join it.
            networks = self.zt_home / "networks.d"
            for f in networks.glob("*"):
                if f.is_file():
                    f.unlink()
        self.cleanup_routes()
        self.profile = None

    def start(self, state, p):
        if p["kind"] == "zerotier":
            self.stop()
            self.clear_guard()
            self.start_zerotier(p)
            return
        config = compile_config(state, p, self.directory, self.uid)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.probe_port = reservation.getsockname()[1]
        self.probe_password = secrets.token_hex(24)
        config["inbounds"].append({"type": "socks", "tag": "health", "listen": "127.0.0.1", "listen_port": self.probe_port, "users": [{"username": "health", "password": self.probe_password}]})
        config["route"]["rules"].insert(0, {"inbound": ["health"], "outbound": "proxy"})
        self.check(config, p)  # Validate before disturbing the previous engine.
        if state["settings"]["kill_switch"]:
            self.install_guard(state["settings"]["lan"])
        self.stop()
        if not state["settings"]["kill_switch"]:
            self.clear_guard()
        config_path = self.directory / "active.json"
        atomic_json(config_path, config)
        os.chown(config_path, self.uid, self.gid)
        args = ["setpriv", "--reuid", str(self.uid), "--regid", str(self.gid), "--clear-groups", "--no-new-privs", "--inh-caps", "+net_admin,+net_raw", "--ambient-caps", "+net_admin,+net_raw", str(self.binary(p)), "run", "-c", str(config_path)]
        self.process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": str(self.directory), "LANG": "C.UTF-8"})
        self.profile = p
        self.started = time.monotonic()
        self.last_probe = None

    def start_zerotier(self, p):
        self.zt_home.mkdir(mode=0o700, exist_ok=True)
        atomic_json(self.zt_home / "local.conf", {"settings": {"allowTcpFallbackRelay": True, "portMappingEnabled": False}})
        networks = self.zt_home / "networks.d"
        networks.mkdir(mode=0o700, exist_ok=True)
        # Write local policy BEFORE joining; a controller can never install a
        # physical default/global route or DNS during the first join window.
        (networks / (p["network_id"] + ".local.conf")).write_text("allowManaged=1\nallowGlobal=0\nallowDefault=0\nallowDNS=0\n")
        os.chmod(networks / (p["network_id"] + ".local.conf"), 0o600)
        self.process = subprocess.Popen([str(self.binaries / "zerotier-one"), "-p19993", str(self.zt_home)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.profile = p
        self.started = time.monotonic()

    def zt(self, *args):
        p = run([self.binaries / "zerotier-cli", "-D" + str(self.zt_home), "-j", *args], check=False, timeout=5)
        if p.returncode:
            return None
        try:
            return json.loads(p.stdout)
        except ValueError:
            return None

    def status(self):
        if not self.process:
            return {"state": "disconnected", "message": "Отключено", "guard": self.guard}
        if self.process.poll() is not None:
            return {"state": "error", "message": f"Сетевой движок завершился (код {self.process.returncode}). Проверьте профиль и доступность TUN.", "guard": self.guard}
        if self.profile["kind"] == "zerotier":
            info = self.zt("info") or {}
            nets = self.zt("listnetworks") or []
            network = next((n for n in nets if n.get("nwid", n.get("id")) == self.profile["network_id"]), None)
            if network is None:
                self.zt("join", self.profile["network_id"])
                return {"state": "connecting", "message": "ZeroTier: запрос конфигурации сети", "node_id": info.get("address", ""), "guard": False}
            status = network.get("status", "REQUESTING_CONFIGURATION")
            messages = {"OK": "Виртуальная сеть доступна. Интернет идёт обычным маршрутом.", "ACCESS_DENIED": "Разрешите этот Node ID в панели ZeroTier Central.", "REQUESTING_CONFIGURATION": "Ожидание конфигурации от контроллера ZeroTier.", "NOT_FOUND": "Сеть ZeroTier не найдена.", "PORT_ERROR": "ZeroTier не смог создать сетевой интерфейс."}
            return {"state": "connected" if status == "OK" else "authorizing" if status in {"ACCESS_DENIED", "REQUESTING_CONFIGURATION"} else "error", "message": messages.get(status, "ZeroTier: " + status), "node_id": info.get("address", ""), "addresses": network.get("assignedAddresses", []), "guard": False}
        if not Path("/sys/class/net/helmsman0").exists():
            return {"state": "connecting" if time.monotonic() - self.started < 20 else "error", "message": "Ожидание TUN-интерфейса", "guard": self.guard}
        # Engine running is deliberately not a successful remote handshake.
        return {"state": "running", "message": "Маршрутизация включена; доступность сервера проверяется отдельно.", "guard": self.guard, "last_probe": self.last_probe}

    def probe(self):
        if not self.process or self.process.poll() is not None or not self.profile or self.profile["kind"] != "sing-box":
            raise UserError("Проверка доступна при включённом VPN-профиле.")
        start = time.monotonic()
        try:
            sock = socks_connect(self.probe_port, "health", self.probe_password, "store.steampowered.com", 443)
            with ssl.create_default_context().wrap_socket(sock, server_hostname="store.steampowered.com") as tls:
                tls.sendall(b"HEAD / HTTP/1.1\r\nHost: store.steampowered.com\r\nConnection: close\r\n\r\n")
                response = tls.recv(64)
                if not response.startswith(b"HTTP/"):
                    raise OSError()
            self.last_probe = {"ok": True, "time": time.time(), "duration_ms": int((time.monotonic() - start) * 1000), "message": "Steam Store доступен через выбранное подключение (DNS, TCP и TLS)."}
        except (OSError, UserError):
            self.last_probe = {"ok": False, "time": time.time(), "message": "Не удалось открыть Steam Store через профиль. Проверьте ключи, сервер, DNS и ограничения сети."}
        return self.last_probe

    def decompile_list(self, data, target):
        path = self.directory / "list.srs"
        path.write_bytes(data)
        try:
            run([self.binaries / "sing-box", "rule-set", "decompile", path, "-o", target])
        finally:
            path.unlink(missing_ok=True)


def network_signature():
    """Cheap netlink snapshot, no public ping every few seconds."""
    return run(["ip", "-j", "route", "show", "table", "main"], check=False).stdout


def receive(sock, size):
    result = b""
    while len(result) < size:
        block = sock.recv(size - len(result))
        if not block:
            raise OSError("EOF")
        result += block
    return result


def socks_connect(port, username, password, target, target_port):
    """Authenticated SOCKS5, including domain resolution inside the tunnel."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        sock.sendall(b"\x05\x01\x02")
        if receive(sock, 2) != b"\x05\x02":
            raise UserError("Проверка прокси не прошла.")
        u, p = username.encode(), password.encode()
        sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        if receive(sock, 2) != b"\x01\x00":
            raise UserError("Ошибка авторизации локальной проверки.")
        t = target.encode("idna")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(t)]) + t + int(target_port).to_bytes(2, "big"))
        header = receive(sock, 4)
        if header[1] != 0:
            raise UserError("Не удалось подключиться к проверочному адресу.")
        size = {1: 4, 4: 16}.get(header[3])
        if header[3] == 3:
            size = receive(sock, 1)[0]
        if size is None:
            raise UserError("Некорректный ответ SOCKS.")
        receive(sock, size + 2)
        return sock
    except Exception:
        sock.close()
        raise
