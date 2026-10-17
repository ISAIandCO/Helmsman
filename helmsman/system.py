"""Only this module touches host networking. No shell and no imported scripts."""
import json
import ipaddress
import os
import pwd
import secrets
import signal
import socket
import ssl
import subprocess
import time
from pathlib import Path

from .common import UserError, atomic_json
from .routing import compile_config
from .xray import compile_xray, uses_xray, socks_outbound


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
        self.xray_process = None
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

    def check_xray(self, profile, state=None):
        path = self.directory / "check-xray.json"
        settings = (state or {}).get("settings", {})
        atomic_json(path, compile_xray(profile, bootstrap=settings.get("dns_bootstrap", "9.9.9.9"), ipv6=settings.get("ipv6", True)))
        try:
            run([self.binaries / "xray", "run", "-test", "-config", path], timeout=20)
        except UserError:
            raise UserError("Xray отклонил профиль. Проверьте mux, транспорт, UUID, TLS/REALITY и версию сервера; действующее подключение сохранено.") from None
        finally:
            path.unlink(missing_ok=True)

    def check(self, config, profile):
        if uses_xray(profile):
            self.check_xray(profile)
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
                o = dict(socks_outbound() if uses_xray(p) else p["outbound"], tag="proxy")
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
        atomic_json(self.directory.parent / "guard.json", {"armed": True, "lan": bool(lan)})

    def clear_guard(self):
        exists = run(["nft", "list", "table", "inet", "helmsman_guard"], check=False).returncode == 0
        if exists:
            run(["nft", "delete", "table", "inet", "helmsman_guard"])
        self.guard = False
        atomic_json(self.directory.parent / "guard.json", {"armed": False, "lan": False})

    def cleanup_routes(self):
        # Reserved exclusively by this application, documented for recovery.
        for family in ("-4", "-6"):
            for pref in range(31800, 31812):
                run(["ip", family, "rule", "del", "pref", str(pref)], check=False)
            run(["ip", family, "route", "flush", "table", "31800"], check=False)
        run(["ip", "link", "del", "helmsman0"], check=False)

    def stop_process(self, process):
        if not process:
            return
        if process.poll() is None:
            self.signal_child(signal.SIGTERM, process)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.signal_child(signal.SIGKILL, process)
            process.wait(timeout=3)

    def stop(self):
        # Stop the TUN client before its XHTTP transport. Guard remains armed.
        self.stop_process(self.process)
        self.process = None
        self.stop_process(self.xray_process)
        self.xray_process = None
        for name in ("active.json", "active-xray.json"):
            (self.directory / name).unlink(missing_ok=True)
        if self.profile and self.profile["kind"] == "zerotier":
            # Process is gone; membership file removed so future starts don't join it.
            networks = self.zt_home / "networks.d"
            for f in networks.glob("*"):
                if f.is_file():
                    f.unlink()
        self.cleanup_routes()
        self.profile = None

    def signal_child(self, sig, process=None):
        process = process or self.process
        try:
            process.send_signal(sig)
        except PermissionError:
            # The root supervisor deliberately has no CAP_KILL. Signal only
            # our tracked child using its reserved engine UID, with no caps.
            # The PID comes from Popen; no RPC parameter can choose a target.
            if not self.profile or self.profile["kind"] != "sing-box":
                raise UserError("Не удалось остановить дочерний сетевой процесс.") from None
            run(["setpriv", "--reuid", str(self.uid), "--regid", str(self.gid), "--clear-groups", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "kill", "-s", str(int(sig)), "--", str(process.pid)], check=False)

    def start(self, state, p):
        if p["kind"] == "zerotier":
            self.stop()
            self.clear_guard()
            self.start_zerotier(p)
            return
        xray_proxy = None
        if uses_xray(p):
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                xray_proxy = (reservation.getsockname()[1], secrets.token_hex(24))
        config = compile_config(state, p, self.directory, self.uid, xray_proxy=xray_proxy)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.probe_port = reservation.getsockname()[1]
        self.probe_password = secrets.token_hex(24)
        config["inbounds"].append({"type": "socks", "tag": "health", "listen": "127.0.0.1", "listen_port": self.probe_port, "users": [{"username": "health", "password": self.probe_password}]})
        config["route"]["rules"][0:0] = [
            {"inbound": ["health"], "action": "resolve", "server": "dns-proxy"},
            {"inbound": ["health"], "outbound": "proxy"},
        ]
        self.check(config, p)  # Validate before disturbing the previous engine.
        if state["settings"]["kill_switch"]:
            self.install_guard(state["settings"]["lan"])
        self.stop()
        if not state["settings"]["kill_switch"]:
            self.clear_guard()
        config_path = self.directory / "active.json"
        atomic_json(config_path, config)
        os.chown(config_path, self.uid, self.gid)
        self.profile = p
        if xray_proxy:
            path = self.directory / "active-xray.json"
            atomic_json(path, compile_xray(p, xray_proxy, state["settings"]["dns_bootstrap"], state["settings"]["ipv6"]))
            os.chown(path, self.uid, self.gid)
            args = ["setpriv", "--reuid", str(self.uid), "--regid", str(self.gid), "--clear-groups", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", str(self.binaries / "xray"), "run", "-config", str(path)]
            try:
                self.xray_process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": str(self.directory), "LANG": "C.UTF-8"})
                ready = False
                for _ in range(40):
                    if self.xray_process.poll() is not None:
                        break
                    try:
                        with socket.create_connection(("127.0.0.1", xray_proxy[0]), timeout=0.05):
                            ready = True
                        break
                    except OSError:
                        time.sleep(0.05)
                if not ready:
                    raise UserError("Xray не запустил локальный XHTTP-транспорт. Проверьте установку и профиль.")
            except (OSError, UserError):
                self.stop()
                raise UserError("Не удалось запустить Xray. Проверьте установку и профиль.") from None
        args = ["setpriv", "--reuid", str(self.uid), "--regid", str(self.gid), "--clear-groups", "--no-new-privs", "--inh-caps", "+net_admin,+net_raw", "--ambient-caps", "+net_admin,+net_raw", str(self.binary(p)), "run", "-c", str(config_path)]
        try:
            self.process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": str(self.directory), "LANG": "C.UTF-8"})
        except OSError:
            self.stop()
            raise UserError("Не удалось запустить системный движок.") from None
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
        self.process = subprocess.Popen([str(self.binaries / "zerotier-one"), "-p19993", str(self.zt_home)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": str(self.zt_home)})
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
        if self.xray_process and self.xray_process.poll() is not None:
            # A live TUN client could otherwise continue serving direct rules
            # after loss of its transport. Stop it while retaining the guard.
            self.stop()
            return {"state": "error", "message": "Xray XHTTP завершился. Сервис повторит подключение.", "guard": self.guard}
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
        try:
            address = ipaddress.ip_address(target)
            encoded = bytes([1 if address.version == 4 else 4]) + address.packed
        except ValueError:
            t = target.encode("idna")
            encoded = b"\x03" + bytes([len(t)]) + t
        sock.sendall(b"\x05\x01\x00" + encoded + int(target_port).to_bytes(2, "big"))
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
