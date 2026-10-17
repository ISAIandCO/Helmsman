import argparse
import copy
import json
import os
import re
import signal
import socket
import socketserver
import struct
import threading
import time
from collections import deque
from pathlib import Path

from .common import MAX_BYTES, PRESETS, RU_BASE, SOCKET, Store, UserError, VERSION, atomic_json, identifier, label
from .importers import parse
from .routing import compile_config, rule, source_list, text_list
from .subscriptions import download, https_url, update, validate_subscription
from .system import Runtime, network_signature

RU_LISTS = {
    "ru-blocked": ("Россия: домены из общественных списков", "rule-set-geosite/geosite-ru-blocked.srs"),
    "ru-ip-blocked": ("Россия: IP из общественных списков", "rule-set-geoip/geoip-ru-blocked.srs"),
    "ru-domains": ("Российские домены", "rule-set-geosite/geosite-category-ru.srs"),
    "ru-ips": ("Российские IP", "rule-set-geoip/geoip-ru.srs"),
}


def wake_clock():
    # CLOCK_MONOTONIC excludes suspend on Linux; BOOTTIME includes it.
    return time.clock_gettime(time.CLOCK_BOOTTIME)


class Controller:
    def __init__(self, store, runtime):
        self.store, self.runtime = store, runtime
        self.lock = threading.RLock()
        self.events = deque(maxlen=100)
        self.last_error = ""
        self.retry_at = 0
        self.last_tick = wake_clock()
        self.net = ""
        self.last_network_check = 0
        for key, (name, url) in RU_LISTS.items():
            if not any(x["id"] == key for x in self.store.data["lists"]):
                self.store.data["lists"].append({"id": key, "name": name, "url": RU_BASE + url, "format": "srs", "interval_hours": 24})
        self.store.save()

    @property
    def data(self):
        return self.store.data

    def event(self, message):
        self.events.append({"time": time.time(), "message": message})

    def status(self):
        s = self.runtime.status()
        if self.last_error:
            s["error"] = self.last_error
        return {**s, "version": VERSION, "selected": self.data["selected"], "desired": self.data["desired"], "preset": self.data["preset"], "presets": PRESETS,
                "profiles": [{"id": p["id"], "name": p["name"], "protocol": "zerotier" if p["kind"] == "zerotier" else "amneziawg" if p["outbound"].get("amnezia_wg") else p["outbound"]["type"]} for p in self.data["profiles"]],
                "subscriptions": [{k: s[k] for k in ("id", "name", "last_update", "error") if k in s} for s in self.data["subscriptions"]]}

    def selected(self, state=None):
        state = state or self.data
        p = next((p for p in state["profiles"] if p["id"] == state["selected"]), None)
        if not p:
            raise UserError("Сначала добавьте и выберите профиль.")
        return p

    def commit(self, candidate, restart=False):
        if restart and self.data["desired"]:
            p = self.selected(candidate)
            if p["kind"] == "sing-box":
                self.runtime.check(compile_config(candidate, p, self.runtime.directory, self.runtime.uid), p)
            # Persist intent first: a crash at any later point cannot clear protection.
            self.store.data = candidate
            self.store.save()
            try:
                self.runtime.start(candidate, p)
            except UserError as e:
                self.last_error = str(e)
                raise
        else:
            self.store.data = candidate
            self.store.save()

    def load_list(self, item, content=None):
        data = download(item["url"]) if content is None else content.encode()
        directory = self.store.directory / "lists"
        directory.mkdir(mode=0o750, exist_ok=True)
        os.chmod(directory, 0o750)
        os.chown(directory, -1, self.runtime.gid)
        tmp = directory / (identifier() + ".json")
        try:
            if item.get("format") == "srs":
                self.runtime.decompile_list(data, tmp)
                obj = source_list(json.loads(tmp.read_text()))
            elif item.get("format") == "text":
                obj = text_list(data.decode("utf-8-sig"))
            else:
                obj = source_list(json.loads(data))
            # Versioned files keep the previous running config usable on failure.
            atomic_json(tmp, obj, mode=0o640)
            os.chown(tmp, -1, self.runtime.gid)
            return {**item, "path": str(tmp), "last_update": time.time(), "last_attempt": time.time(), "error": ""}
        except (ValueError, UnicodeError):
            raise UserError("Некорректный список. Прежняя версия сохранена.") from None

    def apply_preset(self, preset):
        if preset not in PRESETS:
            raise UserError("Неизвестный сценарий.")
        candidate = copy.deepcopy(self.data)
        needed = {"ru-selective": ["ru-blocked", "ru-ip-blocked"], "ru-except": ["ru-domains", "ru-ips"]}.get(preset, [])
        for tag in needed:
            i = next(i for i, x in enumerate(candidate["lists"]) if x["id"] == tag)
            if not candidate["lists"][i].get("path"):
                candidate["lists"][i] = self.load_list(candidate["lists"][i])
        candidate["preset"] = preset
        self.commit(candidate, restart=True)

    def refresh(self, sub_id=""):
        ids = [sub_id] if sub_id else [s["id"] for s in self.data["subscriptions"]]
        errors = []
        for key in ids:
            try:
                candidate = update(self.data, key, self.runtime.validate_profiles)
                self.commit(candidate)
                self.event("Подписка обновлена; действующее подключение сохранено.")
            except UserError as e:
                for s in self.data["subscriptions"]:
                    if s["id"] == key:
                        s.update(error=str(e), last_attempt=time.time())
                self.store.save()
                errors.append(str(e))
        if errors:
            raise UserError(errors[0])

    def call(self, method, params):
        with self.lock:
            if method == "status":
                return self.status()
            if method == "configuration":
                return copy.deepcopy(self.data)
            if method == "diagnostics":
                return {"status": self.status(), "events": list(self.events), "tun_available": Path("/dev/net/tun").exists(), "engines": {n: os.access(self.runtime.binaries / n, os.X_OK) for n in ("sing-box", "sing-box-awg", "zerotier-one")}}
            if method == "connect":
                candidate = copy.deepcopy(self.data)
                if params.get("profile_id"):
                    candidate["selected"] = params["profile_id"]
                p = self.selected(candidate)
                # Full validation before persisting intent/guard.
                if p["kind"] == "sing-box":
                    self.runtime.check(compile_config(candidate, p, self.runtime.directory, self.runtime.uid), p)
                candidate["desired"] = True
                self.commit(candidate)
                self.runtime.start(self.data, p)
                self.last_error = ""
                self.event("Включено выбранное подключение.")
            elif method == "disconnect":
                self.data["desired"] = False
                self.store.save()
                self.runtime.stop()
                self.runtime.clear_guard()
                self.last_error = ""
                self.event("Отключено пользователем; обычный доступ в интернет восстановлен.")
            elif method == "select":
                candidate = copy.deepcopy(self.data)
                candidate["selected"] = params["profile_id"]
                self.selected(candidate)
                self.commit(candidate, restart=True)
                self.last_error = ""
            elif method == "preset":
                self.apply_preset(params["preset"])
            elif method == "import":
                profiles = parse(params["text"])
                self.runtime.validate_profiles(profiles)
                candidate = copy.deepcopy(self.data)
                candidate["profiles"].extend(profiles)
                if not candidate["selected"]:
                    candidate["selected"] = profiles[0]["id"]
                self.commit(candidate)
                return {"imported": len(profiles), "profiles": [p["id"] for p in profiles]}
            elif method == "profile_rename":
                candidate = copy.deepcopy(self.data)
                p = next((p for p in candidate["profiles"] if p["id"] == params["id"]), None)
                if not p:
                    raise UserError("Профиль не найден.")
                p["name"] = label(params["name"])
                self.commit(candidate)
            elif method == "profile_save":
                profiles = parse(params["text"])
                if len(profiles) != 1:
                    raise UserError("Для изменения нужен ровно один профиль.")
                self.runtime.validate_profiles(profiles)
                candidate = copy.deepcopy(self.data)
                i = next((i for i, p in enumerate(candidate["profiles"]) if p["id"] == params["id"]), None)
                if i is None:
                    raise UserError("Профиль не найден.")
                new = profiles[0]
                new["id"], new["name"] = params["id"], label(params["name"])
                if params.get("dns"):
                    import ipaddress
                    new["dns"] = str(ipaddress.ip_address(params["dns"]))
                candidate["profiles"][i] = new
                self.commit(candidate, restart=candidate["selected"] == new["id"])
            elif method == "profile_delete":
                if self.data["desired"] and params["id"] == self.data["selected"]:
                    raise UserError("Перед удалением активного профиля отключитесь.")
                candidate = copy.deepcopy(self.data)
                candidate["profiles"] = [p for p in candidate["profiles"] if p["id"] != params["id"]]
                if candidate["selected"] == params["id"]:
                    candidate["selected"] = candidate["profiles"][0]["id"] if candidate["profiles"] else ""
                self.commit(candidate)
            elif method == "subscription_save":
                candidate = copy.deepcopy(self.data)
                old = next((s for s in candidate["subscriptions"] if s["id"] == params.get("id")), None)
                new = validate_subscription(params, old)
                candidate["subscriptions"] = [s for s in candidate["subscriptions"] if s["id"] != new["id"]] + [new]
                self.commit(candidate)
                return {"id": new["id"]}
            elif method == "subscription_delete":
                candidate = copy.deepcopy(self.data)
                candidate["subscriptions"] = [s for s in candidate["subscriptions"] if s["id"] != params["id"]]
                for p in candidate["profiles"]:
                    if p.get("subscription") == params["id"]:
                        p.pop("subscription")
                self.commit(candidate)
            elif method == "subscriptions_update":
                self.refresh(params.get("id", ""))
            elif method == "hwid":
                value = str(params.get("value") or identifier())
                if not re.fullmatch(r"[!-~]{1,256}", value):
                    raise UserError("HWID: от 1 до 256 ASCII-символов без пробелов.")
                self.data["hwid"] = value
                self.store.save()
            elif method == "rules_save":
                if not isinstance(params["rules"], list) or len(params["rules"]) > 1000:
                    raise UserError("Не более 1000 правил.")
                candidate = copy.deepcopy(self.data)
                candidate["rules"] = [rule(r) for r in params["rules"]]
                self.commit(candidate, restart=True)
            elif method == "settings_save":
                candidate = copy.deepcopy(self.data)
                s = params["settings"]
                if set(s) - candidate["settings"].keys():
                    raise UserError("Неизвестный параметр сервиса.")
                candidate["settings"].update(s)
                c = candidate["settings"]
                if any(type(c[k]) is not bool for k in ("kill_switch", "lan", "ipv6")):
                    raise UserError("Параметр должен быть логическим.")
                if not 1280 <= int(c["mtu"]) <= 9000 or not 5 <= int(c["reconnect_seconds"]) <= 300 or not 1 <= int(c["list_update_hours"]) <= 720:
                    raise UserError("MTU: 1280–9000; повтор: 5–300 с; списки: 1–720 ч.")
                if c["default_action"] not in {"proxy", "direct", "block"}:
                    raise UserError("Некорректный маршрут по умолчанию.")
                import ipaddress
                for key in ("dns_proxy", "dns_direct"):
                    ipaddress.ip_address(c[key])
                self.commit(candidate, restart=True)
            elif method == "list_save":
                candidate = copy.deepcopy(self.data)
                existing = next((x for x in candidate["lists"] if x["id"] == params.get("id")), None)
                if existing and existing["id"] in RU_LISTS:
                    raise UserError("Для изменения встроенного списка создайте пользовательскую копию.")
                item = {"id": existing["id"] if existing else identifier(), "name": label(params["name"]), "url": https_url(params["url"]) if params.get("url") else "", "format": params.get("format", "text"), "interval_hours": 24}
                if item["format"] not in {"text", "source", "srs"}:
                    raise UserError("Формат списка: text/source/srs.")
                if not item["url"] and not params.get("content"):
                    raise UserError("Укажите HTTPS URL или содержимое списка.")
                if params.get("content") and item["format"] == "srs":
                    raise UserError("Бинарный SRS добавляется по URL; локально используйте source JSON или текст.")
                item = self.load_list(item, params.get("content"))
                candidate["lists"] = [x for x in candidate["lists"] if x["id"] != item["id"]] + [item]
                self.commit(candidate, restart=True)
                return {"id": item["id"]}
            elif method == "lists_update":
                candidate = copy.deepcopy(self.data)
                errors = []
                for i, item in enumerate(candidate["lists"]):
                    if not item.get("url") or (params.get("id") and params["id"] != item["id"]):
                        continue
                    if not params.get("id") and not item.get("path"):
                        continue  # Don't download unused Russian preset lists.
                    try:
                        candidate["lists"][i] = self.load_list(item)
                    except UserError as e:
                        item.update(error=str(e), last_attempt=time.time())
                        errors.append(str(e))
                self.commit(candidate, restart=True)
                if errors:
                    raise UserError(errors[0])
            elif method == "list_delete":
                if params["id"] in RU_LISTS:
                    raise UserError("Встроенный список удалять нельзя.")
                if any(params["id"] in r["values"] for r in self.data["rules"] if r["type"] == "list"):
                    raise UserError("Сначала удалите правила, использующие список.")
                candidate = copy.deepcopy(self.data)
                candidate["lists"] = [x for x in candidate["lists"] if x["id"] != params["id"]]
                self.commit(candidate, restart=True)
            elif method == "list_content":
                item = next((x for x in self.data["lists"] if x["id"] == params["id"]), None)
                if not item or not item.get("path"):
                    raise UserError("Список не загружен.")
                return {"content": Path(item["path"]).read_text()}
            elif method == "probe":
                return self.runtime.probe()
            else:
                raise UserError("Неизвестная команда.")
            return self.status()

    def tick(self):
        with self.lock:
            now = time.time()
            current = self.runtime.status()
            mono = wake_clock()
            # A suspend gap or physical route change restarts just the selected
            # mechanism. The guard stays in place throughout recovery.
            changed = False
            if self.data["desired"] and mono - self.last_network_check >= 15:
                net = network_signature()
                changed = bool(self.net and net != self.net)
                self.net, self.last_network_check = net, mono
            gap = mono - self.last_tick > 45
            self.last_tick = mono
            if self.data["desired"] and (current["state"] in {"disconnected", "error"} or changed or gap) and now >= self.retry_at:
                self.retry_at = now + int(self.data["settings"]["reconnect_seconds"])
                try:
                    self.runtime.start(self.data, self.selected())
                    self.last_error = ""
                except UserError as e:
                    self.last_error = str(e)
            for sub in list(self.data["subscriptions"]):
                hours = sub["interval_hours"]
                if hours and now - sub.get("last_attempt", sub.get("last_update", 0)) >= hours * 3600:
                    try:
                        self.refresh(sub["id"])
                    except UserError:
                        pass
            due = [x["id"] for x in self.data["lists"] if x.get("url") and x.get("path") and now - x.get("last_attempt", x.get("last_update", 0)) >= int(self.data["settings"]["list_update_hours"]) * 3600]
            for key in due:
                try:
                    self.call("lists_update", {"id": key})
                except UserError:
                    pass


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(90)
        _, uid, _ = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid not in {0, self.server.owner_uid}:
            return
        try:
            line = self.rfile.readline(MAX_BYTES + 1)
            if len(line) > MAX_BYTES or not line.endswith(b"\n"):
                raise UserError("Слишком большой запрос.")
            req = json.loads(line)
            if not isinstance(req, dict) or not isinstance(req.get("params", {}), dict):
                raise UserError("Некорректный запрос.")
            value = self.server.controller.call(req["method"], req.get("params", {}))
            result = {"ok": True, "result": value}
        except UserError as e:
            result = {"ok": False, "error": str(e)}
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
            result = {"ok": False, "error": "Некорректные параметры запроса."}
        except Exception:
            # Never serialize traceback/URLs/config contents to logs or clients.
            result = {"ok": False, "error": "Внутренняя ошибка сервиса. Проверьте установку и права доступа."}
        try:
            self.wfile.write(json.dumps(result, ensure_ascii=False).encode() + b"\n")
        except OSError:
            pass


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    block_on_close = False
    def __init__(self, path, controller, owner_uid):
        self.controller, self.owner_uid = controller, owner_uid
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(str(path), Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="/var/lib/helmsman")
    parser.add_argument("--binaries", default="/var/lib/helmsman-app/current/engines")
    parser.add_argument("--socket", default=SOCKET)
    parser.add_argument("--owner-uid", required=True, type=int)
    args = parser.parse_args()
    os.umask(0o077)
    store = Store(args.data)
    runtime = Runtime(args.binaries, Path(args.data) / "runtime")
    controller = Controller(store, runtime)
    path = Path(args.socket)
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    import pwd
    gid = pwd.getpwuid(args.owner_uid).pw_gid
    os.chown(path.parent, 0, gid)
    os.chmod(path.parent, 0o751)  # engine UID must traverse /run for host facilities
    server = Server(path, controller, args.owner_uid)
    os.chown(path, 0, gid)
    os.chmod(path, 0o660)
    stop = threading.Event()
    def shutdown(*_):
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    def monitor():
        while not stop.wait(5):
            try:
                controller.tick()
            except Exception:
                controller.last_error = "Ошибка фонового восстановления; доступ по политике защиты сохранён."
    # Re-arm before exposing an apparently idle service after restart.
    if store.data["desired"]:
        try:
            p = controller.selected()
            if p["kind"] == "sing-box" and store.data["settings"]["kill_switch"]:
                runtime.install_guard(store.data["settings"]["lan"])
            runtime.start(store.data, p)
        except UserError as e:
            controller.last_error = str(e)
    threading.Thread(target=monitor, daemon=True).start()
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        runtime.stop()
        # Service stop != explicit disconnect. A crash/restart must not fail open.
        if not store.data["desired"]:
            runtime.clear_guard()
        server.server_close()
        path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
