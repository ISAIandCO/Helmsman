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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .common import MAX_BYTES, PRESETS, SOCKET, Store, UserError, VERSION, atomic_json, identifier, label
from .dns import bootstrap_address, resolver_url
from .importers import parse
from .routing import compile_config, rule, source_list, text_list
from .subscriptions import download, https_url, update, validate_subscription
from .system import Runtime, network_signature, probe_connection
from .fastest import GROUP_ID, PROTOCOLS, candidates, choose, validate as validate_fastest
from .warp import generate as generate_warp
from .xray import is_xhttp
from .subscriptions import fingerprint

from .regions import BUILTIN_LISTS, COUNTRIES, available_presets, required_lists, preset_description
from .i18n import localize_response, translate_message


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
        self.scan_thread = None
        self.health_thread = None
        self.scan_epoch = 0
        self.scan_due = 0
        self.health_due = 0
        self.last_switch = 0
        self.group_results = {}
        for key, (name, url) in BUILTIN_LISTS.items():
            if not any(x["id"] == key for x in self.store.data["lists"]):
                self.store.data["lists"].append({"id": key, "name": name, "url": url, "format": "srs", "interval_hours": 24})
        self.store.save()

    @property
    def data(self):
        return self.store.data

    def event(self, message):
        self.events.append({"time": time.time(), "message": message})

    def status(self):
        s = self.runtime.status()
        if self.data["selected"] == GROUP_ID and self.data["desired"] and s["state"] == "disconnected" and self.scan_thread and self.scan_thread.is_alive():
            s.update(state="connecting", message="VPN: проверка подходящих серверов…")
        if self.last_error:
            s["error"] = self.last_error
        return {**s, "version": VERSION, "selected": self.data["selected"], "desired": self.data["desired"], "auto_connect": self.data['settings']['auto_connect'], "preset": self.data["preset"], "language": self.data['settings']['language'], "country": self.data['settings']['country'],
                "presets": available_presets(self.data['settings']['country']),
                "preset_descriptions": {key: preset_description(key) for key in available_presets(self.data['settings']['country'])},
                "active_preset_name": PRESETS[self.data['preset']], "active_preset_description": preset_description(self.data['preset']),
                "countries": COUNTRIES,
                "fastest": {**self.data["fastest"], "checking": bool(self.scan_thread and self.scan_thread.is_alive()), "results": self.group_results,
                            "active_name": getattr(self.runtime, "profile", None).get("name", "") if getattr(self.runtime, "profile", None) else ""},
                "fastest_protocols": list(PROTOCOLS),
                "profiles": [{"id": p["id"], "name": p["name"], "protocol": "zerotier" if p["kind"] == "zerotier" else "amneziawg" if p["outbound"].get("amnezia_wg") else p["outbound"]["type"] + ("/xhttp" if is_xhttp(p) else "") + ("/mux" if 'xray_mux' in p['outbound'] else '')} for p in self.data["profiles"]] + [{"id": GROUP_ID, "name": "VPN", "protocol": "auto"}],
                "subscriptions": [{k: s[k] for k in ("id", "name", "last_update", "error") if k in s} for s in self.data["subscriptions"]]}

    def selected(self, state=None):
        state = state or self.data
        key = state["fastest"]["active"] if state["selected"] == GROUP_ID else state["selected"]
        p = next((p for p in state["profiles"] if p["id"] == key), None)
        if not p:
            raise UserError("Сначала добавьте и выберите профиль.")
        return p

    def scan_group(self, full=True):
        thread = self.scan_thread if full else self.health_thread
        if thread and thread.is_alive():
            return
        snapshot = copy.deepcopy(self.data)
        epoch = self.scan_epoch
        profiles = candidates(snapshot)
        active = getattr(self.runtime, "profile", None)
        active_id = active["id"] if active and active in profiles and self.runtime.status()["state"] == "running" else ""
        port, password = getattr(self.runtime, "probe_port", 0), getattr(self.runtime, "probe_password", "")
        if not full:
            if not active_id:
                self.health_due = wake_clock() + 30
                return
            profiles = [p for p in profiles if p["id"] == active_id]

        def measure(p):
            if epoch != self.scan_epoch:
                return {"ok": False}
            if p["id"] == active_id:
                return probe_connection(port, password)
            return self.runtime.measure_profile(snapshot, p)

        def scan():
            results = {}
            try:
                # MemoryMax is shared with the serving engine. Two temporary
                # clients bound resource use, including Xray and QUIC profiles.
                with ThreadPoolExecutor(max_workers=2) as pool:
                    pending = {pool.submit(measure, p): p for p in profiles}
                    for future in as_completed(pending):
                        p, result = pending[future], future.result()
                        results[p["id"]] = result
                        with self.lock:
                            if epoch != self.scan_epoch:
                                continue
                            # Large subscriptions needn't finish scanning before
                            # the first working connection can serve traffic.
                            serving = (getattr(self.runtime, "profile", None) or {}).get("id")
                            failed = self.group_results.get(serving, {}).get("ok") is False
                            if full and result.get("ok") and (not serving or failed):
                                try:
                                    self.runtime.start(self.data, p)
                                    self.data["fastest"]["active"] = p["id"]
                                    self.last_switch = wake_clock()
                                    self.store.save()
                                except UserError:
                                    results[p["id"]] = {"ok": False}
                with self.lock:
                    if epoch != self.scan_epoch or not self.data["desired"] or self.data["selected"] != GROUP_ID:
                        return  # A disconnect, edit or subscription update won the race.
                    self.group_results = results if full else {**self.group_results, **results}
                    now = wake_clock()
                    self.health_due = now + 30
                    if not full:
                        serving = (getattr(self.runtime, "profile", None) or {}).get("id")
                        if serving != active_id or getattr(self.runtime, "probe_port", 0) != port:
                            return  # The full scan already replaced this connection.
                        if not results.get(active_id, {}).get("ok"):
                            self.scan_epoch += 1  # Cancel a long scan; prioritize recovery.
                            self.scan_due = 0
                        return
                    self.scan_due = now + snapshot["fastest"]["interval_seconds"]
                    serving = (getattr(self.runtime, "profile", None) or {}).get("id", "")
                    best = choose(results, serving if active_id else "", snapshot["fastest"], now - self.last_switch)
                    if not best:
                        self.last_error = "VPN: нет работающих серверов, соответствующих regex и протоколам."
                        self.scan_due = now + int(self.data["settings"]["reconnect_seconds"])
                        return
                    chosen = next(p for p in profiles if p["id"] == best)
                    if chosen != getattr(self.runtime, "profile", None) or self.runtime.status()["state"] != "running":
                        self.runtime.start(self.data, chosen)
                        self.last_switch = now
                        self.event("VPN: выбран самый быстрый работающий сервер.")
                    self.data["fastest"]["active"] = best
                    self.store.save()
                    self.last_error = ""
            except Exception:
                with self.lock:
                    if epoch == self.scan_epoch:
                        self.last_error = "VPN: ошибка проверки серверов; сервис повторит попытку."
                        self.scan_due = wake_clock() + int(self.data["settings"]["reconnect_seconds"])

        thread = threading.Thread(target=scan, daemon=True)
        if full:
            self.scan_thread = thread
        else:
            self.health_thread = thread
        thread.start()

    def start_selected(self):
        if self.data["selected"] == GROUP_ID:
            if self.data["settings"]["kill_switch"]:
                self.runtime.install_guard(self.data["settings"]["lan"])
            self.scan_due = 0
            self.scan_group()
        else:
            self.runtime.start(self.data, self.selected())

    def commit(self, candidate, restart=False):
        group_restart = restart and candidate["selected"] == GROUP_ID
        active = getattr(self.runtime, "profile", None)
        if candidate["selected"] == GROUP_ID and active and active["id"] not in {p["id"] for p in candidates(candidate)}:
            group_restart = True
        if candidate != self.data:
            self.scan_epoch += 1
            self.scan_due = 0
        if group_restart and self.data["desired"]:
            self.store.data = candidate
            self.store.save()
            self.runtime.stop()
            self.start_selected()
            return
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
        if preset not in available_presets(self.data['settings']['country']):
            raise UserError("Неизвестный сценарий.")
        candidate = copy.deepcopy(self.data)
        needed = required_lists(preset)
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
                return {"status": self.status(), "events": list(self.events), "tun_available": Path("/dev/net/tun").exists(), "engines": {n: os.access(self.runtime.binaries / n, os.X_OK) for n in ("sing-box", "sing-box-awg", "zerotier-one", "xray", "wgcf")}}
            if method == "connect":
                candidate = copy.deepcopy(self.data)
                if params.get("profile_id"):
                    candidate["selected"] = params["profile_id"]
                if candidate["selected"] == GROUP_ID:
                    if not candidates(candidate):
                        raise UserError("VPN: нет серверов, соответствующих regex и протоколам.")
                    candidate["desired"] = True
                    self.commit(candidate)
                    self.start_selected()
                    return self.status()
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
                self.scan_epoch += 1
                self.data["desired"] = False
                self.store.save()
                self.runtime.stop()
                self.runtime.clear_guard()
                self.last_error = ""
                self.event("Отключено пользователем; обычный доступ в интернет восстановлен.")
            elif method == 'auto_connect':
                if set(params) != {'enabled'} or type(params['enabled']) is not bool:
                    raise UserError('Автоподключение: требуется логическое enabled.')
                candidate = copy.deepcopy(self.data)
                candidate['settings']['auto_connect'] = params['enabled']
                self.commit(candidate)
            elif method == "select":
                candidate = copy.deepcopy(self.data)
                candidate["selected"] = params["profile_id"]
                if candidate["selected"] != GROUP_ID:
                    self.selected(candidate)
                self.commit(candidate, restart=True)
                self.last_error = ""
            elif method == "fastest_save":
                candidate = copy.deepcopy(self.data)
                candidate["fastest"] = validate_fastest(params, candidate["fastest"])
                self.commit(candidate)
                self.scan_due = 0
            elif method == "fastest_check":
                if self.data["selected"] != GROUP_ID or not self.data["desired"]:
                    raise UserError("Сначала подключите группу VPN.")
                self.scan_group()
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
            elif method == "warp_generate":
                p = generate_warp(self.runtime.binaries, self.store.directory, params.get("accept_terms"), params.get("mode", "awg"), params.get("endpoint", ""))
                self.runtime.validate_profiles([p])
                existing = next((x for x in self.data["profiles"] if fingerprint(x) == fingerprint(p)), None)
                if existing:
                    return {"id": existing["id"], "message": "Профиль WARP уже добавлен. Выберите его в списке подключений."}
                candidate = copy.deepcopy(self.data)
                candidate["profiles"].append(p)
                if not candidate["selected"]:
                    candidate["selected"] = p["id"]
                self.commit(candidate)
                self.event("Профиль WARP создан из сохранённой учётной записи.")
                return {"id": p["id"], "message": "Cloudflare WARP добавлен. Выберите профиль и нажмите «Подключить»."}
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
                if self.data["desired"] and params["id"] in {self.data["selected"], self.data["fastest"]["active"] if self.data["selected"] == GROUP_ID else ""}:
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
            elif method == "preferences":
                if not params or set(params) - {'language', 'country'}:
                    raise UserError('Неизвестная настройка языка или страны.')
                if ('language' in params and params['language'] not in {'ru', 'en'}) or ('country' in params and params['country'] not in COUNTRIES):
                    raise UserError('Неподдерживаемый язык или страна.')
                candidate = copy.deepcopy(self.data)
                candidate['settings'].update(params)
                self.commit(candidate)  # No restart, downloads or change to the applied preset.
            elif method == "settings_save":
                candidate = copy.deepcopy(self.data)
                s = params["settings"]
                if set(s) - candidate["settings"].keys():
                    raise UserError("Неизвестный параметр сервиса.")
                if set(s) & {'language', 'country'}:
                    raise UserError('Используйте отдельный выбор языка и страны.')
                candidate["settings"].update(s)
                c = candidate["settings"]
                if any(type(c[k]) is not bool for k in ("auto_connect", "kill_switch", "lan", "ipv6")):
                    raise UserError("Параметр должен быть логическим.")
                if not 1280 <= int(c["mtu"]) <= 9000 or not 5 <= int(c["reconnect_seconds"]) <= 300 or not 1 <= int(c["list_update_hours"]) <= 720:
                    raise UserError("MTU: 1280–9000; повтор: 5–300 с; списки: 1–720 ч.")
                if c["default_action"] not in {"proxy", "direct", "block"}:
                    raise UserError("Некорректный маршрут по умолчанию.")
                for key in ("dns_proxy", "dns_direct"):
                    c[key] = resolver_url(c[key])
                c["dns_bootstrap"] = bootstrap_address(c["dns_bootstrap"])
                self.commit(candidate, restart=any(k != 'auto_connect' and c[k] != self.data['settings'][k] for k in s))
            elif method == "list_save":
                candidate = copy.deepcopy(self.data)
                existing = next((x for x in candidate["lists"] if x["id"] == params.get("id")), None)
                if existing and existing["id"] in BUILTIN_LISTS:
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
                if params["id"] in BUILTIN_LISTS:
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
            if self.data["desired"] and self.data["selected"] == GROUP_ID and (changed or gap):
                self.scan_epoch += 1
                self.scan_due = 0
                self.runtime.stop()  # Re-test fresh transports after sleep/underlay changes.
            if self.data["desired"] and (current["state"] in {"disconnected", "error"} or changed or gap) and now >= self.retry_at:
                self.retry_at = now + int(self.data["settings"]["reconnect_seconds"])
                try:
                    self.start_selected()
                    self.last_error = ""
                except UserError as e:
                    self.last_error = str(e)
            if self.data["desired"] and self.data["selected"] == GROUP_ID:
                if mono >= self.scan_due:
                    self.scan_group()
                if mono >= self.health_due:
                    self.scan_group(full=False)
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
            language = self.server.controller.data['settings']['language']
            result = {"ok": True, "result": localize_response(value, language, req['method'])}
        except UserError as e:
            result = {"ok": False, "error": str(e)}
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
            result = {"ok": False, "error": "Некорректные параметры запроса."}
        except Exception:
            # Never serialize traceback/URLs/config contents to logs or clients.
            result = {"ok": False, "error": "Внутренняя ошибка сервиса. Проверьте установку и права доступа."}
        if not result['ok']:
            result['error'] = translate_message(result['error'], self.server.controller.data['settings']['language'])
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
    parser.add_argument("--data", default="/opt/helmsman/state")
    parser.add_argument("--binaries", default="/opt/helmsman/current/engines")
    parser.add_argument("--socket", default=SOCKET)
    parser.add_argument("--owner-uid", required=True, type=int)
    args = parser.parse_args()
    os.umask(0o077)
    store = Store(args.data)
    store.prepare_boot()
    runtime = Runtime(args.binaries, Path(args.data) / "runtime")
    runtime.stop()  # Remove stale owned DNS redirects/routes after an interrupted shutdown.
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
            controller.start_selected()
        except UserError as e:
            controller.last_error = str(e)
    threading.Thread(target=monitor, daemon=True).start()
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        controller.scan_epoch += 1
        runtime.stop()
        # Service stop != explicit disconnect. A crash/restart must not fail open.
        if not store.data["desired"]:
            runtime.clear_guard()
        server.server_close()
        path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
