import copy
import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .common import MAX_BYTES, UserError, identifier, label
from .importers import parse


def https_url(url):
    try:
        u = urlsplit(url)
        if u.scheme != "https" or not u.hostname or u.username or u.password or u.fragment:
            raise ValueError()
        _ = u.port
    except ValueError:
        raise UserError("Нужен HTTPS-адрес без логина, пароля и фрагмента. Токен в пути или query разрешён.") from None
    return url


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        a, b = urlsplit(req.full_url), urlsplit(newurl)
        if b.scheme != "https" or (a.hostname, a.port or 443) != (b.hostname, b.port or 443):
            raise UserError("Сервер перенаправляет на другой узел. Укажите конечный HTTPS URL, чтобы не передавать HWID и токен постороннему серверу.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, headers=None, opener=None):
    https_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": "Helmsman/0.1 (Linux; Steam Deck)", "Accept": "application/json, text/plain, */*", **(headers or {})})
    try:
        with (opener or urllib.request.build_opener(SafeRedirect(), urllib.request.ProxyHandler({}))).open(req, timeout=30) as response:
            data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise UserError("Ответ больше 8 МиБ; прежняя конфигурация сохранена.")
            return data
    except urllib.error.HTTPError as e:
        raise UserError(f"Сервер вернул HTTP {e.code}. Проверьте подписку и HWID; прежняя конфигурация сохранена.") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise UserError("Не удалось безопасно загрузить данные. Проверьте сеть, URL и сертификат сервера; прежняя конфигурация сохранена.") from None


def validate_subscription(s, previous=None):
    result = {"id": previous["id"] if previous else identifier(), "name": label(s.get("name", "Подписка")), "url": https_url(s.get("url", "")), "interval_hours": float(s.get("interval_hours", 24)), "hwid_mode": s.get("hwid_mode", "none"), "hwid_name": s.get("hwid_name", "x-hwid"), "hwid": str(s.get("hwid", "")), "headers": s.get("headers", {})}
    if result["interval_hours"] != 0 and not 1 <= result["interval_hours"] <= 720:
        raise UserError("Обновление: 0 (вручную) или от 1 до 720 часов.")
    if result["hwid_mode"] not in {"none", "remnawave", "header", "query"}:
        raise UserError("Неизвестный способ отправки HWID.")
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", result["hwid_name"]):
        raise UserError("Некорректное имя заголовка/параметра HWID.")
    if len(result["hwid"]) > 256 or any(ord(c) < 33 or ord(c) > 126 for c in result["hwid"]):
        raise UserError("HWID: до 256 ASCII-символов без пробелов.")
    if not isinstance(result["headers"], dict) or len(result["headers"]) > 16:
        raise UserError("Дополнительные заголовки: JSON-объект, не более 16.")
    for k, v in result["headers"].items():
        if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", k) or k.lower() in {"host", "connection", "content-length", "transfer-encoding"} or not isinstance(v, str) or len(v) > 4096 or any(ord(c) < 32 or ord(c) > 126 for c in v):
            raise UserError("Недопустимый HTTP-заголовок.")
    if previous:
        for key in ("last_update", "last_attempt", "error"):
            if key in previous:
                result[key] = previous[key]
    return result


def request_data(sub, global_hwid):
    hwid = sub["hwid"] or global_hwid
    url, headers = sub["url"], dict(sub["headers"])
    mode = sub["hwid_mode"]
    if mode == "remnawave":
        if not re.fullmatch(r"[a-zA-Z0-9=-]{10,64}", hwid):
            raise UserError("Remnawave ожидает HWID из 10–64 латинских букв, цифр, = или -.")
        headers.update({"x-hwid": hwid, "x-device-os": "Linux", "x-device-model": "Steam Deck", "x-ver-os": "SteamOS"})
    elif mode == "header":
        headers[sub["hwid_name"]] = hwid
    elif mode == "query":
        u = urlsplit(url)
        query = [(k, v) for k, v in parse_qsl(u.query, keep_blank_values=True) if k != sub["hwid_name"]]
        query.append((sub["hwid_name"], hwid))
        url = urlunsplit((u.scheme, u.netloc, u.path, urlencode(query), ""))
    return url, headers


def fingerprint(p):
    return hashlib.sha256(json.dumps({k: v for k, v in p.items() if k in {"kind", "outbound", "network_id", "dns"}}, sort_keys=True).encode()).hexdigest()


def update(state, sub_id, validate_profiles, fetch=download):
    """Commit a whole successful update; no partial replacements."""
    result = copy.deepcopy(state)
    sub = next((s for s in result["subscriptions"] if s["id"] == sub_id), None)
    if not sub:
        raise UserError("Подписка не найдена.")
    url, headers = request_data(sub, result["hwid"])
    profiles = parse(fetch(url, headers).decode("utf-8-sig"))
    if len(profiles) > 2000:
        raise UserError("В подписке больше 2000 профилей.")
    validate_profiles(profiles)
    old = {fingerprint(p): p for p in state["profiles"] if p.get("subscription") == sub_id}
    seen, added = set(), []
    for p in profiles:
        key = fingerprint(p)
        if key in seen:
            continue
        seen.add(key)
        p["id"] = old[key]["id"] if key in old else p["id"]
        p["subscription"] = sub_id
        added.append(p)
    keep = [p for p in result["profiles"] if p.get("subscription") != sub_id]
    selected = next((p for p in result["profiles"] if p["id"] == result["selected"]), None)
    if selected and selected.get("subscription") == sub_id and selected["id"] not in {p["id"] for p in added}:
        selected.pop("subscription", None)
        selected["name"] = label(selected["name"][:130] + " (сохранённый)")
        keep.append(selected)
    result["profiles"] = keep + added
    if not result["selected"]:
        result["selected"] = added[0]["id"]
    sub.update(last_update=time.time(), last_attempt=time.time(), error="")
    return result
