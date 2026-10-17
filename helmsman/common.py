"""Private atomic state and bounded local RPC. No network/GUI dependency."""
import json
import os
import tempfile
import uuid
from pathlib import Path

VERSION = "0.1.0-alpha.1"
MAX_BYTES = 8 * 1024 * 1024
SOCKET = "/run/helmsman/control.sock"
PRESETS = {"full": "Весь интернет через VPN", "ru-selective": "Россия: выборочно", "ru-except": "Россия напрямую", "manual": "Мои правила"}
RU_BASE = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/"


class UserError(Exception):
    pass


def atomic_json(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def identifier():
    return uuid.uuid4().hex


def defaults():
    return {"schema": 1, "hwid": identifier(), "profiles": [], "subscriptions": [],
            "selected": "", "desired": False, "preset": "full", "rules": [], "lists": [],
            "settings": {"kill_switch": True, "lan": True, "ipv6": True, "mtu": 1400,
                         "default_action": "proxy", "dns_proxy": "https://cloudflare-dns.com/dns-query", "dns_direct": "https://dns.quad9.net/dns-query",
                         "dns_bootstrap": "9.9.9.9",
                         "reconnect_seconds": 15, "list_update_hours": 24}}


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.directory / "state.json"
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text())
                if self.data["schema"] != 1:
                    raise ValueError("schema")
                for key in defaults():
                    if key not in self.data:
                        raise ValueError(key)
                # Add settings without replacing existing endpoints or HWID.
                for key, value in defaults()["settings"].items():
                    self.data["settings"].setdefault(key, value)
            except (ValueError, KeyError, TypeError):
                raise UserError("Файл настроек повреждён или создан другой версией. Сохраните его и восстановите резервную копию.") from None
        else:
            self.data = defaults()
            self.save()

    def save(self):
        atomic_json(self.path, self.data)


def label(value):
    value = str(value).strip()
    if not value or len(value) > 160 or any(ord(c) < 32 for c in value):
        raise UserError("Название: от 1 до 160 печатных символов.")
    return value
