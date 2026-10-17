"""Decky runs as the desktop user. No root flag and no second network engine."""
import asyncio
import json
import socket

ALLOWED = {"status", "connect", "disconnect", "select", "preset", "subscriptions_update", "probe", "warp_generate"}
SOCKET = "/run/helmsman/control.sock"


def request_service(method, params):
    if method not in ALLOWED or not isinstance(params, dict):
        raise RuntimeError("Команда недоступна в Decky.")
    payload = json.dumps({"method": method, "params": params}).encode() + b"\n"
    if len(payload) > 4096:
        raise RuntimeError("Слишком большой запрос.")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(90)
            sock.connect(SOCKET)
            sock.sendall(payload)
            data = sock.makefile("rb").readline(4 * 1024 * 1024)
            if not data.endswith(b"\n"):
                raise ValueError()
            result = json.loads(data)
    except (OSError, ValueError):
        raise RuntimeError("Сервис Helmsman недоступен. Установите приложение в Desktop Mode.") from None
    if not result.get("ok"):
        raise RuntimeError(result.get("error", "Ошибка сервиса."))
    return result["result"]


class Plugin:
    async def request(self, method: str, params: dict):
        return await asyncio.to_thread(request_service, method, params)
