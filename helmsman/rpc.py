import argparse
import json
import socket
from .common import MAX_BYTES, SOCKET, UserError


def call(method, params=None, path=SOCKET):
    payload = json.dumps({"method": method, "params": params or {}}, ensure_ascii=False).encode() + b"\n"
    if len(payload) > MAX_BYTES:
        raise UserError("Слишком большой запрос.")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(90)
            sock.connect(path)
            sock.sendall(payload)
            f = sock.makefile("rb")
            data = f.readline(MAX_BYTES * 4 + 1)
            if not data.endswith(b"\n"):
                raise UserError("Некорректный ответ сервиса.")
            result = json.loads(data)
    except (OSError, ValueError):
        raise UserError("Сервис Helmsman недоступен. Проверьте установку и systemctl status helmsman.") from None
    if not result.get("ok"):
        raise UserError(result.get("error", "Ошибка сервиса."))
    return result["result"]


def main():
    p = argparse.ArgumentParser(description="Helmsman local control (JSON RPC parameters)")
    p.add_argument("method", nargs="?", default="status")
    p.add_argument("params", nargs="?", default="{}")
    p.add_argument("--socket", default=SOCKET)
    args = p.parse_args()
    try:
        print(json.dumps(call(args.method, json.loads(args.params), args.socket), ensure_ascii=False, indent=2))
    except (UserError, ValueError) as e:
        p.exit(1, str(e) + "\n")


if __name__ == "__main__":
    main()
