"""Explicit user-initiated WARP registration using the pinned upstream wgcf CLI."""
import os
import json
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from .common import UserError
from .importers import parse

TERMS = "https://www.cloudflare.com/application/terms/"


def generate(binaries, directory, accept_terms, mode="awg", endpoint=""):
    if accept_terms is not True:
        raise UserError("Для регистрации WARP примите условия Cloudflare: " + TERMS)
    if mode not in {"awg", "wireguard"}:
        raise UserError("WARP: выберите AmneziaWG или обычный WireGuard.")
    host, port = None, None
    if endpoint:
        try:
            u = urlsplit("udp://" + endpoint.strip())
            host, port = u.hostname, u.port
            if not host or not port or not 1 <= port <= 65535 or u.username or u.password or u.path or u.query or u.fragment or any(c.isspace() for c in host):
                raise ValueError()
        except ValueError:
            raise UserError("WARP endpoint: адрес:порт или [IPv6]:порт.") from None
    binary = Path(binaries) / "wgcf"
    if not os.access(binary, os.X_OK):
        raise UserError("В пакете нет генератора wgcf. Установите полный пакет Helmsman.")
    home = Path(directory) / "warp"
    home.mkdir(mode=0o700, exist_ok=True)
    os.chmod(home, 0o700)
    account = home / "account.toml"
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": str(home), "LANG": "C.UTF-8"}

    def invoke(args):
        try:
            # wgcf prints private keys and account tokens even on success.
            result = subprocess.run([str(binary), "--config", str(account), *args], cwd=home, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            if result.returncode:
                raise UserError("WARP: Cloudflare не выполнил запрос. Проверьте сеть, часы и ограничения регистрации; попробуйте позже или импортируйте готовый WireGuard-профиль. Сохранённая учётная запись и профили не изменены.")
        except (OSError, subprocess.TimeoutExpired):
            raise UserError("WARP: генератор недоступен или Cloudflare не ответил за 30 секунд. Попробуйте позже или импортируйте готовую конфигурацию; сохранённая учётная запись будет использована повторно.") from None
        finally:
            if account.exists():
                os.chmod(account, 0o600)

    # Preserve an account even if a later API request fails; never register again
    # automatically and never expose its credentials over RPC or in diagnostics.
    if not account.exists():
        invoke(["register", "--accept-tos", "--name", "Helmsman", "--model", "Steam Deck"])
    if not account.exists():
        raise UserError("WARP: wgcf не создал учётную запись. Попробуйте позже.")
    with tempfile.TemporaryDirectory(prefix="generate-", dir=home) as temporary:
        target = Path(temporary) / "warp.conf"
        invoke(["generate", "--profile", str(target), "--keepalive", "25"])
        try:
            profiles = parse(target.read_text())
        except OSError:
            raise UserError("WARP: генератор не создал WireGuard-конфигурацию.") from None
    if len(profiles) != 1 or profiles[0]["outbound"]["type"] != "wireguard":
        raise UserError("WARP: генератор вернул неожиданный формат.")
    # wgcf uses public 1.1.1.1 in .conf; generated profiles inherit the user's
    # encrypted VPN DNS instead of overriding it with this plaintext default.
    profiles[0].pop("dns", None)
    if host:
        profiles[0]["outbound"]["peers"][0].update(address=host, port=port)
    if mode == "awg":
        template = json.loads(Path(__file__).with_name("warp-obfuscation.json").read_text())
        profiles[0]["outbound"]["amnezia_wg"] = template["amnezia_wg"]
    profiles[0]["name"] = "Cloudflare WARP" + (" · AmneziaWG" if mode == "awg" else " · WireGuard")
    return profiles[0]
