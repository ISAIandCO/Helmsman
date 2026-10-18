#!/usr/bin/env python3
"""Download a stable GitHub release, verify it and reuse its installer."""
import hashlib
import json
import os
import platform
import pwd
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from pathlib import Path

REPOSITORY = "ISAIandCO/Helmsman"
API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"

# Downloading/extracting is unprivileged. Only the existing package installer
# and SteamOS's readonly switch run under sudo, sharing one global RW lock.
ROOT_INSTALL = r'''
set -euo pipefail
restore_ro=0
cleanup() {
    code=$?
    trap - EXIT
    if ((restore_ro)); then
        if ! steamos-readonly enable; then
            echo 'Не удалось вернуть RO. Выполните: sudo steamos-readonly enable' >&2
            if ((code == 0)); then code=1; fi
        fi
    fi
    exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
case "$(steamos-readonly status)" in
    enabled) restore_ro=1 ;;
    disabled) ;;
    *) echo 'Не удалось определить режим RO/RW SteamOS.' >&2; exit 1 ;;
esac
echo 'Включение RW на время установки…'
steamos-readonly disable
package=$1
shift
bash "$package/install.sh" "$@"
'''


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != "https":
            raise ValueError("GitHub перенаправляет скачивание на незащищённый адрес.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def request(url):
    return urllib.request.build_opener(HTTPSRedirect()).open(urllib.request.Request(
        url, headers={"User-Agent": "Helmsman-Installer", "Accept": "application/vnd.github+json"}), timeout=45)


def read_small(url):
    with request(url) as response:
        data = response.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("Слишком большой ответ GitHub.")
    return data


def latest():
    release = json.loads(read_small(API))
    tag = release.get("tag_name", "")
    if release.get("draft") or release.get("prerelease") or not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise ValueError("GitHub не вернул стабильный релиз Helmsman.")
    version = tag[1:]
    filename = f"helmsman-{version}-linux-x86_64.tar.gz"
    urls = {}
    for name in (filename, "SHA256SUMS"):
        expected = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
        assets = [a for a in release["assets"] if a.get("name") == name]
        if len(assets) != 1 or assets[0].get("browser_download_url") != expected:
            raise ValueError("В релизе отсутствует полный установочный архив или SHA256SUMS.")
        urls[name] = expected
    return version, filename, urls


def unpack(work, version, filename, urls):
    checksums = read_small(urls["SHA256SUMS"]).decode("utf-8")
    hashes = [m[1].lower() for line in checksums.splitlines()
              if (m := re.fullmatch(r"([a-fA-F0-9]{64}) [ *]" + re.escape(filename), line))]
    if len(hashes) != 1:
        raise ValueError("Нет однозначной контрольной суммы установочного архива.")
    archive = work / filename
    digest = hashlib.sha256()
    print(f"Скачивание {filename}…", flush=True)
    with request(urls[filename]) as response, archive.open("wb") as output:
        while chunk := response.read(1024 * 1024):
            output.write(chunk)
            digest.update(chunk)
    if digest.hexdigest() != hashes[0]:
        raise ValueError("SHA256 не совпадает. Установка отменена; запустите ярлык повторно.")
    print("SHA256: OK. Распаковка…", flush=True)
    if not hasattr(tarfile, "data_filter"):
        raise ValueError("Обновите SteamOS: нужен Python с безопасной распаковкой tar.")
    dirname = "helmsman-" + version
    with tarfile.open(archive, "r:gz") as package:
        if any(m.name != dirname and not m.name.startswith(dirname + "/") for m in package.getmembers()):
            raise ValueError("Некорректная структура установочного архива.")
        package.extractall(work, filter="data")
    result = work / dirname
    if not (result / "install.sh").is_file() or (result / "VERSION").read_text().strip() != version:
        raise ValueError("Версия или состав установочного архива не совпадают с релизом.")
    return result


def main():
    if os.geteuid() == 0:
        raise ValueError("Запустите установочный ярлык от обычного пользователя, без sudo.")
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("Этот установщик предназначен для SteamOS x86_64 на Steam Deck.")
    for tool in ("sudo", "bash", "flock", "steamos-readonly"):
        if not shutil.which(tool):
            raise ValueError("Отсутствует системный компонент: " + tool)
    print("Helmsman — установка / обновление последней стабильной версии", flush=True)
    version, filename, urls = latest()
    cache = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "helmsman"
    cache.mkdir(parents=True, exist_ok=True)
    # The large package lives on the home/data partition, not in /tmp or /var.
    with tempfile.TemporaryDirectory(prefix="install-", dir=cache) as temporary:
        package = unpack(Path(temporary), version, filename, urls)
        user = pwd.getpwuid(os.getuid()).pw_name
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        options = ["--user", user]
        if (home / "homebrew/plugins").is_dir():
            options.append("--decky")
            print("Decky Loader найден: плагин будет установлен или обновлён.", flush=True)
        else:
            print("Decky Loader не найден: устанавливается Desktop-приложение. После установки Decky запустите ярлык снова.", flush=True)
        print("Введите пароль пользователя для установки. Настройки Helmsman сохраняются.", flush=True)
        # Keep sudo's stdin on the terminal for password entry. Feed the fixed
        # root script through -c, with all variable arguments passed separately.
        result = subprocess.run(["sudo", "flock", "-n", "-E", "75", "/run/helmsman-online-install.lock",
                                 "bash", "-c", ROOT_INSTALL, "helmsman-install", str(package), *options])
        if result.returncode == 75:
            raise ValueError("Уже выполняется автоматическая установка Helmsman.")
        if result.returncode:
            raise ValueError("Установка не завершена. Причина указана выше; устраните её и запустите ярлык снова.")
    print(f"Helmsman {version} установлен. Откройте Helmsman в меню приложений → Интернет.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nУстановка прервана.", file=sys.stderr)
        sys.exit(130)
    except (ValueError, KeyError, TypeError, OSError, urllib.error.URLError, tarfile.TarError) as error:
        print("Helmsman: " + str(error), file=sys.stderr)
        sys.exit(1)
