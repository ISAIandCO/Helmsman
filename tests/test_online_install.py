"""Installer contracts without sudo, network access or host mount changes."""
import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("online_install", ROOT / "scripts/install-latest.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
VERSION = "1.0.0"
FILENAME = "helmsman-1.0.0-linux-x86_64.tar.gz"
URLS = {name: f"https://github.com/ISAIandCO/Helmsman/releases/download/v{VERSION}/{name}"
        for name in (FILENAME, "SHA256SUMS")}


class OnlineInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="helmsman installer test ")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)

    def archive(self, name="helmsman-1.0.0/VERSION", data=b"1.0.0\n", link=None):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as t:
            for path, content in [("helmsman-1.0.0/install.sh", b"#!/bin/bash\n"), (name, data)]:
                info = tarfile.TarInfo(path)
                info.size = len(content)
                t.addfile(info, io.BytesIO(content))
            if link:
                info = tarfile.TarInfo("helmsman-1.0.0/escape")
                info.type = tarfile.SYMTYPE
                info.linkname = link
                t.addfile(info)
        return output.getvalue()

    def responses(self, archive, checksum=None):
        checksum = checksum or hashlib.sha256(archive).hexdigest()
        bodies = {URLS["SHA256SUMS"]: (checksum + "  " + FILENAME + "\n").encode(), URLS[FILENAME]: archive}
        return patch.object(installer, "request", side_effect=lambda url: io.BytesIO(bodies[url]))

    def test_latest_stable_and_exact_assets(self):
        release = {"tag_name": "v1.0.0", "draft": False, "prerelease": False,
                   "assets": [{"name": n, "browser_download_url": u} for n, u in URLS.items()]}
        with patch.object(installer, "read_small", return_value=json.dumps(release).encode()):
            self.assertEqual(installer.latest(), (VERSION, FILENAME, URLS))
        variants = []
        for field, value in (("prerelease", True), ("draft", True), ("tag_name", "v1.0.1-alpha.1"), ("assets", [])):
            bad = copy.deepcopy(release); bad[field] = value; variants.append(bad)
        bad = copy.deepcopy(release); bad["assets"][0]["browser_download_url"] = "https://example.test/app"; variants.append(bad)
        bad = copy.deepcopy(release); bad["assets"].append(bad["assets"][0]); variants.append(bad)
        for bad in variants:
            with self.subTest(release=bad), patch.object(installer, "read_small", return_value=json.dumps(bad).encode()):
                with self.assertRaises(ValueError): installer.latest()

    def test_verified_archive_and_rejected_checksum(self):
        archive = self.archive()
        with self.responses(archive):
            result = installer.unpack(self.work, VERSION, FILENAME, URLS)
            self.assertEqual((result / "VERSION").read_text().strip(), VERSION)
        with self.responses(archive, "0" * 64):
            with self.assertRaisesRegex(ValueError, "SHA256"):
                installer.unpack(self.work, VERSION, FILENAME, URLS)

    def test_archive_traversal_links_and_wrong_version(self):
        for archive in (self.archive("../escape"), self.archive(link="../../outside"), self.archive(data=b"9.9.9\n")):
            with self.subTest(), self.responses(archive):
                with self.assertRaises((ValueError, tarfile.FilterError)):
                    installer.unpack(self.work, VERSION, FILENAME, URLS)
        self.assertFalse((self.work.parent / "escape").exists())

    def test_main_uses_existing_installer_and_detects_decky(self):
        home = self.work / "user home"
        home.mkdir()
        identity = SimpleNamespace(pw_name="deck", pw_dir=str(home))
        with patch.object(installer.os, "geteuid", return_value=1000), \
             patch.object(installer.platform, "system", return_value="Linux"), \
             patch.object(installer.platform, "machine", return_value="x86_64"), \
             patch.object(installer.shutil, "which", return_value="/bin/tool"), \
             patch.object(installer.pwd, "getpwuid", return_value=identity), \
             patch.dict(os.environ, {"XDG_CACHE_HOME": str(self.work / "cache")}), \
             patch.object(installer, "latest", return_value=(VERSION, FILENAME, URLS)), \
             patch.object(installer.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            for decky in (False, True):
                if decky: (home / "homebrew/plugins").mkdir(parents=True)
                with self.responses(self.archive()): installer.main()
                argv = run.call_args.args[0]
                self.assertEqual(argv[:6], ["sudo", "flock", "-n", "-E", "75", "/run/helmsman-online-install.lock"])
                self.assertIn(installer.ROOT_INSTALL, argv)
                self.assertEqual("--decky" in argv, decky)
                self.assertEqual(argv[argv.index("--user") + 1], "deck")
                self.assertFalse(Path(argv[10]).exists())  # Temporary package cleaned.
            run.reset_mock()
            with self.responses(self.archive(), "0" * 64):
                with self.assertRaisesRegex(ValueError, "SHA256"): installer.main()
            run.assert_not_called()

    def test_root_wrapper_restores_original_mode_on_success_and_error(self):
        tools = self.work / "bin"; tools.mkdir()
        readonly = tools / "steamos-readonly"
        readonly.write_text('''#!/bin/bash
echo "$1" >> "$TEST_RO_LOG"
case $1 in
status) echo "$TEST_RO_MODE" ;;
disable) exit "${TEST_RW_ERROR:-0}" ;;
enable) exit "${TEST_RO_ERROR:-0}" ;;
esac
''')
        readonly.chmod(0o755)
        package = self.work / "package with spaces"; package.mkdir()
        (package / "install.sh").write_text('''#!/bin/bash
printf '%s\\n' "$@" > "$TEST_INSTALL_ARGS"
if [[ ${TEST_SIGNAL:-} == term ]]; then kill -TERM "$PPID"; fi
exit "${TEST_INSTALL_ERROR:-0}"
''')
        for mode, error, rw_error, ro_error, signal, code, expected in (
            ("enabled", 0, 0, 0, "", 0, ["status", "disable", "enable"]),
            ("disabled", 0, 0, 0, "", 0, ["status", "disable"]),
            ("enabled", 7, 0, 0, "", 7, ["status", "disable", "enable"]),
            ("disabled", 7, 0, 0, "", 7, ["status", "disable"]),
            ("enabled", 0, 8, 0, "", 8, ["status", "disable", "enable"]),
            ("enabled", 0, 0, 9, "", 1, ["status", "disable", "enable"]),
            ("enabled", 0, 0, 0, "term", 143, ["status", "disable", "enable"]),
            ("unexpected", 0, 0, 0, "", 1, ["status"]),
        ):
            with self.subTest(mode=mode, error=error, rw_error=rw_error, ro_error=ro_error, signal=signal):
                log = self.work / "ro.log"; log.unlink(missing_ok=True)
                args = self.work / "args"; args.unlink(missing_ok=True)
                env = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                       "TEST_RO_LOG": str(log), "TEST_RO_MODE": mode, "TEST_INSTALL_ARGS": str(args),
                       "TEST_INSTALL_ERROR": str(error), "TEST_RW_ERROR": str(rw_error),
                       "TEST_RO_ERROR": str(ro_error), "TEST_SIGNAL": signal}
                result = subprocess.run(["bash", "-c", installer.ROOT_INSTALL, "helmsman-install", str(package), "--user", "deck", "--decky"], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(log.read_text().splitlines(), expected)
                if not rw_error and mode != "unexpected":
                    self.assertEqual(args.read_text().splitlines(), ["--user", "deck", "--decky"])
                else:
                    self.assertFalse(args.exists())

    def test_download_never_follows_http_redirect(self):
        redirect = installer.HTTPSRedirect()
        with self.assertRaises(ValueError):
            redirect.redirect_request(None, None, 302, "Found", {}, "http://example.test/file")


if __name__ == "__main__":
    unittest.main()
