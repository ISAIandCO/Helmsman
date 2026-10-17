"""Install/update/uninstall idle packaged service on the disposable CI runner."""
import json
import os
import subprocess
import time
from pathlib import Path

version = Path("VERSION").read_text().strip()
stage = Path("build") / ("helmsman-" + version)
user = os.environ["USER"]
binary = "/var/lib/helmsman-app/current/Helmsman"


def config():
    return json.loads(subprocess.check_output([binary, "ctl", "configuration"], text=True))


def rpc(method, params=None):
    return json.loads(subprocess.check_output([binary, "ctl", method, json.dumps(params or {})], text=True))


try:
    subprocess.run(["sudo", "bash", str(stage / "install.sh"), "--user", user], check=True)
    rpc("import", {"text": "vless://00000000-0000-0000-0000-000000000001@127.0.0.1:9?type=xhttp&mode=packet-up#Installed-fixture"})
    rpc("settings_save", {"settings": {"dns_proxy": "tls://dns.google", "dns_direct": "https://dns.quad9.net/dns-query"}})
    before = config()
    subprocess.run(["sudo", "bash", str(stage / "install.sh"), "--user", user], check=True)
    after = config()
    assert before["hwid"] == after["hwid"]
    assert before["profiles"] == after["profiles"]
    assert not after["desired"]
    # This deliberately unreachable fixture verifies the installed unit's
    # actual TUN/guard/capability path, not a remote handshake. Transport data
    # is exercised separately in test_transports.py and test-netns.sh.
    try:
        rpc("connect")
        for _ in range(30):
            status = rpc("status")
            if status["state"] == "running":
                break
            if status["state"] == "error":
                raise AssertionError(status)
            time.sleep(0.1)
        else:
            raise AssertionError(status)
        assert status["guard"]
        assert Path("/var/lib/helmsman/runtime/active-xray.json").exists()
        assert Path("/sys/class/net/helmsman0").exists()
        assert subprocess.run(["sudo", "nft", "list", "table", "inet", "helmsman_guard"], stdout=subprocess.DEVNULL).returncode == 0
        print("PASS installed frozen daemon creates TUN and crash guard under systemd restrictions")
    finally:
        rpc("disconnect")
    assert not Path("/sys/class/net/helmsman0").exists()
    assert not Path("/var/lib/helmsman/runtime/active-xray.json").exists()
    assert config()["settings"] == before["settings"]
    subprocess.run([binary, "--smoke-test"], check=True, timeout=15, env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
    print("PASS packaged systemd service, unprivileged RPC/GUI and update persistence")
finally:
    subprocess.run(["sudo", "bash", str(stage / "uninstall.sh"), "--user", user, "--purge"], check=True)
assert not Path("/var/lib/helmsman-app").exists()
assert not Path("/etc/systemd/system/helmsman.service").exists()
print("PASS packaged uninstall")
