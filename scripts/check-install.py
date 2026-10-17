"""Install/update/uninstall idle packaged service on the disposable CI runner."""
import json
import os
import subprocess
import time
from pathlib import Path

version = Path("VERSION").read_text().strip()
stage = Path("build") / ("helmsman-" + version)
user = os.environ["USER"]
binary = "/opt/helmsman/current/Helmsman"


def config():
    return json.loads(subprocess.check_output([binary, "ctl", "configuration"], text=True))


def rpc(method, params=None):
    return json.loads(subprocess.check_output([binary, "ctl", method, json.dumps(params or {})], text=True))


# GitHub runners make /opt writable for tool installation. Match the secure
# system directory on the target before testing a root service installation.
subprocess.run(["stat", "-c", "%U:%G %a %n", "/opt"], check=True)
subprocess.run(["sudo", "chown", "root:root", "/opt"], check=True)
subprocess.run(["sudo", "chmod", "0755", "/opt"], check=True)

try:
    subprocess.run(["sudo", "bash", str(stage / "install.sh"), "--user", user], check=True)
    rpc("import", {"text": "vless://00000000-0000-0000-0000-000000000001@127.0.0.1:9?type=xhttp&mode=packet-up#Installed-fixture"})
    rpc("settings_save", {"settings": {"dns_proxy": "tls://dns.google", "dns_direct": "https://dns.quad9.net/dns-query"}})
    before = config()
    subprocess.run(["sudo", "python3", "-c", """
from pathlib import Path
account=Path('/opt/helmsman/state/warp/account.toml')
account.parent.mkdir(mode=0o700,exist_ok=True)
account.write_text('test-only-account')
account.chmod(0o600)
"""], check=True)
    subprocess.run(["sudo", "bash", str(stage / "install.sh"), "--user", user], check=True)
    after = config()
    assert before["hwid"] == after["hwid"]
    assert before["profiles"] == after["profiles"]
    assert before["settings"] == after["settings"]
    assert not after["desired"]
    assert not Path('/var/lib/helmsman-app').exists()
    assert not Path('/var/lib/helmsman-app').is_symlink()
    subprocess.run(["sudo", "python3", "-c", """
from pathlib import Path
p=Path('/opt/helmsman/state/warp/account.toml')
assert p.read_text()=='test-only-account'
assert p.stat().st_mode & 0o777 == 0o600
for name in ('/opt/helmsman','/opt/helmsman/state'):
    p=Path(name)
    assert not p.is_symlink()
    assert p.stat().st_uid == 0 and not p.stat().st_mode & 0o022
"""], check=True)
    print("PASS direct opt layout, update preserves HWID, profiles, DNS and private WARP account")
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
        assert subprocess.run(["sudo", "test", "-f", "/opt/helmsman/state/runtime/active-xray.json"]).returncode == 0
        assert Path("/sys/class/net/helmsman0").exists()
        assert subprocess.run(["sudo", "nft", "list", "table", "inet", "helmsman_guard"], stdout=subprocess.DEVNULL).returncode == 0
        print("PASS installed frozen daemon creates TUN and crash guard under systemd restrictions")
    finally:
        rpc("disconnect")
    assert not Path("/sys/class/net/helmsman0").exists()
    assert subprocess.run(["sudo", "test", "-f", "/opt/helmsman/state/runtime/active-xray.json"]).returncode == 1
    assert config()["settings"] == before["settings"]
    subprocess.run([binary, "--smoke-test"], check=True, timeout=15, env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
    subprocess.run(["sudo", "bash", str(stage / "uninstall.sh"), "--user", user], check=True)
    assert not Path('/opt/helmsman/current').exists()
    subprocess.run(["sudo", "bash", str(stage / "install.sh"), "--user", user], check=True)
    assert config()["hwid"] == before["hwid"]
    assert config()["profiles"] == before["profiles"]
    print("PASS packaged systemd service, unprivileged RPC/GUI, update and reinstall persistence")
finally:
    subprocess.run(["sudo", "bash", str(stage / "uninstall.sh"), "--user", user, "--purge"], check=True)
assert not Path("/opt/helmsman").exists()
assert not Path("/etc/systemd/system/helmsman.service").exists()
print("PASS packaged uninstall")
