"""Install/update/uninstall idle packaged service on the disposable CI runner."""
import json
import os
import subprocess
from pathlib import Path

version = Path("VERSION").read_text().strip()
stage = Path("build") / ("helmsman-" + version)
user = os.environ["USER"]
binary = "/var/lib/helmsman-app/current/Helmsman"


def config():
    return json.loads(subprocess.check_output([binary, "ctl", "configuration"], text=True))


try:
    subprocess.run(["sudo", "bash", str(stage / "install.sh"), "--user", user], check=True)
    before = config()
    subprocess.run(["sudo", "bash", str(stage / "install.sh"), "--user", user], check=True)
    after = config()
    assert before["hwid"] == after["hwid"]
    assert before["profiles"] == after["profiles"]
    assert not after["desired"]
    subprocess.run([binary, "--smoke-test"], check=True, timeout=15, env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
    print("PASS packaged systemd service, unprivileged RPC/GUI and update persistence")
finally:
    subprocess.run(["sudo", "bash", str(stage / "uninstall.sh"), "--user", user, "--purge"], check=True)
assert not Path("/var/lib/helmsman-app").exists()
assert not Path("/etc/systemd/system/helmsman.service").exists()
print("PASS packaged uninstall")
