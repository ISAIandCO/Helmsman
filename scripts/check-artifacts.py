import hashlib
import tarfile
import zipfile
import os
import subprocess
import tempfile
import sys
from pathlib import Path

root = Path("dist/release")
for line in (root / "SHA256SUMS").read_text().splitlines():
    digest, name = line.split("  ", 1)
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
app = next(root.glob("*-linux-x86_64.tar.gz"))
with tarfile.open(app) as archive:
    names = archive.getnames()
    for name in ("app/Helmsman", "app/engines/sing-box", "app/engines/sing-box-awg", "app/engines/zerotier-one", "app/engines/xray", "app/engines/wgcf", "app/_internal/helmsman/warp-obfuscation.json", "app/licenses/xray/GO-LICENSE", "app/licenses/wgcf/GO-LICENSE", "install.sh", "uninstall.sh", "decky/dist/index.js"):
        assert any(x.endswith("/" + name) for x in names), name
    with tempfile.TemporaryDirectory() as d:
        archive.extractall(d, filter="data")
        binary = next(Path(d).glob("*/app/Helmsman"))
        subprocess.run([str(binary), "ctl", "--help"], check=True, stdout=subprocess.DEVNULL)
        subprocess.run([str(binary), "--smoke-test"], check=True, timeout=15, env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
        subprocess.run(["xvfb-run", "-a", "-s", "-screen 0 1280x800x24", str(binary), "--smoke-test"], check=True, timeout=20, env={**os.environ, "QT_QPA_PLATFORM": "xcb"})
        subprocess.run([sys.executable, 'scripts/check-wayland.py', str(binary)], check=True, timeout=30)
with zipfile.ZipFile(next(root.glob("helmsman-decky-*.zip"))) as archive:
    for name in ("helmsman/plugin.json", "helmsman/main.py", "helmsman/dist/index.js"):
        assert name in archive.namelist(), name
print("PASS installable archives, plugin layout and SHA256SUMS")
