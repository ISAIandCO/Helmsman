import hashlib
import tarfile
import zipfile
from pathlib import Path

root = Path("dist/release")
for line in (root / "SHA256SUMS").read_text().splitlines():
    digest, name = line.split("  ", 1)
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
app = next(root.glob("*-linux-x86_64.tar.gz"))
with tarfile.open(app) as archive:
    names = archive.getnames()
    for name in ("app/Helmsman", "app/engines/sing-box", "app/engines/sing-box-awg", "app/engines/zerotier-one", "install.sh", "uninstall.sh", "decky/dist/index.js"):
        assert any(x.endswith("/" + name) for x in names), name
with zipfile.ZipFile(next(root.glob("helmsman-decky-*.zip"))) as archive:
    for name in ("helmsman/plugin.json", "helmsman/main.py", "helmsman/dist/index.js"):
        assert name in archive.namelist(), name
print("PASS installable archives, plugin layout and SHA256SUMS")
