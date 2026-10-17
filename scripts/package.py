#!/usr/bin/env python3
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    version = (ROOT / "VERSION").read_text().strip()
    out = ROOT / "dist" / "release"
    stage = ROOT / "build" / ("helmsman-" + version)
    out.mkdir(parents=True, exist_ok=True)
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--name", "Helmsman", "--paths", str(ROOT), "packaging/entry.py"], cwd=ROOT, check=True)
    shutil.copytree(ROOT / "dist" / "Helmsman", stage / "app")
    shutil.copytree(ROOT / "build" / "engines", stage / "app" / "engines", symlinks=True)
    shutil.copytree(ROOT / "packaging", stage / "packaging")
    for name in ("install.sh", "uninstall.sh"):
        shutil.copy2(ROOT / "scripts" / name, stage / name)
    for name in ("README.md", "LICENSE", "VERSION", "THIRD_PARTY.md"):
        shutil.copy2(ROOT / name, stage / name)
    shutil.copytree(ROOT / "docs", stage / "docs")
    plugin = stage / "decky"
    plugin.mkdir()
    for name in ("main.py", "plugin.json", "package.json"):
        shutil.copy2(ROOT / "decky" / name, plugin / name)
    shutil.copytree(ROOT / "decky" / "dist", plugin / "dist")
    shutil.copy2(ROOT / "LICENSE", plugin / "LICENSE")
    with zipfile.ZipFile(out / f"helmsman-decky-{version}.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for path in plugin.rglob("*"):
            if path.is_file():
                z.write(path, "helmsman/" + str(path.relative_to(plugin)))
    # PyInstaller Qt remains dynamically linked and replaceable. Include the
    # original licensing notices from every bundled source/dependency.
    licenses = stage / "app" / "licenses"
    licenses.mkdir()
    for path in (ROOT / "build" / "sources").rglob("*"):
        if path.is_file() and path.name.lower().startswith(("license", "copying", "notice")) and ".git" not in path.parts and "nonfree" not in path.parts:
            target = licenses / path.relative_to(ROOT / "build" / "sources")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    with tarfile.open(out / f"helmsman-{version}-linux-x86_64.tar.gz", "w:gz") as t:
        t.add(stage, arcname=stage.name)
    sources = ROOT / "build" / "sources"
    if sources.exists():
        def source_filter(info):
            if "/.git/" in info.name or info.name.endswith("/.git") or "/nonfree/" in info.name or info.name.endswith("/nonfree") or info.name.endswith((".o", ".a", ".so")) or info.name.endswith("/zerotier-one"):
                return None
            return info
        with tarfile.open(out / f"helmsman-{version}-engine-sources.tar.gz", "w:gz") as t:
            t.add(sources, arcname="engine-sources", filter=source_filter)
    # Include the exact own source tree rather than a moving GitHub branch URL.
    with tarfile.open(out / f"helmsman-{version}-source.tar.gz", "w:gz") as t:
        paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
        for name in paths:
            if name:
                t.add(ROOT / name, arcname="helmsman/" + name)
    manifest = {"version": version, "python": sys.version, "source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip(), "platform": "Linux x86_64; build on Ubuntu 22.04", "engines": json.loads((ROOT / "build" / "engines" / "BUILD.json").read_text())}
    (out / "BUILD.json").write_text(json.dumps(manifest, indent=2))
    files = sorted(p for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    (out / "SHA256SUMS").write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n" for p in files))
    print("Artifacts:", *(p.name for p in out.iterdir()))


if __name__ == "__main__":
    main()
