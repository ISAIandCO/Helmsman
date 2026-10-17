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
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--name", "Helmsman", "--paths", str(ROOT), "--add-data", "helmsman/warp-obfuscation.json:helmsman", "packaging/entry.py"], cwd=ROOT, check=True)
    shutil.copytree(ROOT / "dist" / "Helmsman", stage / "app")
    # QtGui's generic hook also collects PDF and virtual-keyboard plugins.
    # Steam supplies its own keyboard; neither plugin belongs in this app.
    internal = stage / "app/_internal"
    # Host desktop/system libraries belong to SteamOS, not our distribution.
    # Keep the bundled Python/Qt/ICU runtimes; avoid copying Ubuntu GTK, GLib,
    # systemd, crypto and X11 libraries (and their platform-specific versions).
    for path in internal.glob("*.so*"):
        if not path.name.startswith("libpython") and not path.is_symlink():
            path.unlink()
    for path in internal.rglob("*"):
        if path.is_file() and (path.name in {"libqpdf.so", "libqtvirtualkeyboardplugin.so"} or any(path.name.startswith("libQt6" + n) for n in ("Pdf", "Qml", "Quick", "VirtualKeyboard"))):
            path.unlink()
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
    # PyInstaller Qt remains dynamically linked and replaceable. Include the
    # original licensing notices from every bundled source/dependency.
    licenses = stage / "app" / "licenses"
    licenses.mkdir()
    shutil.copytree(ROOT / "packaging/licenses", licenses / "runtime-notices")
    for path in (ROOT / "build" / "sources").rglob("*"):
        if path.is_file() and (path.name.lower().startswith(("license", "copying", "notice")) or path.name in {"GO-LICENSE", "GO-PATENTS"}) and ".git" not in path.parts and "nonfree" not in path.parts:
            target = licenses / path.relative_to(ROOT / "build" / "sources")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    runtime_sources = ROOT / "build/runtime-sources"
    if not (runtime_sources / "SOURCES.json").exists():
        raise RuntimeError("Run python scripts/runtime-sources.py before packaging")
    for archive in runtime_sources.glob("*.tar.*"):
        with tarfile.open(archive) as t:
            for member in t:
                path = Path(member.name)
                licensed = path.name.lower().startswith(("license", "copying", "notice")) or any(p.lower().startswith("license") for p in path.parts)
                if member.isfile() and member.size < 5 * 1024 * 1024 and licensed and ".." not in path.parts:
                    target = licenses / "runtime" / archive.name / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(t.extractfile(member).read())
    for module in ("@decky/api", "@decky/ui", "tslib"):
        for path in (ROOT / "decky/node_modules" / module).glob("*LICENSE*"):
            target = licenses / "decky" / module / path.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    if (licenses / "decky").exists():
        shutil.copytree(licenses / "decky", plugin / "licenses", dirs_exist_ok=True)
    with zipfile.ZipFile(out / f"helmsman-decky-{version}.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for path in plugin.rglob("*"):
            if path.is_file():
                z.write(path, "helmsman/" + str(path.relative_to(plugin)))
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
    with tarfile.open(out / f"helmsman-{version}-runtime-sources.tar.gz", "w:gz") as t:
        for p in runtime_sources.iterdir():
            if not p.name.endswith(".part"):
                t.add(p, arcname="runtime-sources/" + p.name)
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
