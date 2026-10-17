"""Corresponding sources for the unmodified redistributed Qt/Python runtime."""
import concurrent.futures
import hashlib
import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
QT = "https://download.qt.io/archive/qt/6.9/6.9.3/submodules/"
SOURCES = {
    "qtbase-6.9.3.tar.xz": (QT + "qtbase-everywhere-src-6.9.3.tar.xz", "c5a1a2f660356ec081febfa782998ae5ddbc5925117e64f50e4be9cd45b8dc6e"),
    "qtwayland-6.9.3.tar.xz": (QT + "qtwayland-everywhere-src-6.9.3.tar.xz", "e413d4bc9263e80a465761debf8cb8317aa6b01e814b20046a05258e6573dadd"),
    "qtsvg-6.9.3.tar.xz": (QT + "qtsvg-everywhere-src-6.9.3.tar.xz", "db76aa3358cbbe6fce7da576ff4669cb9801920188c750d3b12783bbe97026e2"),
    "qtimageformats-6.9.3.tar.xz": (QT + "qtimageformats-everywhere-src-6.9.3.tar.xz", "4fb26bdbfbd4b8e480087896514e11c33aba7b6b39246547355ea340c4572ffe"),
    "pyside-setup-6.9.3.tar.gz": ("https://github.com/pyside/pyside-setup/archive/7befa4be34d6e5fc49b57e8d500174412092e40e.tar.gz", "a2a41d51307cc53969f7af9baf9f4cfb2a4e84296e096a16bad1ec05634482b7"),
    "cpython-3.12.12.tar.gz": ("https://github.com/python/cpython/archive/4a5632fbf9bf59477c540e3f53fa7cdbeea3e3f5.tar.gz", "6a99f1f62b9633f26fddc77a072f06177493a5334d1e787ed739a662739eb7a6"),
    "pyinstaller-6.16.0.tar.gz": ("https://github.com/pyinstaller/pyinstaller/archive/7f2ae63f703ae27955722eac4891678b546d513a.tar.gz", "abef5df9b9b390b38c611852b5b355d877a62df06fcdb9616e6b6984243b4cd6"),
}


def main():
    out = ROOT / "build/runtime-sources"
    out.mkdir(parents=True, exist_ok=True)
    def fetch(item):
        name, (url, expected) = item
        path = out / name
        if not path.exists():
            with urllib.request.urlopen(url, timeout=60) as response, open(path.with_suffix(".part"), "wb") as f:
                while block := response.read(1024 * 1024):
                    f.write(block)
            path.with_suffix(".part").replace(path)
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        if expected and sha != expected:
            path.unlink()
            raise RuntimeError("Source SHA256 mismatch: " + name)
        print("Runtime source:", name, sha, flush=True)
        return name, {"url": url, "sha256": sha}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        manifest = dict(pool.map(fetch, SOURCES.items()))
    (out / "SOURCES.json").write_text(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
