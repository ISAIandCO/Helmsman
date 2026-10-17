#!/usr/bin/env python3
"""Pinned source builds; complete vendored sources accompany every release."""
import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "build" / "sources"
OUT = ROOT / "build" / "engines"
LOCK = {
    "sing-box": {"repository": "https://github.com/SagerNet/sing-box.git", "commit": "7054cac5124465ffdb145870d7c01885566711b1", "tags": "with_gvisor,with_quic,with_wireguard,with_utls,with_openvpn", "version": "1.14.3"},
    "sing-box-awg": {"repository": "https://github.com/throneproj/sing-box.git", "commit": "8b3b24f856bd875b88c27c40a17a8f8fb5e02718", "tags": "with_gvisor,with_quic,with_wireguard,with_utls", "version": "1.14.1-throne-8b3b24f"},
    "zerotier": {"repository": "https://github.com/zerotier/ZeroTierOne.git", "commit": "899352e38405968516bb12a770f0ac02f6058fa8", "version": "1.16.2"},
}


def run(args, cwd, env=None):
    print("+", " ".join(str(x) for x in args), flush=True)
    subprocess.run(args, cwd=cwd, env=env, check=True)


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CGO_ENABLED="0", GOTOOLCHAIN="local")
    for name, spec in LOCK.items():
        source = WORK / name
        if not (source / ".git").exists():
            source.mkdir(exist_ok=True)
            run(["git", "init"], source)
            run(["git", "remote", "add", "origin", spec["repository"]], source)
        run(["git", "fetch", "--depth=1", "origin", spec["commit"]], source)
        run(["git", "checkout", "--detach", "FETCH_HEAD"], source)
        if name.startswith("sing-box"):
            run(["go", "mod", "vendor"], source, env)
            run(["go", "build", "-mod=vendor", "-buildvcs=false", "-trimpath", "-tags", spec["tags"], "-ldflags", "-s -w -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=" + spec["version"], "-o", str(OUT / name), "./cmd/sing-box"], source, env)
        else:
            # MPL agent only; never compile/distribute the nonfree controller.
            run(["make", "-j2", "ZT_NONFREE=0", "ZT_SSO_SUPPORTED=0", "ZT_STATIC=1", "zerotier-one"], source)
            shutil.copy2(source / "zerotier-one", OUT / "zerotier-one")
        (source / "HELMSMAN-REVISION.json").write_text(json.dumps(spec, indent=2))
    link = OUT / "zerotier-cli"
    link.unlink(missing_ok=True)
    link.symlink_to("zerotier-one")
    (OUT / "BUILD.json").write_text(json.dumps(LOCK, indent=2))
    for name in ("sing-box", "sing-box-awg"):
        run([str(OUT / name), "version"], ROOT)
    run([str(OUT / "zerotier-one"), "-v"], ROOT)


if __name__ == "__main__":
    main()
