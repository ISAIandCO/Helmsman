#!/usr/bin/env python3
"""Pinned source builds; complete vendored sources accompany every release."""
import json
import hashlib
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
    "xray": {"repository": "https://github.com/XTLS/Xray-core.git", "commit": "92ccc939aaf4f8965f369cf0b142e005aeaa11d5", "version": "26.10.17", "toolchain": "go1.27.2"},
    "wgcf": {"repository": "https://github.com/ViRb3/wgcf.git", "commit": "de6bba7147dc965a1b8e4de113a709750697ccea", "version": "2.3.1", "toolchain": "go1.26.8"},
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
        run(["git", "checkout", "--force", "--detach", "FETCH_HEAD"], source)
        if name.startswith("sing-box"):
            patch = ROOT / "patches/sing-box-doh-query.patch"
            run(["git", "apply", str(patch)], source)
            spec["patches"] = {str(patch.relative_to(ROOT)): hashlib.sha256(patch.read_bytes()).hexdigest()}
            run(["go", "mod", "vendor"], source, env)
            run(["go", "build", "-mod=vendor", "-buildvcs=false", "-trimpath", "-tags", spec["tags"], "-ldflags", "-s -w -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=" + spec["version"], "-o", str(OUT / name), "./cmd/sing-box"], source, env)
        elif name in {"xray", "wgcf"}:
            goenv = dict(env, GOTOOLCHAIN=spec["toolchain"])
            run(["go", "mod", "vendor"], source, goenv)
            flags = "-s -w"
            run(["go", "build", "-mod=vendor", "-buildvcs=false", "-trimpath", "-ldflags", flags, "-o", str(OUT / name), "./main" if name == "xray" else "."], source, goenv)
        else:
            # MPL agent only; never compile/distribute the nonfree controller.
            # Use the host C/C++ runtime, as Qt does. Static glibc + host NSS
            # modules can crash during account lookup; keep normal PIE linking.
            run(["make", "-j2", "ZT_NONFREE=0", "ZT_SSO_SUPPORTED=0", "ZT_STATIC=0", "LDFLAGS=-pie -Wl,-z,relro,-z,now", "zerotier-one"], source)
            shutil.copy2(source / "zerotier-one", OUT / "zerotier-one")
        if name != "zerotier":
            goenv = dict(env, GOTOOLCHAIN=spec.get("toolchain", "local"))
            goroot = Path(subprocess.check_output(["go", "env", "GOROOT"], cwd=source, env=goenv, text=True).strip())
            for notice in ("LICENSE", "PATENTS"):
                if (goroot / notice).exists():
                    shutil.copy2(goroot / notice, source / ("GO-" + notice))
        (source / "HELMSMAN-REVISION.json").write_text(json.dumps(spec, indent=2))
    link = OUT / "zerotier-cli"
    link.unlink(missing_ok=True)
    link.symlink_to("zerotier-one")
    (OUT / "BUILD.json").write_text(json.dumps(LOCK, indent=2))
    for name in ("sing-box", "sing-box-awg"):
        run([str(OUT / name), "version"], ROOT)
    run([str(OUT / "zerotier-one"), "-v"], ROOT)
    run([str(OUT / "xray"), "version"], ROOT)
    run([str(OUT / "wgcf"), "--help"], ROOT)


if __name__ == "__main__":
    main()
