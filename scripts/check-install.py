"""Install/update/uninstall idle packaged service on the disposable CI runner."""
import json
import os
import runpy
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


def wait_state(expected):
    for _ in range(50):
        result = subprocess.run([binary, 'ctl', 'status'], capture_output=True, text=True)
        if result.returncode == 0:
            status = json.loads(result.stdout)
            if status['state'] == expected:
                return status
        time.sleep(0.1)
    raise AssertionError(result.stdout + result.stderr)


def previous_boot():
    # Simulates a new OS boot token; does not reboot the shared CI runner.
    subprocess.run(['sudo', 'python3', '-c', """
import json
from pathlib import Path
p=Path('/opt/helmsman/state/state.json')
state=json.loads(p.read_text())
state['boot_id']='previous-test-boot'
p.write_text(json.dumps(state))
"""], check=True)


# GitHub runners make /opt writable for tool installation. Match the secure
# system directory on the target before testing a root service installation.
subprocess.run(["stat", "-c", "%U:%G %a %n", "/opt"], check=True)
subprocess.run(["sudo", "chown", "root:root", "/opt"], check=True)
subprocess.run(["sudo", "chmod", "0755", "/opt"], check=True)

# Exercise the real --decky path with a root-owned, non-writable parent,
# matching the protected plugins directory reported on Steam Deck.
plugins = Path.home() / 'homebrew/plugins'
plugin = plugins / 'helmsman'
other_plugin = plugins / 'unrelated-fixture'
subprocess.run(["sudo", "install", "-d", "-o", "root", "-g", "root", "-m", "0755", str(plugins), str(other_plugin)], check=True)
assert not os.access(plugins, os.W_OK)
subprocess.run(["sudo", "touch", str(other_plugin / 'keep')], check=True)


def check_plugin():
    for name in ('plugin.json', 'main.py', 'package.json', 'dist/index.js'):
        path = plugin / name
        assert path.is_file() and os.access(path, os.R_OK)
        assert path.stat().st_uid == 0
        assert not path.stat().st_mode & 0o022
    assert json.loads((plugin / 'plugin.json').read_text())['flags'] == []
    assert (other_plugin / 'keep').exists()
    backend = runpy.run_path(str(plugin / 'main.py'))
    assert backend['request_service']('status', {})['state'] == rpc('status')['state']


try:
    subprocess.run(["sudo", "bash", str(stage / "install.sh"), "--user", user, "--decky"], check=True)
    check_plugin()
    rpc('import', {'text': 'proxies:\n  - {name: Installed YAML, type: vless, server: 127.0.0.1, port: 9, uuid: 00000000-0000-0000-0000-000000000001}'})
    assert config()['profiles'][0]['name'] == 'Installed YAML'
    rpc("import", {"text": json.dumps({'remarks': 'Installed mux fixture', 'outbounds': [{'protocol': 'vless',
        'settings': {'vnext': [{'address': '127.0.0.1', 'port': 9, 'users': [{'id': '00000000-0000-0000-0000-000000000001', 'encryption': 'none'}]}]},
        'streamSettings': {'network': 'tcp', 'security': 'none', 'sockopt': {'tcpFastOpen': False, 'tcpKeepAliveIdle': 30, 'tcpMaxSeg': 1280}, 'finalmask': {'tcp': [{'type': 'fragment', 'settings': {'packets': '1-3', 'length': '32-64', 'delay': '0', 'maxSplit': '3'}}]}},
        'mux': {'enabled': True, 'concurrency': 8, 'xudpConcurrency': 8, 'xudpProxyUDP443': 'skip'}}]})})
    rpc("settings_save", {"settings": {"dns_proxy": "tls://dns.google", "dns_direct": "https://dns.quad9.net/dns-query"}})
    before = config()
    subprocess.run(["sudo", "python3", "-c", """
from pathlib import Path
account=Path('/opt/helmsman/state/warp/account.toml')
account.parent.mkdir(mode=0o700,exist_ok=True)
account.write_text('test-only-account')
account.chmod(0o600)
"""], check=True)
    subprocess.run(["sudo", "bash", str(stage / "install.sh"), "--user", user, "--decky"], check=True)
    check_plugin()
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
        print("PASS installed frozen daemon starts native Xray mux sidecar, TUN and crash guard under systemd restrictions")
        children = subprocess.check_output(['pgrep', '-u', 'helmsman-engine'], text=True)
        backend = runpy.run_path(str(plugin / 'main.py'))
        backend['request_service']('auto_connect', {'enabled': True})
        assert rpc('status')['auto_connect']
        backend['request_service']('auto_connect', {'enabled': False})
        assert subprocess.check_output(['pgrep', '-u', 'helmsman-engine'], text=True) == children
        subprocess.run(['sudo', 'systemctl', 'restart', 'helmsman.service'], check=True)
        assert wait_state('running')['guard']  # Same boot: recover active VPN even with option off.
        subprocess.run(['sudo', 'systemctl', 'stop', 'helmsman.service'], check=True)
        previous_boot()
        subprocess.run(['sudo', 'systemctl', 'restart', 'helmsman-guard.service', 'helmsman.service'], check=True)
        off = wait_state('disconnected')
        assert not off['desired'] and not off['guard'] and not off['auto_connect']
        assert not Path('/sys/class/net/helmsman0').exists()
        backend['request_service']('auto_connect', {'enabled': True})
        assert not rpc('status')['desired']  # Setting the option alone must never connect.
        subprocess.run(['sudo', 'systemctl', 'stop', 'helmsman.service'], check=True)
        previous_boot()
        subprocess.run(['sudo', 'systemctl', 'restart', 'helmsman-guard.service', 'helmsman.service'], check=True)
        on = wait_state('running')
        assert on['desired'] and on['guard'] and on['auto_connect']
        assert config()['hwid'] == before['hwid']
        assert config()['profiles'] == before['profiles']
        backend['request_service']('auto_connect', {'enabled': False})
        print('PASS Decky/Desktop optional boot autoconnect, same-boot recovery, simulated new boot on/off and early guard')
    finally:
        rpc("disconnect")
    assert not Path("/sys/class/net/helmsman0").exists()
    assert subprocess.run(["sudo", "test", "-f", "/opt/helmsman/state/runtime/active-xray.json"]).returncode == 1
    assert config()["settings"] == before["settings"]
    subprocess.run([binary, "--smoke-test"], check=True, timeout=15, env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
    subprocess.run(["sudo", "bash", str(stage / "uninstall.sh"), "--user", user], check=True)
    assert not Path('/opt/helmsman/current').exists()
    assert not plugin.exists()
    assert (other_plugin / 'keep').exists()
    subprocess.run(["sudo", "bash", str(stage / "install.sh"), "--user", user, "--decky"], check=True)
    check_plugin()
    assert config()["hwid"] == before["hwid"]
    assert config()["profiles"] == before["profiles"]
    print("PASS packaged systemd service, unprivileged RPC/GUI, update and reinstall persistence")
finally:
    subprocess.run(["sudo", "bash", str(stage / "uninstall.sh"), "--user", user, "--purge"], check=True)
assert not plugin.exists()
assert (other_plugin / "keep").exists()
subprocess.run(["sudo", "rm", "-rf", str(other_plugin)], check=True)
assert not Path("/opt/helmsman").exists()
assert not Path("/etc/systemd/system/helmsman.service").exists()
print("PASS --decky install/update/uninstall with protected parent, readable unprivileged backend and unrelated plugin preserved")
print("PASS packaged uninstall")
