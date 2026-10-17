import base64
import copy
import importlib.util
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from helmsman.common import Store, UserError, defaults
from helmsman.daemon import Controller, Server
from helmsman.dns import DNS_PRESETS, dns_server, resolver_url
from helmsman.importers import parse
from helmsman.routing import compile_config, rule, text_list
from helmsman.rpc import call
from helmsman.subscriptions import SafeRedirect, request_data, update, validate_subscription
from helmsman.system import Runtime, firewall_script

LINK = "vless://00000000-0000-0000-0000-000000000001@127.0.0.1:12345?security=none#One"
WG = """[Interface]
PrivateKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address=10.44.0.2/32,fd00:44::2/128
[Peer]
PublicKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint=127.0.0.1:51820
AllowedIPs=0.0.0.0/0,::/0
PersistentKeepalive=25
"""


class MemoryRuntime:
    """State-machine test double; not evidence of a successful VPN connection."""
    def __init__(self, root):
        self.binaries = self.directory = Path(root)
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.active = None
        self.guard = False
    def status(self):
        return {"state": "running" if self.active else "disconnected", "message": "test", "guard": self.guard}
    def validate_profiles(self, profiles):
        if not profiles:
            raise UserError("empty")
    def check(self, *args):
        self.validate_profiles([args])
    def start(self, state, p):
        self.active = p
        self.guard = state["settings"]["kill_switch"]
    def stop(self):
        self.active = None
    def clear_guard(self):
        self.guard = False


class CoreTests(unittest.TestCase):
    def test_formats_and_reject_unsupported(self):
        self.assertEqual(parse(LINK)[0]["outbound"]["type"], "vless")
        self.assertEqual(len(parse(base64.b64encode((LINK + "\n" + LINK).encode()).decode())), 2)
        self.assertEqual(parse("ss://YWVzLTEyOC1nY206c2VjcmV0@127.0.0.1:8388")[0]["outbound"]["password"], "secret")
        self.assertEqual(parse("hy2://secret@127.0.0.1:443?sni=example.com")[0]["outbound"]["type"], "hysteria2")
        self.assertEqual(parse("zerotier://0123456789abcdef")[0]["network_id"], "0123456789abcdef")
        for bad in (LINK.replace("security=none", "security=reality"), LINK + "&type=unsupported-transport", "zerotier://bad", "", "<html>error</html>"):
            with self.subTest(bad=bad), self.assertRaises(UserError):
                # Fragment is not a query parameter.
                parse(bad.replace("#One&", "&"))

    def test_wg_awg_and_no_scripts(self):
        p = parse(WG)[0]
        self.assertEqual(p["outbound"]["peers"][0]["allowed_ips"], ["0.0.0.0/0", "::/0"])
        awg = WG.replace("Address=", "Jc=4\nJmin=40\nJmax=80\nS3=12\nH1=123-456\nI1=<b 0xdeadbeef>\nAddress=")
        p = parse(awg)[0]
        self.assertEqual(p["outbound"]["amnezia_wg"]["h1"], "123-456")
        self.assertEqual(p["outbound"]["amnezia_wg"]["s3"], 12)
        with self.assertRaises(UserError):
            parse(WG.replace("Address=", "PostUp=touch /tmp/bad\nAddress="))

    def test_no_root_file_access_from_import(self):
        p = parse(LINK)[0]["outbound"]
        for field in ({"tls": {"enabled": True, "certificate_path": "/etc/shadow"}}, {"detour": "direct"}, {"bind_interface": "eth0"}, {"tls": {"enabled": True, "insecure": True}}):
            with self.subTest(field=field), self.assertRaises(UserError):
                parse(json.dumps({**p, **field}))
        with self.assertRaises(UserError):
            parse("client\nremote host 1194\ndev tun\nup /tmp/script\n")

    def test_hwid_contracts(self):
        base = {"name": "Test", "url": "https://example.com/sub?a=1", "hwid_mode": "remnawave"}
        s = validate_subscription(base)
        url, headers = request_data(s, "0123456789abcdef")
        self.assertEqual(headers["x-hwid"], "0123456789abcdef")
        self.assertEqual(headers["x-device-os"], "Linux")
        s.update(hwid_mode="query", hwid_name="device", hwid="manual-id")
        self.assertIn("a=1&device=manual-id", request_data(s, "ignored")[0])
        s.update(hwid_mode="header", hwid_name="X-Device-Id")
        self.assertEqual(request_data(s, "ignored")[1]["x-device-id"], "manual-id")
        with self.assertRaises(UserError):
            validate_subscription({**base, "headers": {"x-bad": "abc\r\nInjected: yes"}})

    def test_redirect_does_not_forward_hwid(self):
        import urllib.request
        req = urllib.request.Request("https://example.com/sub", headers={"x-hwid": "private"})
        with self.assertRaises(UserError):
            SafeRedirect().redirect_request(req, None, 302, "", {}, "https://evil.example.com/sub")
        with self.assertRaises(UserError):
            SafeRedirect().redirect_request(req, None, 302, "", {}, "http://example.com/sub")

    def test_subscription_atomic_identity_and_selected_removed(self):
        state = defaults()
        s = validate_subscription({"name": "Test", "url": "https://example.com/sub"})
        state["subscriptions"] = [s]
        updated = update(state, s["id"], lambda p: None, lambda *_: LINK.encode())
        p = updated["profiles"][0]
        again = update(updated, s["id"], lambda p: None, lambda *_: LINK.replace("#One", "#Renamed").encode())
        self.assertEqual(again["profiles"][0]["id"], p["id"])
        replacement = update(updated, s["id"], lambda p: None, lambda *_: LINK.replace(":12345", ":12346").encode())
        self.assertIn(p["id"], [x["id"] for x in replacement["profiles"]])
        self.assertNotIn("subscription", next(x for x in replacement["profiles"] if x["id"] == p["id"]))
        before = copy.deepcopy(updated)
        with self.assertRaises(UserError):
            update(updated, s["id"], lambda p: None, lambda *_: b"<html>502</html>")
        self.assertEqual(updated, before)

    def test_store_survives_restart_and_hwid_stable(self):
        with tempfile.TemporaryDirectory() as d:
            a = Store(d)
            value = a.data["hwid"]
            a.data["profiles"] = parse(LINK)
            a.save()
            b = Store(d)
            self.assertEqual(b.data["hwid"], value)
            self.assertEqual(b.data["profiles"], a.data["profiles"])
            self.assertEqual(b.path.stat().st_mode & 0o777, 0o600)
            b.path.write_text("broken")
            with self.assertRaises(UserError):
                Store(d)

    def test_rules_presets_dns_and_cidr(self):
        p = parse(LINK)[0]
        state = defaults()
        state["preset"] = "manual"
        state["settings"]["default_action"] = "block"
        state["rules"] = [rule({"type": "domain_suffix", "values": [".пример.рф"], "action": "direct"}), rule({"type": "ip_cidr", "values": ["203.0.113.1"], "action": "proxy"})]
        config = compile_config(state, p, "/tmp", 999)
        r = config["route"]["rules"]
        self.assertLess(next(i for i,x in enumerate(r) if x.get("action") == "resolve"), next(i for i,x in enumerate(r) if x.get("ip_cidr") == ["203.0.113.1/32"]))
        self.assertEqual(r[-1], {"action": "reject"})
        self.assertEqual(config["dns"]["rules"][-1], {"action": "reject"})
        self.assertEqual(config["inbounds"][0]["exclude_uid"], [999])
        self.assertTrue(config["inbounds"][0]["strict_route"])
        self.assertLess(next(i for i,x in enumerate(r) if x.get("port") == [5353, 5355]), next(i for i,x in enumerate(r) if x.get("action") == "hijack-dns"))
        self.assertEqual(config["dns"]["servers"][2]["detour"], "proxy")
        self.assertEqual(text_list("example.com\n203.0.113.0/24")["rules"][1]["ip_cidr"], ["203.0.113.0/24"])
        original = copy.deepcopy(state["rules"])
        state["preset"] = "full"
        compile_config(state, p, "/tmp", 999)
        self.assertEqual(state["rules"], original)

    def test_custom_encrypted_dns_and_invalid_update_preserves_settings(self):
        for value in ("https://private.example/custom/token?device=abc", "tls://dns.example:8853", "https://[2606:4700:4700::1111]/dns-query"):
            self.assertEqual(resolver_url(value), value)
        self.assertEqual(resolver_url("dot://DNS.Example/"), "tls://dns.example")
        self.assertEqual(resolver_url("1.1.1.1"), "https://1.1.1.1/dns-query")
        for invalid in ("http://dns.example", "https://user:password@dns.example/dns-query", "tls://dns.example/query", "tls://dns.example?token=x", "https://dns.example:0/x", "https://dns.example/#secret", "https://dns example/", "https://dns.example:/x"):
            with self.subTest(invalid=invalid), self.assertRaises(UserError):
                resolver_url(invalid)
        with tempfile.TemporaryDirectory() as d:
            c = Controller(Store(d), MemoryRuntime(d))
            c.call("settings_save", {"settings": {"dns_proxy": "tls://dns.google", "dns_direct": "https://private.example/custom?key=abc", "dns_bootstrap": "1.1.1.1"}})
            before = copy.deepcopy(c.data)
            for key, value in (("dns_proxy", "http://unsafe.example"), ("dns_direct", "tls://dns.example:99999"), ("dns_bootstrap", "not-an-ip")):
                with self.assertRaises(UserError):
                    c.call("settings_save", {"settings": {key: value}})
                self.assertEqual(c.data, before)
            reopened = Store(d)
            self.assertEqual(reopened.data, before)
            del reopened.data["settings"]["dns_bootstrap"]
            reopened.save()
            self.assertEqual(Store(d).data["settings"]["dns_proxy"], "tls://dns.google")
            self.assertEqual(Store(d).data["settings"]["dns_bootstrap"], "9.9.9.9")

    def test_large_public_list_and_failed_list_update(self):
        from helmsman.routing import source_list
        source_list({"version": 3, "rules": [{"domain_suffix": ["example.com"] * 15000}]})
        with tempfile.TemporaryDirectory() as d:
            c = Controller(Store(d), MemoryRuntime(d))
            new = c.call("list_save", {"name": "test", "content": "example.com\n203.0.113.0/24", "format": "text"})
            item = next(x for x in c.data["lists"] if x["id"] == new["id"])
            old_path = item["path"]
            with self.assertRaises(UserError):
                c.call("list_save", {"id": item["id"], "name": "test", "content": "not a domain!", "format": "text"})
            self.assertEqual(next(x for x in c.data["lists"] if x["id"] == new["id"])["path"], old_path)
            self.assertEqual((Path(d) / "lists").stat().st_mode & 0o777, 0o750)
            self.assertEqual(Path(old_path).stat().st_mode & 0o777, 0o640)
            self.assertIn("example.com", c.call("list_content", {"id": item["id"]})["content"])

    def test_guard_no_physical_established_bypass(self):
        script = firewall_script(999, True)
        self.assertNotIn("ct state established", script)
        self.assertIn('oifname "helmsman0" accept', script)
        self.assertIn("meta skuid 999 accept", script)
        self.assertLess(script.index("th dport 53 reject"), script.index("ip daddr"))
        self.assertNotIn("flush ruleset", script)

    def test_boot_guard_recovers_damaged_state_conservatively(self):
        from helmsman.boot_guard import policy
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(policy(d), (False, False))
            (Path(d) / "guard.json").write_text('{"armed":true,"lan":true}')
            self.assertEqual(policy(d), (True, True))
            (Path(d) / "state.json").write_text("damaged")
            self.assertEqual(policy(d), (True, True))
            (Path(d) / "guard.json").write_text("damaged")
            self.assertEqual(policy(d), (True, False))

    def test_gui_rpc_and_decky_use_same_controller(self):
        with tempfile.TemporaryDirectory() as d:
            controller = Controller(Store(d), MemoryRuntime(d))
            path = str(Path(d) / "control.sock")
            try:
                server = Server(path, controller, os.getuid())
            except PermissionError:
                if os.environ.get("HELMSMAN_CI"):
                    raise
                self.skipTest("This sandbox forbids Unix sockets; required in GitHub CI")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            spec = importlib.util.spec_from_file_location("decky_backend", Path(__file__).parents[1] / "decky/main.py")
            decky = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(decky)
            decky.SOCKET = path
            try:
                imported = call("import", {"text": LINK}, path)
                status = decky.request_service("status", {})
                self.assertEqual(status["profiles"][0]["id"], imported["profiles"][0])
                decky.request_service("connect", {})
                self.assertTrue(call("status", path=path)["desired"])
                self.assertTrue(controller.runtime.guard)
                decky.request_service("disconnect", {})
                self.assertFalse(call("status", path=path)["desired"])
                self.assertFalse(controller.runtime.guard)
                with self.assertRaises(RuntimeError):
                    decky.request_service("configuration", {})
                private = call("configuration", path=path)
                self.assertNotIn(private["hwid"], json.dumps(decky.request_service("status", {})))
                denied = Server.__new__(Server)
                # Actual credential check: the same client UID is rejected when
                # the configured owner is different (root is intentionally admin).
                if os.getuid() != 0:
                    server.owner_uid = os.getuid() + 1
                    with self.assertRaises(UserError):
                        call("status", path=path)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


class EngineSchemaTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("HELMSMAN_ENGINES"), "set HELMSMAN_ENGINES to run real engine checks")
    def test_all_dns_presets_and_custom_endpoints_with_both_engines(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            state = defaults()
            for name in ("sing-box", "sing-box-awg"):
                for _, value in DNS_PRESETS + (("custom", "https://private.example:8443/dns/token?device=abc"), ("custom", "tls://dns.example:8853")):
                    state["settings"].update(dns_proxy=value, dns_direct=value)
                    config = compile_config(state, parse(LINK)[0], d, os.getuid())
                    direct, remote = config["dns"]["servers"][1:3]
                    self.assertNotIn("detour", direct)
                    self.assertEqual(remote["detour"], "proxy")
                    self.assertEqual(remote["domain_resolver"]["server"], "bootstrap")
                    self.assertNotIn("insecure", remote["tls"])
                    file = Path(d) / "dns-check.json"
                    file.write_text(json.dumps(config))
                    result = subprocess.run([str(Path(os.environ["HELMSMAN_ENGINES"]) / name), "check", "-c", str(file)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, name + " " + value + " " + result.stderr)

    @unittest.skipUnless(os.environ.get("HELMSMAN_ENGINES"), "set HELMSMAN_ENGINES to run real engine checks")
    def test_generated_configs_with_both_engines(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            engine_root = Path(os.environ["HELMSMAN_ENGINES"])
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "key"), "-out", str(root / "cert"), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "extendedKeyUsage=serverAuth"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cert = (root / "cert").read_text()
            ovpn = "client\ndev tun\nproto udp\nremote 127.0.0.1 1194\ncipher AES-256-GCM\nremote-cert-tls server\n<ca>\n" + cert + "</ca>\n"
            items = [parse(LINK)[0], parse(WG)[0], parse(WG.replace("Address=", "Jc=4\nJmin=40\nJmax=80\nS3=12\nH1=123-456\nAddress="))[0], parse(ovpn)[0], parse("hy2://test@127.0.0.1:443?sni=localhost")[0]]
            for p in items:
                name = "sing-box-awg" if p["outbound"].get("amnezia_wg") else "sing-box"
                binary = engine_root / name
                self.assertTrue(binary.is_file(), name)
                state = defaults()
                source = root / "mixed-list.json"
                source.write_text(json.dumps({"version": 3, "rules": [{"domain": ["exact.example"]}, {"domain_suffix": ["fixture.example"]}, {"ip_cidr": ["203.0.113.0/24"]}]}))
                state["lists"] = [{"id": "a" * 32, "path": str(source)}]
                state["rules"] = [rule({"type": "list", "values": ["a" * 32], "action": "proxy"})]
                config = compile_config(state, p, root, os.getuid())
                file = root / "check.json"
                file.write_text(json.dumps(config))
                result = subprocess.run([str(binary), "check", "-c", str(file)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, name + " " + p["outbound"]["type"] + " " + result.stderr)


if __name__ == "__main__":
    unittest.main()
