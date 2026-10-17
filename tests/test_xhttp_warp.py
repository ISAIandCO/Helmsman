"""Import contracts, WARP account reuse and genuine Xray schema validation."""
import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

from helmsman.common import Store, UserError, defaults
from helmsman.daemon import Controller
from helmsman.importers import parse
from helmsman.routing import compile_config
from helmsman.warp import generate
from helmsman.xray import compile_xray, is_xhttp
from test_core import MemoryRuntime, WG, LINK

ENGINES = os.environ.get("HELMSMAN_ENGINES")
XHTTP = LINK.replace("security=none", "security=none&type=xhttp&path=%2Fhelmsman&mode=packet-up")


class XhttpWarpTests(unittest.TestCase):
    def test_xhttp_uri_native_json_and_policy_isolation(self):
        extra = {"xPaddingBytes": "100-200", "xmux": {"maxConcurrency": "8-16"}, "downloadSettings": {"address": "down.example", "port": 443, "network": "xhttp", "security": "tls", "tlsSettings": {"serverName": "down.example"}, "xhttpSettings": {"path": "/down"}}}
        p = parse(XHTTP.replace("#One", "&" + urlencode({"extra": json.dumps(extra)}) + "#XHTTP"))[0]
        self.assertTrue(is_xhttp(p))
        x = compile_xray(p, (1234, "secret"))
        self.assertEqual(x["outbounds"][0]["streamSettings"]["xhttpSettings"]["extra"], extra)
        # Native Xray configuration imports connection data, never its policy.
        x["outbounds"][0]["streamSettings"].pop("sockopt")
        native = {"outbounds": x["outbounds"], "routing": {"domainStrategy": "AsIs"}, "inbounds": [{"listen": "0.0.0.0", "port": 9999}]}
        imported = parse(json.dumps(native))[0]
        self.assertEqual(imported["outbound"], p["outbound"])
        c = compile_config(defaults(), p, "/tmp/test", 1234, xray_proxy=(1234, "secret"))
        proxy = next(o for o in c["outbounds"] if o["tag"] == "proxy")
        self.assertEqual(proxy["type"], "socks")
        self.assertEqual(proxy["password"], "secret")
        self.assertTrue(compile_xray(p)["outbounds"][0]["streamSettings"]["sockopt"]["penetrate"])
        self.assertEqual(c["route"]["final"], "proxy")
        self.assertEqual(c["inbounds"][0]["type"], "tun")
        # Download transport cannot smuggle root files, interfaces or services.
        for bad in ({"downloadSettings": {"sockopt": {"interface": "eth0"}}}, {"downloadSettings": {"tlsSettings": {"keyLog": "/etc/shadow"}}}, {"unknown": 1}):
            with self.subTest(bad=bad), self.assertRaises(UserError):
                parse(XHTTP.replace("#One", "&" + urlencode({"extra": json.dumps(bad)})))

    def test_xhttp_reality_and_modes(self):
        for mode in ("auto", "packet-up", "stream-up", "stream-one"):
            p = parse(XHTTP.replace("packet-up", mode).replace("security=none", "security=reality&pbk=" + "A" * 43 + "&sid=1234&sni=example.com&spx=%2F"))[0]
            s = compile_xray(p)["outbounds"][0]["streamSettings"]
            self.assertEqual(s["xhttpSettings"]["mode"], mode)
            self.assertEqual(s["realitySettings"]["spiderX"], "/")
            self.assertEqual(s["security"], "reality")

    def test_warpgen_comments_and_obfuscation_preserved(self):
        # Synthetic keys and signature; private uploaded configuration is never
        # committed. Covers its actual leading comments and parameter shape.
        conf = "\ufeff\n# Export comment\n########\n" + WG.replace("Address=", "S1=0\nS2=0\nJc=4\nJmin=40\nJmax=70\nH1=1\nH2=2\nH3=3\nH4=4\nI1=<b 0xc200000001><r 20>\nAddress=")
        p = parse(conf)[0]
        awg = p["outbound"]["amnezia_wg"]
        self.assertEqual(awg["h4"], "4")
        self.assertEqual(awg["i1"], "<b 0xc200000001><r 20>")
        self.assertEqual(awg["jc"], 4)
        self.assertEqual(awg["s1"], 0)

    def test_warp_reserved_conf_and_json(self):
        for reserved in ("[1,2,255]", "1, 2, 255", "AQL/"):
            p = parse(WG.replace("[Peer]", "Reserved=" + reserved + "\n[Peer]"))[0]
            self.assertEqual(p["outbound"]["peers"][0]["reserved"], [1, 2, 255])
        for reserved in ("[1,2]", "[1,2,256]", "[true,2,3]"):
            with self.assertRaises(UserError):
                parse(WG.replace("[Peer]", "Reserved=" + reserved + "\n[Peer]"))
        x = {"protocol": "wireguard", "settings": {"secretKey": "A" * 43 + "=", "address": ["172.16.0.2/32"], "peers": [{"publicKey": "A" * 43 + "=", "endpoint": "[2606:4700:d0::a29f:c001]:2408"}], "reserved": [1, 2, 3], "mtu": 1280}}
        p = parse(json.dumps(x))[0]
        self.assertEqual(p["outbound"]["peers"][0]["reserved"], [1, 2, 3])
        self.assertEqual(p["outbound"]["peers"][0]["allowed_ips"], ["0.0.0.0/0", "::/0"])
        old = {"type": "wireguard", "server": "127.0.0.1", "server_port": 2408, "local_address": ["172.16.0.2/32"], "private_key": "A" * 43 + "=", "peer_public_key": "A" * 43 + "=", "reserved": "AQID"}
        self.assertEqual(parse(json.dumps(old))[0]["outbound"]["peers"][0]["reserved"], [1, 2, 3])

    def test_warp_generator_account_reuse_failure_and_consent(self):
        with tempfile.TemporaryDirectory() as root:
            binary = Path(root) / "wgcf"
            binary.write_text("fixture")
            binary.chmod(0o700)
            commands = []
            def invoke(args, **kwargs):
                commands.append(args)
                self.assertIs(kwargs["stdout"], subprocess.DEVNULL)
                self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
                if "register" in args:
                    Path(args[2]).write_text('access_token="secret"')
                if "generate" in args:
                    Path(args[args.index("--profile") + 1]).write_text(WG)
                return subprocess.CompletedProcess(args, 0)
            with patch("helmsman.warp.subprocess.run", side_effect=invoke):
                with self.assertRaises(UserError):
                    generate(root, root, False)
                self.assertEqual(commands, [])
                p = generate(root, root, True, endpoint="[::1]:2408")
                self.assertIn("amnezia_wg", p["outbound"])
                self.assertNotIn("dns", p)
                self.assertGreater(len(p["outbound"]["amnezia_wg"]["i1"]), 1000)
                self.assertEqual(p["outbound"]["peers"][0]["address"], "::1")
                generate(root, root, True, mode="wireguard")
            self.assertEqual(sum("register" in c for c in commands), 1)
            account = Path(root) / "warp/account.toml"
            self.assertEqual(account.stat().st_mode & 0o777, 0o600)
            store = Store(Path(root) / "state")
            controller = Controller(store, MemoryRuntime(root))
            before = copy.deepcopy(store.data)
            with patch("helmsman.warp.subprocess.run", return_value=subprocess.CompletedProcess([], 1)):
                with self.assertRaises(UserError) as error:
                    controller.call("warp_generate", {"accept_terms": True})
            self.assertNotIn("secret", str(error.exception))
            self.assertEqual(before, store.data)
            self.assertEqual(account.read_text(), 'access_token="secret"')
            # Both UIs call one API; repeated generation does not duplicate a
            # profile, change active intent or overwrite user routing/settings.
            with patch("helmsman.daemon.generate_warp", return_value=p):
                first = controller.call("warp_generate", {"accept_terms": True})
                again = controller.call("warp_generate", {"accept_terms": True})
            self.assertEqual(first["id"], again["id"])
            self.assertEqual(len(store.data["profiles"]), 1)
            self.assertFalse(store.data["desired"])
            self.assertEqual(Store(store.directory).data["profiles"], store.data["profiles"])

    @unittest.skipUnless(ENGINES, "set HELMSMAN_ENGINES for actual Xray checks")
    def test_native_xray_schema_all_modes_and_reality(self):
        with tempfile.TemporaryDirectory() as root:
            for mode in ("auto", "packet-up", "stream-up", "stream-one"):
                for security in ("none", "tls&sni=example.com&alpn=h2", "reality&pbk=" + "A" * 43 + "&sid=1234&sni=example.com"):
                    p = parse(XHTTP.replace("packet-up", mode).replace("security=none", "security=" + security))[0]
                    path = Path(root) / "test.json"
                    path.write_text(json.dumps(compile_xray(p)))
                    result = subprocess.run([str(Path(ENGINES) / "xray"), "run", "-test", "-config", str(path)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
