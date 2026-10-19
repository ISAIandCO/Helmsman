#!/usr/bin/env python3
"""Opt-in live source/native checks; never changes host routes or starts VPN."""
import argparse
import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from helmsman.common import defaults
from helmsman.importers import parse
from helmsman.regions import BUILTIN_LISTS, PRESETS
from helmsman.routing import compile_config, source_list
from helmsman.subscriptions import download

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('engines', type=Path)
parser.add_argument('--lists', type=Path, help='use previously downloaded TAG.srs files')
args = parser.parse_args()
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    state = defaults()
    for tag, (_, url) in BUILTIN_LISTS.items():
        path = root / (tag + '.srs')
        path.write_bytes((args.lists / path.name).read_bytes() if args.lists else download(url))
        source = path.with_suffix('.json')
        subprocess.run([args.engines / 'sing-box', 'rule-set', 'decompile', path, '-o', source], check=True, capture_output=True)
        obj = source_list(json.loads(source.read_text()))
        source.write_text(json.dumps(obj))
        state['lists'].append({'id': tag, 'path': str(source)})
        print('PASS source', tag, ','.join(sorted(set().union(*(set(r) for r in obj['rules'])))), flush=True)
    profiles = [parse('vless://00000000-0000-0000-0000-000000000001@127.0.0.1:443?security=none')[0],
                parse('vless://00000000-0000-0000-0000-000000000001@127.0.0.1:443?security=none&type=xhttp')[0],
                {'id': 'wg', 'name': 'WG', 'kind': 'sing-box', 'outbound': {'type': 'wireguard', 'private_key': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'address': ['10.0.0.2/32'], 'peers': [{'public_key': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'address': '127.0.0.1', 'port': 51820, 'allowed_ips': ['0.0.0.0/0']}]}}]
    awg = copy.deepcopy(profiles[-1]); awg['outbound']['amnezia_wg'] = {'jc': 4, 'jmin': 40, 'jmax': 80}; profiles.append(awg)
    count = 0
    for preset in PRESETS:
        state['preset'] = preset
        for profile in profiles:
            for lan in (True, False):
                state['settings']['lan'] = lan
                config = compile_config(state, profile, root, 999, xray_proxy=(13080, 'test'))
                target = root / 'config.json'; target.write_text(json.dumps(config))
                engine = 'sing-box-awg' if profile['outbound'].get('amnezia_wg') else 'sing-box'
                result = subprocess.run([args.engines / engine, 'check', '-c', target], capture_output=True, text=True)
                if result.returncode:
                    raise RuntimeError(preset + ': ' + result.stderr)
                count += 1
        print('PASS preset', preset, flush=True)
    print('PASS', count, 'native configurations, all regional sources; no host network mutations')
