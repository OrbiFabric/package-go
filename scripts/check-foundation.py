#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check SDK dependency boundaries and optionally exact upstream git bytes.

This is foundation evidence only, not implementation conformance certification.
Run from anywhere with --spec-dir pointing at a local package-spec clone.
No fetch, network, package installation or repository mutation is performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--spec-dir', type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
lock = json.loads((root / 'internal/specassets/checksums.json').read_text())
authority = '7ff166365dc83cee783e4e6715225968c81ef7b9'
assert lock['authority'] == authority
snapshot = root / 'internal/specassets/data'
assert {p.relative_to(snapshot).as_posix() for p in snapshot.rglob('*.json')} == set(lock['sha256'])
for name, digest in lock['sha256'].items():
    data = (snapshot / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, name
    if args.spec_dir:
        upstream = subprocess.check_output(['git', '-C', str(args.spec_dir), 'show', authority + ':' + name])
        assert data == upstream, name
if args.spec_dir:
    names = subprocess.check_output(['git', '-C', str(args.spec_dir), 'ls-tree', '-r', '--name-only', authority], text=True).splitlines()
    areas = {'schemas', 'profiles', 'vocabularies', 'fixtures', 'vectors', 'conformance'}
    assert {n for n in names if n.split('/')[0] in areas and n.endswith('.json')} == set(lock['sha256'])
    print(f'Exact frozen git-tree machine assets: {len(lock["sha256"])} PASS')
else:
    print('Upstream git-tree comparison: NOT_RUN (--spec-dir required)')

raw = subprocess.check_output(['go', 'list', '-deps', '-json', './...'], cwd=root, text=True)
decoder = json.JSONDecoder()
packages = []
while raw.strip():
    item, end = decoder.raw_decode(raw.lstrip())
    packages.append(item)
    raw = raw.lstrip()[end:]
for item in packages:
    assert item.get('Standard') or item['ImportPath'].startswith('github.com/orbifabric/package-go'), item['ImportPath']
    if item['ImportPath'].startswith('github.com/orbifabric/package-go'):
        assert not any(n == 'net' or n.startswith(('net/', 'database/')) for n in item.get('Imports', [])), item['ImportPath']
print(f'Production dependency graph: {len(packages)} packages; no external/network/database runtime imports PASS')
