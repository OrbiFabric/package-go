#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate NFC data from an explicit local Unicode 16.0.0 UCD directory.
No network access. Upstream data URLs/checksums are recorded with output.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('ucd_dir', type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1] / 'internal/unicode16'
source = args.ucd_dir
expected_sha256 = {'UnicodeData.txt': 'ff58e5823bd095166564a006e47d111130813dcf8bf234ef79fa51a870edb48f', 'DerivedNormalizationProps.txt': '4d4c03892dea9146d674b686e495df2d55a28d071ac474041d73518f887abddc', 'NormalizationTest.txt': 'd811971453e7075e1ad56fb1b301eece5aa80757b81f6156e74a1bfb3ae5ceb1'}
expected_sha256['CaseFolding.txt'] = '6f1f9c588eb4a5c718d9e8f93b782685e5c7fec872cf05e8e6878053599e09bb'
for name, digest in expected_sha256.items():
    assert hashlib.sha256((source / name).read_bytes()).hexdigest() == digest, name
assert (source / 'DerivedNormalizationProps.txt').read_text().startswith('# DerivedNormalizationProps-16.0.0.txt')
assert (source / 'NormalizationTest.txt').read_text().startswith('# NormalizationTest-16.0.0.txt')
ccc, decomp, excluded = {}, {}, set()
for line in (source / 'UnicodeData.txt').read_text().splitlines():
    row = line.split(';')
    cp = int(row[0], 16)
    if int(row[3]):
        ccc[cp] = int(row[3])
    if row[5] and not row[5].startswith('<'):
        decomp[cp] = [int(n, 16) for n in row[5].split()]
for line in (source / 'DerivedNormalizationProps.txt').read_text().splitlines():
    line = line.split('#')[0].strip()
    if not line:
        continue
    fields = [n.strip() for n in line.split(';')]
    if fields[1] == 'Full_Composition_Exclusion':
        bounds = fields[0].split('..')
        excluded.update(range(int(bounds[0], 16), int(bounds[-1], 16) + 1))
pairs = {f'{pair[0]},{pair[1]}': cp for cp, pair in decomp.items() if len(pair) == 2 and cp not in excluded}
assert (source / 'CaseFolding.txt').read_text().startswith('# CaseFolding-16.0.0.txt')
fold = {}
for line in (source / 'CaseFolding.txt').read_text().splitlines():
    fields = [n.strip() for n in line.split('#')[0].split(';')]
    if len(fields) >= 3 and fields[1] in {'C', 'F'}:
        fold[int(fields[0], 16)] = [int(n, 16) for n in fields[2].split()]
data = {'version': '16.0.0', 'ccc': ccc, 'decomp': decomp, 'compose': pairs, 'fold': fold}
(root / 'tables.json').write_text(json.dumps(data, sort_keys=True, separators=(',', ':')) + '\n')
norm = (source / 'NormalizationTest.txt').read_bytes()
(root / 'testdata/NormalizationTest.txt.gz').write_bytes(gzip.compress(norm, mtime=0))
(root / 'testdata/CaseFolding.txt.gz').write_bytes(gzip.compress((source / 'CaseFolding.txt').read_bytes(), mtime=0))
(root / 'UNICODE-LICENSE').write_bytes((source / 'LICENSE').read_bytes())
lock = {'version': '16.0.0', 'source_base': 'https://www.unicode.org/Public/16.0.0/ucd/',
        'source_sha256': {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                          for name in ['UnicodeData.txt', 'DerivedNormalizationProps.txt', 'NormalizationTest.txt', 'CaseFolding.txt']},
        'tables_sha256': hashlib.sha256((root / 'tables.json').read_bytes()).hexdigest()}
(root / 'source-lock.json').write_text(json.dumps(lock, indent=2) + '\n')
print(f'Unicode 16.0.0 NFC: {len(ccc)} combining classes, {len(decomp)} canonical decompositions, {len(pairs)} composition pairs, {len(fold)} C/F case folds')
