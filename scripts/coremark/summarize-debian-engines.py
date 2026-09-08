#!/usr/bin/env python3
"""Validate all Debian engine samples and retain raw timing/CRC evidence."""
import argparse
import hashlib
import json
import re
import statistics
from pathlib import Path


def parse(path, validation=False):
    text = path.read_text()
    def field(label):
        match = re.search(r'^' + re.escape(label) + r'\s*:\s*(\S+)', text, re.M)
        assert match, (path, label)
        return match[1]
    expected = ('0x18f2', '0xe3c1', '0x0747', '0x8d84') if validation else ('0xe9f5', '0xe714', '0x1fd7', '0x8e3a')
    for key, value in zip(('seedcrc', '[0]crclist', '[0]crcmatrix', '[0]crcstate'), expected):
        assert field(key) == value, (path, key)
    seconds = float(field('Total time (secs)'))
    assert seconds >= 10 and 'Correct operation validated' in text and 'Errors detected' not in text, path
    result = dict(seconds=seconds, iterations=int(field('Iterations')), score=float(field('Iterations/Sec')))
    stderr = path.with_suffix('.stderr').read_text()
    for key, pattern in [('setup_seconds', r'setup_seconds=([0-9.]+)'), ('execution_seconds', r'(?:execution_seconds| seconds)=([0-9.]+)'), ('rss_kib', r'Maximum resident set size \(kbytes\): (\d+)'), ('polls', r'polls=(\d+)')]:
        match = re.search(pattern, stderr)
        if match:
            result[key] = float(match[1])
    assert 'Exit status: 0' in stderr, path
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('results', type=Path)
    args = p.parse_args()
    modes = {}
    for mode in ('native', 'wasmi', 'wasmtime', 'wasmtime-fuel'):
        samples = [parse(args.results/f'{mode}-performance-{i}.stdout') for i in range(1, 4)]
        modes[mode] = dict(samples=samples, median=statistics.median(x['score'] for x in samples), validation=parse(args.results/f'{mode}-validation.stdout', True))
    baseline = modes['native']['median']
    for value in modes.values():
        value['native_slowdown'] = baseline / value['median']
    record = dict(modes=modes, sources={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(args.results.glob('*.stdout'))})
    (args.results/'engine-results.json').write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps({k: {f:v[f] for f in ('median', 'native_slowdown')} for k,v in modes.items()}, indent=2))

if __name__ == '__main__':
    main()
