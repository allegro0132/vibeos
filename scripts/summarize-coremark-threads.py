#!/usr/bin/env python3
"""Verify retained evidence and compare matched CoreMark pthread runs."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import statistics

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs', nargs='+', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('measure', ROOT/'scripts/benchmark-coremark-threads.py')
    measure = importlib.util.module_from_spec(spec); spec.loader.exec_module(measure)
    matched = None
    report = []
    for work in args.runs:
        env = json.loads((work/'environment.json').read_text())
        config = (env['module_sha256'], env['configuration'], env['qemu'])
        if matched is None: matched = config
        assert matched == config, f'unmatched Wasm/QEMU configuration: {work}'
        rows = json.loads((work/'results.json').read_text())
        assert len(rows) == (env['samples']+1)*len(env['workers'])
        expected = {f'{sample}-m{n}' for sample in [f'performance-{i+1}' for i in range(env['samples'])]+['validation'] for n in env['workers']}
        assert {r['name'] for r in rows} == expected, 'missing or duplicate samples'
        for row in rows:
            text = (work/f"{row['name']}.stdout").read_text()
            verified = measure.parse(text, row['workers'])
            assert all(row[key] == value for key, value in verified.items())
            validation = row['name'].startswith('validation')
            crcs = ['0x18f2', '0xe3c1', '0x0747', '0x8d84'] if validation else ['0xe9f5', '0xe714', '0x1fd7', '0x8e3a']
            assert re.search(r'^seedcrc\s*:\s*'+crcs[0]+r'\s*$', text, re.M)
            for index in range(row['workers']):
                for label, crc in zip(['crclist', 'crcmatrix', 'crcstate'], crcs[1:]):
                    assert re.search(r'^\['+str(index)+r'\]'+label+r'\s*:\s*'+crc+r'\s*$', text, re.M)
            if env['platform'] == 'vibeos':
                assert json.loads((work/f"{row['name']}.request.json").read_text())['exit'] == 0
        if env['platform'] == 'vibeos':
            boot = (work/'boot.log').read_text()
            assert 'reclaimed=false' not in boot
            # Every measured run, every calibration attempt and the optional
            # capacity probe is one invocation with a clean lifecycle line.
            calibrations = len(list(work.glob('calibration-m*.stdout')))
            assert calibrations >= len(env['workers'])
            assert boot.count('reclaimed=true caps=0 waiters=0') == len(rows)+calibrations+int(env.get('capacity_probe', False))
            profiles = json.loads((work/'thread-profiles.json').read_text())
            by_name = {r['name']:r for r in profiles}
            for row in rows:
                profile = by_name[row['name']]
                assert profile['spawned'] == row['workers']
                assert int(profile['harts_used'], 16).bit_count() == min(row['workers'], env['configuration']['harts'])
        medians = {n:statistics.median(r['score'] for r in rows if r['workers']==n and r['name'].startswith('performance')) for n in env['workers']}
        summary = []
        for n, score in medians.items():
            values = [r['score'] for r in rows if r['workers']==n and r['name'].startswith('performance')]
            summary.append(dict(workers=n, median_score=score, min_score=min(values), max_score=max(values),
                speedup=score/medians[1], parallel_efficiency=score/medians[1]/n))
        report.append(dict(work=str(work), platform=env['platform'], runner=env.get('runner', 'vibeos-wasmtime'), fuel=env.get('fuel', 'VibeOS async 10000-fuel quanta'),
            revision=env['revision'], kernel_sha256=env.get('kernel_sha256'),
            runner_sha256=env.get('wasmtime_sha256'), features=env.get('features'),
            native_sha256=measure.digest(work/'coremark-native') if env.get('runner') == 'native-pthreads' else None,
            configuration=env['configuration'], module_sha256=env['module_sha256'], samples=env['samples'], summary=summary))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__': main()
