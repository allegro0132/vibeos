#!/usr/bin/env python3
"""Audit saved Mars soak evidence without opening serial or sending traffic."""
import argparse
import importlib.util
import json
from pathlib import Path
import re


def audit(root):
    terminal = (root / 'summary.json').exists()
    state = json.loads((root / ('summary.json' if terminal else 'live.json')).read_text())
    rows = state.get('results', [])
    problems = []
    checked = []
    previous_after = None
    spec = importlib.util.spec_from_file_location('residency', Path(__file__).with_name('mars-cpu-residency.py'))
    residency = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(residency)
    expected = state.get('requested_rounds')
    if expected != 60 or state.get('seconds_per_round') != 60:
        problems.append('unexpected soak duration contract')
    for index, row in enumerate(rows, 1):
        prefix = f'{index:02}'
        if row.get('round') != index:
            problems.append(f'{prefix}: missing or duplicate round identity')
        data = json.loads((root / (prefix + '-iperf.json')).read_text())
        rx = data.get('end', {}).get('sum_received', {})
        if data.get('error') or rx.get('seconds', 0) < 59:
            problems.append(f'{prefix}: incomplete client transfer')
        if rx.get('bits_per_second', 0) <= 900e6:
            problems.append(f'{prefix}: receive throughput below 900 Mbps')
        if rx != row.get('received'):
            problems.append(f'{prefix}: summary differs from raw receiver result')
        before = (root / (prefix + '-before.log')).read_text()
        after = (root / (prefix + '-after.log')).read_text()
        if previous_after is not None:
            try:
                residency.compare(previous_after, before)
            except ValueError as error:
                problems.append(f'{prefix}: CPU continuity between rounds failed: {error}')
        cpu = residency.compare(before, after)
        previous_after = after
        cores = sum(h['active_percent'] for h in cpu['harts']) / 100
        if len(cpu['harts']) != 4 or abs(cores - row.get('resident_cores', -1)) > 1e-8:
            problems.append(f'{prefix}: CPU summary differs from four-hart snapshots')
        if any(h['seconds'] < rx.get('seconds', 0) - .01 or h['seconds'] > rx.get('seconds', 0) + 10 for h in cpu['harts']):
            problems.append(f'{prefix}: CPU window does not cover the transfer duration')
        pool = {k: int(v) for k, v in re.findall(
            r'(received|acquired|released|full|dropped|free|ready|borrowed): (\d+)',
            (root / (prefix + '-pool.log')).read_text())}
        if len(pool) != 8 or pool != row.get('pool'):
            problems.append(f'{prefix}: pool summary differs from raw snapshot')
        if index > 1 and (not isinstance(row.get('gap_seconds'), (int, float)) or row['gap_seconds'] < 0):
            problems.append(f'{prefix}: missing connection-gap measurement')
        checked.append({'round': index, 'mbps': rx.get('bits_per_second', 0) / 1e6,
                        'resident_cores': cores, 'gap_seconds': row.get('gap_seconds'),
                        'pool_quiescent': pool.get('acquired') == pool.get('released') and
                            pool.get('free') == 128 and pool.get('ready') == 0 and pool.get('borrowed') == 0,
                        'full': pool.get('full'), 'dropped': pool.get('dropped')})
    complete = terminal and state.get('passed') is True and state.get('phase') == 'complete'
    if terminal and not complete:
        problems.append('runner terminated without passing: ' + str(state.get('error')))
    if complete:
        if len(rows) != expected:
            problems.append('terminal success lacks all requested rounds')
        integrity = json.loads((root / 'integrity.json').read_text())
        if not (integrity.get('passed') is True and integrity.get('phase') == 'complete'
                and integrity.get('requested_bytes') == 67108864
                and integrity.get('confirmed_bytes') == 67108864):
            problems.append('missing complete 64 MiB post-soak integrity result')
        final_pool = {k: int(v) for k, v in re.findall(
            r'(acquired|released|free|ready|borrowed): (\d+)', (root / 'pool-final.log').read_text())}
        if not (len(final_pool) == 5 and final_pool['acquired'] == final_pool['released']
                and final_pool['free'] == 128 and final_pool['ready'] == 0 and final_pool['borrowed'] == 0):
            problems.append('post-soak pool has not returned all loans')
        starts = []
        for name in ['bootlog-before.log', 'bootlog-after.log']:
            text = (root / name).read_text()
            match = re.search(r'entry_ticks=(\d+) now_ticks=(\d+)', text)
            if not match or 'BOOTLOG_END' not in text:
                problems.append('incomplete boot continuity evidence: ' + name)
            else:
                starts.append(tuple(map(int, match.groups())))
        if len(starts) == 2 and (starts[0][0] != starts[1][0] or starts[1][1] <= starts[0][1]):
            problems.append('boot timestamps do not establish continuity')
    return {'status': 'failed' if problems else ('passed' if complete else 'collecting'),
            'completed_rounds': len(rows), 'required_rounds': expected,
            'problems': problems, 'rounds': checked,
            'scope': 'Sequential 60-second RX connections; not continuous single-connection, storage/WASM, cold-boot or sub-one-core qualification.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = audit(args.directory)
    output = json.dumps(result, indent=2) + '\n'
    if args.output:
        with args.output.open('x') as handle:
            handle.write(output)
    print(output, end='')
    return 1 if result['status'] == 'failed' else 0


if __name__ == '__main__':
    raise SystemExit(main())
