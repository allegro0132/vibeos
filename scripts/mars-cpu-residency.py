#!/usr/bin/env python3
"""Compare two nidle snapshots; report WFI-interval CPU residency."""
import argparse
import json
from pathlib import Path
import re

MOD = 1 << 64


def parse(text):
    headers = re.findall(r'^NIDLE hz=(\d+) harts=(\d+) units=timer_ticks source=wfi_interval\r?$', text, re.M)
    if len(headers) != 1 or int(headers[0][0]) == 0 or text.count('NIDLE_END') != 1:
        raise ValueError('missing/duplicate/incomplete NIDLE snapshot')
    if not 1 <= int(headers[0][1]) <= 256 or int(headers[0][0]) >= MOD:
        raise ValueError('invalid hart count or clock')
    if 'NIDLE_UNAVAILABLE' in text:
        raise ValueError('snapshot unavailable; never interpret this as idle')
    rows = {}
    for h, active, since, now, idle, sleeps in re.findall(
            r'^NIDLE_HART h=(\d+) active=(true|false) since=(\d+) now=(\d+) idle=(\d+) sleeps=(\d+)\r?$', text, re.M):
        h = int(h)
        if h in rows:
            raise ValueError('duplicate hart')
        values = [int(v) for v in (since, now, idle, sleeps)]
        if any(v >= MOD for v in values):
            raise ValueError('counter exceeds u64')
        rows[h] = dict(zip(('since', 'now', 'idle', 'sleeps'), values), active=active == 'true')
    if not rows or set(rows) != set(range(int(headers[0][1]))):
        raise ValueError('missing hart samples')
    if len(re.findall(r'^NIDLE_HART ', text, re.M)) != len(rows):
        raise ValueError('malformed hart sample')
    return int(headers[0][0]), rows


def compare(before, after):
    hz, first = parse(before)
    next_hz, last = parse(after)
    if hz != next_hz or first.keys() != last.keys():
        raise ValueError('clock or hart set changed')
    result = []
    for h, a in first.items():
        b = last[h]
        if a['active'] != b['active'] or a['since'] != b['since']:
            raise ValueError('hart lifecycle changed')
        if not a['active']:
            continue
        elapsed = (b['now'] - a['now']) % MOD
        idle = (b['idle'] - a['idle']) % MOD
        if not 0 < elapsed < MOD // 2 or idle > elapsed:
            raise ValueError('invalid duration/residency or counter reset')
        result.append(dict(hart=h, seconds=elapsed / hz, idle_seconds=idle / hz,
                           active_seconds=(elapsed - idle) / hz,
                           active_percent=100 * (elapsed - idle) / elapsed,
                           sleeps=(b['sleeps'] - a['sleeps']) % MOD))
    if not result:
        raise ValueError('no active harts')
    return dict(hz=hz, harts=result,
                total_active_core_seconds=sum(v['active_seconds'] for v in result),
                limitations=['WFI interval proxy includes bounded entry/exit bookkeeping.',
                             'Interrupt handlers and MMIO stalls count as active.',
                             'Each hart snapshot has its own timestamp; the interval includes command overhead.',
                             'This does not measure CPU cycles or electrical sleep residency.'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('before', type=Path)
    p.add_argument('after', type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    data = compare(args.before.read_text(), args.after.read_text())
    with args.output.open('x') as out:
        out.write(json.dumps(data, indent=2) + '\n')
    print(json.dumps(data, indent=2))


if __name__ == '__main__':
    main()
