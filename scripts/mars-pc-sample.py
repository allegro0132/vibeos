#!/usr/bin/env python3
"""Symbolize bounded NPC timer samples with the exact RAM image ELF.

These are timer interrupt delivery locations, not unbiased CPU-cycle shares.
Interrupt-masked sections and deterministic sampling can distort the histogram.
"""
import argparse
import bisect
import collections
import hashlib
import json
from pathlib import Path
import re
import subprocess


def parse(text):
    headers = re.findall(r'NPC window=\((\d+), (\d+), (\d+)\) hz=(\d+)', text)
    if len(headers) != 1 or text.count('NPC_END') != 1:
        raise ValueError('require one complete dump')
    start, end, period, hz = map(int, headers[0])
    if not start < end or period <= 0 or hz <= 0:
        raise ValueError('invalid capture window')
    harts = {}
    for h, count, dropped in re.findall(r'NPC_HART h=(\d+) count=(\d+) dropped=(\d+)', text):
        h = int(h)
        if h in harts or not 0 <= h < 4:
            raise ValueError('duplicate/invalid hart')
        harts[h] = dict(count=int(count), dropped=int(dropped), samples=[])
    if text.count('NPC_HART ') != len(harts) or set(harts) != set(range(4)):
        raise ValueError('missing hart header')
    rows = re.findall(r'NPC_SAMPLE h=(\d+) i=(\d+) time=(\d+) due=(\d+) pc=(0x[0-9a-f]+) ra=(0x[0-9a-f]+)', text)
    if text.count('NPC_SAMPLE ') != len(rows):
        raise ValueError('malformed sample')
    for h, i, time, due, pc, ra in rows:
        h, i, time, due = map(int, (h, i, time, due))
        if h not in harts or i != len(harts[h]['samples']) or not start <= due <= time < end:
            raise ValueError('sample order or window invalid')
        samples = harts[h]['samples']
        if samples and due != samples[-1]['time'] + period:
            raise ValueError('sample deadline discontinuity')
        samples.append(dict(time=time, due=due, pc=int(pc, 16), ra=int(ra, 16)))
    if any(len(h['samples']) != h['count'] or h['dropped'] for h in harts.values()):
        raise ValueError('incomplete or overflowing capture')
    return dict(start=start, end=end, period=period, hz=hz, harts=harts)


def symbol_groups(nm_output):
    groups = collections.defaultdict(set)
    for line in nm_output.splitlines():
        m = re.match(r'^([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+[tT]\s+(.+)$', line)
        if m:
            addr, size, name = m.groups()
            if int(size, 16):
                groups[(int(addr, 16), int(size, 16))].add(name)
    if not groups:
        raise ValueError('ELF contains no sized text symbols')
    return groups


def symbols(nm_output):
    return sorted((addr, size, next(iter(names)) if len(names) == 1 else f'shared@{addr:#x} ({len(names)} aliases)')
                  for (addr, size), names in symbol_groups(nm_output).items())


def symbolize(table, address):
    index = bisect.bisect_right(table, (address, float('inf'), '')) - 1
    if index >= 0:
        base, size, name = table[index]
        if base <= address < base + size:
            return name
    return '<unmapped>'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('log', type=Path)
    ap.add_argument('--elf', type=Path, required=True)
    ap.add_argument('--nm', required=True, help='llvm-nm path')
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    capture = parse(args.log.read_text(errors='replace'))
    nm_output = subprocess.check_output([args.nm, '--numeric-sort', '--print-size', '--demangle', '--defined-only', str(args.elf)], text=True)
    table = symbols(nm_output)
    result = dict(elf=str(args.elf), elf_sha256=hashlib.sha256(args.elf.read_bytes()).hexdigest(),
                  log_sha256=hashlib.sha256(args.log.read_bytes()).hexdigest(),
                  window={k: capture[k] for k in ('start', 'end', 'period', 'hz')},
                  limitations=['IRQ-masked execution is underrepresented; delivery can land at irq_restore.',
                               'RA is the interrupted register, not a call stack or reliable caller.',
                               'Periodic sampling can alias work; percentages are sample shares, not CPU-cycle shares.',
                               'The collector adds timer interrupts during this window only.',
                               'Code folding shares bodies; available aliases are retained, but the representative generic type can be misleading.'],
                  symbol_aliases={f'{addr:#x}': sorted(names) for (addr, size), names in symbol_groups(nm_output).items() if len(names) > 1}, harts={})
    for h, data in capture['harts'].items():
        rows = data['samples']
        lateness = sorted((r['time'] - r['due']) * 1e6 / capture['hz'] for r in rows)
        hist = {}
        for field in ('pc', 'ra'):
            counts = collections.Counter(symbolize(table, r[field]) for r in rows)
            hist[field] = [dict(symbol=s, count=n, sample_percent=100*n/len(rows)) for s, n in counts.most_common()]
        result['harts'][h] = dict(count=len(rows), dropped=data['dropped'],
            lateness_us={str(p): lateness[min(len(lateness)-1, int((len(lateness)-1)*p/100))] if lateness else None for p in (50, 90, 99, 100)},
            first_time=rows[0]['time'] if rows else None, last_time=rows[-1]['time'] if rows else None, **hist)
    with args.output.open('x') as f:
        json.dump(result, f, indent=2)
    for h, data in result['harts'].items():
        print('hart', h, 'samples', data['count'], 'lateness_us', data['lateness_us'])
        for entry in data['pc'][:8]:
            print('  %.1f%% %s' % (entry['sample_percent'], entry['symbol']))


if __name__ == '__main__':
    main()
