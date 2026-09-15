#!/usr/bin/env python3
"""Analyze a complete, deferred NPROF serial dump. Units are timer ticks."""
import argparse
import json
from pathlib import Path
import re

STAGES = ['executor', 'driver', 'stack', 'application', 'other', 'rx', 'tx', 'frontend']

EXTENDED_STAGES = STAGES + ['packet_queue', 'completion', 'packet_build', 'protocol_poll']

RX_STAGES = EXTENDED_STAGES + ['rx_loan', 'rx_gro', 'tx_reserve', 'tx_flush']

def arrays(line):
    return {key: json.loads(value) for key, value in
            re.findall(r'(ticks|wait|calls|high|full|dma)=(\[[^\]]*\])', line)}


def analyze(text):
    header = re.search(r'NPROF window=\((\d+), (\d+), (\d+)\)', text)
    if not header or 'NPROF_END' not in text:
        raise ValueError('missing complete NPROF header/end marker')
    start, end, width = map(int, header.groups())
    names = re.search(r'NPROF window=[^\n]* stages=(\[[^\]]*\])', text)
    stages = json.loads(names[1]) if names else STAGES
    if stages not in (STAGES, EXTENDED_STAGES, RX_STAGES):
        raise ValueError('unsupported stage schema')
    sampling = re.search(r'NPROF_SAMPLING stages=(\[[^\]]*\]) interval=(\d+)', text)
    if text.count('NPROF_SAMPLING') != (1 if sampling else 0):
        raise ValueError('invalid or duplicate sampling metadata')
    sampled_stages, interval = (json.loads(sampling[1]), int(sampling[2])) if sampling else ([], 1)
    if sampling and (sampled_stages != RX_STAGES[-4:] or stages != RX_STAGES or interval != 64):
        raise ValueError('unsupported sampling schema')
    count = len(stages)
    if not (width > 0 and end > start):
        raise ValueError('invalid measurement interval')
    expected = min(600, (end-start+width-1)//width)
    buckets, harts = {}, {}
    for line in text.splitlines():
        match = re.search(r'NPROF i=(\d+) ', line)
        hart = re.search(r'NPROF_HART h=(\d+) ', line)
        if not match and not hart:
            continue
        index = int((match or hart)[1])
        values = arrays(line)
        required = {'ticks': count, 'wait': count, 'calls': count}
        if match:
            required.update(high=2, full=2, dma=3)
        for name, length in required.items():
            if len(values.get(name, [])) != length or any(
                    not isinstance(n, int) or n < 0 for n in values[name]):
                raise ValueError(f'invalid {name} in row {index}')
        target = buckets if match else harts
        if index in target:
            raise ValueError('duplicate row')
        target[index] = values
    if set(buckets) != set(range(expected)) or not harts:
        raise ValueError('missing buckets or hart summaries')
    work = [sum(b['ticks'][i] for b in buckets.values()) for i in range(count)]
    wait = [sum(b['wait'][i] for b in buckets.values()) for i in range(count)]
    for key, total in [('ticks', work), ('wait', wait)]:
        if total != [sum(h[key][i] for h in harts.values()) for i in range(count)]:
            raise ValueError('hart and timeline totals disagree; capture may not be quiescent')
    locks = []
    names = dict(re.findall(r'NPROF_LOCK_NAME address=(0x[0-9a-f]+) name=(\S+)', text))
    identities = set()
    for match in re.finditer(r'NPROF_LOCK h=(\d+) address=(0x[0-9a-f]+) ([^\r\n]+)', text):
        h, address, fields = match.groups()
        values = arrays(fields)
        key = (int(h), address)
        if key in identities or int(h) not in harts:
            raise ValueError('duplicate or unknown lock hart/address')
        identities.add(key)
        for name in ['wait', 'calls']:
            if len(values.get(name, [])) != count or any(type(n) is not int or n < 0 for n in values[name]):
                raise ValueError('invalid lock counters')
        locks.append(dict(hart=int(h), address=address, name=names.get(address), **values))
    if locks:
        for h, totals in harts.items():
            if totals['wait'] != [sum(r['wait'][i] for r in locks if r['hart'] == h) for i in range(count)]:
                raise ValueError('lock identities and hart wait totals disagree')
    active = sum(work) + sum(wait)
    phases = {name: dict(exclusive_ticks=work[i], contended_wait_ticks=wait[i],
                        percent_active_work=100*work[i]/max(1, active),
                        percent_active_wait=100*wait[i]/max(1, active))
              for i, name in enumerate(stages)}
    queues = {}
    for i, name in enumerate(['inbound', 'outbound']):
        queues[name] = dict(high_water=max(b['high'][i] for b in buckets.values()),
            full_attempts=sum(b['full'][i] for b in buckets.values()),
            full_buckets=[j for j, b in buckets.items() if b['full'][i]])
    dma = [dict(bucket=i, ticks=start+i*width, observations=b['dma'][0],
                status=b['dma'][1], mtl=b['dma'][2])
           for i, b in buckets.items() if b['dma'][0]]
    return dict(start=start, end=end, width=width, stages=stages, phases=phases, harts=harts,
                sampling=dict(stages=sampled_stages, interval=interval),
                queues=queues, dma_observations=dma, buckets=buckets, locks=locks,
                limitations=['Sampled child stages contain only selected calls; unsampled work remains in parents. Do not scale timeline totals.',
                    'Elapsed 4 MHz timer ticks on Mars, not CPU cycles.',
                    'Work includes interrupts, MMIO polling, and instrumentation overhead.',
                    'Only contended core SpinLock acquisition time is classified as wait.',
                    'Unrecorded scopes skipped by fault unwind are folded into their task.',
                    'Scopes crossing a bucket edge are charged to their completion bucket.',
                    'Full counts are retry attempts, not distinct dropped packets.',
                    'DMA observations are approximately once per second; omitted buckets are unknown.'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('log', type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    result = analyze(args.log.read_text(errors='replace'))
    with args.output.open('x') as output:
        json.dump(result, output, indent=2)
        output.write('\n')


if __name__ == '__main__':
    main()
