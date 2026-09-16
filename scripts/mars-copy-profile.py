#!/usr/bin/env python3
"""Decode bounded memcpy caller/alignment samples using the exact image ELF."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

spec = importlib.util.spec_from_file_location('pc_symbols', Path(__file__).with_name('mars-pc-sample.py'))
syms = importlib.util.module_from_spec(spec)
spec.loader.exec_module(syms)


def parse(text):
    headers = re.findall(r'NCOPY window=\((\d+), (\d+)\) hz=(\d+) interval=(\d+) min_bytes=(\d+) capacity=(\d+) units=timer_ticks', text)
    if len(headers) != 1 or text.count('NCOPY_END') != 1:
        raise ValueError('require one complete copy dump')
    start, end, hz, interval, minimum, capacity = map(int, headers[0])
    if not start < end or hz <= 0 or end-start > hz*5 or interval != 127 or minimum != 256 or capacity != 512:
        raise ValueError('invalid sampling configuration')
    harts = {}
    for h, eligible, dropped in re.findall(r'NCOPY_HART h=(\d+) eligible=(\d+) dropped=(\d+)', text):
        h = int(h)
        if h in harts or h not in range(4) or int(dropped):
            raise ValueError('duplicate hart or overflowing capture')
        harts[h] = dict(eligible=int(eligible), entries=[])
    if set(harts) != set(range(4)) or text.count('NCOPY_HART ') != 4:
        raise ValueError('incomplete hart headers')
    rows = re.findall(r'NCOPY_ENTRY h=(\d+) caller=(0x[0-9a-f]+) key=(\d+) calls=(\d+) bytes=(\d+) ticks=(\d+) max=(\d+)', text)
    if len(rows) != text.count('NCOPY_ENTRY '):
        raise ValueError('malformed entry')
    seen = set()
    for h, caller, key, calls, size, ticks, maximum in rows:
        h,key,calls,size,ticks,maximum = map(int,(h,key,calls,size,ticks,maximum))
        caller = int(caller,16)
        identity = (h,caller,key)
        if h not in harts or identity in seen or not caller or not 0 <= key < 512 or not calls or maximum > ticks:
            raise ValueError('invalid or duplicate copy entry')
        seen.add(identity)
        bin = key >> 6
        if size < (256 << bin)*calls or (bin < 7 and size >= (512 << bin)*calls):
            raise ValueError('copy byte count outside size bin')
        harts[h]['entries'].append(dict(caller=caller,src_mod8=key&7,dst_mod8=(key>>3)&7,
            size_bin=bin,calls=calls,bytes=size,ticks=ticks,max_ticks=maximum))
    for data in harts.values():
        if len(data['entries']) > capacity or sum(x['calls'] for x in data['entries']) != (data['eligible']+interval-1)//interval:
            raise ValueError('missing samples or inconsistent eligible count')
    return dict(start=start,end=end,hz=hz,interval=interval,min_bytes=minimum,harts=harts)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('log',type=Path)
    ap.add_argument('--elf',type=Path,required=True)
    ap.add_argument('--nm',required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    result=parse(args.log.read_text(errors='replace'))
    nm=subprocess.check_output([args.nm,'--numeric-sort','--print-size','--demangle','--defined-only',str(args.elf)],text=True)
    table=syms.symbols(nm)
    result['elf_sha256']=hashlib.sha256(args.elf.read_bytes()).hexdigest()
    result['log_sha256']=hashlib.sha256(args.log.read_bytes()).hexdigest()
    result['symbol_aliases']={f'{a:#x}':sorted(names) for (a,size),names in syms.symbol_groups(nm).items() if len(names)>1}
    result['limitations']=[
        'Only external memcpy calls of at least 256 bytes; inline copies and memmove are excluded.',
        'One in 127 eligible calls per hart; deterministic sampling can alias traffic patterns.',
        'Elapsed timer ticks include interrupt work and timer-read overhead, not CPU instruction cycles.',
        'A copy admitted before expiry may finish beyond it; freeze waits for the admitted writer.',
        'The wrapper changes code layout and adds overhead; compare throughput with the same image unarmed.',
        'Do not multiply sample times into exact CPU shares; bins may include unlike lengths and alignment.',
        'Copied payload is never inspected; only low address bits and return addresses are recorded.',
    ]
    for data in result['harts'].values():
        groups={}
        for e in data['entries']:
            # RA points after the call, possibly at the end of a symbol.
            e['symbol']=syms.symbolize(table,e['caller']-1)
            g=groups.setdefault(e['caller'],dict(caller=f"{e['caller']:#x}",symbol=e['symbol'],calls=0,bytes=0,ticks=0))
            for field in ('calls','bytes','ticks'):g[field]+=e[field]
        data['callers']=sorted(groups.values(),key=lambda g:g['ticks'],reverse=True)
        for g in data['callers']:
            g['ns_per_byte']=g['ticks']*1e9/result['hz']/g['bytes']
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    for hart,data in result['harts'].items():
        print('hart',hart,'eligible',data['eligible'])
        for g in data['callers'][:8]:print(g)

if __name__=='__main__':main()
