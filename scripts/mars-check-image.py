#!/usr/bin/env python3
"""Validate the Mars ELF load contract. Passing does not imply hardware boot."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

LOAD = 0x40200000
RAM_END = 0x140000000

def inspect(data):
    def unpack(fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(data):
            raise ValueError('truncated ELF structure')
        return struct.unpack_from(fmt, data, offset)
    h = unpack('<16sHHIQQQIHHHHHH', 0)
    if h[0][:7] != b'\x7fELF\x02\x01\x01' or h[1:4] != (2, 243, 1):
        raise ValueError('expected little-endian ELF64 RISC-V executable')
    if h[4] != LOAD or h[8:10] != (64, 56) or h[11] != 64 or not (0 < h[10] < 0xffff and h[12] > 0):
        raise ValueError('unsupported entry or ELF table format')
    loads = []
    for i in range(h[10]):
        kind, flags, offset, virtual, physical, filesz, memsz, align = unpack('<IIQQQQQQ', h[5] + i * h[9])
        if kind != 1:
            continue
        if not memsz or filesz > memsz or offset + filesz > len(data) or virtual != physical:
            raise ValueError('invalid load span')
        if physical < LOAD or physical + memsz > RAM_END or (flags & 3) == 3:
            raise ValueError('load span enters firmware RAM or violates W^X')
        if align != 4096 or (offset - physical) % align:
            raise ValueError('load alignment mismatch')
        loads.append({'address': physical, 'file_bytes': filesz, 'memory_bytes': memsz, 'flags': flags})
    loads.sort(key=lambda p: p['address'])
    if not loads or loads[0]['address'] != LOAD or not loads[0]['flags'] & 1:
        raise ValueError('entry is not executable')
    if any(a['address'] + a['memory_bytes'] > b['address'] for a, b in zip(loads, loads[1:])):
        raise ValueError('overlapping loads')
    sections = [unpack('<IIQQQQIIQQ', h[6] + i * h[11]) for i in range(h[12])]
    symbols = {}
    for section in sections:
        if section[1] != 2:
            continue
        if section[9] != 24 or section[5] % 24 or section[6] >= len(sections):
            raise ValueError('invalid symbol table')
        strings = sections[section[6]]
        if strings[1] != 3 or strings[4] + strings[5] > len(data):
            raise ValueError('invalid string table')
        table = data[strings[4]:strings[4] + strings[5]]
        for offset in range(section[4], section[4] + section[5], 24):
            name, info, _, shndx, value, _ = unpack('<IBBHQQ', offset)
            if name >= len(table):
                raise ValueError('symbol name outside table')
            end = table.find(b'\0', name)
            if end < 0:
                raise ValueError('unterminated symbol name')
            label = table[name:end].decode('utf-8', errors='replace')
            if shndx and label and info >> 4 in (1, 2):
                if label in symbols and symbols[label] != value:
                    raise ValueError('ambiguous symbol')
                symbols[label] = value
    required = ['_start', '__heap_start', '__heap_end', '__stacks_bottom', '__stacks_top',
                '__stack_guard_size', '__kernel_stack_stride', '__bss_start', '__bss_end']
    if any(name not in symbols for name in required):
        raise ValueError('missing boot symbols (use an ELF with its symbol table)')
    heap = symbols['__heap_start']
    if symbols['_start'] != LOAD or symbols['__heap_end'] != RAM_END or not LOAD < heap < RAM_END or heap % 4096:
        raise ValueError('heap or entry differs from Mars 4 GiB contract')
    bottom, top = symbols['__stacks_bottom'], symbols['__stacks_top']
    if symbols['__stack_guard_size'] != 4096 or symbols['__kernel_stack_stride'] != 256 * 1024 or top - bottom != 4 * 256 * 1024 or top != heap or bottom % 4096:
        raise ValueError('four guarded boot stacks are not reserved')
    if max(p['address'] + p['memory_bytes'] for p in loads) > bottom:
        raise ValueError('load overlaps boot stacks')
    bss = (symbols['__bss_start'], symbols['__bss_end'])
    if not any(p['flags'] & 2 and p['address'] <= bss[0] < bss[1] <= p['address'] + p['memory_bytes'] for p in loads):
        raise ValueError('BSS is not in writable loaded RAM')
    return {'status': 'elf-contract-passed', 'entry': LOAD, 'heap_start': heap, 'heap_end': RAM_END,
            'elf_sha256': hashlib.sha256(data).hexdigest(), 'loads': loads,
            'physical_acceptance': False, 'flashable_sd_image': False}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        result = inspect(args.elf.read_bytes())
    except (ValueError, OSError) as error:
        parser.exit(1, f'MARS_IMAGE FAIL: {error}\n')
    payload = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(payload)
    print(payload, end='')
