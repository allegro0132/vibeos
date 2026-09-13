#!/usr/bin/env python3
"""Validate the universal PIE, relocations and per-board static memory budget."""
import argparse
import hashlib
import json
import struct
from pathlib import Path


def inspect(data):
    def unpack(fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(data):
            raise ValueError('truncated ELF structure')
        return struct.unpack_from(fmt, data, offset)

    h = unpack('<16sHHIQQQIHHHHHH', 0)
    if h[0][:7] != b'\x7fELF\x02\x01\x01' or h[1:4] != (3, 243, 1):
        raise ValueError('expected little-endian RISC-V ELF64 PIE')
    if h[4] != 0 or h[8:10] != (64, 56) or h[11] != 64 or not (0 < h[10] < 65535 and 0 < h[12] < 65535):
        raise ValueError('entry must be zero; unsupported ELF tables')
    loads = []
    for i in range(h[10]):
        kind, flags, offset, address, physical, filesz, memsz, align = unpack('<IIQQQQQQ', h[5] + i * h[9])
        if kind == 3:
            raise ValueError('dynamic interpreter is forbidden')
        if kind != 1:
            continue
        if not memsz or filesz > memsz or offset + filesz > len(data) or address != physical:
            raise ValueError('invalid load segment')
        if flags & 3 == 3 or align != 4096 or (offset - address) % align:
            raise ValueError('W^X or segment alignment violation')
        loads.append(dict(address=address, offset=offset, file_bytes=filesz, memory_bytes=memsz, flags=flags))
    loads.sort(key=lambda p: p['address'])
    if not loads or loads[0]['address'] != 0 or not loads[0]['flags'] & 1:
        raise ValueError('entry is not executable')
    if any(a['address'] + a['memory_bytes'] > b['address'] for a, b in zip(loads, loads[1:])):
        raise ValueError('overlapping load segments')
    sections = [unpack('<IIQQQQIIQQ', h[6] + i * h[11]) for i in range(h[12])]
    symbols = {}
    for section in sections:
        if section[1] != 2:
            continue
        if section[9] != 24 or section[5] % 24 or section[6] >= len(sections):
            raise ValueError('invalid symbol table')
        strings = sections[section[6]]
        if strings[1] != 3 or strings[4] + strings[5] > len(data):
            raise ValueError('invalid symbol strings')
        table = data[strings[4]:strings[4] + strings[5]]
        for offset in range(section[4], section[4] + section[5], 24):
            name, info, _, shndx, value, size = unpack('<IBBHQQ', offset)
            if name >= len(table) or table.find(b'\0', name) < 0:
                raise ValueError('invalid symbol name')
            label = table[name:table.find(b'\0', name)].decode('utf-8', errors='strict')
            if shndx:
                symbols[label] = value
            elif name and info >> 4 != 2:
                raise ValueError(f'unresolved symbol: {label}')
    names = ['_start', '__text_end', '__rodata_start', '__rodata_end', '__rela_start', '__rela_end',
             '__image_file_end', '__image_mem_end', '__bss_start', '__bss_end', '__heap_start']
    if any(name not in symbols for name in names):
        raise ValueError('missing boot layout symbols')
    file_end, mem_end = symbols['__image_file_end'], symbols['__image_mem_end']
    if not 0 < symbols['__text_end'] <= symbols['__rodata_start'] < symbols['__rodata_end'] <= file_end <= symbols['__bss_start'] <= symbols['__bss_end'] <= mem_end:
        raise ValueError('invalid static memory layout')
    if symbols['_start'] != 0 or symbols['__heap_start'] != mem_end or mem_end % 4096:
        raise ValueError('invalid entry or heap boundary')
    if max(p['address'] + p['file_bytes'] for p in loads if p['file_bytes']) != file_end:
        raise ValueError('unexpected initialized data beyond raw image')
    if any(p['address'] + p['memory_bytes'] > mem_end for p in loads):
        raise ValueError('load segment outside static memory')
    relocations = []
    for section in sections:
        if section[1] in (4, 9) and section[2] & 2:
            if section[1] != 4 or section[9] != 24 or section[5] % 24:
                raise ValueError('only ELF64 RELA relocations are supported')
            if section[3] != symbols['__rela_start'] or section[3] + section[5] != symbols['__rela_end']:
                raise ValueError('relocation table is outside boot stub bounds')
            for offset in range(section[4], section[4] + section[5], 24):
                target, kind, addend = unpack('<QQq', offset)
                if kind != 3:
                    raise ValueError('only symbol-free R_RISCV_RELATIVE is supported')
                if target % 8 or not symbols['__text_end'] <= target <= file_end - 8 or not 0 <= addend <= mem_end:
                    raise ValueError('relocation target/addend outside permitted image region')
                if not any(p['address'] <= target and target + 8 <= p['address'] + p['file_bytes'] and not p['flags'] & 1 for p in loads):
                    raise ValueError('relocation writes executable or uninitialized memory')
                relocations.append(target)
    if not relocations or len(set(relocations)) != len(relocations) or len(relocations) * 24 != symbols['__rela_end'] - symbols['__rela_start']:
        raise ValueError('empty, duplicate or incomplete relocation table')
    return dict(file_bytes=file_end, static_bytes=mem_end, relocations=len(relocations), loads=loads,
                symbols={name: symbols[name] for name in names})


def verify_raw(data, raw, layout):
    if len(raw) != layout['file_bytes']:
        raise ValueError('raw image size does not match ELF')
    expected = bytearray(len(raw))
    for p in layout['loads']:
        if p['file_bytes']:
            expected[p['address']:p['address'] + p['file_bytes']] = data[p['offset']:p['offset'] + p['file_bytes']]
    if expected != raw:
        raise ValueError('raw image bytes do not match ELF load segments')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', required=True, type=Path)
    parser.add_argument('--image', required=True, type=Path)
    parser.add_argument('--board', action='append', choices=['qemu-virt', 'milkv-duo', 'milkv-mars'], required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    data, raw = args.elf.read_bytes(), args.image.read_bytes()
    layout = inspect(data)
    verify_raw(data, raw, layout)
    budgets = {}
    for board in args.board:
        load, end = {'qemu-virt': (0x80200000, 0x88000000), 'milkv-duo': (0x80200000, 0x83e00000), 'milkv-mars': (0x40200000, 0x140000000)}[board]
        # Root + one 4-KiB leaf table per 2-MiB RAM span, plus bounded MMIO tables.
        tables = (((end - load + 0x1fffff) // 0x200000) + 16) * 4096
        heap = end - load - layout['static_bytes'] - tables
        if heap < 8 * 1024 * 1024:
            raise ValueError(f'{board}: less than 8 MiB heap after static image and page tables')
        if board == 'milkv-duo' and len(raw) > 0x1200000:
            raise ValueError('Duo image overlaps FIT source')
        budgets[board] = dict(load_address=load, ram_end=end, static_bytes=layout['static_bytes'], page_tables_budget=tables, heap_budget=heap)
    result = dict(schema=1, elf_sha256=hashlib.sha256(data).hexdigest(), sha256=hashlib.sha256(raw).hexdigest(),
                  layout=layout, boards=budgets, physical_acceptance=False)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(f"PIE verified: {len(raw)} file bytes, {layout['static_bytes']} static bytes, {layout['relocations']} relative relocations")


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit(f'universal-image: {error}')
