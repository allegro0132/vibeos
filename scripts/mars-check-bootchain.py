#!/usr/bin/env python3
"""Inspect paired boot firmware and FIT payloads using the build container tools."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib


def require(ok, message):
    if not ok:
        raise ValueError(message)


def check(out):
    artifacts = out / "artifacts"
    spl = (artifacts / "u-boot-spl.bin.normal.out").read_bytes()
    require(len(spl) >= 1024, "short SPL header")
    require(struct.unpack_from("<II", spl) == (0x240, 0x200000), "SPL offsets")
    version, size, offset, crc = struct.unpack_from("<IIII", spl, 644)
    require(version == 0x01010101 and offset == 0x400 and 0 < size <= 180048,
            "SPL version/size/offset")
    require(len(spl) == offset + size and zlib.crc32(spl[offset:]) == crc, "SPL CRC")
    require(spl[offset:] == (out / "uboot/spl/u-boot-spl.bin").read_bytes(), "SPL source mismatch")
    payload = (artifacts / "fw_payload.bin").read_bytes()
    uboot = (out / "uboot/u-boot.bin").read_bytes()
    require(payload[0x200000:0x200000 + len(uboot)] == uboot, "OpenSBI U-Boot payload offset")
    tail = payload[0x200000 + len(uboot):]
    require(len(tail) < 16 and not any(tail), "OpenSBI payload alignment padding")
    config = (artifacts / "uboot.config").read_text().splitlines()
    for setting in ['CONFIG_ENV_IS_NOWHERE=y', 'CONFIG_RISCV_SMODE=y',
                    'CONFIG_SPL_SMP=y', 'CONFIG_BOOTM_LINUX=y', 'CONFIG_SPL_LOAD_FIT=y',
                    'CONFIG_SYS_MMCSD_RAW_MODE_U_BOOT_PARTITION=0x2',
                    'CONFIG_BOOTCOMMAND="mmc dev 1; if load mmc 1:3 0x46000000 vibeos.itb; then bootm 0x46000000; fi"']:
        require(setting in config, "missing U-Boot setting: " + setting)
    require('CONFIG_SMP=y' not in config and 'CONFIG_ENV_IS_IN_SPI_FLASH=y' not in config,
            "U-Boot must leave secondary harts stopped and avoid SPI environment")
    sbi_config = (artifacts / "opensbi.config").read_text().splitlines()
    symbols = subprocess.check_output(['riscv64-linux-gnu-nm', str(out / 'opensbi/platform/generic/firmware/fw_payload.elf')], text=True)
    for ext in ['TIME', 'IPI', 'RFENCE', 'HSM']:
        require('CONFIG_SBI_ECALL_' + ext + '=y' in sbi_config, "SBI extension disabled: " + ext)
        require(' ecall_' + ext.lower() + '\n' in symbols, "SBI extension absent from ELF: " + ext)

    def prop(fit, node, name, kind='s'):
        return subprocess.check_output(['fdtget', '-t', kind, str(artifacts / fit), node, name], text=True).strip()

    for fit, node, load, os_name in [('firmware.itb', 'firmware', '0 40000000', 'u-boot'),
                                    ('vibeos.itb', 'kernel', '0 40200000', 'linux')]:
        path = '/images/' + node
        for name, expected, kind in [('load', load, 'x'), ('entry', load, 'x'),
                                      ('arch', 'riscv', 's'), ('os', os_name, 's'),
                                      ('compression', 'none', 's')]:
            require(prop(fit, path, name, kind) == expected, 'FIT handoff: ' + name)
    require(prop('vibeos.itb', '/configurations', 'default') == 'mars-4gb', 'FIT configuration')
    require(prop('vibeos.itb', '/configurations/mars-4gb', 'kernel') == 'kernel', 'FIT kernel reference')
    require(prop('vibeos.itb', '/configurations/mars-4gb', 'fdt') == 'fdt', 'FIT DTB reference')
    with tempfile.TemporaryDirectory() as temp:
        for fit, index, node, source in [('firmware.itb', 0, 'firmware', 'fw_payload.bin'),
                                         ('vibeos.itb', 0, 'kernel', 'vibeos.bin'),
                                         ('vibeos.itb', 1, 'fdt', 'mars.dtb')]:
            extracted = Path(temp) / 'payload'
            subprocess.run(['dumpimage', '-T', 'flat_dt', '-p', str(index), '-o', str(extracted),
                            str(artifacts / fit)], check=True, stdout=subprocess.DEVNULL)
            data = extracted.read_bytes()
            require(data == (artifacts / source).read_bytes(), 'FIT embedded bytes: ' + source)
            path = '/images/' + node + '/hash-1'
            require(prop(fit, path, 'algo') == 'sha256', 'FIT hash algorithm')
            digest = bytes(int(x, 16) for x in prop(fit, path, 'value', 'bx').split())
            require(digest == hashlib.sha256(data).digest(), 'FIT hash: ' + source)
    return {'status': 'bootchain-contract-passed', 'opensbi': '1.2', 'uboot': '2021.10',
            'sbi_extensions_built': ['TIME', 'IPI', 'RFENCE', 'HSM'],
            'spi_environment': False, 'physical_acceptance': False,
            'checked_sha256': {name: hashlib.sha256((artifacts / name).read_bytes()).hexdigest()
                               for name in ['u-boot-spl.bin.normal.out', 'fw_payload.bin',
                                            'uboot.config', 'opensbi.config', 'firmware.itb',
                                            'vibeos.itb', 'vibeos.bin', 'mars.dtb']}}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out', type=Path)
    args = parser.parse_args()
    result = check(args.out)
    text = json.dumps(result, indent=2) + '\n'
    (args.out / 'bootchain-check.json').write_text(text)
    print(text, end='')
