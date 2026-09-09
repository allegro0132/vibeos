#!/usr/bin/env python3
"""Prepare/check the Wasmtime FIT for the pinned CV1800B SDK boot layout."""
import argparse
import lzma
from pathlib import Path

LOAD = 0x81400000
# SDK U-Boot relocates at 0x82435000 and reserves 0x840000 for malloc,
# then board/global data, DTB and a descending stack below 0x81bf5000.
# Leave almost 1 MiB below that boundary; the advertised 15 MiB UIMAG_SIZE
# is not a safe FAT read limit for this relocated U-Boot configuration.
FIT_LIMIT = 7 * 1024 * 1024
ENTRY = 0x80200000


def check_layout(kernel_bytes, fit_bytes):
    if not 0 < kernel_bytes <= LOAD - ENTRY:
        raise ValueError("decompressed kernel overlaps its FIT source at 0x81400000")
    if not 0 < fit_bytes <= FIT_LIMIT:
        raise ValueError("FIT exceeds 7 MiB safe load window below U-Boot stack")


def prepare(directory, template):
    raw = (directory / "vibeos-milkv-duo.bin").read_bytes()
    check_layout(len(raw), 1)
    packed = lzma.compress(raw, format=lzma.FORMAT_ALONE,
                           filters=[{"id": lzma.FILTER_LZMA1, "preset": 6,
                                     "dict_size": 1024 * 1024}])
    # Keep the encoder's standard LZMA-alone end-marker/unknown-size form.
    # U-Boot bounds this by CONFIG_SYS_BOOTM_LEN; the verifier separately
    # bounds decoding by the expected kernel size.
    assert lzma.decompress(packed, format=lzma.FORMAT_ALONE) == raw
    check_layout(len(raw), len(packed))
    its = template.read_text()
    source = 'data = /incbin/("vibeos-milkv-duo.bin");'
    assert its.count(source) == 1
    its = its.replace(source, 'data = /incbin/("vibeos-milkv-duo.bin.lzma");')
    its = its.replace('compression = "none";', 'compression = "lzma";', 1)
    (directory / "vibeos-milkv-duo.bin.lzma").write_bytes(packed)
    (directory / "milkv-duo.its").write_text(its)
    print(f"LZMA kernel: {len(raw)} -> {len(packed)} bytes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["prepare", "check"])
    parser.add_argument("directory", type=Path)
    parser.add_argument("--fit", type=Path)
    args = parser.parse_args()
    if args.mode == "prepare":
        prepare(args.directory, Path(__file__).with_name("milkv-duo.its"))
    else:
        fit = args.fit or args.directory / "boot.sd"
        size = fit.stat().st_size
        check_layout((args.directory / "vibeos-milkv-duo.bin").stat().st_size, size)
        print(f"FIT load window OK: {LOAD:#x}..{LOAD + size:#x}; limit {LOAD + FIT_LIMIT:#x}")


if __name__ == "__main__":
    main()
