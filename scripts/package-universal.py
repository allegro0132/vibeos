#!/usr/bin/env python3
"""Package the same verified raw kernel in a board-specific U-Boot FIT."""
import argparse
import hashlib
import json
import lzma
import shutil
import subprocess
import tempfile
from pathlib import Path
from universal_artifacts import load_manifest


def prepare(manifest_path, board, dtb, output, mkimage, prepare_only):
    manifest, image = load_manifest(manifest_path, board)
    if output.exists():
        raise ValueError(f'output already exists: {output}; choose a fresh package directory')
    output.parent.mkdir(parents=True, exist_ok=True)
    compatible = subprocess.check_output(['fdtget', '-t', 's', str(dtb), '/', 'compatible'], text=True).split()
    valid = (board == 'milkv-duo' and any(c in compatible for c in ['milk-v,duo', 'cvitek,cv1800b', 'cvitek,cv180x'])) or (
        board == 'milkv-mars' and {'milk-v,mars', 'starfive,jh7110'} <= set(compatible))
    if not valid:
        raise ValueError('DTB root compatible does not match the requested board')
    raw = image.read_bytes()
    load = 0x80200000 if board == 'milkv-duo' else 0x40200000
    with tempfile.TemporaryDirectory(prefix='.vibeos-package-', dir=output.parent) as tmp:
        stage = Path(tmp)
        shutil.copyfile(image, stage / 'vibeos.bin')
        shutil.copyfile(dtb, stage / 'board.dtb')
        # Preserve vendor resources; add only an explicit admission marker.
        subprocess.run(['fdtput', '-t', 's', str(stage / 'board.dtb'), '/', 'vibeos,board-id', board], check=True)
        if board == 'milkv-duo':
            packed = lzma.compress(raw, format=lzma.FORMAT_ALONE, filters=[{'id': lzma.FILTER_LZMA1, 'preset': 6, 'dict_size': 1024 * 1024}])
            if lzma.decompress(packed, format=lzma.FORMAT_ALONE) != raw or len(raw) > 0x1200000:
                raise ValueError('Duo decompression/load contract failed')
            (stage / 'vibeos.bin.lzma').write_bytes(packed)
            source, compression, fit = 'vibeos.bin.lzma', 'lzma', 'boot.sd'
        else:
            source, compression, fit = 'vibeos.bin', 'none', 'vibeos.itb'
        its = f'''/dts-v1/;
/ {{
    description = "VibeOS universal / {board}";
    #address-cells = <2>;
    images {{
        kernel {{
            data = /incbin/("{source}");
            type = "kernel"; arch = "riscv"; os = "linux";
            compression = "{compression}";
            load = <0x0 0x{load:x}>; entry = <0x0 0x{load:x}>;
            hash {{ algo = "sha256"; }};
        }};
        fdt {{
            data = /incbin/("board.dtb");
            type = "flat_dt"; arch = "riscv"; compression = "none";
            hash {{ algo = "sha256"; }};
        }};
    }};
    configurations {{
        default = "vibeos";
        vibeos {{ kernel = "kernel"; fdt = "fdt"; }};
    }};
}};
'''
        (stage / 'image.its').write_text(its, encoding='ascii')
        if not prepare_only:
            subprocess.run([mkimage, '-f', 'image.its', fit], cwd=stage, check=True)
            subprocess.run([mkimage, '-l', fit], cwd=stage, check=True)
            if board == 'milkv-duo' and (stage / fit).stat().st_size > 7 * 1024 * 1024:
                raise ValueError('Duo FIT exceeds the 7 MiB bootloader load window')
        record = dict(schema=1, board=board, configuration=manifest['configuration'], kernel_sha256=manifest['sha256'],
                      original_dtb_sha256=hashlib.sha256(dtb.read_bytes()).hexdigest(),
                      files={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in stage.iterdir() if p.is_file()},
                      load_address=load, fit=fit if not prepare_only else None, physical_acceptance=False)
        (stage / 'package.json').write_text(json.dumps(record, indent=2) + '\n', encoding='ascii')
        shutil.copytree(stage, output)
    if hashlib.sha256((output / 'vibeos.bin').read_bytes()).hexdigest() != manifest['sha256']:
        raise ValueError('packaging changed raw kernel bytes')
    print(f'Prepared {output}; unchanged kernel SHA-256 {manifest["sha256"]}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--board', choices=['milkv-duo', 'milkv-mars'], required=True)
    parser.add_argument('--dtb', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mkimage', default='mkimage')
    parser.add_argument('--prepare-only', action='store_true', help='write raw kernel, DTB and ITS without invoking mkimage')
    args = parser.parse_args()
    prepare(args.manifest, args.board, args.dtb, args.output.resolve(), args.mkimage, args.prepare_only)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'package-universal: {error}')
