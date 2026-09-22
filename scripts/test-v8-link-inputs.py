#!/usr/bin/env python3
"""Verify link-input evidence covers thin members, not just archive indexes."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent

def main():
    spec = importlib.util.spec_from_file_location('checker', ROOT / 'scripts/check-v8-firmware-link.py')
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    ar = ROOT / 'target/node-runtime/toolchain/xpack-riscv-none-elf-gcc-14.2.0-3/bin/riscv-none-elf-ar'
    with tempfile.TemporaryDirectory(prefix='vibeos-link-inputs-') as directory:
        work = Path(directory)
        member = work / 'member.o'
        member.write_bytes(b'original member bytes')
        thin, normal = work / 'thin.a', work / 'normal.a'
        subprocess.run([str(ar), 'crT', str(thin), str(member)], check=True)
        subprocess.run([str(ar), 'cr', str(normal), str(member)], check=True)
        before = checker.archive_inputs([thin], ar)
        index = checker.digest(thin)
        member.write_bytes(b'changed member bytes')
        assert checker.digest(thin) == index
        assert checker.archive_inputs([thin], ar) != before
        assert len(before) == 2
        assert len(checker.archive_inputs([normal], ar)) == 1
        member.unlink()
        try:
            checker.archive_inputs([thin], ar)
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass
        else:
            raise AssertionError('missing thin member accepted')
    print('PASS: member mutation detected with unchanged thin index; regular archive self-contained; missing member rejected')

if __name__ == '__main__':
    main()
