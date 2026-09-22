#!/usr/bin/env python3
"""Host contract checks with mock bridges; not V8/QEMU acceptance."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent

def main():
    with tempfile.TemporaryDirectory(prefix='vibeos-native-libc-') as directory:
        work = Path(directory)
        # macOS has no newlib malloc.h. Declare only the injected allocator.
        (work / 'malloc.h').write_text(
            '#include <stddef.h>\nextern "C" void *memalign(size_t, size_t);\n')
        subprocess.run(['c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-I' + str(work), '-I' + str(ROOT / 'tools/node-runtime/platform'),
            '-D_READ_WRITE_RETURN_TYPE=ssize_t', '-D_exit=vibeos_test_exit',
            '-Dposix_memalign=vibeos_test_posix_memalign',
            '-Dmemalign=vibeos_test_memalign', '-c',
            str(ROOT / 'tools/node-runtime/platform/platform-vibeos-libc.cc'),
            '-o', str(work / 'libc.o')], check=True)
        subprocess.run(['c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            str(ROOT / 'tools/node-runtime/tests/native-libc-test.cc'),
            str(work / 'libc.o'), '-o', str(work / 'test')], check=True)
        subprocess.run([str(work / 'test')], check=True)
    print('PASS: native libc host contracts (mock bridges; target acceptance NOT_RUN)')

if __name__ == '__main__':
    main()
