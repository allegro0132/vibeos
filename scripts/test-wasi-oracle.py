#!/usr/bin/env python3
"""Compare genuine standard-library fixtures with the pinned Wasmtime 48.0.0 CLI."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--wasmtime', required=True)
a = p.parse_args()
version = subprocess.check_output([a.wasmtime, '--version'], text=True).strip()
assert version.startswith('wasmtime 48.0.0 '), version
root = Path(__file__).resolve().parent.parent
records = []
for lang in ['rust', 'c']:
    module = root / f'target/wasi-examples/{lang}-hello.wasm'
    for args, data, out, err, status in [
        ([], b'', f'Hello from {"Rust" if lang == "rust" else "C"} WASI!\n'.encode(), b'', 0),
        (['args', 'a b', '中文'], b'', 'a b\n中文\n'.encode(), b'', 0),
        (['filter'], b'ab\0c\n', b'AB\0C\n', b'', 0),
        (['stderr'], b'', b'out\n', b'err\n', 0),
        (['exit'], b'', b'', b'', 7),
    ]:
        result = subprocess.run([a.wasmtime, 'run', '-C', 'cache=n', str(module), *args], input=data, capture_output=True, timeout=30)
        assert (result.stdout, result.stderr, result.returncode) == (out, err, status), (lang, args, result)
        records.append({'language': lang, 'arguments': args, 'exit': status, 'sha256': hashlib.sha256(module.read_bytes()).hexdigest()})
(root / 'target/wasi-examples/wasmtime-oracle.json').write_text(json.dumps({'version': version, 'cases': records}, indent=2) + '\n')
print('PASS Wasmtime 48.0.0: 10 Rust/C standard-library cases')
