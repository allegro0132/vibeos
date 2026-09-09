#!/usr/bin/env python3
"""Compare ported Wasmtime translation with pinned upstream before code generation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
ROOT = Path(__file__).resolve().parents[1]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work', type=Path, default=ROOT/'target/wasmtime-translation')
    p.add_argument('--module', type=Path, action='append')
    args = p.parse_args()
    work = args.work.resolve(); work.mkdir(parents=True, exist_ok=True)
    ref = work/'upstream'; (ref/'src').mkdir(parents=True, exist_ok=True)
    (ref/'Cargo.toml').write_text('''[package]
name = "wasmtime-translation-reference"
version = "0.0.0"
edition = "2024"
[workspace]
[dependencies]
wasmtime-environ = { version = "=48.0.0", default-features = false, features = ["compile", "component-model"] }
wasmparser = { version = "=0.254.0", default-features = false, features = ["features", "validate", "component-model"] }
''')
    (ref/'src/main.rs').write_bytes((ROOT/'wasmtime-runtime/examples/translate.rs').read_bytes())
    if not (ref/'Cargo.lock').exists():
        (ref/'Cargo.lock').write_bytes((ROOT/'tools/coremark-engines/Cargo.lock').read_bytes())
        subprocess.run(['cargo','metadata','--format-version','1','--offline','--manifest-path',str(ref/'Cargo.toml')],check=True,stdout=subprocess.DEVNULL)
    env = dict(os.environ, CARGO_TARGET_DIR=str(ROOT/'target/wasmtime-platform'))
    commands = [
        ['cargo','run','--locked','--offline','--manifest-path',str(ROOT/'wasmtime-runtime/Cargo.toml'),'--features','compiler-environment','--example','translate','--'],
        ['cargo','run','--locked','--offline','--manifest-path',str(ref/'Cargo.toml'),'--'],
    ]
    modules = args.module or [ROOT/'target/coremark-wasi/coremark.wasm']
    invalid = work/'invalid.wasm'; invalid.write_bytes(b'\x00asm\xff\xff\xff\xff')
    records = []
    for index, module in enumerate([*modules, invalid]):
        outputs = []
        for mode, command in zip(('ported','upstream'), commands):
            run = subprocess.run([*command,str(module.resolve())],env=env,capture_output=True)
            (work/f'{index}-{mode}.stdout').write_bytes(run.stdout)
            (work/f'{index}-{mode}.stderr').write_bytes(run.stderr)
            outputs.append(run)
        if module == invalid:
            assert all(x.returncode != 0 and b'module translation' in x.stderr for x in outputs)
        else:
            assert all(x.returncode == 0 for x in outputs), f'inspect {work}'
            assert outputs[0].stdout == outputs[1].stdout
        records.append(dict(module=str(module),sha256=hashlib.sha256(module.read_bytes()).hexdigest(),accepted=module!=invalid,summary=outputs[0].stdout.decode()))
    (work/'results.json').write_text(json.dumps(dict(scope='translation metadata only; no code generation or execution',modules=records),indent=2)+'\n')
    print(json.dumps(records,indent=2))
if __name__ == '__main__': main()
