#!/usr/bin/env python3
"""Compare complete RISC-V module compilation; does not execute native code."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
from wasmtime.reference import compiler_reference
import argparse

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, default=ROOT/'target/wasmtime-module')
    parser.add_argument('--module', type=Path, default=ROOT/'target/coremark-wasi/coremark.wasm')
    args = parser.parse_args()
    work = args.work.resolve()
    ref = work/'upstream'
    (ref/'src').mkdir(parents=True, exist_ok=True)
    (ref/'Cargo.toml').write_text('''[package]
name = "wasmtime-module-reference"
version = "0.0.0"
edition = "2024"
[workspace]
[dependencies]
wasmtime = { version = "=48.0.0", default-features = false, features = ["runtime", "cranelift", "std", "custom-virtual-memory", "custom-sync-primitives"] }
cranelift-codegen = { version = "=0.135.0", default-features = false, features = ["riscv64"] }
''')
    example = (ROOT/'wasmtime-runtime/examples/module.rs').read_text()
    config = (ROOT/'wasmtime-runtime/src/lib.rs').read_text().split('pub fn configuration()', 1)[1]
    (ref/'src/main.rs').write_text(example.replace('vibeos_wasmtime_runtime::configuration()', 'configuration()') + '\nextern crate alloc;\n#[path = ' + json.dumps(str(ROOT/'wasmtime-runtime/src/memory.rs')) + ']\nmod memory;\nuse wasmtime::Config;\npub fn configuration()' + config)
    # Keep target correctness fixes identical while comparing std/core-alloc.
    compiler = compiler_reference(work)
    with (ref/'Cargo.toml').open('a') as manifest:
        manifest.write('\n[patch.crates-io]\ncranelift-codegen = { path = ' + json.dumps(str(ROOT/'vendor/wasmtime-48/cranelift-codegen')) + ' }\n')
        manifest.write('wasmtime-internal-cranelift = { path = ' + json.dumps(str(compiler)) + ' }\n')
    if not (ref/'Cargo.lock').exists():
        (ref/'Cargo.lock').write_bytes((ROOT/'tools/coremark-engines/Cargo.lock').read_bytes())
    subprocess.run(['cargo','metadata','--format-version','1','--offline','--manifest-path',str(ref/'Cargo.toml')],check=True,stdout=subprocess.DEVNULL)
    env = dict(os.environ, CARGO_TARGET_DIR=str(ROOT/'target/wasmtime-platform'))
    commands = [
        ['cargo','run','--locked','--offline','--manifest-path',str(ROOT/'wasmtime-runtime/Cargo.toml'),'--features','compiler,host-tools','--example','module','--'],
        ['cargo','run','--locked','--offline','--manifest-path',str(ref/'Cargo.toml'),'--'],
        ['cargo','run','--locked','--offline','--manifest-path',str(ROOT/'wasmtime-runtime/Cargo.toml'),'--features','compiler,host-custom','--example','module-custom','--'],
    ]
    artifacts = []
    for mode, command in zip(('ported','upstream','custom'), commands):
        artifact = work/f'{mode}.cwasm'
        run = subprocess.run([*command,str(args.module.resolve()),str(artifact)],env=env,capture_output=True)
        (work/f'{mode}.stdout').write_bytes(run.stdout)
        (work/f'{mode}.stderr').write_bytes(run.stderr)
        assert run.returncode == 0, f'inspect {work}/{mode}.stderr'
        artifacts.append(artifact.read_bytes())
    assert artifacts[0] == artifacts[1] == artifacts[2], 'complete module artifacts differ'
    results = dict(scope='complete compiled module bytes, including inlining, trampolines and linking; host std and no_std custom-platform harnesses; not executed', module_sha256=hashlib.sha256(args.module.read_bytes()).hexdigest(), artifact_sha256=hashlib.sha256(artifacts[0]).hexdigest(), artifact_bytes=len(artifacts[0]), reference='upstream 48.0.0 plus riscv64-fs1-abi.patch and riscv64-inline-copy.patch', reference_identical=True)
    (work/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(results,indent=2))

if __name__ == '__main__':
    main()
