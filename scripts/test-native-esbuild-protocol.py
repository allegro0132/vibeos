#!/usr/bin/env python3
"""Run the transform admission tests with the repository's pinned Rust compiler."""
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def main():
    channel = tomllib.loads((ROOT / 'rust-toolchain.toml').read_text())['toolchain']['channel']
    compiler = subprocess.check_output(['rustup', 'which', '--toolchain', channel, 'rustc'], text=True).strip()
    (ROOT / 'target').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='esbuild-protocol-', dir=ROOT / 'target') as temp:
        directory = Path(temp)
        source = ROOT / 'kernel/src/native_esbuild_protocol.rs'
        harness = directory / 'harness.rs'
        harness.write_text(f'#[path = {json.dumps(str(source), ensure_ascii=False)}]\nmod protocol;\n')
        binary = directory / 'tests'
        subprocess.run([compiler, '--edition=2021', '--test', str(harness), '-o', str(binary)], check=True)
        return subprocess.run([str(binary)]).returncode


if __name__ == '__main__':
    raise SystemExit(main())
