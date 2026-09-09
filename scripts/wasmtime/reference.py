"""Pinned std compiler reference with the same target correctness fixes."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]

def compiler_reference(work):
    registry = Path(os.environ.get("CARGO_HOME", str(Path.home()/".cargo")))/"registry/src"
    sources = list(registry.glob("*/wasmtime-internal-cranelift-48.0.0"))
    expected = json.loads((ROOT/"vendor/wasmtime-48/UPSTREAM.json").read_text())["crates"]["wasmtime-internal-cranelift"]["files_sha256"]
    source = next((p for p in sources if all((p/name).is_file() and hashlib.sha256((p/name).read_bytes()).hexdigest() == digest for name, digest in expected.items())), None)
    assert source is not None, "pinned original compiler source unavailable or changed"
    target = work/"reference-cranelift"
    shutil.copytree(source, target, dirs_exist_ok=True)
    subprocess.run(["patch", "-p1", "-i", str(ROOT/"vendor/wasmtime-48/riscv64-inline-copy.patch")], cwd=target, check=True)
    return target
