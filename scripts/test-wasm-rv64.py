#!/usr/bin/env python3
"""Execute generated RV64 code against Rust reference results on QEMU/OpenSBI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, default=ROOT/'target/wasm-rv64-probe')
    args = parser.parse_args()
    os.chdir(ROOT)
    work = args.work.resolve()
    clang = os.environ.get('RISCV_CLANG', 'clang')
    version = subprocess.check_output([clang, '--version'], text=True)
    assert 'riscv64' in subprocess.check_output([clang, '--print-targets'], text=True), 'probe requires a Clang build with the RISC-V backend'
    subprocess.run(['cargo','run','--release','--locked','--offline','-p','vibeos-wasm-rv64','--example','probe','--',str(work)],check=True)
    sysroot = Path(subprocess.check_output(['rustc','--print','sysroot'],text=True).strip())
    host = next(line.split(': ',1)[1] for line in subprocess.check_output(['rustc','-Vv'],text=True).splitlines() if line.startswith('host: '))
    linker = sysroot/'lib/rustlib'/host/'bin/rust-lld'
    objects=[]
    for name in ['start.S','generated.S','probe.c']:
        obj=work/(name+'.o');objects.append(str(obj))
        subprocess.run([clang,'--target=riscv64-unknown-elf','-march=rv64imac','-mabi=lp64','-mcmodel=medany','-msmall-data-limit=0','-ffreestanding','-fno-builtin','-fno-stack-protector','-O2','-c',str(work/name),'-o',str(obj)],check=True)
    elf=work/'probe.elf'
    subprocess.run([linker,'-flavor','gnu','-T',str(work/'link.ld'),*objects,'-o',str(elf)],check=True)
    command=['qemu-system-riscv64','-machine','virt','-cpu','rv64','-smp','1','-m','128M','-accel','tcg,thread=single','-nographic','-bios','default','-kernel',str(elf)]
    try:
        result=subprocess.run(command,capture_output=True,timeout=30)
    except subprocess.TimeoutExpired as error:
        (work/'qemu.log').write_bytes((error.stdout or b'')+(error.stderr or b''))
        raise
    output=result.stdout+result.stderr
    (work/'qemu.log').write_bytes(output)
    assert result.returncode==0 and b'PASS RV64_CODEGEN 200' in output and b'FAIL RV64_CODEGEN' not in output and b'PASS RV64_MEMORY 16416' in output and b'PASS RV64_CONTROL 1500' in output and b'PASS RV64_FLOW 240' in output and b'PASS RV64_COPIES 150' in output and b'PASS RV64_CACHE interpreter and trap transitions' in output, output.decode(errors='replace')
    sources=['wasm-rv64/src/lib.rs','wasm-rv64/examples/probe.rs','wasm-rv64/examples/probe/memory.rs','wasm-rv64/examples/probe/control.rs','wasm-rv64/examples/probe/flow.rs','wasm-rv64/examples/probe/copies.rs','wasm-rv64/examples/probe/cache.rs','scripts/test-wasm-rv64.py','Cargo.lock']
    (work/'results.json').write_text(json.dumps({'command':command,'clang':version,'rustc':subprocess.check_output(['rustc','-Vv'],text=True),'qemu':subprocess.check_output(['qemu-system-riscv64','--version'],text=True),'elf_sha256':hashlib.sha256(elf.read_bytes()).hexdigest(),'sources_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sources},'cases':200,'memory_cases':16416,'control_cases':1500,'flow_cases':240,'copy_cases':150,'cache_transition_cases':1,'result':'passed'},indent=2)+'\n')
    print(f'PASS: 200 arithmetic/fuel and 16416 checked-memory generated-code cases; evidence: {work}')

if __name__=='__main__':
    main()
