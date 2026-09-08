#!/usr/bin/env python3
"""Check isolated Cranelift integer code and execute-only compatibility on QEMU."""
import argparse, hashlib, json, os, pathlib, subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE=ROOT/'wasm-rv64/experiments/cranelift-no-std'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',type=pathlib.Path,default=ROOT/'target/cranelift-rv64-probe')
    args=parser.parse_args();work=args.work.resolve();work.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,CARGO_TARGET_DIR=str(ROOT/'target/cranelift-no-std-check/target'))
    subprocess.run(['cargo','run','--locked','--offline','--release','--manifest-path',str(SOURCE/'Cargo.toml'),'--example','emit','--',str(work)],cwd=ROOT,env=env,check=True)
    external=(work/'external.bin').read_bytes()
    assert len(external)%4==0
    # Audit this leaf probe's complete instruction stream, including ABI writes.
    # This whitelist is deliberately specific to this probe, not a general JIT verifier.
    caller_saved={5,6,7,10,11,12,13,14,15,16,17,28,29,30,31}
    for position in range(0,len(external),4):
        word=int.from_bytes(external[position:position+4],'little')
        opcode=word&127;rd=(word>>7)&31;f3=(word>>12)&7;f7=word>>25
        allowed=(opcode==0x13 and f3==0) or opcode==0x37 or (opcode==0x33 and (f7,f3) in {(0,0),(0,4),(1,0)}) or (opcode==3 and f3==3 and (word>>15)&31==13 and word>>20==0) or (opcode==0x63 and f3==0) or (opcode==0x6f and rd==0) or word==0x00008067
        assert allowed, f'probe instruction outside audited RV64IM subset: {word:08x}'
        if opcode in {0x13,0x37,0x33,3}:assert rd in caller_saved, f'probe clobbers preserved register {rd}'
    clang=os.environ.get('RISCV_CLANG','clang')
    assert 'riscv64' in subprocess.check_output([clang,'--print-targets'],text=True)
    objects=[]
    for source in [SOURCE/'start.S',SOURCE/'probe.c',work/'generated.S',work/'external.S',work/'wasmi.S']:
        obj=work/(source.name+'.o');objects.append(str(obj))
        subprocess.run([clang,'--target=riscv64-unknown-elf','-march=rv64imac','-mabi=lp64','-mcmodel=medany','-msmall-data-limit=0','-ffreestanding','-fno-builtin','-fno-stack-protector','-O2','-c',str(source),'-o',str(obj)],check=True)
    sysroot=pathlib.Path(subprocess.check_output(['rustc','--print','sysroot'],text=True).strip())
    host=next(x.split(': ',1)[1] for x in subprocess.check_output(['rustc','-Vv'],text=True).splitlines() if x.startswith('host: '))
    linker=sysroot/'lib/rustlib'/host/'bin/rust-lld';elf=work/'probe.elf'
    subprocess.run([str(linker),'-flavor','gnu','-T',str(SOURCE/'link.ld'),*objects,'-o',str(elf)],check=True)
    (work/'disassembly.txt').write_bytes(subprocess.check_output(['llvm-objdump','-d',str(elf)]))
    command=['qemu-system-riscv64','-machine','virt','-cpu','rv64','-smp','1','-m','128M','-accel','tcg,thread=single','-nographic','-bios','default','-kernel',str(elf)]
    result=subprocess.run(command,capture_output=True,timeout=30);output=result.stdout+result.stderr;(work/'qemu.log').write_bytes(output)
    assert result.returncode==0 and b'FAIL ' not in output and b'PASS CRANELIFT_RX 500' in output and b'PASS CRANELIFT_EXTERNAL_XO 500' in output and b'PASS CRANELIFT_WASMI_XO 200' in output,output.decode(errors='replace')
    compatible=b'PASS CRANELIFT_XO' in output
    assert compatible or b'PASS EXPECTED_XO_CONSTANT_POOL_FAULT' in output,output.decode(errors='replace')
    record={'cases':500,'wasmi_ir_cases':200,'integer_rx_passed':True,'execute_only_compatible':compatible,'external_literal_execute_only_compatible':True,'kernel_integration_ready':False,'external_probe_rv64im_leaf_abi_audited':True,'qemu_command':command,'elf_sha256':hashlib.sha256(elf.read_bytes()).hexdigest(),'code_sha256':hashlib.sha256((work/'code.bin').read_bytes()).hexdigest(),'external_code_sha256':hashlib.sha256((work/'external.bin').read_bytes()).hexdigest(),'rustc':subprocess.check_output(['rustc','-Vv'],text=True),'qemu':subprocess.check_output(['qemu-system-riscv64','--version'],text=True),'sources_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [SOURCE/'src/lib.rs',SOURCE/'src/wasmi.rs',SOURCE/'examples/emit.rs',SOURCE/'Cargo.lock',SOURCE/'probe.c',SOURCE/'start.S',SOURCE/'link.ld',pathlib.Path(__file__).resolve()]}}
    (work/'results.json').write_text(json.dumps(record,indent=2)+'\n')
    print(f'500 RX and 500 external-literal XO cases passed; inline-pool XO compatible: {compatible}; evidence: {work}')

if __name__=='__main__':main()
