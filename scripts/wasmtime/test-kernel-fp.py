#!/usr/bin/env python3
"""Boot a supplied kernel and run its real catch/longjmp/platform self-tests."""
import argparse, hashlib, json, os, re, select, shutil, subprocess, time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--kernel',required=True,type=Path)
p.add_argument('--work',required=True,type=Path)
p.add_argument('--require-wasmtime',action='store_true')
p.add_argument('--require-wasi',action='store_true')
p.add_argument('--require-async',action='store_true')
p.add_argument('--require-streams',action='store_true')
p.add_argument('--require-memory-recovery',action='store_true')
p.add_argument('--require-code-recovery',action='store_true')
p.add_argument('--require-active-recovery',action='store_true')
p.add_argument('--require-fiber-recovery',action='store_true')
p.add_argument('--require-trap-stack',action='store_true')
p.add_argument('--require-fiber-stack',action='store_true')
p.add_argument('--require-compile-recovery',action='store_true')
p.add_argument('--require-hardware-traps',action='store_true')
p.add_argument('--require-guarded-memory',action='store_true')
p.add_argument('--require-threads',action='store_true',help='Require the shared-memory wait/notify/grow probe')
p.add_argument('--host-fault',action='store_true',help='After selftests require a fatal host rodata write fault')
p.add_argument('--coremark-module',type=Path,help='Require a >=10-second validated embedded CoreMark run')
p.add_argument('--harts',type=int,choices=(1,4),default=4)
p.add_argument('--cpu',default='rv64')
p.add_argument('--isa-mask',type=lambda s:int(s,0),choices=range(16))
a=p.parse_args();a.work.mkdir(parents=True,exist_ok=True)
# Freeze the measured ELF so subsequent builds cannot change the evidence.
source=a.kernel.resolve(); frozen=(a.work/'kernel.elf').resolve()
if source != frozen: shutil.copyfile(source,frozen)
a.kernel=frozen
disk=a.work/'disk.raw'
if not disk.exists():
    with disk.open('wb') as f:f.truncate(128*1024*1024)
cmd=['qemu-system-riscv64','-machine','virt','-cpu',a.cpu,'-smp',str(a.harts),'-m','128M','-accel','tcg,thread='+('single' if a.harts == 1 else 'multi'),'-rtc','base=utc,clock=vm','-nographic','-bios','default','-kernel',str(a.kernel.resolve()),'-drive',f'if=none,id=disk,format=raw,file={disk.resolve()},cache=writeback','-device','virtio-blk-device,drive=disk,bus=virtio-mmio-bus.0,queue-size=8','-global','virtio-mmio.force-legacy=false']
(a.work/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
vm=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,bufsize=0)
pending=bytearray()
with (a.work/'boot.log').open('wb') as log:
    def prompt(seconds):
        deadline=time.monotonic()+seconds
        while b'vibe> ' not in pending:
            if vm.poll() is not None:raise RuntimeError('kernel exited; inspect boot.log')
            if time.monotonic()>deadline:raise TimeoutError('kernel prompt timeout; inspect boot.log')
            if select.select([vm.stdout],[],[],1)[0]:
                data=os.read(vm.stdout.fileno(),65536);log.write(data);log.flush();pending.extend(data)
        pos=pending.index(b'vibe> ')+6
        result=bytes(pending[:pos]);del pending[:pos];return result
    try:
        boot=prompt(90)
        vm.stdin.write(b'quiet\n');vm.stdin.flush();prompt(30)
        vm.stdin.write(b'selftest\n');vm.stdin.flush();result=prompt(300)
        assert b'0 failed' in result and b'SELFTEST OK' in result, 'selftest failed; inspect boot.log'
        native = [x.decode(errors='replace') for x in result.splitlines() if b'WASMTIME NATIVE PASS' in x]
        if a.require_wasmtime: assert native, 'Wasmtime native selftest marker missing'
        wasi = [x.decode(errors='replace') for x in result.splitlines() if b'WASMTIME WASI PASS' in x]
        if a.require_wasi: assert wasi, 'Wasmtime WASI selftest marker missing'
        hardware = [x.decode(errors='replace') for x in result.splitlines() if b'WASMTIME HARDWARE TRAPS PASS' in x or b'WASMTIME HARDWARE COUNTS' in x]
        if a.require_hardware_traps: assert any('TRAPS PASS' in x for x in hardware), 'native hardware trap test missing'
        guarded = [x.decode(errors='replace') for x in result.splitlines() if b'WASMTIME GUARDED MEMORY PASS' in x]
        if a.require_guarded_memory: assert guarded, 'guarded guest memory test missing'
        threads = [x.decode(errors='replace') for x in result.splitlines() if b'WASMTIME THREADS PASS' in x]
        if a.require_threads:
            assert any('wait=1 notify=1 timeout=1 mismatch=1 grow_shared=1' in x for x in threads), 'shared-memory threads probe missing'
            parallel = [x.decode(errors='replace') for x in result.splitlines() if b'WASMTIME PARALLEL RECOVERY PASS' in x]
            assert any('cycles=16 siblings=3 drops=0' in x for x in parallel), 'parallel domain recovery probe missing'
            if a.harts > 1:
                harts = int(re.search(r'harts=(0x[0-9a-f]+)', parallel[0]).group(1), 16)
                assert bin(harts).count('1') >= 2, 'siblings never ran on a second hart'
                assert int(re.search(r'remote_detaches=(\d+)', parallel[0]).group(1)) > 0, 'no sibling was collected mid-poll on another hart'
        async_probes = [x.decode(errors='replace') for x in result.splitlines() if b'WASMTIME ASYNC PASS' in x or b'WASMTIME ASYNC HEAP' in x]
        if a.require_async: assert any('ASYNC PASS' in x for x in async_probes), 'native async test missing'
        streams = [x.decode(errors='replace') for x in result.splitlines() if b'WASMTIME STREAMS PASS' in x]
        if a.require_streams: assert streams, 'streaming WASI test missing'
        memory_recovery = [x.decode(errors='replace') for x in result.splitlines() if b'WASMTIME MEMORY RECOVERY PASS' in x]
        if a.require_memory_recovery: assert memory_recovery, 'memory-only raw recovery test missing'
        code_registry = [x.decode(errors='replace') for x in result.splitlines() if b'WASMTIME CODE REGISTRY PASS' in x]
        code_recovery = [x.decode(errors='replace') for x in result.splitlines() if b'WASMTIME CODE RECOVERY PASS' in x]
        if a.require_code_recovery:
            assert any('capacity=16 live=0' in x for x in code_registry), 'fixed code registry idle check missing'
            assert any('faults=16 post_call=1 drops=0 registry=0 maps=0 heap=0' in x for x in code_recovery), 'post-call code recovery check missing'
        active_recovery = [x.decode(errors='replace') for x in result.splitlines() if b'WASMTIME ACTIVE RECOVERY PASS' in x]
        if a.require_active_recovery:
            assert any('faults=16 tls=0 drops=0 registry=0 maps=0 heap=0' in x for x in active_recovery), 'active native call recovery missing'
        fiber_recovery = [x.decode(errors='replace') for x in result.splitlines() if b'WASMTIME FIBER RECOVERY PASS' in x]
        if a.require_fiber_recovery:
            assert any('suspended=16 resumed_fault=16 cancel_drop_fault=16 tls=0 drops=0 registry=0 maps=0 heap=0' in x for x in fiber_recovery), 'native fiber raw recovery missing'
        trap_stack = [x.decode(errors='replace') for x in result.splitlines() if b'WASMTIME TRAP STACK PASS' in x]
        if a.require_trap_stack:
            assert any('invalid_sp=16 bytes=65536 guard=1 returned=1' in x for x in trap_stack), 'independent trap-stack regression missing'
        fiber_stack = [x.decode(errors='replace') for x in result.splitlines() if b'WASMTIME FIBER STACK PASS' in x or b'WASMTIME STACK LIMIT PASS' in x]
        if a.require_fiber_stack:
            assert any('slots=4 limit=262144 guard=4096 idle=1' in x for x in fiber_stack), 'protected native fiber stack regression missing'
            assert any('recursive_traps=16 fuel_remaining=1' in x for x in fiber_stack), 'recursive guest stack overflow regression missing'
        compile_recovery = [x.decode(errors='replace') for x in result.splitlines() if b'WASMTIME COMPILE RECOVERY PASS' in x or b'WASMTIME COMPILE BUDGET' in x]
        if a.require_compile_recovery:
            assert any('COMPILE RECOVERY PASS budgets=8' in x and 'heap=0 maps=0 registry=0' in x for x in compile_recovery), 'compiler arena budget recovery missing'
        isa = re.search(rb'Wasmtime ISA firmware_harts=(\d+) extra_mask=(0x[0-9a-f]+)',boot)
        isa_info = dict(harts=int(isa[1]),extra_mask=int(isa[2],16)) if isa else None
        if a.isa_mask is not None:
            assert isa_info and isa_info['extra_mask']==a.isa_mask and isa_info['harts']==a.harts, 'firmware CPU extension intersection mismatch'
        coremark = None
        if a.coremark_module:
            module_bytes = a.coremark_module.read_bytes()
            assert a.kernel.read_bytes().count(module_bytes) == 1, 'kernel must embed the exact ordinary Wasm module'
            report = result.decode(errors='replace')
            begin = report.index('WASMTIME COREMARK stdout begin')
            end = report.index('WASMTIME COREMARK stdout end',begin)
            output = report[begin:end]
            assert 'Correct operation validated' in output and 'Errors detected' not in output
            seconds = float(re.search(r'Total time \(secs\)\s*:\s*([0-9.]+)',output)[1])
            score = float(re.search(r'Iterations/Sec\s*:\s*([0-9.]+)',output)[1])
            assert seconds >= 10 and score > 0
            timing = re.search(r'WASMTIME COREMARK compile_ticks=(\d+) run_ticks=(\d+) hz=(\d+) fuel=(\d+)',report)
            peak = re.search(r'WASMTIME COREMARK heap_peak=(\d+) heap_live=(\d+) denials=(\d+)',report)
            assert timing and peak and int(peak[2]) == 0 and int(peak[3]) == 0
            coremark = dict(scope='trusted synchronous probe; no async command scheduling',module_sha256=hashlib.sha256(module_bytes).hexdigest(),score=score,seconds=seconds,compile_seconds=int(timing[1])/int(timing[3]),call_seconds=int(timing[2])/int(timing[3]),fuel=int(timing[4]),heap_peak=int(peak[1]),heap_live=int(peak[2]),harts=a.harts)
            async_timing = re.search(r'WASMTIME COREMARK async_polls=(\d+) fuel_quantum=(\d+) scheduler=(\w+)',report)
            if async_timing:
                coremark.update(scope='native async fibers, manually polled; no command-service scheduler', async_polls=int(async_timing[1]), fuel_quantum=int(async_timing[2]), scheduler=async_timing[3])

        report={'scope':'kernel platform/catcher and recorded Wasmtime probes; CoreMark measurement only when populated, not command-service acceptance','wasmtime_native':native,'wasmtime_wasi':wasi,'hardware_traps':hardware,'guarded_memory':guarded,'async':async_probes,'streams':streams,'memory_recovery':memory_recovery,'code_registry':code_registry,'code_recovery':code_recovery,'active_recovery':active_recovery,'fiber_recovery':fiber_recovery,'trap_stack':trap_stack,'fiber_stack':fiber_stack,'compile_recovery':compile_recovery,'expected_host_fault':a.host_fault,'isa':isa_info,'coremark':coremark,'kernel_sha256':hashlib.sha256(a.kernel.read_bytes()).hexdigest(),'passed':True,'summary':[x.decode(errors='replace') for x in result.splitlines() if b'selftest:' in x or b'SELFTEST' in x]}
        if a.host_fault:
            vm.stdin.write(b'mmu ro fault rodata\n');vm.stdin.flush()
            fault=bytearray();deadline=time.monotonic()+30
            while True:
                if select.select([vm.stdout],[],[],1)[0]:
                    chunk=os.read(vm.stdout.fileno(),65536);log.write(chunk);log.flush();fault.extend(chunk)
                    if not chunk: break
                if time.monotonic()>deadline: raise TimeoutError('expected host-fault shutdown')
            vm.wait(timeout=10)
            assert b'fatal trap:' in fault and b'read-only .rodata blocked store page fault' in fault, 'host fault was not preserved'
        else:
            vm.stdin.write(b'\x01x');vm.stdin.flush();vm.wait(timeout=10)
        (a.work/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    finally:
        if vm.poll() is None:vm.terminate();vm.wait(timeout=10)
print((a.work/'results.json').read_text())
