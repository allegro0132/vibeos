#!/usr/bin/env python3
"""Fresh QEMU + OpenSSH WASI gate. Retains source hashes, logs and disk evidence."""
import argparse
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parent.parent

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',type=Path,default=ROOT/'target/wasi-acceptance')
    parser.add_argument('--cycles',type=int,default=100)
    parser.add_argument('--boot-timeout',type=int,default=300)
    args=parser.parse_args();os.chdir(ROOT);work=args.work.resolve();work.mkdir(parents=True,exist_ok=True)
    if (work/'disk.raw').exists():raise SystemExit('use a fresh --work directory for source-bound acceptance')
    spec=importlib.util.spec_from_file_location('wasi_peer',ROOT/'scripts/openssh-peer.py');peer=importlib.util.module_from_spec(spec);sys.modules[spec.name]=peer;spec.loader.exec_module(peer)
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    env=dict(os.environ,WASI_SKIP_BUILD='1',WASI_WORK_DIR=str(work),WASI_SSH_PORT=str(port))
    command=peer._base_ssh_command('ssh','127.0.0.1',port,'vibe',work/'id_ed25519',work/'known_hosts',15,None)
    sdk=Path(os.environ['WASI_SDK_PATH'])
    # Fail before boot/upload work if the compiler needed by the live-update
    # test is absent (for example after a temporary SDK directory is cleaned).
    sdk_version=subprocess.check_output([str(sdk/'bin/clang'),'--version'],text=True)
    assert '22.1.0-wasi-sdk' in sdk_version, 'acceptance requires wasi-sdk 33'
    results=[];qemu=None;log=None
    def ssh(words,data=b'',status=0,out=None,err=b'',timeout=60):
        for attempt in range(5):
            before=(work/'boot-1.log').stat().st_size
            p=subprocess.run([*command,shlex.join(words)],input=data,capture_output=True,timeout=timeout)
            observed=(work/'boot-1.log').read_bytes()[before:]
            pre_auth_failure=(b'kex_exchange_identification:' in p.stderr or (b'timed out' in p.stderr and b'Connection' in p.stderr))
            # These known fixtures cannot synthesize transport diagnostics.
            # Never retry a timeout after the kernel has begun this request.
            began=b'WASI running' in observed or b'WASI upload receiving' in observed or b'WASI admission rejected' in observed
            if p.returncode==255 and not p.stdout and pre_auth_failure and not began:
                time.sleep(.25)
                continue
            break
        time.sleep(.3)
        if status is not None:assert p.returncode==status,(words,p.returncode,p.stdout,p.stderr)
        if out is not None:assert p.stdout==out,(words,p.stdout[:500],out[:500])
        if err is not None:assert p.stderr==err,(words,p.stderr)
        results.append({'command':words,'status':p.returncode,'stdout_bytes':len(p.stdout),'stderr_bytes':len(p.stderr)})
        return p
    def upload(name,data,status=0,hash=None,length=None):
        return ssh(['wasm-upload',name,str(len(data) if length is None else length),hash or hashlib.sha256(data).hexdigest()],data,status,out=b'')
    def start(boot):
        nonlocal qemu,log
        log=open(work/f'boot-{boot}.log','wb');qemu=subprocess.Popen([str(ROOT/'scripts/run-wasi-qemu.sh')],env=env,stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT)
        deadline=time.monotonic()+args.boot_timeout
        while time.monotonic()<deadline:
            if qemu.poll() is not None:raise AssertionError((work/f'boot-{boot}.log').read_text(errors='replace'))
            if 'vsh> ' in (work/f'boot-{boot}.log').read_text(errors='replace'):
                try:
                    p=subprocess.run([*command,'echo ready'],input=b'',capture_output=True,timeout=8)
                    if p.returncode==0 and p.stdout==b'ready\n':
                        time.sleep(.25);return
                except subprocess.TimeoutExpired:pass
            time.sleep(.2)
        raise AssertionError('QEMU/SSH readiness timed out')
    def stop():
        nonlocal qemu,log
        if qemu is not None:
            qemu.terminate()
            try:qemu.wait(timeout=10)
            except subprocess.TimeoutExpired:qemu.kill();qemu.wait()
            qemu=None
        if log is not None:log.close();log=None
    def local(source,marker):
        before=(work/'boot-1.log').stat().st_size
        qemu.stdin.write((source+'\n').encode());qemu.stdin.flush()
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            text=(work/'boot-1.log').read_bytes()[before:].decode(errors='replace')
            # command echo also contains marker, so require the separate output line.
            if '\r\n'+marker+'\r\n' in text or '\n'+marker+'\n' in text:return text
            time.sleep(.05)
        raise AssertionError(('local command timeout',text[-2000:]))
    def wait_uart(marker, before, timeout=20):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            text=(work/'boot-1.log').read_bytes()[before:]
            if marker in text:return
            time.sleep(.02)
        raise AssertionError(('missing UART marker',marker,text[-1000:]))
    try:
        subprocess.run(['cargo','run','--locked','--offline','-p','vibeos-wasi-runtime','--example','fixtures','--',str(work/'fixtures')],check=True)
        start(1)
        for lang in ['rust','c']:
            data=(ROOT/f'target/wasi-examples/{lang}-hello.wasm').read_bytes();name=f'{lang}.wasm';upload(name,data)
            ssh(['wasm-run',name],out=f'Hello from {"Rust" if lang=="rust" else "C"} WASI!\n'.encode())
            ssh(['wasm-run',name,'args','a b','中文'],out='a b\n中文\n'.encode())
            binary=(b'ab\0cde\n'*1900);ssh(['wasm-run',name,'filter'],binary,out=binary.upper())
            ssh(['wasm-run',name,'filter'],out=b'')
            ssh(['wasm-run',name,'stderr'],out=b'out\n',err=b'err\n')
            ssh(['wasm-run',name,'exit'],status=7,out=b'')
        print('PASS standard Rust/C commands, arguments, binary stdin, stderr, exit',flush=True)
        subprocess.run(['python3',str(ROOT/'scripts/openssh-test-key.py'),'--fixture','rejected','--output',str(work/'rejected_key')],check=True)
        rejected=peer._base_ssh_command('ssh','127.0.0.1',port,'vibe',work/'rejected_key',work/'known_hosts',15,None)
        # A transport reset before key exchange is not authentication evidence.
        # Retry only that pre-auth failure; never accept it as a denied key or
        # retry a request that has reached the WASI service.
        for attempt in range(5):
            before=(work/'boot-1.log').stat().st_size
            denied=subprocess.run([*rejected,'wasm-run c.wasm'],input=b'',capture_output=True,timeout=20)
            observed=(work/'boot-1.log').read_bytes()[before:]
            began=any(marker in observed for marker in (b'WASI running',b'WASI upload receiving',b'WASI admission rejected'))
            if denied.returncode==255 and not denied.stdout and b'kex_exchange_identification:' in denied.stderr and not began:
                time.sleep(.25)
                continue
            break
        assert denied.returncode!=0 and b'Permission denied (publickey)' in denied.stderr,denied
        results.append({'case':'unauthorized key','status':denied.returncode})
        time.sleep(.25)
        original=(ROOT/'target/wasi-examples/c-hello.wasm').read_bytes()
        upload('c.wasm',original,2,hash='0'*64)
        upload('c.wasm',original[:-1],2,length=len(original),hash=hashlib.sha256(original).hexdigest())
        upload('c.wasm',original+b'x',2,length=len(original),hash=hashlib.sha256(original).hexdigest())
        # Interrupt a live upload without EOF; the previous file must survive.
        before=(work/'boot-1.log').stat().st_size
        partial=subprocess.Popen([*command,shlex.join(['wasm-upload','c.wasm',str(len(original)),hashlib.sha256(original).hexdigest()])],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        partial.stdin.write(original[:1024]);partial.stdin.flush();wait_uart(b'WASI upload receiving c.wasm',before);time.sleep(.1);partial.terminate();partial.communicate(timeout=10);time.sleep(.25)
        ssh(['wasm-run','c.wasm'],out=b'Hello from C WASI!\n')
        ssh(['wasm-run','../c.wasm'],status=None,err=None)
        assert results[-1]['status']!=0
        upload('malformed.wasm',b'not wasm');ssh(['wasm-run','malformed.wasm'],status=126,out=b'')
        for name,status in [('bounds',0),('memory',124),('trap',125),('unknown',126),('loop',124),('output',124)]:
            upload(name+'.wasm',(work/f'fixtures/{name}.wasm').read_bytes())
            p=ssh(['wasm-run',name+'.wasm'],status=status,out=None)
            assert len(p.stdout)<=65536
        # Disconnect while executing; the same server must admit a fresh invocation.
        before=(work/'boot-1.log').stat().st_size
        p=subprocess.Popen([*command,'wasm-run rust.wasm filter'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        wait_uart(b'WASI running',before)
        text=local('wasm-run @home/wasm/c.wasm; echo BUSY_CHECK_DONE','BUSY_CHECK_DONE')
        assert 'Unavailable' in text,text[-2000:]
        p.terminate();p.communicate(timeout=10)
        wait_uart(b'WASI terminal=Cancelled reclaimed=true',before)
        time.sleep(.2)
        ssh(['wasm-run','c.wasm'],out=b'Hello from C WASI!\n')
        print('PASS upload failures, containment and disconnect recovery',flush=True)
        text=local('echo local-pipe | wasm-run @home/wasm/c.wasm filter; echo LOCAL_WASI_DONE','LOCAL_WASI_DONE')
        assert 'LOCAL-PIPE' in text,text[-2000:]
        before=(work/'boot-1.log').stat().st_size
        qemu.stdin.write(b'wasm-run @home/wasm/rust.wasm loop\n');qemu.stdin.flush()
        wait_uart(b'WASI running',before)
        qemu.stdin.write(b'\x03');qemu.stdin.flush()
        wait_uart(b'WASI terminal=Cancelled reclaimed=true',before)
        text=local('wasm-run @home/wasm/c.wasm; echo AFTER_CANCEL','AFTER_CANCEL')
        assert 'Hello from C WASI!' in text,text[-2000:]
        # Compile a different real stdio program after boot, with no kernel rebuild.
        source=work/'changed.c';source.write_text('#include <stdio.h>\nint main(void){puts("Updated after boot!");return 0;}\n')
        subprocess.run([str(sdk/'bin/clang'),'--target=wasm32-wasip1','-Oz',str(source),'-Wl,--max-memory=16777216','-Wl,-z,stack-size=65536','-Wl,--strip-all','-o',str(work/'changed.wasm')],check=True)
        upload('changed.wasm',(work/'changed.wasm').read_bytes());ssh(['wasm-run','changed.wasm'],out=b'Updated after boot!\n')
        for i in range(args.cycles):ssh(['wasm-run','c.wasm'],out=b'Hello from C WASI!\n')
        log.flush();text=(work/'boot-1.log').read_text(errors='replace')
        assert text.count('reclaimed=true')>=args.cycles
        assert 'reclaimed=false' not in text
        assert len(re.findall(r'reclaimed=true caps=0 waiters=0',text))>=args.cycles
        print(f'PASS local pipeline, post-boot compilation, {args.cycles} reclaimed invocations',flush=True)
        (work/'phase-1-results.json').write_text(json.dumps(results,indent=2)+'\n')
        stop();start(2)
        ssh(['wasm-run','rust.wasm'],out=b'Hello from Rust WASI!\n');ssh(['wasm-run','changed.wasm'],out=b'Updated after boot!\n')
        stop()
        record={'profile':'wasi-preview1-command-v1','cycles':args.cycles,'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'dirty_diff_sha256':hashlib.sha256(subprocess.check_output(['git','diff'])).hexdigest(),'qemu':subprocess.check_output(['qemu-system-riscv64','--version'],text=True).splitlines()[0],'rustc':subprocess.check_output(['rustc','-Vv'],text=True),'examples':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'target/wasi-examples').glob('*-hello.wasm')},'results':results}
        paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
        record['source_files_sha256']={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in paths if p and (ROOT/p).is_file()}
        record['kernel_sha256']=hashlib.sha256((ROOT/'target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt').read_bytes()).hexdigest()
        record['wasi_sdk']=sdk_version
        record['post_boot_module_sha256']=hashlib.sha256((work/'changed.wasm').read_bytes()).hexdigest()
        (work/'results.json').write_text(json.dumps(record,indent=2)+'\n')
        print(f'PASS WASI_QEMU: upload, execution, lifecycle, restart; evidence: {work}',flush=True)
    finally:stop()
if __name__=='__main__':main()
