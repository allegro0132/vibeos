#!/usr/bin/env python3
"""Exercise real stdlib commands and adversarial ABI fixtures on custom Wasmtime.
Build wasi-custom with compiler,host-custom first; no QEMU performance claims.
"""
import argparse, hashlib, json, pathlib, struct, subprocess
ROOT=pathlib.Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--runner',type=pathlib.Path,default=ROOT/'target/wasmtime-platform/debug/examples/wasi-custom')
parser.add_argument('--work',type=pathlib.Path,default=ROOT/'target/coremark-performance/wasmtime-wasi-host')
args=parser.parse_args()
OUT=args.work.resolve();OUT.mkdir(parents=True,exist_ok=True)
RUN=args.runner.resolve()
results=[]
def run(name,module,args=(),stdin=b'',out=None,err=None,code=0):
    p=subprocess.run([str(RUN),str(module),*args],input=stdin,capture_output=True,timeout=60)
    (OUT/(name+'.stdout')).write_bytes(p.stdout)
    (OUT/(name+'.stderr')).write_bytes(p.stderr)
    assert p.returncode==code,(name,p.returncode,p.stderr)
    if out is not None: assert p.stdout==out,(name,p.stdout)
    if err is not None: assert p.stderr.startswith(err),(name,p.stderr)
    results.append(dict(name=name,exit=code,module_sha256=hashlib.sha256(module.read_bytes()).hexdigest()))
for lang in ('c','rust'):
    module=ROOT/f'target/wasi-examples/{lang}-hello.wasm'
    run(lang+'-hello',module,out=f'Hello from {"C" if lang=="c" else "Rust"} WASI!\n'.encode())
    run(lang+'-args',module,('args','hello world','中文'),out='hello world\n中文\n'.encode())
    run(lang+'-filter',module,('filter',),stdin=b'abc\nxyz\n'*2000,out=b'ABC\nXYZ\n'*2000)
    run(lang+'-stderr',module,('stderr',),out=b'out\n',err=b'err\n')
    run(lang+'-exit',module,('exit',),code=7,out=b'')
def leb(n):
    out=bytearray()
    while n>=128: out.append((n&127)|128); n>>=7
    out.append(n); return bytes(out)
def sec(n,b): return bytes([n])+leb(len(b))+b
def string(s): b=s.encode(); return leb(len(b))+b
def fixture(name,params,returns,body,start=False):
    data=b'\0asm\1\0\0\0'+sec(1,b'\2\x60'+leb(len(params))+params+leb(len(returns))+returns+b'\x60\0\0')
    data+=sec(2,b'\1'+string('wasi_snapshot_preview1')+string(name)+b'\0\0')
    data+=sec(3,b'\1\1')+sec(5,b'\1\1\1\1')+sec(7,b'\2'+string('memory')+b'\2\0'+string('_start')+b'\0\1')
    if start: data+=sec(8,b'\1')
    code=b'\0'+body+b'\x0b'; data+=sec(10,b'\1'+leb(len(code))+code)
    return data
fixtures={
    # Exit preserves u32 and the following unreachable must never execute.
    'exit-u32':(fixture('proc_exit',b'\x7f',b'',b'\x41\x7f\x10\0\0'),1,b'wasi_exit=4294967295'),
    'bad-signature':(fixture('fd_close',b'\x7e',b'\x7f',b''),1,None),
    'unknown':(fixture('unknown',b'',b'',b''),1,None),
    'start-section':(fixture('proc_exit',b'\x7f',b'',b'',True),1,None),
    # An invalid timestamp pointer must produce FAULT, without a clock write.
    'clock-fault':(fixture('clock_time_get',b'\x7f\x7e\x7f',b'\x7f',
        b'\x41\1\x42\0\x41\x7f\x10\0\x41\x15\x47\x04\x40\0\x0b'),0,b'wasi_exit=0'),
}
# Later invalid iovec: the valid first vector must not leak any output.
data=struct.pack('<IIII',32,1,65535,2)+bytes(16)+b'X'
body=b'\x41\1\x41\0\x41\2\x41\x10\x10\0\x41\x15\x47\x04\x40\0\x0b'
bad_iov=fixture('fd_write',b'\x7f'*4,b'\x7f',body)
bad_iov+=sec(11,b'\1\0\x41\0\x0b'+leb(len(data))+data)
fixtures['iovec-atomic-fault']=(bad_iov,0,b'wasi_exit=0')
# A known unimplemented function must link and return NOSYS.
fixtures['known-nosys']=(fixture('random_get',b'\x7f'*2,b'\x7f',
    b'\x41\0\x41\0\x10\0\x41\x34\x47\x04\x40\0\x0b'),0,b'wasi_exit=0')
def command(types=1, locals_count=0, nesting=0, pages=1):
    data=b'\0asm\1\0\0\0'+sec(1,leb(types)+b'\x60\0\0'*types)
    data+=sec(3,b'\1\0')+sec(5,b'\1\0'+leb(pages))
    data+=sec(7,b'\2'+string('memory')+b'\2\0'+string('_start')+b'\0\0')
    local=b'\1'+leb(locals_count)+b'\x7f' if locals_count else b'\0'
    body=local+b'\x02\x40'*nesting+b'\x0b'*nesting+b'\x0b'
    return data+sec(10,b'\1'+leb(len(body))+body)
for name, data in {
    'admission-types':command(types=1025),
    'admission-locals':command(locals_count=4097),
    'admission-nesting':command(nesting=129),
    'admission-memory':command(pages=257),
}.items(): fixtures[name]=(data,1,None)
for name,(data,code,err) in fixtures.items():
    path=OUT/(name+'.wasm');path.write_bytes(data);run(name,path,out=b'',code=code,err=err)
    if name.startswith('admission-'):
        assert b'WASI admission: Limit' in (OUT/(name+'.stderr')).read_bytes(), name
# A shared stdout/stderr quota must terminate an ignored-error hostcall loop.
# Both streaming (short writes) and buffered runners use this same oracle.
write=lambda fd: b'\x41'+bytes([fd])+b'\x41\0\x41\1\x41\x10\x10\0\x1a'
body=b'\x03\x40'+write(1)+write(2)+b'\x0c\0\x0b'
data=struct.pack('<II',32,1024)
quota=fixture('fd_write',b'\x7f'*4,b'\x7f',body)
quota+=sec(11,b'\1\0\x41\0\x0b'+leb(len(data))+data)
path=OUT/'output-limit.wasm';path.write_bytes(quota)
run('output-limit',path,code=1)
stdout=(OUT/'output-limit.stdout').read_bytes()
stderr=(OUT/'output-limit.stderr').read_bytes()
assert stdout == bytes(len(stdout)) and b'WASI output limit' in stderr
assert len(stdout)+stderr.count(b'\0') == 65536
module=ROOT/'target/coremark-wasi/coremark.wasm'
run('coremark-smoke',module,('0','0','0x66','1000'))
text=(OUT/'coremark-smoke.stdout').read_text()
assert all(crc in text for crc in ('seedcrc          : 0xe9f5', '[0]crclist       : 0xe714', '[0]crcmatrix     : 0x1fd7', '[0]crcstate      : 0x8e3a'))
# Short run validates the ABI/CRC path only; it is deliberately not a formal score.
(OUT/'results.json').write_text(json.dumps(dict(scope='host custom-platform WASI ABI; not VibeOS benchmark',runner=str(RUN),runner_sha256=hashlib.sha256(RUN.read_bytes()).hexdigest(),tests=results),indent=2)+'\n')
print(f'PASS {len(results)} cases; logs: {OUT}')
