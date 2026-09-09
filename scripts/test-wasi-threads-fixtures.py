#!/usr/bin/env python3
"""On-target wasi-threads lifecycle regression without wasi-sdk.

Boots an ordinary-limit `wasi-ssh-upload,wasmtime-command-fuel-batch,
wasmtime-threads` image (10 million fuel, 4 harts, icount) and drives the
generated wasi-threads fixtures, a prebuilt pthreads program, repeated short
pthread CoreMark runs and repeated worker faults over SSH. Every invocation
must report `reclaimed=true caps=0 waiters=0`; the interleaved fault/normal
runs are what exposed the retirement-versus-reclaim race. This is a subset of
scripts/test-wasi-qemu.py --threads that needs no compiler on the host.

usage: test-wasi-threads-fixtures.py KERNEL WORK FIXTURES_DIR THREADS_WASM COREMARK_THREADS_WASM
  FIXTURES_DIR: output of `cargo run -p vibeos-wasi-runtime --example fixtures -- DIR`
"""
import hashlib, importlib.util, json, os, re, shlex, socket, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if len(sys.argv) != 6:
    sys.exit(__doc__)
kernel, work, fixtures, pthreads, coremark = (Path(a).resolve() for a in sys.argv[1:6])
work.mkdir(parents=True, exist_ok=True)
spec = importlib.util.spec_from_file_location('peer', ROOT/'scripts/openssh-peer.py')
peer = importlib.util.module_from_spec(spec); sys.modules['peer'] = peer; spec.loader.exec_module(peer)
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
env = dict(os.environ, WASI_WORK_DIR=str(work), WASI_SSH_PORT=str(port), WASI_SKIP_BUILD='1', WASI_KERNEL=str(kernel),
           WASI_WASMTIME='1', WASI_FUEL_BATCH='1', WASI_THREADS='1')
log = open(work/'boot.log', 'wb')
vm = subprocess.Popen([str(ROOT/'scripts/run-wasi-qemu.sh')], cwd=ROOT, env=env, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT)
results = []
def boot_text():
    return (work/'boot.log').read_text(errors='replace')
try:
    end = time.monotonic()+300
    while 'vsh> ' not in boot_text():
        assert vm.poll() is None and time.monotonic() < end, 'boot failed'
        time.sleep(.5)
    command = peer._base_ssh_command('ssh', '127.0.0.1', port, 'vibe', work/'id_ed25519', work/'known_hosts', 30, None)
    def ssh(words, data=b'', timeout=120):
        before = (work/'boot.log').stat().st_size
        for attempt in range(4):
            p = subprocess.run([*command, shlex.join(words)], input=data, capture_output=True, timeout=timeout)
            if p.returncode == 255 and (b'kex_exchange_identification:' in p.stderr or b'not responding' in p.stderr):
                time.sleep(1); continue
            break
        # Wait for the reaper's lifecycle line before the next request; a
        # request that arrives earlier is refused as busy (75) by design.
        deadline = time.monotonic()+60
        while True:
            text = (work/'boot.log').read_bytes()[before:].decode(errors='replace')
            if 'terminal=' in text or words[0] != 'wasm-run' or time.monotonic() > deadline: break
            time.sleep(.1)
        time.sleep(.2)
        return p, (work/'boot.log').read_bytes()[before:].decode(errors='replace')
    def upload(name, data):
        p, _ = ssh(['wasm-upload', name, str(len(data)), hashlib.sha256(data).hexdigest()], data)
        assert p.returncode == 0, (name, p.returncode, p.stderr)
    def check(case, words, status, out=None, terminal=None):
        p, text = ssh(['wasm-run', *words])
        clean = 'reclaimed=true caps=0 waiters=0' in text and 'reclaimed=false' not in text
        ok = p.returncode == status and clean and (out is None or p.stdout == out) and (terminal is None or f'terminal={terminal}' in text)
        m = re.search(r'thread fuel checks=(\d+) continued=(\d+)', text)
        results.append(dict(case=case, status=p.returncode, expected=status, clean=clean, ok=ok,
                            terminal=re.findall(r'terminal=(\S+)', text), thread_fuel=m.groups() if m else None))
        print(json.dumps(results[-1]), flush=True)
        if not ok:
            # Ask vsh for the executor's view before tearing the VM down.
            before = (work/'boot.log').stat().st_size
            vm.stdin.write(b'ps\n'); vm.stdin.flush(); time.sleep(5)
            print('VSH PS:\n' + (work/'boot.log').read_bytes()[before:].decode(errors='replace'), flush=True)
        assert ok, (case, p.returncode, p.stdout[-300:], p.stderr[-300:], text[-1500:])
    for name, status in [('threads-atomics', 0), ('threads-counter', 0), ('threads-wait-timeout', 0), ('threads-exit', 7),
                         ('threads-spawn-cap', 3), ('threads-grow', 0), ('threads-fault', 125), ('threads-busy', 124),
                         ('threads-defined-shared', 126), ('threads-no-start', 126)]:
        upload(name+'.wasm', (fixtures/f'{name}.wasm').read_bytes())
        check(name, [name+'.wasm'], status)
    upload('c-threads.wasm', pthreads.read_bytes())
    check('pthreads', ['c-threads.wasm'], 0, b'sum=3000 cond=1\n')
    check('pthreads exit', ['c-threads.wasm', 'exit'], 7, b'')
    check('pthreads spawnmany', ['c-threads.wasm', 'spawnmany'], 0, b'eagain=1 created=3\n')
    upload('coremark.wasm', coremark.read_bytes())
    # Ordinary fuel: ~10 iterations per worker fit; the join hand-off races the
    # last fuel yield of each worker, which is the case the probe must survive.
    for cycle in range(12):
        check(f'coremark M3 x{cycle}', ['coremark.wasm', 'M3', '0', '0', '0x66', '3'], 0)
        check(f'coremark M2 x{cycle}', ['coremark.wasm', 'M2', '0', '0', '0x66', '3'], 0)
    for cycle in range(10):
        check(f'threads-fault x{cycle}', ['threads-fault.wasm'], 125)
        check(f'threads-counter x{cycle}', ['threads-counter.wasm'], 0)
    text = boot_text()
    used = [int(m, 16) for m in re.findall(r'harts_used=(0x[0-9a-f]+)', text)]
    assert used and max(bin(u).count('1') for u in used) >= 2, 'guest threads never ran on a second hart'
    assert 'reclaimed=false' not in text and 'panic' not in text.lower(), 'unclean lifecycle or panic in boot log'
    (work/'results.json').write_text(json.dumps(dict(kernel_sha256=hashlib.sha256(kernel.read_bytes()).hexdigest(),
        cases=results, invocations=text.count('reclaimed=true caps=0 waiters=0')), indent=2)+'\n')
    print(f'PASS {len(results)} cases, {text.count("reclaimed=true caps=0 waiters=0")} clean lifecycles', flush=True)
finally:
    vm.terminate(); vm.wait(timeout=10); log.close()
