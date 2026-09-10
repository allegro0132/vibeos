#!/usr/bin/env python3
"""Disconnect the SSH client while a pthread CoreMark run is in progress on a
`wasi-benchmark,wasmtime-command-fuel-batch,wasmtime-threads` image (long fuel
budget), then require the job to end as Cancelled with a clean lifecycle within
30 seconds and the service to accept the next run. A main thread parked in
`memory.atomic.wait` for its join used to sleep forever here.

usage: test-wasi-threads-disconnect.py KERNEL WORK [rounds]
"""
import hashlib, importlib.util, os, re, shlex, socket, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if len(sys.argv) < 3:
    sys.exit(__doc__)
kernel, work = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 3
work.mkdir(parents=True, exist_ok=True)
spec = importlib.util.spec_from_file_location('peer', ROOT/'scripts/openssh-peer.py')
peer = importlib.util.module_from_spec(spec); sys.modules['peer'] = peer; spec.loader.exec_module(peer)
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
env = dict(os.environ, WASI_WORK_DIR=str(work), WASI_SSH_PORT=str(port), WASI_BENCHMARK='1', WASI_HARTS='4', WASI_TCG_THREAD='multi',
           WASI_SKIP_BUILD='1', WASI_KERNEL=str(kernel), WASI_WASMTIME='1', WASI_FUEL_BATCH='1', WASI_THREADS='1')
log = open(work/'boot.log', 'wb')
vm = subprocess.Popen([str(ROOT/'scripts/run-wasi-qemu.sh')], cwd=ROOT, env=env, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT)
def text(before=0): return re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', (work/'boot.log').read_bytes()[before:].decode(errors='replace'))
def wait_for(marker, before, timeout):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        if marker in text(before): return True
        time.sleep(.2)
    return False
ok = True
try:
    peer.wait_for_vsh(work/'boot.log', vm)
    command = peer.vsh_ssh_command(port, work)
    data = (ROOT/'target/coremark-wasi/coremark-threads.wasm').read_bytes()
    p = peer.run_ssh_retrying(command, shlex.join(['wasm-upload', 'coremark.wasm', str(len(data)), hashlib.sha256(data).hexdigest()]), data, 120)
    assert p.returncode == 0, p.stderr
    for round in range(rounds):
        for workers in (3, 2):
            for attempt in range(4):
                before = (work/'boot.log').stat().st_size
                client = subprocess.Popen([*command, shlex.join(['wasm-run', 'coremark.wasm', f'M{workers}', '0', '0', '0x66', '200000'])], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                client.stdin.close()
                if wait_for('WASI running backend=wasmtime', before, 60): break
                # Pre-session SSH failures are transport noise, not evidence.
                client.kill(); client.wait(); time.sleep(2)
            else:
                raise AssertionError('run never started')
            time.sleep(3)
            client.kill(); client.wait()
            since = (work/'boot.log').stat().st_size
            finished = wait_for('terminal=', before, 30)
            tail = text(before)
            clean = 'terminal=Cancelled reclaimed=true caps=0 waiters=0' in tail
            print(f'round {round} M{workers}: finished_within_30s={finished} clean_cancel={clean} :: ' + ' | '.join(l.strip() for l in tail.splitlines() if 'terminal=' in l or 'unclean' in l), flush=True)
            ok &= finished and clean
            if not finished: break
            time.sleep(1)
            before = (work/'boot.log').stat().st_size
            p = subprocess.run([*command, shlex.join(['wasm-run', 'coremark.wasm', 'M2', '0', '0', '0x66', '100'])], input=b'', capture_output=True, timeout=300)
            wait_for('terminal=', before, 30)
            follow = 'terminal=Exited(0) reclaimed=true caps=0 waiters=0' in text(before)
            print(f'  follow-up run exit={p.returncode} clean={follow}', flush=True)
            ok &= p.returncode == 0 and follow
        if not ok: break
    print('PASS' if ok else 'FAIL', flush=True)
finally:
    vm.terminate(); vm.wait(timeout=10); log.close()
sys.exit(0 if ok else 1)
