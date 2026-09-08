#!/usr/bin/env python3
"""Run real-clock CoreMark via OpenSSH; retain every calibration and measurement."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]

def measurement(output, require_valid=True):
    text = output.decode()
    def field(name):
        return re.search(r'^' + re.escape(name) + r'\s*:\s*(\S+)', text, re.M)[1]
    result = dict(seconds=float(field('Total time (secs)')), iterations=int(field('Iterations')),
                  score=float(field('Iterations/Sec')), valid='Correct operation validated' in text)
    if require_valid:
        assert result['valid'] and result['seconds'] >= 10 and 'Errors detected' not in text, text
    return result

def instruction_diagnostic(output, seeds):
    text = output.decode()
    expected = ('0x18f2', '0xe3c1', '0x0747', '0x8d84') if seeds.startswith('0x3415') else ('0xe9f5', '0xe714', '0x1fd7', '0x8e3a')
    for name, crc in zip(('seedcrc', '[0]crclist', '[0]crcmatrix', '[0]crcstate'), expected):
        assert re.search(r'^' + re.escape(name) + r'\s*:\s*' + crc + r'\s*$', text, re.M), text
    errors = [line for line in text.splitlines() if 'ERROR' in line]
    assert all(line == 'ERROR! Must execute for at least 10 secs for a valid result!' for line in errors), text
    def field(name):
        return re.search(r'^' + re.escape(name) + r'\s*:\s*(\S+)', text, re.M)[1]
    result = dict(seconds=float(field('Total time (secs)')), iterations=int(field('Iterations')),
                  valid='Correct operation validated' in text)
    assert result['seconds'] > 0, 'diagnostic interval too short; increase --icount-iterations'
    assert len(errors) <= 1 and 'Cannot validate operation' not in text, text
    if errors:
        assert result['seconds'] < 10 and 'Errors detected' in text, text
    else:
        assert result['valid'] and 'Errors detected' not in text, text
    # Virtual-clock-derived work estimate, not elapsed real time or a rating.
    # CPU-bound intervals avoid idle warp; retain raw logs to inspect anomalies.
    return dict(mode='instruction-count-diagnostic', formal=False, crc_valid=True,
                iterations=result['iterations'], virtual_seconds=result['seconds'],
                estimated_instructions_per_iteration=result['seconds'] * 1e9 / result['iterations'])

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, default=ROOT/'target/coremark-benchmark/vibeos-single')
    parser.add_argument('--module', type=Path, default=ROOT/'target/coremark-wasi/coremark.wasm')
    parser.add_argument('--skip-build', action='store_true')
    parser.add_argument('--rv64-cache', action='store_true', help='Use the experimental WASI RV64 cache image')
    parser.add_argument('--kernel', type=Path, help='Run this existing firmware ELF (implies --skip-build)')
    parser.add_argument('--icount-iterations', type=int, help='Diagnostic only: fixed iterations with icount virtual time, never a formal score')
    args = parser.parse_args()
    if args.icount_iterations is not None and args.icount_iterations < 1:
        parser.error('--icount-iterations must be positive')
    os.chdir(ROOT)
    if args.kernel:
        args.kernel = args.kernel.resolve(strict=True)
        args.skip_build = True
    work = args.work.resolve(); work.mkdir(parents=True, exist_ok=True)
    (work/'results.json').write_text('[]\n')
    spec = importlib.util.spec_from_file_location('peer', ROOT/'scripts/openssh-peer.py')
    peer = importlib.util.module_from_spec(spec); sys.modules[spec.name] = peer; spec.loader.exec_module(peer)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    command = peer._base_ssh_command('ssh', '127.0.0.1', port, 'vibe', work/'id_ed25519', work/'known_hosts', 30, None)
    env = dict(os.environ, WASI_WORK_DIR=str(work), WASI_SSH_PORT=str(port), WASI_BENCHMARK='1', WASI_DIAGNOSTIC_ICOUNT=str(int(args.icount_iterations is not None)), WASI_SKIP_BUILD=str(int(args.skip_build)), WASI_RV64_CACHE=str(int(args.rv64_cache)))
    if args.kernel:
        env['WASI_KERNEL'] = str(args.kernel)
    else:
        env.pop('WASI_KERNEL', None)
    records = []
    def ssh(name, request, data=b''):
        for attempt in range(4):
            started = time.monotonic()
            p = subprocess.run([*command, request], input=data, capture_output=True, timeout=150)
            # Retry only failures occurring before authentication/request dispatch.
            if p.returncode == 255 and b'kex_exchange_identification:' in p.stderr:
                (work/f'{name}-preauth-{attempt}.stderr').write_bytes(p.stderr)
                time.sleep(1); continue
            break
        (work/f'{name}.stdout').write_bytes(p.stdout); (work/f'{name}.stderr').write_bytes(p.stderr)
        record = dict(name=name, command=request, exit=p.returncode, host_seconds=time.monotonic()-started)
        records.append(record)
        (work/'requests.json').write_text(json.dumps(records, indent=2)+'\n')
        assert p.returncode == 0, (record, p.stderr)
        time.sleep(1)
        return p.stdout
    def upload(path, name):
        data=path.read_bytes()
        ssh('upload-'+name, f'wasm-upload {name} {len(data)} {hashlib.sha256(data).hexdigest()}', data)
    log = open(work/'boot.log', 'wb')
    vm = subprocess.Popen([str(ROOT/'scripts/run-wasi-qemu.sh')], env=env, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline=time.monotonic()+360
        while 'vsh> ' not in (work/'boot.log').read_text(errors='replace'):
            assert vm.poll() is None and time.monotonic()<deadline, 'QEMU boot failed or timed out'
            time.sleep(.5)
        metadata = dict(qemu=subprocess.check_output(['qemu-system-riscv64','--version'],text=True),
            workspace_revision=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
            workspace_diff_sha256=hashlib.sha256(subprocess.check_output(['git','diff','HEAD'])).hexdigest(),
            kernel_origin='explicit ELF' if args.kernel else 'existing build' if args.skip_build else 'built by launcher',
            module_sha256=hashlib.sha256(args.module.read_bytes()).hexdigest(),
            kernel_sha256=hashlib.sha256((args.kernel or ROOT/'target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt').read_bytes()).hexdigest(),
            configuration=dict(machine='virt',cpu='rv64',harts=1,memory='1G',accel='tcg,thread=single',rtc='base=utc,clock=vm',icount='shift=0,align=off,sleep=off' if args.icount_iterations is not None else None,feature='wasi-benchmark,wasi-rv64-cache' if args.rv64_cache else 'wasi-benchmark'))
        metadata['measurement_mode'] = 'instruction-count-diagnostic' if args.icount_iterations is not None else 'formal-real-clock'
        (work/'environment.json').write_text(json.dumps(metadata,indent=2)+'\n')
        upload(args.module, 'coremark.wasm')
        clock = ROOT/'target/coremark-benchmark/clock.wasm'
        if clock.exists() and args.icount_iterations is None:
            upload(clock, 'clock.wasm'); ssh('clock', 'wasm-run clock.wasm')
        # Fixed short calibration avoids upstream auto calibration rounding below 10 s.
        if args.icount_iterations is None:
            calibration = measurement(ssh('calibration', 'wasm-run coremark.wasm 0 0 0x66 10'), False)
            assert calibration['seconds'] > 0, calibration
            iterations=max(1, math.ceil(20*calibration['iterations']/calibration['seconds']))
        else:
            iterations=args.icount_iterations
        samples=[]
        for name, seeds in [('performance-1','0 0 0x66'), ('performance-2','0 0 0x66'), ('performance-3','0 0 0x66'), ('validation','0x3415 0x3415 0x66')]:
            output=ssh(name, f'wasm-run coremark.wasm {seeds} {iterations}')
            sample=measurement(output) if args.icount_iterations is None else instruction_diagnostic(output, seeds)
            sample.update(name=name, seeds=seeds); samples.append(sample)
            (work/'results.json').write_text(json.dumps(samples,indent=2)+'\n')
            print(json.dumps(sample), flush=True)
        assert (work/'boot.log').read_text().count('reclaimed=true caps=0 waiters=0') >= sum(record['command'].startswith('wasm-run ') for record in records)
        profiles = re.findall(r'WASI profile polls=(\d+) fuel=(\d+) runtime_ticks=(\d+) wall_ticks=(\d+) hz=(\d+)', (work/'boot.log').read_text())
        if profiles:
            runs = [record for record in records if record['command'].startswith('wasm-run ')]
            assert len(profiles) == len(runs), 'incomplete runtime profile records'
            data = []
            for run, values in zip(runs, profiles):
                polls, fuel, runtime, wall, hz = map(int, values)
                assert 0 <= runtime <= wall and wall > 0 and hz > 0
                data.append(dict(name=run['name'], mode=metadata['measurement_mode'], polls=polls, fuel=fuel,
                    runtime_seconds=runtime/hz, invocation_seconds=wall/hz,
                    outside_poll_seconds=(wall-runtime)/hz, runtime_fraction=runtime/wall))
            (work/'profiles.json').write_text(json.dumps(data,indent=2)+'\n')
    finally:
        vm.terminate(); vm.wait(timeout=10); log.close()

if __name__ == '__main__': main()
