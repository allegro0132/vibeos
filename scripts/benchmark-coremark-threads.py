#!/usr/bin/env python3
"""Same upstream pthread CoreMark module on VibeOS and Debian RV64 Wasmtime.

Each invocation uses M1/M2/M3 (worker count, plus a waiting main thread).
Run platforms sequentially on an otherwise idle host. Raw output is retained.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import pty
import re
import select
import shutil
import socket
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def parse(text, workers, formal=True):
    def field(label):
        match = re.search(r'^' + re.escape(label) + r'\s*:\s*(\S+)', text, re.M)
        assert match, (label, text)
        return match[1]
    row = dict(seconds=float(field('Total time (secs)')),
               iterations=int(field('Iterations')), score=float(field('Iterations/Sec')),
               workers=int(field('Parallel PThreads')))
    assert row['workers'] == workers and row['seconds'] > 0, text
    assert row['iterations'] % workers == 0, text
    for index in range(workers):
        for kind in ('crclist', 'crcmatrix', 'crcstate', 'crcfinal'):
            assert re.search(r'^\[' + str(index) + r'\]' + kind + r'\s*:', text, re.M), text
    errors = [line for line in text.splitlines() if 'ERROR' in line]
    assert all(line == 'ERROR! Must execute for at least 10 secs for a valid result!' for line in errors), text
    assert 'Cannot validate operation' not in text, text
    if formal:
        assert row['seconds'] >= 10 and 'Correct operation validated' in text and not errors, text
    row['valid'] = 'Correct operation validated' in text and not errors
    return row


class Serial:
    def __init__(self, command, work):
        self.master, slave = pty.openpty()
        self.log = open(work / 'boot.log', 'wb')
        self.vm = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        self.pending = b''

    def expect(self, token, timeout=300):
        end = time.monotonic() + timeout
        while token not in self.pending:
            assert self.vm.poll() is None and time.monotonic() < end, (token, self.pending[-3000:])
            if select.select([self.master], [], [], 1)[0]:
                data = os.read(self.master, 65536)
                self.log.write(data); self.log.flush(); self.pending += data
        before, self.pending = self.pending.split(token, 1)
        return before

    def command(self, text, timeout=300):
        os.write(self.master, (text + '; rc=$?; printf "\\nCOREMARK_DONE=%s\\n" "$rc"\n').encode())
        self.expect(b'COREMARK_DONE=', timeout)
        code = self.expect(b'\r\n', 30).strip()
        assert code == b'0', (text, code)

    def close(self):
        self.vm.terminate(); self.vm.wait(timeout=10)
        os.close(self.master); self.log.close()


def measure(run, work, args):
    iterations = {}
    rows = []
    diagnostic = args.icount_iterations is not None
    for workers in args.workers:
        if diagnostic:
            # Instruction-count virtual time: fixed work, no calibration, no rating.
            iterations[workers] = args.icount_iterations
            continue
        output = run(f'calibration-m{workers}', workers, '0 0 0x66', 1000)
        row = parse(output, workers, False)
        iterations[workers] = max(1, math.ceil(args.seconds * 1000 / row['seconds']))
    # Interleave worker counts so an entire configuration does not occupy one
    # thermal/frequency window. Validation uses the second upstream seed set.
    for sample in [f'performance-{n+1}' for n in range(args.samples)] + ['validation']:
        seeds = '0x3415 0x3415 0x66' if sample == 'validation' else '0 0 0x66'
        for workers in args.workers:
            name = f'{sample}-m{workers}'
            output = run(name, workers, seeds, iterations[workers])
            row = parse(output, workers, not diagnostic)
            assert row['iterations'] == iterations[workers] * workers
            row.update(name=name, seeds=seeds, iterations_per_worker=iterations[workers])
            if diagnostic:
                # Virtual seconds are an instruction-count estimate, not elapsed time.
                row.update(formal=False, mode='instruction-count-diagnostic', virtual_seconds=row.pop('seconds'))
            rows.append(row); save(work / 'results.json', rows)
            print(json.dumps(dict(platform=args.platform, **row)), flush=True)
    medians = {n: statistics.median(r['score'] for r in rows if r['workers'] == n and r['name'].startswith('performance')) for n in args.workers}
    key = 'median_virtual_iterations_per_second' if diagnostic else 'median_score'
    save(work / 'summary.json', [dict(workers=n, formal=not diagnostic, **{key: value}, speedup=value/medians[1]) for n, value in medians.items()])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('platform', choices=['vibeos', 'debian'])
    p.add_argument('--work', required=True, type=Path)
    p.add_argument('--module', type=Path, default=ROOT/'target/coremark-wasi/coremark-threads.wasm')
    p.add_argument('--kernel', type=Path, help='Explicit VibeOS wasi-benchmark,wasmtime-threads ELF')
    p.add_argument('--thread-fixture', type=Path, help='Optional tests/wasi/threads.c Wasm for capacity check')
    p.add_argument('--debian-image', type=Path)
    p.add_argument('--debian-kernel', type=Path)
    p.add_argument('--debian-initrd', type=Path)
    p.add_argument('--wasmtime', type=Path, help='RV64 Linux wasmtime-threads runner')
    p.add_argument('--official-cli', action='store_true', help='Reproduce official CLI compatibility controls instead of the library runner')
    p.add_argument('--harts', type=int, choices=[1, 2, 4], default=4)
    p.add_argument('--cpu', default='rv64', help='Identical QEMU CPU model for both platforms')
    p.add_argument('--workers', nargs='+', type=int, choices=[1, 2, 3, 4], default=[1, 2, 3])
    p.add_argument('--samples', type=int, default=3)
    p.add_argument('--seconds', type=float, default=20)
    p.add_argument('--debian-fuel', action='store_true', help='100 billion fuel per store; not VibeOS async scheduling')
    p.add_argument('--native-debian', action='store_true', help='Compile the same upstream POSIX pthread sources with Debian GCC -O3')
    p.add_argument('--prepare-sysroot', action='store_true', help='Debian only: install build dependencies and export sysroot, without measuring')
    p.add_argument('--fuel-batch', action='store_true', help='VibeOS kernel was built with wasmtime-command-fuel-batch: record it and require its per-thread evidence')
    p.add_argument('--icount-iterations', type=int, help='VibeOS diagnostic only: fixed iterations per worker under icount virtual time and single-thread TCG; never a formal score')
    args = p.parse_args()
    if args.native_debian and (args.platform != 'debian' or args.debian_fuel or args.official_cli or args.prepare_sysroot):
        p.error('--native-debian requires debian and excludes fuel/CLI/sysroot modes')
    if args.prepare_sysroot and args.platform != 'debian':
        p.error('--prepare-sysroot requires debian')
    if args.seconds < 15 or args.samples < 1 or 1 not in args.workers:
        p.error('require >=15 seconds, >=1 sample, and M1 for speedup')
    if args.icount_iterations is not None and (args.platform != 'vibeos' or args.icount_iterations < 1):
        p.error('--icount-iterations requires vibeos and a positive count')
    work = args.work.resolve(); work.mkdir(parents=True, exist_ok=True)
    if (work/'results.json').exists() or (work/'boot.log').exists():
        p.error('choose a fresh work directory to preserve evidence')
    shutil.copy2(__file__, work/'measurement-script.py')
    args.module = args.module.resolve(strict=True)
    metadata = dict(platform=args.platform, module_sha256=digest(args.module),
        qemu=subprocess.check_output(['qemu-system-riscv64', '--version'], text=True),
        revision=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        tracked_diff_sha256=hashlib.sha256(subprocess.check_output(['git', 'diff', 'HEAD'], cwd=ROOT)).hexdigest(),
        script_sha256=digest(__file__), configuration=dict(cpu=args.cpu, machine='virt', memory='1G',
            harts=args.harts, accel='tcg,thread=multi', rtc='base=utc,clock=vm', icount=None),
        samples=args.samples, target_seconds=args.seconds, workers=args.workers)
    if args.platform == 'debian':
        for name in ['debian_image', 'debian_kernel', 'debian_initrd'] + ([] if args.prepare_sysroot or args.native_debian else ['wasmtime']):
            path = getattr(args, name)
            if not path: p.error(f'--{name.replace("_", "-")} required')
            path = path.resolve(strict=True); setattr(args, name, path)
            metadata[name + '_sha256'] = digest(path)
        inputs = work/'inputs'; inputs.mkdir()
        shutil.copy2(args.module, inputs/'coremark.wasm')
        if args.native_debian:
            source = ROOT/'target/coremark-upstream'
            revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
            assert revision == '1f483d5b8316753a742cbf5590caf5bd0a4e4777'
            subprocess.run(['git', '-C', str(source), 'diff', '--exit-code', 'HEAD'], check=True, stdout=subprocess.DEVNULL)
            shutil.copytree(source, inputs/'source', ignore=shutil.ignore_patterns('.git'))
            metadata['coremark_revision'] = revision
            metadata['source_sha256'] = {str(f.relative_to(inputs/'source')): digest(f)
                for f in sorted((inputs/'source').rglob('*')) if f.is_file()}
        elif not args.prepare_sysroot:
            shutil.copy2(args.wasmtime, inputs/'wasmtime')
        subprocess.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(args.debian_image), str(work/'disk.qcow2')], check=True)
        command = ['qemu-system-riscv64', '-machine', 'virt', '-cpu', args.cpu, '-smp', str(args.harts),
            '-m', '1G', '-accel', 'tcg,thread=multi', '-rtc', 'base=utc,clock=vm', '-nographic', '-bios', 'default',
            '-kernel', str(args.debian_kernel), '-initrd', str(args.debian_initrd),
            '-append', 'root=/dev/vda1 rw console=ttyS0 systemd.firstboot=off systemd.debug_shell=ttyS0 systemd.mask=serial-getty@ttyS0.service',
            '-drive', f'if=none,id=disk,format=qcow2,file={work}/disk.qcow2', '-device', 'virtio-blk-device,drive=disk',
            '-virtfs', f'local,path={inputs},mount_tag=inputs,security_model=none,readonly=on',
            '-virtfs', f'local,path={work},mount_tag=results,security_model=none', '-global', 'virtio-mmio.force-legacy=false']
        metadata['fuel'] = 100_000_000_000 if args.debian_fuel else None
        metadata['runner'] = 'native-pthreads' if args.native_debian else 'sysroot-preparation' if args.prepare_sysroot else 'official-cli' if args.official_cli else 'std-linux-threads'
        if args.prepare_sysroot:
            command += ['-netdev', 'user,id=net,ipv6=off', '-device', 'virtio-net-device,netdev=net']
        save(work/'qemu-command.json', command); save(work/'environment.json', metadata)
        serial = Serial(command, work)
        try:
            serial.expect(b'# ')
            os.write(serial.master, b'stty -echo\n'); serial.expect(b'# ', 30)
            serial.command('timeout 60 systemctl is-system-running --wait >/dev/null || true')
            serial.command('mkdir -p /mnt/inputs /mnt/results; mount -t 9p -o trans=virtio,version=9p2000.L,ro inputs /mnt/inputs; mount -t 9p -o trans=virtio,version=9p2000.L results /mnt/results')
            serial.command('{ uname -a; cat /etc/os-release; cat /proc/cpuinfo; } > /mnt/results/guest-environment.txt')
            if args.prepare_sysroot:
                serial.command('apt-get update > /mnt/results/apt.log 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc libc6-dev >> /mnt/results/apt.log 2>&1', 900)
                serial.command("tar -C / --exclude='usr/include/linux/netfilter*' -cf /mnt/results/sysroot.tar usr/lib/riscv64-linux-gnu usr/lib/gcc usr/include", 300)
                serial.command('sync')
                return
            if args.native_debian:
                build = '''set -eu
mkdir -p /root/coremark-threads
cp -r /mnt/inputs/source/. /root/coremark-threads/
cd /root/coremark-threads
cc -O3 -pthread -DMULTITHREAD=4 -DUSE_PTHREAD=1 -DITERATIONS=1 '-DFLAGS_STR="-O3 -pthread -DMULTITHREAD=4 -DUSE_PTHREAD=1 -DITERATIONS=1"' '-DMEM_LOCATION="Debian process memory"' -I. -Iposix core_list_join.c core_main.c core_matrix.c core_state.c core_util.c posix/core_portme.c -o /root/coremark-native
cp /root/coremark-native /mnt/results/coremark-native
{ cc --version; sha256sum /root/coremark-native; dpkg-query -W gcc libc6 libc6-dev; } >> /mnt/results/guest-environment.txt
'''
                (work/'native-build.sh').write_text(build)
                serial.command('sh /mnt/results/native-build.sh > /mnt/results/native-build.log 2>&1')
            else:
                serial.command('cp /mnt/inputs/wasmtime /root/wasmtime; chmod +x /root/wasmtime; cp /mnt/inputs/coremark.wasm /root/coremark.wasm')
                serial.command('/root/wasmtime --version >> /mnt/results/guest-environment.txt')
            if args.official_cli:
                serial.command('/root/wasmtime run -W help > /mnt/results/wasmtime-wasm-options.txt 2>&1')
            def run(name, workers, seeds, iterations):
                if args.official_cli:
                    fuel = ' -W fuel=100000000000' if args.debian_fuel else ''
                    runner = f'/root/wasmtime run -W threads=y -S threads=y{fuel}'
                else:
                    runner = '/root/wasmtime' + (' --fuel' if args.debian_fuel else '')
                cmd = f'/root/coremark-native M{workers} {seeds} {iterations}' if args.native_debian else f'{runner} /root/coremark.wasm M{workers} {seeds} {iterations}'
                (work/f'{name}.command').write_text(cmd+'\n')
                serial.command(f'{cmd} > /mnt/results/{name}.stdout 2> /mnt/results/{name}.stderr', 300)
                if not args.official_cli and not args.native_debian:
                    evidence = (work/f'{name}.stderr').read_text()
                    spawned = re.search(r'scheduler=os-threads .*spawned=(\d+)', evidence)
                    assert spawned and int(spawned[1]) == workers, evidence
                return (work/f'{name}.stdout').read_text()
            measure(run, work, args)
            serial.command('sync')
        finally:
            serial.close()
    else:
        if not args.kernel: p.error('--kernel required')
        shutil.copy2(args.kernel.resolve(strict=True), work/'kernel.elf')
        metadata['kernel_sha256'] = digest(work/'kernel.elf')
        metadata['features'] = 'wasi-benchmark,wasmtime-command-fuel-batch,wasmtime-threads' if args.fuel_batch else 'wasi-benchmark,wasmtime-threads'
        if args.icount_iterations is not None:
            metadata['measurement_mode'] = 'instruction-count-diagnostic'
            metadata['configuration'].update(accel='tcg,thread=single', icount='shift=0,align=off,sleep=off')
        metadata['capacity_probe'] = bool(args.thread_fixture)
        if args.thread_fixture:
            metadata['capacity_probe_sha256'] = digest(args.thread_fixture)
        save(work/'environment.json', metadata)
        spec = importlib.util.spec_from_file_location('coremark_peer', ROOT/'scripts/openssh-peer.py')
        peer = importlib.util.module_from_spec(spec); sys.modules[spec.name] = peer; spec.loader.exec_module(peer)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        env = dict(os.environ, WASI_WORK_DIR=str(work), WASI_SSH_PORT=str(port), WASI_BENCHMARK='1',
            WASI_WASMTIME='1', WASI_THREADS='1', WASI_SKIP_BUILD='1', WASI_KERNEL=str(work/'kernel.elf'),
            WASI_HARTS=str(args.harts), WASI_CPU=args.cpu, WASI_TCG_THREAD='single' if args.icount_iterations is not None else 'multi',
            WASI_DIAGNOSTIC_ICOUNT=str(int(args.icount_iterations is not None)), WASI_FUEL_BATCH=str(int(args.fuel_batch)), WASI_RV64_CACHE='0')
        save(work/'launcher-environment.json', {k:v for k,v in env.items() if k.startswith('WASI_')})
        log = open(work/'boot.log', 'wb')
        vm = subprocess.Popen([str(ROOT/'scripts/run-wasi-qemu.sh')], cwd=ROOT, env=env, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT)
        try:
            end = time.monotonic()+300
            while 'vsh> ' not in (work/'boot.log').read_text(errors='replace'):
                assert vm.poll() is None and time.monotonic()<end, 'VibeOS boot failed'
                time.sleep(.5)
            command = peer._base_ssh_command('ssh', '127.0.0.1', port, 'vibe', work/'id_ed25519', work/'known_hosts', 30, None)
            def request(name, cmd, data=b''):
                (work/f'{name}.command').write_text(cmd+'\n')
                started = time.monotonic()
                for attempt in range(4):
                    result = subprocess.run([*command, cmd], input=data, capture_output=True, timeout=300)
                    if result.returncode != 255 or b'kex_exchange_identification:' not in result.stderr: break
                    (work/f'{name}-preauth-{attempt}.stderr').write_bytes(result.stderr); time.sleep(1)
                (work/f'{name}.stdout').write_bytes(result.stdout); (work/f'{name}.stderr').write_bytes(result.stderr)
                save(work/f'{name}.request.json', dict(exit=result.returncode, host_seconds=time.monotonic()-started))
                assert result.returncode == 0, (name, result.returncode, result.stderr)
                time.sleep(1)
                return result.stdout.decode()
            data = args.module.read_bytes()
            request('upload', f'wasm-upload coremark.wasm {len(data)} {digest(args.module)}', data)
            profile_offset = 0
            if args.thread_fixture:
                data = args.thread_fixture.read_bytes()
                request('upload-fixture', f'wasm-upload threads.wasm {len(data)} {digest(args.thread_fixture)}', data)
                output = request('capacity', 'wasm-run threads.wasm spawnmany')
                assert 'eagain=1 created=3' in output, output
                profile_offset = 1
            profiles = []
            def run(name, workers, seeds, iterations):
                output = request(name, f'wasm-run coremark.wasm M{workers} {seeds} {iterations}')
                boot = (work/'boot.log').read_text()
                matches = re.findall(r'WASI Wasmtime threads spawned=(\d+) harts_used=(0x[0-9a-f]+)', boot)
                assert len(matches) == profile_offset+len(profiles)+1, 'missing per-invocation thread evidence'
                spawned, mask = matches[-1]
                assert int(spawned) == workers, matches[-1]
                assert int(mask, 16).bit_count() == min(workers, args.harts), matches[-1]
                assert boot.count('reclaimed=true caps=0 waiters=0') >= len(matches), 'missing cleanup evidence'
                profile = dict(name=name, spawned=int(spawned), harts_used=mask)
                if args.fuel_batch:
                    # The hook must be present. With ready peers (notably more
                    # workers than harts), every boundary may correctly yield.
                    fuel = re.findall(r'WASI Wasmtime thread fuel checks=(\d+) continued=(\d+) max_batch=32', boot)
                    assert len(fuel) == len(matches), 'missing per-thread fuel batching evidence'
                    checks, continued = map(int, fuel[-1])
                    assert 0 <= continued < checks, fuel[-1]
                    profile.update(thread_fuel_checks=checks, thread_fuel_continued=continued)
                profiles.append(profile)
                save(work/'thread-profiles.json', profiles)
                return output
            measure(run, work, args)
            assert 'WASI running backend=wasmtime' in (work/'boot.log').read_text()
        finally:
            vm.terminate(); vm.wait(timeout=10); log.close()


if __name__ == '__main__':
    main()
