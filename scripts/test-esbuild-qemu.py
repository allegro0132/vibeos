#!/usr/bin/env python3
"""Run the pinned upstream esbuild WASI binary inside a fresh VibeOS QEMU image."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, default=ROOT / 'target/esbuild-qemu-acceptance')
    parser.add_argument('--module', type=Path,
                        default=ROOT / 'target/node-runtime/unpacked/esbuild/package/esbuild.wasm')
    parser.add_argument('--skip-build', action='store_true')
    args = parser.parse_args()
    os.chdir(ROOT)
    work = args.work.resolve()
    if work.exists():
        parser.error('use a fresh --work directory; previous evidence is never overwritten')
    tools = load('node_runtime', ROOT / 'scripts/node-runtime.py')
    lock = json.loads(tools.LOCK.read_text())
    module = args.module.resolve(strict=True)
    if tools.digest(module) != lock['artifacts']['esbuild']['module_sha256']:
        parser.error('module does not match the pinned official esbuild WASI artifact')
    work.mkdir(parents=True)
    rust, env = tools.rust_tools()
    if not args.skip_build:
        result = tools.check('build', [rust['cargo'], 'build', '--locked', '--offline',
            '--release', '--features', 'esbuild-wasi'], work,
            cwd=ROOT / 'firmware/qemu-virt', env=env, timeout=900)
        if result['exit_code']:
            return result['exit_code']
    kernel = ROOT / 'target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt'
    frozen = work / 'kernel.elf'
    frozen.write_bytes(kernel.read_bytes())
    with socket.socket() as connection:
        connection.bind(('127.0.0.1', 0))
        port = connection.getsockname()[1]
    env.update(WASI_ESBUILD='1', WASI_SKIP_BUILD='1', WASI_KERNEL=str(frozen),
               WASI_WORK_DIR=str(work), WASI_SSH_PORT=str(port),
               WASI_PYTHON='0', WASI_WASMTIME='0', WASI_RV64_CACHE='0',
               WASI_BENCHMARK='0', WASI_THREADS='0', WASI_FUEL_BATCH='0',
               WASI_DIAGNOSTIC_ICOUNT='0', WASI_TCG_THREAD='single')
    client = [sys.executable, str(ROOT / 'scripts/wasi-client.py'), '--esbuild',
              '--port', str(port), '--identity', str(work / 'id_ed25519'),
              '--known-hosts', str(work / 'known_hosts')]
    report = {'backend': 'VibeOS/QEMU/Wasmi', 'stage': 'esbuild transforms (not Node/V8)',
              'module_sha256': tools.digest(module), 'kernel_sha256': tools.digest(frozen),
              'repository_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
              'cases': [], 'status': 'RUNNING'}
    (work / 'repository-status.txt').write_bytes(subprocess.check_output(['git', 'status', '--short']))
    (work / 'source.patch').write_bytes(subprocess.check_output(['git', 'diff', '--binary', 'HEAD']))
    (work / 'submodules.txt').write_bytes(subprocess.check_output(['git', 'submodule', 'status']))
    (work / 'test-esbuild-qemu.py').write_bytes(Path(__file__).read_bytes())
    (work / 'sources.lock.json').write_bytes(tools.LOCK.read_bytes())
    (work / 'rustc-version.txt').write_bytes(subprocess.check_output([rust['rustc'], '-Vv']))
    (work / 'qemu-version.txt').write_bytes(subprocess.check_output(['qemu-system-riscv64', '--version']))
    log = work / 'qemu.log'

    def save():
        (work / 'results.json').write_text(json.dumps(report, indent=2) + '\n')

    def run(name, argv, data=b'', status=0, expected=None):
        started = time.monotonic()
        result = subprocess.run(client + ['run', 'esbuild.wasm', *argv], input=data,
                                capture_output=True, timeout=660)
        (work / f'{name}.stdout').write_bytes(result.stdout)
        (work / f'{name}.stderr').write_bytes(result.stderr)
        (work / f'{name}.stdin').write_bytes(data)
        case = {'case': name, 'argv': argv, 'exit_code': result.returncode,
                'seconds': round(time.monotonic() - started, 3),
                'stdin_sha256': hashlib.sha256(data).hexdigest()}
        report['cases'].append(case)
        save()
        if result.returncode != status:
            raise RuntimeError(f'{name}: exit {result.returncode}, expected {status}: {result.stderr[-2000:]!r}')
        if expected is not None and result.stdout != expected:
            raise RuntimeError(f'{name}: unexpected output {result.stdout[:2000]!r}')
        if status == 0 and result.stderr:
            raise RuntimeError(f'{name}: unexpected stderr {result.stderr[:2000]!r}')
        print(f'{name}: PASS ({case["seconds"]}s)', flush=True)
        return result

    save()
    qemu = None
    try:
        with log.open('wb') as output:
            qemu = subprocess.Popen(['sh', 'scripts/run-wasi-qemu.sh'], env=env,
                                    stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 120
        while b'vsh> ' not in log.read_bytes():
            if qemu.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('QEMU did not reach VSH; see qemu.log')
            time.sleep(.1)
        upload = subprocess.run(client + ['upload', str(module), '--name', 'esbuild.wasm'],
                                capture_output=True, timeout=660)
        (work / 'upload.stdout').write_bytes(upload.stdout)
        (work / 'upload.stderr').write_bytes(upload.stderr)
        if upload.returncode:
            raise RuntimeError(f'upload failed: {upload.stderr[-2000:]!r}')
        print('official esbuild module uploaded', flush=True)
        run('version', ['--version'], expected=b'0.25.0\n')
        source = b'const answer: number = 42; console.log(answer);\n'
        expected = b'const answer = 42;\nconsole.log(answer);\n'
        run('typescript', ['--loader=ts', '--format=cjs'], source, expected=expected)
        run('tsx', ['--loader=tsx', '--jsx-factory=h'],
            b'const view = <box value={42}/>; console.log(view);\n',
            expected=b'const view = /* @__PURE__ */ h("box", { value: 42 });\nconsole.log(view);\n')
        mapped = run('source-map', ['--loader=ts', '--sourcemap=inline', '--sourcefile=example.ts'], source)
        marker = b'//# sourceMappingURL=data:application/json;base64,'
        if marker not in mapped.stdout:
            raise RuntimeError('inline source map missing')
        source_map = json.loads(base64.b64decode(mapped.stdout.split(marker)[1].strip(), validate=True))
        if source_map.get('sourcesContent') != [source.decode()] or not source_map.get('mappings'):
            raise RuntimeError('source map does not contain original source and mappings')
        invalid = run('syntax-error', ['--loader=ts'], b'const value: = ;\n', status=1)
        if b'ERROR' not in invalid.stderr:
            raise RuntimeError('missing real compiler diagnostic')
        denied = run('no-ambient-files', ['--loader=ts', '--outfile=/outside.js'], source, status=1)
        if b'ERROR' not in denied.stderr:
            raise RuntimeError('missing denied-file diagnostic')
        run('reuse', ['--loader=ts', '--format=cjs'], source, expected=expected)
        deadline = time.monotonic() + 10
        while log.read_bytes().count(b'reclaimed=true caps=0 waiters=0') < len(report['cases']):
            if time.monotonic() >= deadline:
                raise RuntimeError('every invocation must reclaim its arena, capabilities and waiters')
            time.sleep(.1)
        report['reclaimed_invocations'] = log.read_bytes().count(b'reclaimed=true caps=0 waiters=0')
        peaks = re.findall(rb'WASI esbuild owner_peak_bytes=(\d+)', log.read_bytes())
        fuel = re.findall(rb'WASI esbuild fuel=(\d+) max_required_fuel=(\d+)', log.read_bytes())
        if len(peaks) != len(report['cases']) or len(fuel) != len(report['cases']):
            raise RuntimeError('missing per-invocation memory/fuel telemetry')
        for case, peak, (consumed, maximum) in zip(report['cases'], peaks, fuel):
            case.update(owner_peak_bytes=int(peak), consumed_fuel=int(consumed),
                        maximum_fuel_requirement=int(maximum))
        report['status'] = 'PASS'
        print('esbuild QEMU transform gate: PASS', flush=True)
        return 0
    except Exception as error:
        report['status'] = 'FAIL'
        report['error'] = str(error)
        print(str(error), file=sys.stderr)
        return 1
    finally:
        if qemu is not None:
            qemu.terminate()
            try:
                qemu.wait(timeout=10)
            except subprocess.TimeoutExpired:
                qemu.kill()
                qemu.wait()
        save()


if __name__ == '__main__':
    sys.exit(main())
