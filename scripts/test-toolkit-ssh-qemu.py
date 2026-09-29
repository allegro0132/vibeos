#!/usr/bin/env python3
"""Exercise Node, official tsc and adapted tsx through an authenticated OpenSSH PTY."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('vtop_ssh', ROOT / 'scripts/qemu-vtop-ssh-test.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
peer = helper.peer

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    if not work.is_relative_to(ROOT / 'target') or work.exists():
        parser.error('--work must be a fresh directory under target')
    work.mkdir(parents=True)
    kernel = work / 'kernel.elf'
    shutil.copy2(args.kernel, kernel)
    with (work / 'project.raw').open('wb') as f:
        f.truncate(128 * 1024 * 1024)
    subprocess.run(['python3', str(ROOT / 'scripts/openssh-test-key.py'), '--fixture',
                    'accepted', '--output', str(work / 'id_ed25519')], check=True,
                    stdout=subprocess.DEVNULL)
    port = peer.pick_loopback_port()
    peer.write_expected_known_hosts(work / 'known_hosts', '127.0.0.1', port)
    command = ['qemu-system-riscv64', '-machine', 'virt', '-cpu', 'rv64', '-smp', '4', '-m', '1G',
        '-nographic', '-bios', 'default', '-kernel', str(kernel),
        '-object', 'rng-random,id=rng,filename=/dev/urandom',
        '-device', 'virtio-rng-device,rng=rng,bus=virtio-mmio-bus.1',
        '-netdev', f'user,id=net,net=10.0.2.0/24,host=10.0.2.2,restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:{port}-10.0.2.15:2222',
        '-device', 'virtio-net-device,netdev=net,bus=virtio-mmio-bus.0,mac=02:00:00:00:00:01',
        '-drive', f'if=none,id=project,format=raw,file={work / "project.raw"},cache=writeback',
        '-device', 'virtio-blk-device,drive=project,bus=virtio-mmio-bus.2,queue-size=8',
        '-global', 'virtio-mmio.force-legacy=false']
    report = dict(passed=False, command=command,
                  kernel_sha256=hashlib.sha256(kernel.read_bytes()).hexdigest(), checks={})
    inputs = [ROOT / 'services/file-store/src/lib.rs'] + [Path(__file__), ROOT / 'kernel/src/ssh_platform.rs', ROOT / 'kernel/src/vsh_platform.rs',
              ROOT / 'kernel/src/segment_store_platform.rs', ROOT / 'components/sshd/src/lib.rs']
    inputs += sorted((ROOT / 'kernel/src').glob('native_*.rs'))
    inputs += sorted((ROOT / 'tools/node-runtime/runtime').glob('node-*'))
    inputs += sorted((ROOT / 'tools/node-runtime/toolkit').glob('*.*'))
    report['source_sha256'] = {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    started = time.monotonic()
    terminal = None
    with (work / 'serial.log').open('wb') as log:
        vm = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        try:
            peer.wait_for_vsh(work / 'serial.log', vm, timeout=60)
            deadline = time.monotonic() + 30
            while b'ssh-test listening' not in (work / 'serial.log').read_bytes():
                if time.monotonic() >= deadline or vm.poll() is not None:
                    raise AssertionError('SSH listener not ready')
                time.sleep(0.1)
            base = peer.vsh_ssh_command(port, work)
            terminal = helper.Terminal(base[:-1] + ['-tt', base[-1]])
            terminal.expect(b'vsh> ', timeout=45)
            def execute(command, marker, timeout=30):
                start = terminal.send(command.encode() + b'\r')
                terminal.expect(marker.encode(), start, timeout=timeout)
                terminal.expect(b'vsh> ', start + bytes(terminal.data[start:]).index(marker.encode()) + len(marker), timeout=30)
                report['checks'][marker] = True
            # Prepare project data inside the explicitly granted home root.
            execute('node --root @home -e "require(\'fs\').mkdirSync(\'ssh-project\'); console.log(\'SSH_NODE_\' + \'SETUP=ok\')"', 'SSH_NODE_SETUP=ok')
            execute('node --root @home/ssh-project -e "console.log(\'SSH_NODE_\' + \'EVAL=42\')"', 'SSH_NODE_EVAL=42')
            execute('echo wire-input | node --root @home/ssh-project -e "let s=\'\'; process.stdin.on(\'data\',x=>s+=x); process.stdin.on(\'end\',()=>console.log(\'SSH_NODE_\'+\'STDIN=\'+s.trim()))"', 'SSH_NODE_STDIN=wire-input')
            execute('node --root @home/ssh-project -e "process.exit(7)"', 'Returned(7)')
            start = terminal.send(b'node --root @home/ssh-project -e "require(\'fs\').writeFileSync(\'cpu-entered\',\'yes\'); console.log(\'SSH_NODE_\'+\'CPU_READY\'); for(;;){}"\r')
            # Existing SSH/VSH captures output until command completion.
            # Give the command a turn, then interrupt it through the real PTY.
            time.sleep(1)
            start = terminal.send(b'\x03')
            terminal.expect(b'Cancelled', start)
            terminal.expect(b'vsh> ', start)
            time.sleep(0.3)
            execute('node --root @home/ssh-project -e "if(require(\'fs\').readFileSync(\'cpu-entered\',\'utf8\')!==\'yes\')throw Error(\'loop not reached\'); console.log(\'SSH_NODE_\'+\'AFTER_CANCEL=ok\')"', 'SSH_NODE_AFTER_CANCEL=ok')
            report['checks']['remote_ctrl_c'] = True
            execute('node --root @home/ssh-project -e \'require("fs").writeFileSync("main.ts","export const value: number = 42; console.log(\\"SSH_TSX_\\" + \\"OK=\\" + value);");console.log("SSH_TOOL_"+"SOURCE=ok")\'', 'SSH_TOOL_SOURCE=ok', timeout=30)
            execute('node --root @home/ssh-project -e \'require("fs").writeFileSync("tsconfig.json","{\\"compilerOptions\\":{\\"target\\":\\"ES2020\\",\\"module\\":\\"commonjs\\",\\"outDir\\":\\"dist\\",\\"declaration\\":true},\\"include\\":[\\"main.ts\\"]}");console.log("SSH_TOOL_"+"CONFIG=ok")\'', 'SSH_TOOL_CONFIG=ok', timeout=30)
            execute('tsc --root @home/ssh-project --version', 'Version 5.9.3', timeout=60)
            execute('if tsc --root @home/ssh-project -p tsconfig.json; then node --root @home/ssh-project -e "if(!require(\'fs\').readFileSync(\'dist/main.d.ts\',\'utf8\').includes(\'value: number\'))throw Error(\'declaration\'); console.log(\'SSH_TSC_\'+\'EMIT=ok\')"; fi', 'SSH_TSC_EMIT=ok', timeout=240)
            execute('node --root @home/ssh-project dist/main.js', 'SSH_TSX_OK=42', timeout=30)
            report['checks']['emitted_js_executed'] = True
            execute('tsx --root @home/ssh-project main.ts', 'SSH_TSX_OK=42', timeout=180)
            report['checks']['tsx_executed'] = True
            report['passed'] = True
        except Exception as error:
            report['error'] = str(error)
        finally:
            if terminal:
                (work / 'ssh-pty.log').write_bytes(terminal.data)
                terminal.close()
            if vm.poll() is None:
                vm.terminate()
            try:
                vm.wait(timeout=5)
            except subprocess.TimeoutExpired:
                vm.kill(); vm.wait()
            serial = (work / 'serial.log').read_text(errors='replace').lower()
            report['checks']['no_fatal'] = all(s not in serial for s in ('native fatal', 'fatal trap', 'panicked'))
            report['passed'] &= all(report['checks'].values())
            report['seconds'] = time.monotonic() - started
            report['checks']['source_unchanged'] = all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in report['source_sha256'].items())
            report['passed'] &= report['checks']['source_unchanged']
            (work / 'results.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
