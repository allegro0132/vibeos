#!/usr/bin/env python3
"""Boot Debian RISC-V under QEMU TCG and measure native CoreMark via serial."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
REVISION = '1f483d5b8316753a742cbf5590caf5bd0a4e4777'

GUEST = r'''#!/bin/sh
set -eu
systemctl is-system-running --wait || true
mountpoint -q /mnt/coremark || mount -t 9p -o trans=virtio,version=9p2000.L,ro coremark /mnt/coremark
mountpoint -q /mnt/results || mount -t 9p -o trans=virtio,version=9p2000.L results /mnt/results
export DEBIAN_FRONTEND=noninteractive
apt-get update > /mnt/results/apt.log 2>&1
apt-get install -y --no-install-recommends gcc libc6-dev make >> /mnt/results/apt.log 2>&1
mkdir -p /root/coremark
cp -r /mnt/coremark/source/. /root/coremark/
cd /root/coremark
cc -O3 -DITERATIONS=1 '-DFLAGS_STR="-O3 -DITERATIONS=1"' '-DMEM_LOCATION="Debian process memory"' -I. -Iposix core_list_join.c core_main.c core_matrix.c core_state.c core_util.c posix/core_portme.c -o coremark
{ uname -a; cat /etc/os-release; cc --version; lscpu; sha256sum coremark; sha256sum *.c *.h posix/core_portme.*; dpkg-query -W gcc gcc-14 libc6 libc6-dev linux-image-riscv64; } > /mnt/results/environment.txt
./coremark 0 0 0x66 1000 > /mnt/results/calibration.stdout
seconds=$(awk '/Total time \(secs\)/ {print $NF}' /mnt/results/calibration.stdout)
iterations=$(awk -v t="$seconds" 'BEGIN {if (t<=0) exit 1; printf "%d\n", (20000/t)+1}')
for sample in performance-1 performance-2 performance-3 validation; do
  case "$sample" in validation) seeds='0x3415 0x3415 0x66';; *) seeds='0 0 0x66';; esac
  ./coremark $seeds "$iterations" > "/mnt/results/$sample.stdout" 2> "/mnt/results/$sample.stderr"
  cat "/mnt/results/$sample.stdout"
  grep -q 'Correct operation validated' "/mnt/results/$sample.stdout"
  awk '/Total time \(secs\)/ {if ($NF<10) exit 1; good=1} END {if (!good) exit 1}' "/mnt/results/$sample.stdout"
done
sync
'''

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work', type=Path, default=ROOT/'target/coremark-benchmark/debian')
    p.add_argument('--timeout', type=int, default=1200)
    p.add_argument('--image-work', type=Path, help='Prepared image directory; benchmark output stays in --work')
    p.add_argument('--guest-script', type=Path, help='Run a custom guest measurement/preparation script; retain raw results')
    args=p.parse_args(); work=args.work.resolve(); work.mkdir(parents=True,exist_ok=True)
    source=ROOT/'target/coremark-upstream'
    assert subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()==REVISION
    subprocess.run(['git','-C',str(source),'diff','--exit-code','HEAD','--','.'],check=True,stdout=subprocess.DEVNULL)
    image_work=(args.image_work or work).resolve()
    sums=(image_work/'SHA512SUMS').read_text()
    expected=re.search(r'^(\w+)\s+debian-13-nocloud-riscv64.qcow2$',sums,re.M)[1]
    assert hashlib.file_digest(open(image_work/'base.qcow2','rb'),'sha512').hexdigest()==expected, 'Debian base image checksum mismatch'
    for filename, sha in [('vmlinux-6.12.107+deb13-riscv64', '8898c27a38f0bfcc3d9a4b0687ee752c4a2b3028576f919ba8955d2cbd6d4722'), ('initrd.img-6.12.107+deb13-riscv64', '74e9f1cb179fa2ba64363bb2196416d459827cde0443a58971f3b9a929df0d8e')]:
        assert hashlib.sha256((image_work/'extracted/boot'/filename).read_bytes()).hexdigest()==sha, filename
    inputs=work/'inputs'; inputs.mkdir(exist_ok=True)
    shutil.copytree(source,inputs/'source',ignore=shutil.ignore_patterns('.git'),dirs_exist_ok=True)
    (inputs/'run.sh').write_text(args.guest_script.read_text() if args.guest_script else GUEST)
    results=work/'results'; results.mkdir(exist_ok=True)
    (results/'results.json').write_text('[]\n')
    disk=work/'run.qcow2'
    if not disk.exists():
        subprocess.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(image_work/'base.qcow2'),str(disk)],check=True)
    command=['qemu-system-riscv64','-machine','virt','-cpu','rv64','-smp','1','-m','1G','-accel','tcg,thread=single',
        '-rtc','base=utc,clock=vm','-nographic','-bios','default',
        '-kernel',str(image_work/'extracted/boot/vmlinux-6.12.107+deb13-riscv64'),
        '-initrd',str(image_work/'extracted/boot/initrd.img-6.12.107+deb13-riscv64'),
        '-append','root=/dev/vda1 rw console=ttyS0 systemd.firstboot=off systemd.debug_shell=ttyS0 systemd.mask=serial-getty@ttyS0.service',
        '-drive',f'if=none,id=disk,format=qcow2,file={disk},cache=writeback','-device','virtio-blk-device,drive=disk',
        '-netdev','user,id=net,ipv6=off','-device','virtio-net-device,netdev=net',
        '-object','rng-random,id=rng,filename=/dev/urandom','-device','virtio-rng-device,rng=rng',
        '-virtfs',f'local,path={inputs},mount_tag=coremark,security_model=none,readonly=on',
        '-virtfs',f'local,path={results},mount_tag=results,security_model=none',
        '-global','virtio-mmio.force-legacy=false']
    (work/'qemu-command.json').write_text(json.dumps(command,indent=2)+'\n')
    master,slave=pty.openpty()
    log=open(work/'boot.log','wb')
    vm=subprocess.Popen(command,stdin=slave,stdout=slave,stderr=slave,close_fds=True); os.close(slave)
    pending=b''
    def expect(token,timeout):
        nonlocal pending
        end=time.monotonic()+timeout
        while token not in pending:
            assert vm.poll() is None and time.monotonic()<end, f'Waiting for {token!r}: {pending[-2000:]!r}'
            if select.select([master],[],[],1)[0]:
                data=os.read(master,65536); log.write(data); log.flush(); pending+=data
        pending=pending.split(token,1)[1]
    try:
        expect(b'# ',300)
        # Disable command echo so completion cannot match the command itself.
        os.write(master,b'stty -echo\n'); expect(b'# ',30)
        os.write(master,b'mkdir -p /mnt/coremark /mnt/results; mount -t 9p -o trans=virtio,version=9p2000.L,ro coremark /mnt/coremark; sh /mnt/coremark/run.sh; result=$?; printf "\\nBENCHMARK_DONE=%s\\n" "$result"\n')
        expect(b'BENCHMARK_DONE=',args.timeout); expect(b'\r\n',30)
        assert b'BENCHMARK_DONE=0' in (work/'boot.log').read_bytes(), 'Guest benchmark failed; inspect logs'
        samples=[]
        for name in ([] if args.guest_script else ['performance-1','performance-2','performance-3','validation']):
            text=(results/f'{name}.stdout').read_text()
            def value(label): return re.search(r'^'+re.escape(label)+r'\s*:\s*(\S+)',text,re.M)[1]
            sample=dict(name=name,seconds=float(value('Total time (secs)')),iterations=int(value('Iterations')),score=float(value('Iterations/Sec')))
            assert sample['seconds']>=10 and 'Correct operation validated' in text
            samples.append(sample)
        (results/'results.json').write_text(json.dumps(samples,indent=2)+'\n')
        print(json.dumps(samples,indent=2),flush=True)
        os.write(master,b'poweroff\n')
        # Drain the PTY during shutdown: a full serial buffer can otherwise
        # block QEMU before it reaches the SBI shutdown call.
        deadline=time.monotonic()+60
        while vm.poll() is None and time.monotonic()<deadline:
            if select.select([master],[],[],1)[0]:
                try: data=os.read(master,65536)
                except OSError: break
                log.write(data); log.flush()
        vm.wait(timeout=10)
    finally:
        if vm.poll() is None: vm.terminate(); vm.wait(timeout=10)
        os.close(master); log.close()

if __name__=='__main__': main()
