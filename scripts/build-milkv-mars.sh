#!/bin/sh
# Build the serial/SD bring-up payload, not a bootable SD card image.
set -eu
mars_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$mars_root/firmware/milkv-mars"
cargo build --offline --locked --release
cd "$mars_root"
mars_objcopy=${LLVM_OBJCOPY:-llvm-objcopy}
if ! command -v "$mars_objcopy" >/dev/null 2>&1; then
  mars_objcopy=/opt/homebrew/opt/llvm/bin/llvm-objcopy
fi
if [ ! -x "$mars_objcopy" ] && ! command -v "$mars_objcopy" >/dev/null 2>&1; then
  echo 'Set LLVM_OBJCOPY to an LLVM objcopy executable.' >&2
  exit 1
fi
mkdir -p target/milkv-mars/bringup
"$mars_objcopy" --strip-debug target/riscv64imac-unknown-none-elf/release/vibeos-milkv-mars target/milkv-mars/bringup/vibeos.elf
"$mars_objcopy" -O binary target/milkv-mars/bringup/vibeos.elf target/milkv-mars/bringup/vibeos.bin
python3 scripts/mars-check-image.py target/milkv-mars/bringup/vibeos.elf --output target/milkv-mars/bringup/elf-check.json
python3 - <<'PY'
import hashlib, json, re, subprocess
from pathlib import Path
out = Path('target/milkv-mars/bringup')
source = Path('firmware/milkv-mars/src/lib.rs').read_text()
def value(name):
    match = re.search(r'pub const ' + name + r': u64 = ([0-9_]+);', source)
    if not match:
        raise SystemExit('Missing literal SD layout constant: ' + name)
    return int(match[1].replace('_', ''))
manifest = {
    'profile': 'mars-4gb-serial-sd-bringup',
    'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
    'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], text=True)),
    'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip(),
    'target': 'riscv64imac-unknown-none-elf',
    'sdk_commit': json.loads(Path('boards/milkv-mars/sdk-reference.json').read_text()).get('commit'),
    'sd_data_first_sector': value('DATA_FIRST_SECTOR'),
    'sd_data_sector_count': value('DATA_SECTOR_COUNT'),
    'sector_bytes': 512,
    'network_available': False, 'ssh_enabled': False,
    'paired_boot_firmware_bundled': False,
    'flashable_sd_image': False, 'physical_acceptance': False,
    'artifacts': [{'name': p.name, 'bytes': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                  for p in [out / 'vibeos.elf', out / 'vibeos.bin', out / 'elf-check.json']],
}
if not manifest['sdk_commit']:
    raise SystemExit('Missing pinned SDK commit')
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
PY
