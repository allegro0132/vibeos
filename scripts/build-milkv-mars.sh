#!/bin/sh
# Build a serial/SD or --ethernet DHCP/iperf3 test payload, not an SD card image.
set -eu
mars_network=0
mars_trng=0
for mars_arg in "$@"; do
  case "$mars_arg" in
    --ethernet) [ "$mars_network" -eq 0 ] || exit 2; mars_network=1 ;;
    --trng-probe) [ "$mars_trng" -eq 0 ] || exit 2; mars_trng=1 ;;
    *) echo 'usage: build-milkv-mars.sh [--ethernet] [--trng-probe]' >&2; exit 2 ;;
  esac
done
mars_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$mars_root/firmware/milkv-mars"
mars_features=image
if [ "$mars_network" -eq 1 ]; then mars_features="$mars_features,ethernet"; fi
if [ "$mars_trng" -eq 1 ]; then mars_features="$mars_features,trng-probe"; fi
cargo build --offline --locked --release --features "$mars_features"
cd "$mars_root"
mars_objcopy=${LLVM_OBJCOPY:-llvm-objcopy}
if ! command -v "$mars_objcopy" >/dev/null 2>&1; then
  mars_objcopy=/opt/homebrew/opt/llvm/bin/llvm-objcopy
fi
if [ ! -x "$mars_objcopy" ] && ! command -v "$mars_objcopy" >/dev/null 2>&1; then
  echo 'Set LLVM_OBJCOPY to an LLVM objcopy executable.' >&2
  exit 1
fi
mars_out=target/milkv-mars/bringup
if [ "$mars_network" -eq 1 ]; then mars_out=target/milkv-mars/ethernet; fi
if [ "$mars_trng" -eq 1 ]; then mars_out="$mars_out-trng-probe"; fi
mkdir -p "$mars_out"
"$mars_objcopy" --strip-debug target/riscv64imac-unknown-none-elf/release/vibeos-milkv-mars "$mars_out/vibeos.elf"
"$mars_objcopy" -O binary "$mars_out/vibeos.elf" "$mars_out/vibeos.bin"
if [ "$mars_network" -eq 1 ]; then
  python3 scripts/mars-check-image.py "$mars_out/vibeos.elf" --ethernet --output "$mars_out/elf-check.json"
else
  python3 scripts/mars-check-image.py "$mars_out/vibeos.elf" --output "$mars_out/elf-check.json"
fi
python3 - "$mars_out" "$mars_network" "$mars_trng" <<'PY'
import hashlib, json, re, subprocess, sys
from pathlib import Path
out = Path(sys.argv[1])
network = sys.argv[2] == '1'
trng = sys.argv[3] == '1'
source = Path('firmware/milkv-mars/src/lib.rs').read_text()
def value(name):
    match = re.search(r'pub const ' + name + r': u64 = ([0-9_]+);', source)
    if not match:
        raise SystemExit('Missing literal SD layout constant: ' + name)
    return int(match[1].replace('_', ''))
manifest = {
    'profile': ('mars-4gb-sd-dhcp-iperf3-bringup' if network else 'mars-4gb-serial-sd-bringup') + ('-trng-probe' if trng else ''),
    'trng_boot_probe': trng, 'entropy_qualified': False,
    'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
    'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], text=True)),
    'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip(),
    'target': 'riscv64imac-unknown-none-elf',
    'sdk_commit': json.loads(Path('boards/milkv-mars/sdk-reference.json').read_text()).get('commit'),
    'sd_data_first_sector': value('DATA_FIRST_SECTOR'),
    'sd_data_sector_count': value('DATA_SECTOR_COUNT'),
    'sector_bytes': 512,
    'network_available': network, 'network_composed': network,
    'network_hardware_verified': False, 'ssh_enabled': False,
    'network_services': ['dhcp', 'iperf3-tcp-5201'] if network else [],
    'paired_boot_firmware_bundled': False,
    'flashable_sd_image': False, 'physical_acceptance': False,
    'artifacts': [{'name': p.name, 'bytes': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                  for p in [out / 'vibeos.elf', out / 'vibeos.bin', out / 'elf-check.json']],
}
if not manifest['sdk_commit']:
    raise SystemExit('Missing pinned SDK commit')
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
PY
