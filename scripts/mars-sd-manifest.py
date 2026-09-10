#!/usr/bin/env python3
"""Record the source states and checked artifacts of the serial/SD test image."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent.parent
out = root / 'target/mars-boot/out'
payload = json.loads((root / 'target/milkv-mars/bringup/manifest.json').read_text())
sdk = json.loads((root / 'boards/milkv-mars/resource-reference.json').read_text())
spec = importlib.util.spec_from_file_location('sd', root / 'scripts/mars-sd-image.py')
sd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sd)
report = sd.inspect(out / 'mars-serial-sd.img', out / 'artifacts')
sd.require(payload['sd_data_first_sector'] == report['partitions'][3]['first_sector'], 'firmware data offset')
sd.require(payload['sd_data_sector_count'] == report['partitions'][3]['sector_count'], 'firmware data capacity')


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


sd.require(digest(out / 'artifacts/mars.dtb') == sdk['dtb_sha256'], 'pinned SDK DTB hash')
sd.require(digest(out / 'artifacts/vibeos.bin') == next(a['sha256'] for a in payload['artifacts'] if a['name'] == 'vibeos.bin'), 'payload build hash')
bootcheck = json.loads((out / 'bootchain-check.json').read_text())
sd.require(bootcheck['status'] == 'bootchain-contract-passed', 'bootchain check status')
for name, expected in bootcheck['checked_sha256'].items():
    sd.require(digest(out / 'artifacts' / name) == expected, 'stale bootchain check: ' + name)
manifest = {
    'profile': 'mars-4gb-serial-sd-bringup',
    'flashable_sd_image': True,
    'physical_acceptance': False,
    'network_available': False, 'ssh_enabled': False,
    'bootchain_source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'bootchain_source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=root, text=True)),
    'payload_build': payload,
    'sdk_commit': sdk['commit'],
    'bootchain_check': bootcheck,
    'sd_check': report,
    'artifacts': [
        {'path': str(p.relative_to(out)), 'bytes': p.stat().st_size, 'sha256': digest(p)}
        for p in sorted((out / 'artifacts').iterdir()) if p.is_file()
    ],
    'remaining': ['Physical cold boot and SD persistence qualification',
                  'EQoS, DMA/cache and PHY implementation/qualification',
                  'Qualified Mars entropy, independent SSH identity and SSH/WASM acceptance',
                  'Three cold boots and one hour concurrent stability evidence'],
}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
(out / 'SHA256SUMS').write_text(report['sha256'] + '  mars-serial-sd.img\n')
print(out / 'manifest.json')
