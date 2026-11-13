"""Composition invariants; target tests additionally exercise the real providers."""
from pathlib import Path
import re
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
FEATURES = tomllib.loads((ROOT / 'kernel/Cargo.toml').read_text())['features']


def closure(features):
    seen = set()
    pending = list(features)
    while pending:
        feature = pending.pop()
        if feature not in seen:
            seen.add(feature)
            pending.extend(FEATURES.get(feature, ()))
    return seen


class FrontendComposition(unittest.TestCase):
    def test_frontends_do_not_enable_board_profiles_or_services(self):
        for block in ['pio-block', 'queued-block']:
            for net in ['packet-network', 'queued-network']:
                selected = closure([block, net])
                self.assertFalse(selected & {'qemu-virt', 'milkv-duo', 'provisioned-ssh', 'jitter-entropy'})
                self.assertEqual(selected & {'pio-block', 'queued-block'}, {block})
                self.assertEqual(selected & {'packet-network', 'queued-network'}, {net})

    def test_compatibility_profiles_select_original_interfaces(self):
        for board, expected in [('qemu-virt', {'queued-block', 'queued-network'}),
                                ('milkv-duo', {'pio-block', 'packet-network'})]:
            self.assertEqual(closure([board]) & {'queued-block', 'queued-network', 'pio-block', 'packet-network'}, expected)

    def test_kernel_client_adapters_have_no_board_selection(self):
        for name in ['block_device.rs', 'net_device.rs', 'segment_store_platform.rs']:
            source = (ROOT / 'kernel/src' / name).read_text()
            self.assertNotRegex(source, r'feature\s*=\s*"(?:qemu-virt|milkv-duo)"')

    def test_existing_firmware_storage_identities_are_preserved(self):
        for board, suffix in [('qemu-virt', 1), ('milkv-duo', 2), ('qemu-hal-test', 1)]:
            source = (ROOT / 'firmware' / board / 'src/main.rs').read_text()
            match = re.search(r'const MANAGED_BLOCK_ID:.*?NonZeroU128::new\((0x[0-9a-fA-F_]+)\)', source, re.S)
            self.assertIsNotNone(match)
            self.assertEqual(int(match[1].replace('_', ''), 16), 0x564942454f5300000000000000000000 + suffix)

    def test_target_fixture_uses_no_kernel_board_profile(self):
        manifest = tomllib.loads((ROOT / 'firmware/qemu-hal-test/Cargo.toml').read_text())
        dependency = manifest['dependencies']['vibeos-kernel']
        self.assertFalse(dependency['default-features'])
        selected = closure(dependency['features'])
        self.assertFalse(selected & {'qemu-virt', 'milkv-duo'})
        self.assertTrue({'queued-block', 'queued-network', 'legacy-shell'} <= selected)
