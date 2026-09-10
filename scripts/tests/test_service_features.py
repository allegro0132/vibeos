"""Check service aliases and explicit firmware entropy selection."""
from pathlib import Path
import tomllib
import unittest
ROOT=Path(__file__).resolve().parents[2]
FEATURES=tomllib.loads((ROOT/'kernel/Cargo.toml').read_text())['features']
def closure(*roots):
    seen=set();pending=list(roots)
    while pending:
        feature=pending.pop()
        if feature in seen:continue
        seen.add(feature);pending.extend(FEATURES.get(feature,[]))
    return seen
class ServiceFeatures(unittest.TestCase):
    def test_legacy_aliases_preserve_service_and_provider(self):
        for old,new in [('milkv-ssh','provisioned-ssh'),('milkv-command','provisioned-command'),('milkv-wasmtime','provisioned-wasmtime')]:
            self.assertEqual(closure(old)-{old},closure(new,'jitter-entropy'))
        self.assertEqual(closure('milkv-iperf3-server')-{'milkv-iperf3-server'},closure('dhcp-iperf3-server'))
    def test_generic_services_do_not_select_fixture_or_timer_entropy(self):
        for feature in ['provisioned-ssh','provisioned-command','provisioned-wasmtime']:
            selected=closure(feature)
            self.assertNotIn('jitter-entropy',selected)
            self.assertFalse(any('acceptance' in f or f in {'ssh-test','ssh-security-test'} for f in selected))
        self.assertTrue({'wasi-preview1','vibeos-sshd/wasi-exec'}<=closure('provisioned-command'))
        self.assertIn('wasmtime-threads',closure('provisioned-wasmtime'))
    def test_firmware_selects_duo_provider_without_forcing_it_on_qemu(self):
        duo=tomllib.loads((ROOT/'firmware/milkv-duo/Cargo.toml').read_text())['features']
        qemu=tomllib.loads((ROOT/'firmware/qemu-virt/Cargo.toml').read_text())['features']
        self.assertIn('vibeos-kernel/jitter-entropy',duo['provisioned-ssh'])
        self.assertNotIn('vibeos-kernel/jitter-entropy',qemu['provisioned-ssh'])
if __name__=='__main__':unittest.main()
