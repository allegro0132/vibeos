"""Cold-entry ordering guard; live QEMU covers execution of the callback."""
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[2]
class BootAdmissionOrder(unittest.TestCase):
    def test_admission_precedes_runtime_publication_and_memory_initialization(self):
        source = (ROOT / 'kernel/src/lib.rs').read_text()
        cold = source[source.index('pub extern "C" fn kmain('):]
        admission = cold.index('unsafe { admit(request) }')
        for later in ['exec::configure_timebase(', 'mmu::init_boot(', 'HEAP.init(', 'HEAP.init_regions(', 'ipi::mark_online(']:
            self.assertLess(admission, cold.index(later), later)
        self.assertEqual(source.count('unsafe { admit(request) }'), 1)
    def test_kernel_uses_published_callbacks(self):
        source = (ROOT / 'kernel/src/platform.rs').read_text()
        self.assertIn('(description().hart_ids)()', source)
        self.assertIn('(description().timebase_hz)()', source)
