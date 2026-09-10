//! Runs the actual kernel invocation adapter against a synthetic firmware.
//! This proves dispatch/publication semantics, not SD register timing.
#[path = "../../kernel/src/pio_block.rs"]
mod adapter;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use vibeos_hal::{block::{Diagnostics, Error, PioBlockDevice}, AddressRange};
static WRITES: AtomicUsize = AtomicUsize::new(0);
static VERIFY: AtomicBool = AtomicBool::new(true);
#[no_mangle]
static VIBEOS_PIO_BLOCK_DEVICE: PioBlockDevice = PioBlockDevice {
    resource_kind: "test", name: "test", registers: AddressRange::new(0, 4096), irq: 3,
    initialize: |hz, time, _| { assert_eq!(hz, 4000000); assert_eq!(time(), 7); Ok(32) },
    read: |sector, out| { if sector >= 32 { return Err(Error::OutOfRange); } out.fill(sector as u8); Ok(()) },
    write: |sector, data, verify, published| {
        if sector >= 32 { return Err(Error::OutOfRange); }
        assert_eq!(data.len(), 512); VERIFY.store(verify, SeqCst);
        published(); published(); // adapter must suppress accidental repeated notifications
        WRITES.fetch_add(1, SeqCst);
        if sector == 31 { Err(Error::TimedOut) } else { Ok(()) }
    },
    flush: |published| { published(); Ok(()) },
    diagnostics: || Diagnostics { command: 24, interrupt_status: 8, present_state: 9 },
    probe_read: None,
};
#[test]
fn firmware_dispatch_preserves_publication_and_failure() {
    let mut card = unsafe { adapter::FirmwareCard::initialize(4000000, || 7, |_| {}) }.unwrap();
    assert_eq!(card.info().capacity_sectors, 32);
    assert_eq!(card.read_sector(12).unwrap(), [12;512]);
    assert_eq!(card.read_sector(32), Err(Error::OutOfRange));
    let mut publications = 0;
    card.write_sector_tracked(2, &[0;512], || publications += 1).unwrap();
    assert_eq!(publications, 1); assert!(VERIFY.load(SeqCst));
    card.set_write_readback(false);
    assert_eq!(card.write_blocks_tracked(31, &[0;512], || publications += 1), Err(Error::TimedOut));
    assert_eq!(publications, 2); assert!(!VERIFY.load(SeqCst));
    assert_eq!(card.write_blocks_tracked(32, &[0;512], || publications += 1), Err(Error::OutOfRange));
    assert_eq!(publications, 2); assert_eq!(WRITES.load(SeqCst), 2);
    card.flush_tracked(|| publications += 1).unwrap(); assert_eq!(publications, 3);
    assert_eq!((card.last_command(), card.last_interrupt_status(), card.present_state()), (24,8,9));
    assert_eq!(card.diagnostic_probe_multiblock_read(0, &mut [0;512], 10), (0, Err(Error::Unsupported)));
}
