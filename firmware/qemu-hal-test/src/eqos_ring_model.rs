//! RV64 ring model: atomics emulate DMA completion; no actual MMIO/cache work.
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use vibeos_eqos_net::{descriptor::OWN, ring::*};
static TX: AtomicU32 = AtomicU32::new(0);
static RX: AtomicU32 = AtomicU32::new(0);
static RESET: AtomicBool = AtomicBool::new(true);
struct Model;
struct Storage(UnsafeCell<Model>);
unsafe impl Sync for Storage {}
static STORAGE: Storage = Storage(UnsafeCell::new(Model));
const L: Layout = Layout {
    tx_descriptors: 0x42000000,
    rx_descriptors: 0x42001000,
    tx_buffers: 0x42002000,
    rx_buffers: 0x42004000,
    count: 2,
    axi_bytes: 8,
};
unsafe impl Backend for Model {
    fn reset(&mut self) -> bool {
        RESET.load(Ordering::Acquire)
    }
    fn configure(&mut self, l: Layout) -> bool {
        assert_eq!(l, L);
        true
    }
    fn start(&mut self) -> bool {
        true
    }
    fn stop(&mut self) -> bool {
        false
    }
    fn read_word(&mut self, a: u64, w: usize) -> u32 {
        assert_eq!(w, 3);
        match a {
            0x42000000 => TX.load(Ordering::Acquire),
            0x42001000 => RX.load(Ordering::Acquire),
            _ => panic!("model descriptor"),
        }
    }
    fn write_word(&mut self, a: u64, w: usize, v: u32) {
        if w == 3 {
            match a {
                0x42000000 => TX.store(v, Ordering::Release),
                0x42001000 => RX.store(v, Ordering::Release),
                _ => {}
            }
        }
    }
    fn copy_tx(&mut self, a: u64, p: &[u8]) {
        assert_eq!(a, L.tx_buffers);
        assert_eq!(p.len(), 60);
    }
    fn copy_rx(&mut self, a: u64, p: &mut [u8]) {
        assert_eq!(a, L.rx_buffers);
        p.fill(0x5a);
    }
    fn for_device(&mut self, a: u64, n: usize, _: Direction) {
        assert_eq!(a % 64, 0);
        assert_eq!(n % 64, 0);
    }
    fn for_cpu(&mut self, a: u64, n: usize, _: Direction) {
        assert_eq!(a % 64, 0);
        assert_eq!(n % 64, 0);
    }
    fn barrier(&mut self) {}
    fn tail(&mut self, _: bool, a: u64) {
        assert_eq!(a % 64, 0);
    }
}
/// Invoked once by the boot hart; static model storage is never reused.
pub unsafe fn run() {
    let mut r = Ring::new(&mut *STORAGE.0.get(), L).unwrap();
    r.initialize().unwrap();
    r.transmit(&[0; 60]).unwrap();
    assert_ne!(TX.load(Ordering::Acquire) & OWN, 0);
    assert_eq!(r.transmit(&[0; 60]), Err(Error::Full));
    TX.store(0x30000000, Ordering::Release);
    assert_eq!(r.reap(), Ok(1));
    RX.store(0x30000040, Ordering::Release);
    let mut p = [0; 64];
    assert_eq!(r.receive(&mut p), Ok(Some(60)));
    assert_eq!(&p[..60], &[0x5a; 60]);
    assert_eq!(&p[60..], &[0; 4]);
    assert_eq!(RX.load(Ordering::Acquire), OWN | (1 << 24));
    assert!(!r.shutdown());
    assert!(r.quarantined());
    RESET.store(false, Ordering::Release);
    assert_eq!(r.initialize(), Err(Error::Controller));
    assert_eq!(r.transmit(&[0; 60]), Err(Error::Offline));
    RESET.store(true, Ordering::Release);
    r.initialize().unwrap();
    assert_eq!(r.pending(), 0);
    r.fault();
}
