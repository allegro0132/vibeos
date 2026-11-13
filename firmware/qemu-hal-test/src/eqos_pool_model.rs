//! Real pool/cache/controller code on RV64, with register and DMA effects modeled.
use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicUsize, Ordering},
};
use vibeos_eqos_net::{
    backend::Backend,
    controller::{Config, Controller, Io, Speed},
    mdio::Registers,
    pool::{Pool, Storage},
    ring::Ring,
};
use vibeos_platform_jh7110::cache::{Cache, Registers as CacheIo};
struct Permanent<T>(UnsafeCell<T>);
unsafe impl<T> Sync for Permanent<T> {}
struct Csr([u32; 0x1164 / 4]);
impl Registers for Csr {
    fn read(&mut self, a: usize) -> u32 {
        self.0[a / 4]
    }
    fn write(&mut self, a: usize, v: u32) {
        self.0[a / 4] = if a == 0x1000 { 0 } else { v };
    }
}
unsafe impl Io for Csr {
    fn ticks(&mut self) -> u64 {
        0
    }
}
struct L2;
static FLUSHES: AtomicUsize = AtomicUsize::new(0);
unsafe impl CacheIo for L2 {
    fn read32(&mut self, a: usize) -> u32 {
        match a {
            0 => 0x060b1001,
            8 => 15,
            _ => panic!("L2 model offset"),
        }
    }
    fn write64(&mut self, a: usize, v: u64) {
        assert_eq!(a, 0x200);
        assert_eq!(v % 64, 0);
        assert!((0x42000000..0x42001900).contains(&v));
        FLUSHES.fetch_add(1, Ordering::Relaxed);
    }
    fn barrier(&mut self) {}
}
type DmaPool = Pool<Cache<L2>, 2>;
type Driver = Backend<Csr, DmaPool>;
static BYTES: Permanent<Storage<2>> = Permanent(UnsafeCell::new(Storage::new()));
static POOL: Permanent<MaybeUninit<DmaPool>> = Permanent(UnsafeCell::new(MaybeUninit::uninit()));
static DRIVER: Permanent<MaybeUninit<Driver>> = Permanent(UnsafeCell::new(MaybeUninit::uninit()));
/// Boot hart calls this once. Raw writes below emulate a device, never another
/// unsynchronized CPU in production; physical addresses are intentionally fake.
pub unsafe fn run() {
    let cpu = BYTES.0.get() as usize;
    let pool = Pool::new(&mut *BYTES.0.get(), 0x42000000, Cache::new(L2).unwrap(), 8).unwrap();
    let layout = pool.layout();
    (*POOL.0.get()).write(pool);
    let mut csr = Csr([0; 0x1164 / 4]);
    csr.0[0x120 / 4] = 5 << 6 | 5;
    let controller = Controller::new(
        csr,
        Config {
            mac: [2, 3, 4, 5, 6, 7],
            speed: Speed::Mbps1000,
            full_duplex: true,
            csr_hz: 125_000_000,
            timebase_hz: 4_000_000,
            max_polls: 4,
        },
    )
    .unwrap();
    (*DRIVER.0.get()).write(Backend::new(controller, (*POOL.0.get()).assume_init_mut()));
    let mut ring = Ring::new((*DRIVER.0.get()).assume_init_mut(), layout).unwrap();
    ring.initialize().unwrap();
    ring.transmit(&[0xab; 60]).unwrap();
    let txbuf = cpu + (layout.tx_buffers - layout.tx_descriptors) as usize;
    assert_eq!(
        core::slice::from_raw_parts(txbuf as *const u8, 60),
        &[0xab; 60]
    );
    core::ptr::write_volatile((cpu + 12) as *mut u32, 0x30000000u32.to_le());
    assert_eq!(ring.reap(), Ok(1));
    let rxbuf = cpu + (layout.rx_buffers - layout.tx_descriptors) as usize;
    core::ptr::write_bytes(rxbuf as *mut u8, 0x5a, 64);
    let rxdesc = cpu + (layout.rx_descriptors - layout.tx_descriptors) as usize;
    core::ptr::write_volatile((rxdesc + 12) as *mut u32, 0x30000040u32.to_le());
    let mut output = [0; 64];
    assert_eq!(ring.receive(&mut output), Ok(Some(60)));
    assert_eq!(&output[..60], &[0x5a; 60]);
    assert_eq!(&output[60..], &[0; 4]);
    assert!(FLUSHES.load(Ordering::Relaxed) > 100);
    assert!(ring.shutdown());
    #[cfg(feature = "mars-ethernet-device-test")]
    {
        use vibeos_firmware_milkv_mars::packet::Engine;
        let backend = ring.into_stopped_backend().ok().unwrap();
        let mut engine = Engine::new(backend, layout, super::phy_model::initialized()).unwrap();
        assert_eq!(engine.poll_link(), Ok(()));
        assert!(!engine.tx_owned().unwrap());
        assert!(engine.transmit(&[0xbc; 60]).is_err());
        super::phy_model::link(0xac00);
        engine.poll_link().unwrap();
        assert_eq!(engine.link().unwrap().speed, Speed::Mbps1000);
        engine.transmit(&[0xbc; 60]).unwrap();
        assert_eq!(
            core::slice::from_raw_parts(txbuf as *const u8, 60),
            &[0xbc; 60]
        );
        assert!(engine.tx_owned().unwrap());
        super::phy_model::link(0);
        engine.poll_link().unwrap();
        assert!(engine.link().is_none());
        assert!(!engine.tx_owned().unwrap());
        super::phy_model::link(0x6c00);
        engine.poll_link().unwrap();
        assert_eq!(engine.link().unwrap().speed, Speed::Mbps100);
        assert!(!engine.tx_owned().unwrap()); // prior TX is never replayed
        assert!(engine.shutdown());
        assert!(engine.poll_link().is_err());
    }
}
