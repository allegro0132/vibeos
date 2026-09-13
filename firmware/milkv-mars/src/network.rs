//! Production static assembly. HAL invocation authority serializes engine
//! operations; telemetry uses only atomics and never borrows mutable engines.
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use vibeos_bsp_milkv_mars as mars;
use vibeos_eqos_net::{
    backend::Backend,
    controller::{Config, Controller, Io, Speed},
    mdio::{Port, Registers},
    pool::{Pool, Storage},
    ring,
};
use vibeos_ethernet::phy::{Tuning, Yt8531};
use vibeos_firmware_milkv_mars::packet::{Engine, Error as EngineError};
use vibeos_hal::network::{Device, Error, Telemetry};
use vibeos_platform_jh7110::{cache, ethernet};

const COUNT: usize = 32;
struct Slot<T>(UnsafeCell<Option<T>>);
unsafe impl<T> Sync for Slot<T> {} // accesses require the HAL's exclusive invocation
struct Dma(UnsafeCell<Storage<COUNT>>);
unsafe impl Sync for Dma {}
#[link_section = ".dma"]
#[export_name = "VIBEOS_MARS_EQOS_DMA"]
static DMA: Dma = Dma(UnsafeCell::new(Storage::new()));
type Memory = Pool<cache::Cache<cache::Mmio>, COUNT>;
type Hardware = Backend<Lane, Memory>;
type PacketEngine = Engine<Lane, Memory, Port<Lane>>;
static POOL: Slot<Memory> = Slot(UnsafeCell::new(None));
static HARDWARE: Slot<Hardware> = Slot(UnsafeCell::new(None));
static ENGINE: Slot<PacketEngine> = Slot(UnsafeCell::new(None));
static CLAIMED: AtomicBool = AtomicBool::new(false);
static LINK: AtomicBool = AtomicBool::new(false);
static TX: AtomicU64 = AtomicU64::new(0);
static RX: AtomicU64 = AtomicU64::new(0);

// Installed by the boot hart before publishing secondary harts or devices.
static LOG: AtomicUsize = AtomicUsize::new(0);
pub fn install_logger(write: fn(&str)) {
    LOG.store(write as usize, Ordering::Release);
}
struct Output(fn(&str));
impl core::fmt::Write for Output {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        (self.0)(text);
        Ok(())
    }
}
fn report(args: core::fmt::Arguments<'_>) {
    let address = LOG.load(Ordering::Acquire);
    if address != 0 {
        // Only install_logger writes this slot, and fn pointers live forever.
        let write: fn(&str) = unsafe { core::mem::transmute(address) };
        let _ = core::fmt::write(&mut Output(write), args);
    }
}
fn failed(stage: &str, detail: impl core::fmt::Debug, error: Error) -> Error {
    report(format_args!("MARS_NET_INIT FAIL stage={} detail={:?}\n", stage, detail));
    error
}

// Disjoint register views of one firmware-owned controller. The PHY view may
// touch only MDIO registers; the DMA/MAC view cannot touch them. Neither view
// exposes Rust references to MMIO, and all calls are serialized by HAL policy.
struct Lane {
    base: usize,
    mdio: bool,
    time: fn() -> u64,
}
impl Lane {
    fn address(&self, offset: usize) -> usize {
        assert!(offset % 4 == 0 && offset <= 0x1160);
        assert_eq!(self.mdio, matches!(offset, 0x200 | 0x204));
        self.base + offset
    }
}
fn fence() {
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack));
    }
}
impl Registers for Lane {
    fn read(&mut self, o: usize) -> u32 {
        fence();
        let v = unsafe { (self.address(o) as *const u32).read_volatile() };
        fence();
        v
    }
    fn write(&mut self, o: usize, v: u32) {
        fence();
        unsafe { (self.address(o) as *mut u32).write_volatile(v) };
        fence();
    }
}
unsafe impl Io for Lane {
    fn ticks(&mut self) -> u64 {
        (self.time)()
    }
}
unsafe fn engine() -> &'static mut PacketEngine {
    (*ENGINE.0.get()).as_mut().expect("claimed Mars NIC")
}
unsafe fn snapshot() {
    if let Some(e) = (&*ENGINE.0.get()).as_ref() {
        LINK.store(e.link().is_some(), Ordering::Release);
        TX.store(e.tx_packets, Ordering::Relaxed);
        RX.store(e.rx_packets, Ordering::Relaxed);
    } else {
        LINK.store(false, Ordering::Release);
    }
}
fn error(e: EngineError) -> Error {
    match e {
        EngineError::Ring(ring::Error::Full) => Error::QueueFull,
        EngineError::Ring(ring::Error::Packet) => Error::PacketTooLarge,
        _ => Error::TimedOut,
    }
}
unsafe fn claim(mac: [u8; 6], time: fn() -> u64, hz: u64) -> Result<(), Error> {
    CLAIMED
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|e| failed("ownership", e, Error::Busy))?;
    let result = (|| {
        let r = super::admission()
            .network
            .ok_or_else(|| failed("resources", "missing DTB network", Error::InvalidDescription))?;
        let base = super::admission().resources;
        let mut platform = ethernet::Mmio::new(
            [r.sys_crg, base.syscon, r.aon_crg, r.aon_syscon, r.aon_pins],
            time,
        )
        .map_err(|e| failed("platform-resources", e, Error::InvalidDescription))?;
        let prepared = ethernet::prepare(&mut platform, mars::GMAC0_TX_DRIVE, hz)
            .map_err(|e| failed("platform-prepare", e, Error::TimedOut))?;
        report(format_args!("MARS_NET_INIT clocks csr={} gtx={} ptp={}\n", prepared.csr_hz, prepared.gtx_hz, prepared.ptp_hz));
        let controller = Controller::new(
            Lane {
                base: r.mac.start,
                mdio: false,
                time,
            },
            Config {
                mac,
                speed: Speed::Mbps1000,
                full_duplex: true,
                csr_hz: u64::from(prepared.csr_hz),
                timebase_hz: hz,
                max_polls: 1_000_000,
            },
        )
        .map_err(|e| failed("controller-config", e, Error::InvalidDescription))?;
        let port = Port::new(
            Lane {
                base: r.mac.start,
                mdio: true,
                time,
            },
            u64::from(prepared.csr_hz),
        )
        .map_err(|e| failed("mdio-config", e, Error::InvalidDescription))?;
        let mut phy = Yt8531::probe(port, mars::PHY_SCAN_ADDRESSES, 100_000).map_err(|e| failed("phy-probe", e, Error::TimedOut))?;
        report(format_args!("MARS_NET_INIT phy={:?}\n", phy.identity()));
        let p = r.phy;
        phy.initialize(
            Tuning {
                drive: [p.drive[0] as u8, p.drive[1] as u8, p.drive[2] as u8],
                rxc_delay_enabled: p.rxc_delay_enabled,
                rx_delay: p.rx_delay as u8,
                tx_delay_fe: p.tx_delay_fe as u8,
                tx_delay: p.tx_delay as u8,
                tx_inverted: p.tx_inverted,
            },
            10_000,
        )
        .map_err(|e| failed("phy-init", e, Error::TimedOut))?;
        let cache =
            cache::Cache::new(cache::Mmio::new(r.cache).map_err(|e| failed("cache-resources", e, Error::InvalidDescription))?)
                .map_err(|e| failed("cache-geometry", e, Error::InvalidDescription))?;
        // .dma is NOLOAD; initialize every byte before creating the Rust pool.
        // No ring has started in this claim; earlier claims require proven stop.
        core::ptr::write_bytes(DMA.0.get(), 0, 1);
        let pool = Pool::new(&mut *DMA.0.get(), DMA.0.get() as u64, cache, 8)
            .map_err(|e| failed("dma-pool", e, Error::AddressTooWide))?;
        let layout = pool.layout();
        *POOL.0.get() = Some(pool);
        *HARDWARE.0.get() = Some(Backend::new(controller, (*POOL.0.get()).as_mut().unwrap()));
        *ENGINE.0.get() =
            Some(Engine::new((*HARDWARE.0.get()).as_mut().unwrap(), layout, phy).map_err(|e| { report(format_args!("MARS_NET_INIT FAIL stage=ring-init detail={:?}\n", e)); error(e) })?);
        LINK.store(false, Ordering::Release);
        TX.store(0, Ordering::Relaxed);
        RX.store(0, Ordering::Relaxed);
        report(format_args!("MARS_NET_INIT ready\n"));
        Ok(())
    })();
    if result.is_err() {
        // Claim never starts DMA. Publication/start happens only in poll_link
        // after the invocation token exists, so construction errors can retire.
        *ENGINE.0.get() = None;
        *HARDWARE.0.get() = None;
        *POOL.0.get() = None;
        CLAIMED.store(false, Ordering::Release);
    }
    result
}
unsafe fn retire() -> bool {
    LINK.store(false, Ordering::Release);
    let stopped = (*ENGINE.0.get()).as_mut().is_none_or(|e| e.shutdown());
    if stopped {
        // Drop references in ownership order only after reset proved stop.
        *ENGINE.0.get() = None;
        *HARDWARE.0.get() = None;
        *POOL.0.get() = None;
        CLAIMED.store(false, Ordering::Release);
    }
    stopped
}
#[no_mangle]
pub static VIBEOS_PACKET_DEVICE: Device = Device {
    present: true,
    registers: mars::GMAC0_REGISTERS,
    irq: mars::GMAC0_IRQ,
    rx_queue_size: COUNT,
    dma_base: || DMA.0.get() as usize,
    telemetry: || Telemetry {
        phy_link_up: LINK.load(Ordering::Acquire),
        tx_packets: TX.load(Ordering::Relaxed),
        rx_packets: RX.load(Ordering::Relaxed),
        ..Telemetry::default()
    },
    claim,
    tx_owned: || unsafe {
        let result = engine().tx_owned();
        snapshot();
        result.expect("Mars EQoS TX fault")
    },
    transmit: |p| unsafe {
        let result = engine().transmit(p);
        snapshot();
        result.map_err(error)
    },
    receive: |out| unsafe {
        let result = engine().receive(out);
        snapshot();
        result.expect("Mars EQoS RX fault")
    },
    poll_link: || unsafe {
        let result = engine().poll_link();
        snapshot();
        result.expect("Mars EQoS PHY fault")
    },
    shutdown: retire,
    // HAL guarantees the faulted owner cannot resume. Retain the old static
    // ring for reset proof; never overwrite it merely because a task faulted.
    recover: retire,
};
