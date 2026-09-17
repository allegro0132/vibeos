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

// Both directions share the current layout count. The experiment increases
// dedicated DMA storage by 307200 bytes; ownership and cache isolation persist.
#[cfg(feature = "dma-ring128-experiment")]
const COUNT: usize = 128;
#[cfg(not(feature = "dma-ring128-experiment"))]
const COUNT: usize = 32;
#[cfg(feature = "rx-pool-experiment")]
const RX_COUNT: usize = COUNT * 2;
#[cfg(not(feature = "rx-pool-experiment"))]
const RX_COUNT: usize = COUNT;
#[cfg(feature = "rx-pool-experiment")]
static DMA_INITIALIZED: AtomicBool = AtomicBool::new(false);
struct Slot<T>(UnsafeCell<Option<T>>);
unsafe impl<T> Sync for Slot<T> {} // accesses require the HAL's exclusive invocation
struct Dma(UnsafeCell<Storage<COUNT, RX_COUNT>>);
unsafe impl Sync for Dma {}
#[link_section = ".dma"]
#[export_name = "VIBEOS_MARS_EQOS_DMA"]
static DMA: Dma = Dma(UnsafeCell::new(Storage::new()));
#[cfg(feature = "gmac-coherent-experiment")]
type DmaCache = cache::GmacCoherent<cache::Mmio>;
#[cfg(not(feature = "gmac-coherent-experiment"))]
type DmaCache = cache::Cache<cache::Mmio>;
type Memory = Pool<DmaCache, COUNT, RX_COUNT>;
type Hardware = Backend<Lane, Memory>;
type PacketEngine = Engine<Lane, Memory, Port<Lane>>;
static POOL: Slot<Memory> = Slot(UnsafeCell::new(None));
static HARDWARE: Slot<Hardware> = Slot(UnsafeCell::new(None));
static ENGINE: Slot<PacketEngine> = Slot(UnsafeCell::new(None));
static CLAIMED: AtomicBool = AtomicBool::new(false);
static LINK: AtomicBool = AtomicBool::new(false);
static TX: AtomicU64 = AtomicU64::new(0);
static RX: AtomicU64 = AtomicU64::new(0);
#[cfg(all(feature = "rx-status-experiment", feature = "controller-profile"))]
static mut PROFILE_CHECKSUM_LAST: u64 = 0;

// Opt-in diagnostic counters; disabled counters add no timing reads. Device
// invocation authority is the sole owner, just as for ENGINE and its DMA ring.
#[cfg(feature = "controller-profile")]
struct Profile {
    ticks: [u64; 3],
    calls: [u64; 3],
    last: u64,
}
#[cfg(feature = "controller-profile")]
struct ProfileSlot(UnsafeCell<Profile>);
#[cfg(feature = "controller-profile")]
unsafe impl Sync for ProfileSlot {}
#[cfg(feature = "controller-profile")]
static PROFILE: ProfileSlot = ProfileSlot(UnsafeCell::new(Profile {
    ticks: [0; 3],
    calls: [0; 3],
    last: 0,
}));
fn profile_time() -> u64 {
    vibeos_runtime_riscv::time()
}
#[cfg(feature = "controller-profile")]
unsafe fn profile_end(kind: usize, start: u64) {
    let p = &mut *PROFILE.0.get();
    p.ticks[kind] += profile_time().wrapping_sub(start);
    p.calls[kind] += 1;
}
#[cfg(feature = "controller-profile")]
unsafe fn profile_report() {
    let now = profile_time();
    let p = &mut *PROFILE.0.get();
    if !cfg!(feature = "network-profile") && now.wrapping_sub(p.last) >= 20_000_000 {
        report(format_args!(
            "MARS_NET_PROFILE dt={} owned={}/{} tx={}/{} rx={}/{} packets={}/{}\n",
            now.wrapping_sub(p.last),
            p.ticks[0],
            p.calls[0],
            p.ticks[1],
            p.calls[1],
            p.ticks[2],
            p.calls[2],
            TX.load(Ordering::Relaxed),
            RX.load(Ordering::Relaxed)
        ));
        p.last = now;
        p.ticks = [0; 3];
        p.calls = [0; 3];
    }
}

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
    #[cfg(feature = "network-profile")]
    if vibeos_kernel::net_profile::active() { return; }
    let address = LOG.load(Ordering::Acquire);
    if address != 0 {
        // Only install_logger writes this slot, and fn pointers live forever.
        let write: fn(&str) = unsafe { core::mem::transmute(address) };
        let _ = core::fmt::write(&mut Output(write), args);
    }
}
fn failed(stage: &str, detail: impl core::fmt::Debug, error: Error) -> Error {
    report(format_args!(
        "MARS_NET_INIT FAIL stage={} detail={:?}\n",
        stage, detail
    ));
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
        if o == 0x1004 {
            report(format_args!(
                "MARS_NET_AXI base={:#x} bus={:#010x}\n",
                self.base, v
            ));
        }
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

#[cfg(feature = "network-tx-audit")]
unsafe fn service_tx_audit() {
    use vibeos_kernel::net_tx_audit as a;
    let Some(request) = a::pending_hardware_request() else { return; };
    // Called under exclusive HAL engine ownership, immediately after reaping
    // TX descriptors. MMC access stays inside the controller driver.
    let e = engine();
    let mut values = [0, e.tx_packets, e.pending_tx() as u64, 0, 0, 0, 0, 0, 0, 65536, 65536];
    if let Some(m) = e.mmc_tx_counters() {
        values = [1, e.tx_packets, e.pending_tx() as u64, m.control as u64,
            m.frames_good_bad as u64, m.frames_good as u64, m.underflow as u64,
            m.carrier_error as u64, m.pause as u64, 65536, 65536];
    }
    if let Ok((local, partner)) = e.advertisements() {
        values[9] = local as u64; values[10] = partner as u64;
    }
    a::publish_hardware(request, values);
}
fn error(e: EngineError) -> Error {
    match e {
        EngineError::Ring(ring::Error::Full) => Error::QueueFull,
        EngineError::Ring(ring::Error::Packet) => Error::PacketTooLarge,
        _ => Error::TimedOut,
    }
}
unsafe fn claim(mac: [u8; 6], time: fn() -> u64, hz: u64) -> Result<(), Error> {
    #[cfg(feature = "tso-experiment")]
    vibeos_kernel::net_tso_probe::invalidate();
    CLAIMED
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|e| failed("ownership", e, Error::Busy))?;
    let result = (|| {
        let r = super::admission().network.ok_or_else(|| {
            failed(
                "resources",
                "missing DTB network",
                Error::InvalidDescription,
            )
        })?;
        let base = super::admission().resources;
        let mut platform = ethernet::Mmio::new(
            [r.sys_crg, base.syscon, r.aon_crg, r.aon_syscon, r.aon_pins],
            time,
        )
        .map_err(|e| failed("platform-resources", e, Error::InvalidDescription))?;
        let prepared = ethernet::prepare(&mut platform, mars::GMAC0_TX_DRIVE, hz)
            .map_err(|e| failed("platform-prepare", e, Error::TimedOut))?;
        report(format_args!(
            "MARS_NET_INIT clocks csr={} gtx={} ptp={}\n",
            prepared.csr_hz, prepared.gtx_hz, prepared.ptp_hz
        ));
        let mut controller = Controller::new(
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
        report(format_args!(
            "MARS_NET_CHECKSUM_CAP {:?}\n",
            controller.checksum_capabilities()
        ));
        #[cfg(feature = "rx-status-experiment")]
        controller
            .set_rx_checksum(true)
            .map_err(|e| failed("rx-checksum-mode", e, Error::InvalidDescription))?;
        #[cfg(feature = "rx-error-forward-experiment")]
        controller
            .set_rx_error_forwarding(true)
            .map_err(|e| failed("rx-error-forward", e, Error::InvalidDescription))?;
        #[cfg(feature = "rx-interrupt-experiment")]
        controller.set_rx_watchdog(100)
            .map_err(|e| failed("rx-watchdog", e, Error::InvalidDescription))?;
        let port = Port::new(
            Lane {
                base: r.mac.start,
                mdio: true,
                time,
            },
            u64::from(prepared.csr_hz),
        )
        .map_err(|e| failed("mdio-config", e, Error::InvalidDescription))?;
        let mut phy = Yt8531::probe(port, mars::PHY_SCAN_ADDRESSES, 100_000)
            .map_err(|e| failed("phy-probe", e, Error::TimedOut))?;
        report(format_args!("MARS_NET_INIT phy={:?}\n", phy.identity()));
        let p = r.phy;
        phy.initialize_with_symmetric_pause(
            Tuning {
                drive: [p.drive[0] as u8, p.drive[1] as u8, p.drive[2] as u8],
                rxc_delay_enabled: p.rxc_delay_enabled,
                rx_delay: p.rx_delay as u8,
                tx_delay_fe: p.tx_delay_fe as u8,
                tx_delay: p.tx_delay as u8,
                tx_inverted: p.tx_inverted,
            },
            10_000,
            cfg!(feature = "symmetric-pause-experiment"),
        )
        .map_err(|e| failed("phy-init", e, Error::TimedOut))?;
        let cache = cache::Cache::new(
            cache::Mmio::new(r.cache)
                .map_err(|e| failed("cache-resources", e, Error::InvalidDescription))?,
        )
        .map_err(|e| failed("cache-geometry", e, Error::InvalidDescription))?;
        let cache = cache.with_readonly_recycle(cfg!(feature = "rx-readonly-recycle-experiment"));
        // JH7110 GMAC0/1 use the coherent CPU front port (StarFive coherence
        // table, row GMACx2); this pool is cached identity RAM below 4 GiB.
        // Claim has not started DMA. No other device receives this service.
        #[cfg(feature = "gmac-coherent-experiment")]
        let cache = cache.into_gmac_coherent();
        report(format_args!("MARS_NET_DMA coherent-front-port={}\n",
            cfg!(feature = "gmac-coherent-experiment")));
        // .dma is NOLOAD; initialize every byte before creating the Rust pool.
        // No ring has started in this claim; earlier claims require proven stop.
        #[cfg(feature = "rx-pool-experiment")]
        if !DMA_INITIALIZED.load(Ordering::Acquire) {
            core::ptr::write_bytes(DMA.0.get(), 0, 1);
            DMA_INITIALIZED.store(true, Ordering::Release);
        }
        #[cfg(not(feature = "rx-pool-experiment"))]
        core::ptr::write_bytes(DMA.0.get(), 0, 1);
        let pool = Pool::from_raw(DMA.0.get(), DMA.0.get() as u64, cache, 8)
            .map_err(|e| failed("dma-pool", e, Error::AddressTooWide))?;
        let layout = pool.layout();
        #[cfg(feature = "rx-pool-experiment")]
        { RX_META.lock().view = Some(pool.rx_view()); }
        report(format_args!(
            "MARS_NET_RING count={} bytes={} tx_single_sync={}\n",
            COUNT,
            core::mem::size_of::<Storage<COUNT, RX_COUNT>>(),
            cfg!(feature = "tx-single-sync-experiment")
        ));
        *POOL.0.get() = Some(pool);
        *HARDWARE.0.get() = Some(Backend::new(controller, (*POOL.0.get()).as_mut().unwrap()));
        *ENGINE.0.get() = Some(
            Engine::new((*HARDWARE.0.get()).as_mut().unwrap(), layout, phy).map_err(|e| {
                report(format_args!(
                    "MARS_NET_INIT FAIL stage=ring-init detail={:?}\n",
                    e
                ));
                error(e)
            })?,
        );
        #[cfg(feature = "rx-pool-experiment")]
        engine().set_rx_initializer(initialize_rx_pool);
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
// Only the exclusively authorized driver borrows this fixed diagnostic scratch.
// It is never handed directly to DMA and consumes no component heap quota.
#[cfg(feature = "tso-experiment")]
struct ProbeBuffer(UnsafeCell<[u8;32768]>);
#[cfg(feature = "tso-experiment")]
unsafe impl Sync for ProbeBuffer {}
#[cfg(feature = "tso-experiment")]
static PROBE_BUFFER:ProbeBuffer=ProbeBuffer(UnsafeCell::new([0;32768]));
#[cfg(feature = "tso-experiment")]
unsafe fn service_tso_probe() {
    use vibeos_kernel::net_tso_probe as probe;
    if probe::state()==6 {probe::finish(true);return;}
    let Some(r)=probe::take() else {return;};
    let buffer = &mut *PROBE_BUFFER.0.get();
    let p = &mut buffer[..54+r.payload];
    p.fill(0);
    p[..6].copy_from_slice(&r.dst_mac);p[6..12].copy_from_slice(&r.src_mac);
    p[12..14].copy_from_slice(&[8,0]);p[14]=0x45;
    p[16..18].copy_from_slice(&((40+r.payload) as u16).to_be_bytes());
    p[18..20].copy_from_slice(&0x6000u16.to_be_bytes());p[20]=0x40;p[22]=64;p[23]=6;
    p[26..30].copy_from_slice(&r.src_ip);p[30..34].copy_from_slice(&r.dst_ip);
    p[34..36].copy_from_slice(&5304u16.to_be_bytes());p[36..38].copy_from_slice(&5305u16.to_be_bytes());
    p[38..42].copy_from_slice(&0x1000_0000u32.to_be_bytes());p[46]=0x50;p[47]=0x18;p[48]=0x7f;
    for (i,b) in p[54..].iter_mut().enumerate(){*b=((i*17+i/251)%253) as u8;}
    let request=vibeos_hal::tcp_segmentation::TcpSegments::new(&p,r.mss).unwrap();
    if let Err(error)=engine().transmit_segments(request) {
        report(format_args!("NTSO_DRIVER_FAIL {:?}\n",error));probe::finish(false);
    } else {probe::submitted();}
}
// A fresh register view has no reference to ENGINE/POOL. Its IRQ-register
// writes are serialized with task-side arm by the boot-hart adapter.
#[cfg(feature = "rx-interrupt-experiment")]
fn irq_lane() -> Lane {
    Lane { base: mars::GMAC0_REGISTERS.start, mdio: false, time: profile_time }
}
#[cfg_attr(not(feature = "universal"), no_mangle)]
pub static VIBEOS_PACKET_DEVICE: Device = Device {
    #[cfg(feature = "rx-pool-experiment")]
    receive_buffers: Some(vibeos_hal::network_rx::Operations {
        #[cfg(feature = "rx-batch-experiment")]
        poll_batch: Some(poll_rx_batch),
        #[cfg(not(feature = "rx-batch-experiment"))]
        poll_batch: None,
        #[cfg(feature = "rx-admission-batch")]
        acquire_batch: Some(acquire_rx_loans),
        stats: rx_pool_stats,
        poll: poll_rx_ticket, acquire: acquire_rx_loan, discard: discard_rx_ticket, recover: recover_rx_borrower,
    }),
    #[cfg(not(feature = "rx-pool-experiment"))]
    receive_buffers: None,
    #[cfg(feature = "rx-interrupt-experiment")]
    rx_interrupts: Some(vibeos_hal::network::RxInterrupts {
        mask: || vibeos_eqos_net::rx_irq::mask(&mut irq_lane()),
        acknowledge: || vibeos_eqos_net::rx_irq::mask_and_acknowledge(&mut irq_lane())
            & vibeos_eqos_net::rx_irq::FATAL_EVENTS == 0,
        arm: || vibeos_eqos_net::rx_irq::arm_and_check(&mut irq_lane(),
            vibeos_eqos_net::rx_irq::Revision::Gmac410OrLater),
        pending: || unsafe { engine().receive_pending() },
    }),
    #[cfg(not(feature = "rx-interrupt-experiment"))]
    rx_interrupts: None,
    present: true,
    registers: mars::GMAC0_REGISTERS,
    irq: mars::GMAC0_IRQ,
    rx_queue_size: COUNT,
    dma_base: || DMA.0.get() as usize,
    telemetry: || Telemetry {
        phy_link_up: LINK.load(Ordering::Acquire),
        tx_packets: TX.load(Ordering::Relaxed),
        // This profile requests complete IPv4 checksums. The ring falls back
        // to software when the feature register lacks TXCOE.
        tx_checksum_offload: cfg!(feature = "tx-checksum-experiment"),
        rx_checksum_offload: cfg!(feature = "rx-ipv4-checksum-experiment"),
        rx_packets: RX.load(Ordering::Relaxed),
        ..Telemetry::default()
    },
    claim,
    tx_owned: || unsafe {
        #[cfg(feature = "controller-profile")]
        let start = profile_time();
        let result = engine().tx_owned();
        #[cfg(feature = "tso-experiment")]
        if matches!(result,Ok(false)) { service_tso_probe(); }
        #[cfg(feature = "network-tx-audit")]
        service_tx_audit();
        #[cfg(feature = "controller-profile")]
        profile_end(0, start);
        snapshot();
        result.expect("Mars EQoS TX fault")
    },
    transmit: |p| unsafe {
        #[cfg(feature = "controller-profile")]
        let start = profile_time();
        #[cfg(not(feature = "tx-checksum-experiment"))]
        let result = engine().transmit(p);
        #[cfg(feature = "tx-checksum-experiment")]
        let result = engine().transmit_checksum(p);
        #[cfg(feature = "controller-profile")]
        profile_end(1, start);
        snapshot();
        result.map_err(|e| {
            if !matches!(e, EngineError::Ring(ring::Error::Full)) {
                report(format_args!(
                    "MARS_NET_TX FAIL bytes={} detail={:?}\n",
                    p.len(),
                    e
                ));
            }
            error(e)
        })
    },
    segmentation: {
        #[cfg(feature = "tso-experiment")]
        { Some(vibeos_hal::network::Segmentation {
            max_packet_bytes: vibeos_hal::tcp_segmentation::MAX_LOGICAL_PACKET,
            min_mss: 64,
            transmit: |request| unsafe {
                let result=engine().transmit_segments(request);
                snapshot();result.map_err(error)
            },
        }) }
        #[cfg(not(feature = "tso-experiment"))]
        { None }
    },
    receive: |out| unsafe {
        #[cfg(feature = "controller-profile")]
        let start = profile_time();
        let result = engine().receive(out);
        #[cfg(feature = "controller-profile")]
        profile_end(2, start);
        snapshot();
        result.expect("Mars EQoS RX fault")
    },
    poll_link: || unsafe {
        #[cfg(feature = "network-profile")]
        if let Some(d) = engine().dma_diagnostics() {
            vibeos_kernel::net_profile::dma_status(d.dma_status, d.mtl_interrupt);
        }
        let before = engine().link();
        let result = engine().poll_link();
        let after = engine().link();
        if before != after {
            report(format_args!("MARS_NET_LINK {:?}\n", after));
            #[cfg(feature = "symmetric-pause-experiment")]
            report(format_args!("MARS_FLOW_CONFIG {:?}\n", engine().flow_diagnostics()));
        }
        #[cfg(all(feature = "rx-status-experiment", feature = "controller-profile"))]
        if !cfg!(feature = "network-profile") && engine().rx_packets != 0 && PROFILE_CHECKSUM_LAST + 20_000_000 < profile_time() {
            PROFILE_CHECKSUM_LAST = profile_time();
            report(format_args!(
                "MARS_NET_RX_CHECKSUM {:?}\n",
                engine().rx_checksum_status
            ));
            #[cfg(feature = "rx-ipv4-checksum-experiment")]
            report(format_args!(
                "MARS_NET_RX_VERIFY {:?}\n",
                engine().rx_verified
            ));
            if let Some(d) = engine().dma_diagnostics() {
                report(format_args!(
                    "MARS_NET_DMA_STATUS dma={:#010x} mtl_irq={:#010x} mtl_rx={:#010x}\n",
                    d.dma_status, d.mtl_interrupt, d.mtl_rx_debug
                ));
            }
            let drops = engine().rx_diagnostics();
            report(format_args!(
                "MARS_NET_RX_REJECT count={} status={:#010x} word1={:#010x}\n",
                drops.rejected, drops.last_status, drops.last_word1
            ));
        }
        #[cfg(feature = "controller-profile")]
        profile_report();
        snapshot();
        #[cfg(feature = "symmetric-pause-experiment")]
        if result.is_err() { report(format_args!("MARS_FLOW_REJECT {:?}\n", engine().flow_diagnostics())); }
        result.expect("Mars EQoS PHY fault")
    },
    shutdown: retire,
    // HAL guarantees the faulted owner cannot resume. Retain the old static
    // ring for reset proof; never overwrite it merely because a task faulted.
    recover: retire,
};


#[cfg(feature = "rx-pool-experiment")]
struct RxMetadata {
    buffers: Option<vibeos_eqos_net::rx_buffers::Buffers<COUNT, RX_COUNT>>,
    lengths: [usize; RX_COUNT],
    counts: [u64; 5],
    #[cfg(feature = "gro-batch-release")]
    batch_releases: [u64; 2],
    view: Option<vibeos_eqos_net::pool::RxView>,
}
#[cfg(feature = "rx-pool-experiment")]
static RX_META: vibeos_core::sync::SpinLock<RxMetadata> = vibeos_core::sync::SpinLock::new_recoverable(
    RxMetadata { buffers: None, lengths: [0; RX_COUNT], counts: [0; 5], view: None,
        #[cfg(feature = "gro-batch-release")]
        batch_releases: [0; 2],
    });
// Only the four hot metadata paths below are sampled. Timer intervals include
// lock bookkeeping; nested work is inclusive and must not be summed with the
// existing network stage profile. No packet contents or MMIO are recorded.
#[cfg(feature = "rx-metadata-profile")]
#[repr(align(64))]
struct MetadataCounters([[AtomicU64; 5]; 4]);
#[cfg(feature = "rx-metadata-profile")]
static METADATA_COUNTERS: [MetadataCounters; 4] = [const { MetadataCounters(
    [const { [const { AtomicU64::new(0) }; 5] }; 4]) }; 4];
#[cfg(feature = "rx-pool-experiment")]
#[inline]
fn with_rx_metadata<T>(_kind: usize, f: impl FnOnce(&mut RxMetadata) -> T) -> T {
    #[cfg(feature = "rx-metadata-profile")]
    let sample = vibeos_core::arch::cached_logical_hart_index()
        .and_then(|h| METADATA_COUNTERS.get(h))
        .map(|h| &h.0[_kind])
        .filter(|c| c[0].fetch_add(1, Ordering::Relaxed) % 127 == 0);
    #[cfg(feature = "rx-metadata-profile")]
    let start = sample.map(|_| profile_time());
    let mut metadata = RX_META.lock();
    #[cfg(feature = "rx-metadata-profile")]
    let acquired = sample.map(|_| profile_time());
    let result = f(&mut metadata);
    #[cfg(feature = "rx-metadata-profile")]
    let end = sample.map(|_| profile_time());
    drop(metadata);
    #[cfg(feature = "rx-metadata-profile")]
    if let Some(c) = sample {
        let held = end.unwrap().wrapping_sub(acquired.unwrap());
        c[1].fetch_add(1, Ordering::Relaxed);
        c[2].fetch_add(acquired.unwrap().wrapping_sub(start.unwrap()), Ordering::Relaxed);
        c[3].fetch_add(held, Ordering::Relaxed);
        c[4].fetch_max(held, Ordering::Relaxed);
    }
    result
}
#[cfg(feature = "rx-pool-experiment")]
fn initialize_rx_pool(ring: &mut ring::Ring<Hardware>) -> Result<(), ring::Error> {
    let mut metadata = RX_META.lock();
    if metadata.buffers.is_none() {
        metadata.buffers = Some(vibeos_eqos_net::rx_buffers::Buffers::new().map_err(|_| ring::Error::Controller)?);
    }
    ring.initialize_pooled(metadata.buffers.as_mut().unwrap())
}
#[cfg(feature = "rx-pool-experiment")]
struct RxAccess {
    // Captured under the first metadata guard of this invocation. The HAL
    // engine lease excludes pool replacement/reset until validation finishes.
    view: Option<vibeos_eqos_net::pool::RxView>,
}
// HAL invocation authority excludes concurrent engine initialization/reset.
// Stack callbacks only borrow/release/discard entries in this permanent table.
#[cfg(feature = "rx-pool-experiment")]
unsafe impl vibeos_eqos_net::rx_buffers::Access<COUNT, RX_COUNT> for RxAccess {
    fn with<T>(&mut self, f: impl FnOnce(&mut vibeos_eqos_net::rx_buffers::Buffers<COUNT, RX_COUNT>) -> T)
        -> Result<T, vibeos_eqos_net::rx_buffers::Error>
    {
        with_rx_metadata(0, |metadata| {
            if self.view.is_none() { self.view = metadata.view; }
            metadata.buffers.as_mut().map(f).ok_or(vibeos_eqos_net::rx_buffers::Error::Geometry)
        })
    }
}
#[cfg(feature = "rx-pool-experiment")]
unsafe fn poll_rx_ticket() -> Result<Option<vibeos_hal::network_rx::Ticket>, Error> {
    // Only the driver touches descriptor ownership. Empty polling needs no
    // allocator metadata and must not delay stack-side acquire/release.
    // Fault/invalid-ring states return true and take the normal error path.
    if !engine().receive_pending() { return Ok(None); }
    let mut access = RxAccess { view: None };
    let frame = match engine().receive_detached(&mut access) {
        Ok(Some(frame)) => frame, Ok(None) => return Ok(None),
        Err(EngineError::Ring(ring::Error::Full)) => { RX_META.lock().counts[3] += 1; return Ok(None); }
        Err(e) => return Err(error(e)),
    };
    let view = access.view.expect("admitted permanent RX view");
    // The ticket remains private until return. HAL engine ownership excludes
    // reset while validating, and no queue consumer can acquire this ticket yet.
    let accepted = view.read(frame.ticket.index(), frame.bytes,
        |bytes| engine().validate_rx_frame(bytes, frame.checksum)).expect("validated RX span");
    {
        let mut metadata = RX_META.lock();
        if !accepted {
            metadata.counts[4] += 1;
            let _ = metadata.buffers.as_mut().unwrap().discard(frame.ticket);
            return Ok(None);
        }
        metadata.counts[0] += 1;
        metadata.lengths[frame.ticket.index()] = frame.bytes;
    }
    let engine = engine(); engine.rx_packets = engine.rx_packets.saturating_add(1);
    snapshot();
    Ok(Some(frame.ticket))
}
// Cumulative across driver restarts; read deltas outside traffic. Only calls
// which pass the descriptor-ready probe are counted, so bucket zero does not
// represent idle polling. Atomics permit diagnostics without engine borrowing.
#[cfg(feature = "rx-batch-profile")]
static RX_BATCH_HIST: [AtomicU64; ring::RX_BATCH + 1] =
    [const { AtomicU64::new(0) }; ring::RX_BATCH + 1];
// Sample complete callback scopes, including early exits. No printing in the
// receive path. Times include waits/preemption, not exclusive CPU cycles.
#[cfg(feature = "rx-callback-profile")]
static RX_CALLBACK: [AtomicU64; 12] = [const { AtomicU64::new(0) }; 12];
#[cfg(feature = "rx-callback-profile")]
struct RxCallbackSample {
    sampled: bool, phase: usize, last: u64, ticks: [u64; 5],
    frames: usize, outcome: usize,
}
#[cfg(feature = "rx-callback-profile")]
impl RxCallbackSample {
    fn new() -> Self {
        let sampled = RX_CALLBACK[0].fetch_add(1, Ordering::Relaxed) % 127 == 0;
        Self { sampled, phase: 0, last: if sampled { profile_time() } else { 0 },
            ticks: [0; 5], frames: 0, outcome: 3 }
    }
    fn next(&mut self) {
        if self.sampled {
            let now = profile_time();
            self.ticks[self.phase] += now.wrapping_sub(self.last);
            self.last = now;
        }
        self.phase += 1;
    }
}
#[cfg(feature = "rx-callback-profile")]
impl Drop for RxCallbackSample {
    fn drop(&mut self) {
        if !self.sampled { return; }
        self.ticks[self.phase] += profile_time().wrapping_sub(self.last);
        RX_CALLBACK[1].fetch_add(1, Ordering::Relaxed);
        for (counter, ticks) in RX_CALLBACK[2..7].iter().zip(self.ticks) {
            counter.fetch_add(ticks, Ordering::Relaxed);
        }
        RX_CALLBACK[7].fetch_add(self.frames as u64, Ordering::Relaxed);
        RX_CALLBACK[8 + self.outcome].fetch_add(1, Ordering::Relaxed);
    }
}
#[cfg(feature = "rx-batch-experiment")]
unsafe fn poll_rx_batch() -> Result<vibeos_hal::network_rx::TicketBatch, Error> {
    #[cfg(feature = "rx-callback-profile")]
    let mut profile = RxCallbackSample::new();
    let mut output = [None; ring::RX_BATCH];
    if !engine().receive_pending() {
        #[cfg(feature = "rx-callback-profile")]
        { profile.outcome = 1; }
        return Ok(output);
    }
    #[cfg(feature = "rx-callback-profile")]
    profile.next();
    let mut access = RxAccess { view: None };
    let frames = match engine().receive_detached_batch(&mut access) {
        Ok(frames) => frames,
        Err(EngineError::Ring(ring::Error::Full)) => {
            #[cfg(feature = "rx-callback-profile")]
            { profile.outcome = 2; }
            RX_META.lock().counts[3] += 1; return Ok(output);
        }
        Err(e) => return Err(error(e)),
    };
    #[cfg(feature = "rx-callback-profile")]
    profile.next();
    #[cfg(feature = "rx-batch-profile")]
    RX_BATCH_HIST[frames.iter().flatten().count()].fetch_add(1, Ordering::Relaxed);
    if frames.iter().all(Option::is_none) {
        #[cfg(feature = "rx-callback-profile")]
        { profile.outcome = 1; }
        return Ok(output);
    }
    let view = access.view.expect("admitted permanent RX view");
    let mut accepted = [false; ring::RX_BATCH];
    for (i, frame) in frames.iter().enumerate() {
        if let Some(frame) = frame {
            accepted[i] = view.read(frame.ticket.index(), frame.bytes,
                |bytes| engine().validate_rx_frame(bytes, frame.checksum)).expect("validated RX span");
        }
    }
    #[cfg(feature = "rx-callback-profile")]
    profile.next();
    let mut count = 0;
    with_rx_metadata(1, |metadata| {
        for (i, frame) in frames.into_iter().enumerate() {
            if let Some(frame) = frame {
                if accepted[i] {
                    metadata.counts[0] += 1;
                    metadata.lengths[frame.ticket.index()] = frame.bytes;
                    output[count] = Some(frame.ticket);
                    count += 1;
                } else {
                    metadata.counts[4] += 1;
                    let _ = metadata.buffers.as_mut().unwrap().discard(frame.ticket);
                }
            }
        }
    });
    #[cfg(feature = "rx-callback-profile")]
    { profile.next(); profile.frames = count; profile.outcome = 0; }
    let engine = engine(); engine.rx_packets = engine.rx_packets.saturating_add(count as u64);
    snapshot();
    Ok(output)
}

#[cfg(feature = "rx-pool-experiment")]
unsafe fn release_rx_borrow(borrow: vibeos_hal::network_rx::Borrow) {
    with_rx_metadata(3, |metadata| {
        if metadata.buffers.as_mut().is_some_and(|buffers| buffers.release(borrow).is_ok()) {
            metadata.counts[2] += 1;
        }
    });
}
#[cfg(feature = "gro-batch-release")]
unsafe fn release_rx_borrows(borrows: &mut [Option<vibeos_hal::network_rx::Borrow>]) {
    with_rx_metadata(3, |metadata| {
        metadata.batch_releases[0] += 1;
        for borrow in borrows.iter_mut().filter_map(Option::take) {
            if metadata.buffers.as_mut().is_some_and(|buffers| buffers.release(borrow).is_ok()) {
                metadata.counts[2] += 1;
                metadata.batch_releases[1] += 1;
            }
        }
    });
}
#[cfg(feature = "rx-pool-experiment")]
unsafe fn acquire_rx_loan(ticket: vibeos_hal::network_rx::Ticket, owner: vibeos_hal::network_rx::Owner)
    -> Result<vibeos_hal::network_rx::Loan, Error>
{
    with_rx_metadata(2, |metadata| acquire_rx_loan_locked(metadata, ticket, owner))
}
#[cfg(feature = "rx-pool-experiment")]
unsafe fn acquire_rx_loan_locked(metadata: &mut RxMetadata, ticket: vibeos_hal::network_rx::Ticket, owner: vibeos_hal::network_rx::Owner) -> Result<vibeos_hal::network_rx::Loan, Error> {

        let view = metadata.view.ok_or(Error::InvalidDescription)?;
        let bytes = *metadata.lengths.get(ticket.index()).ok_or(Error::InvalidDescription)?;
        let buffers = metadata.buffers.as_mut().ok_or(Error::InvalidDescription)?;
        let borrow = buffers.borrow(ticket, owner.key()).map_err(|_| Error::Busy)?;
        let pointer = match view.read(borrow.index(), bytes, |bytes| bytes.as_ptr()) {
            Ok(pointer) => pointer,
            Err(_) => { let _ = buffers.release(borrow); return Err(Error::InvalidDescription); }
        };
        match vibeos_hal::network_rx::Loan::new(borrow, pointer, bytes, release_rx_borrow) {
            Ok(loan) => {
                #[cfg(feature = "gro-batch-release")]
                let loan = loan.with_batch_release(release_rx_borrows);
                metadata.counts[1] += 1; Ok(loan)
            },
            Err(borrow) => { let _ = buffers.release(borrow); Err(Error::InvalidDescription) }
        }
}

#[cfg(feature = "rx-admission-batch")]
unsafe fn acquire_rx_loans(tickets: &vibeos_hal::network_rx::TicketBatch, owner: vibeos_hal::network_rx::Owner) -> [Option<Result<vibeos_hal::network_rx::Loan, Error>>; vibeos_hal::network_rx::BATCH_SIZE] {
    with_rx_metadata(2, |metadata| core::array::from_fn(|i| tickets[i].map(|ticket| acquire_rx_loan_locked(metadata, ticket, owner))))
}
#[cfg(feature = "rx-pool-experiment")]
unsafe fn discard_rx_ticket(ticket: vibeos_hal::network_rx::Ticket) -> bool {
    RX_META.lock().buffers.as_mut().is_some_and(|buffers| buffers.discard(ticket).is_ok())
}
#[cfg(feature = "rx-pool-experiment")]
unsafe fn recover_rx_borrower(owner: vibeos_hal::network_rx::Owner) -> usize {
    let key = owner.key();
    let domain = vibeos_core::heap::AllocationDomain::new(
        vibeos_core::heap::OwnerId::new((key >> 64) as u64), vibeos_core::heap::ArenaId::new(key as u64));
    let _ = RX_META.recover_after_fault(domain);
    RX_META.lock().buffers.as_mut().map_or(0, |buffers| buffers.recover_borrower(key))
}

#[cfg(feature = "rx-pool-experiment")]
fn rx_pool_stats() -> vibeos_hal::network_rx::Stats {
    #[cfg(feature = "rx-ring-profile")]
    report(format_args!("RX_RING_STAGE interval=131 fields=[calls,samples,lookup,descriptor,sync,prepare,rearm,publish,finish,frames,ok,empty,error] values={:?}\n",
        ring::rx_stage_profile::snapshot()));
    #[cfg(feature = "rx-callback-profile")]
    report(format_args!("RX_CALLBACK interval=127 fields=[calls,samples,probe,detach,validate,metadata,finish,frames,ok,empty,full,error] values={:?}\n",
        RX_CALLBACK.each_ref().map(|v| v.load(Ordering::Relaxed))));
    #[cfg(feature = "rx-metadata-profile")]
    for (hart, counters) in METADATA_COUNTERS.iter().enumerate() {
        for (kind, row) in counters.0.iter().enumerate() {
            report(format_args!("RX_META_SAMPLE hart={} kind={} interval=127 fields=[calls,samples,acquire_ticks,held_ticks,max_held_ticks] values={:?}\n",
                hart, kind, row.each_ref().map(|v| v.load(Ordering::Relaxed))));
        }
    }
    // Emit before taking RX_META: diagnostics must not invert console/metadata
    // lock order. No extra logging occurs on the receive path.
    #[cfg(feature = "rx-batch-profile")]
    report(format_args!("RX_BATCH_HIST {:?}\n",
        core::array::from_fn::<_, { ring::RX_BATCH + 1 }, _>(|i|
            RX_BATCH_HIST[i].load(Ordering::Relaxed))));
    let metadata = RX_META.lock();
    let slots = metadata.buffers.as_ref().map(|b| b.stats()).unwrap_or_default();
    let stats = vibeos_hal::network_rx::Stats { received: metadata.counts[0], acquired: metadata.counts[1],
        released: metadata.counts[2], full: metadata.counts[3], dropped: metadata.counts[4],
        free: slots.free, ready: slots.ready, borrowed: slots.borrowed };
    #[cfg(feature = "gro-batch-release")]
    let batch = metadata.batch_releases;
    drop(metadata);
    #[cfg(feature = "gro-batch-release")]
    report(format_args!("RX_RELEASE_BATCH fields=[calls,frames] values={:?}\n", batch));
    stats
}
