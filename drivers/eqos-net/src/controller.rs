//! GMAC4/5 single-queue register engine. Platform clocks/PHY/cache are separate.
use crate::{
    descriptor,
    mdio::{self, Registers},
    ring::{Layout, BUFFER, STRIDE},
};

const MAC: usize = 0;
const FILTER: usize = 8;
const FEATURE0: usize = 0x11c;
const FEATURE1: usize = 0x120;
const DMA_MODE: usize = 0x1000;
const TX: usize = 0x1104;
const RX: usize = 0x1108;
const IRQ_ENABLE: usize = 0x1134;
const SWR: u32 = 1;

/// # Safety
/// Register accesses must faithfully reach the exclusively owned controller (or
/// a complete test model), preserve device ordering, and return actual readback.
/// In particular, falsely reporting SWR clear can authorize reuse of live DMA.
pub unsafe trait Io: Registers {
    fn ticks(&mut self) -> u64;
    fn relax(&mut self) {
        core::hint::spin_loop();
    }
}

pub use vibeos_ethernet::phy::Speed;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    pub mac: [u8; 6],
    pub speed: Speed,
    pub full_duplex: bool,
    pub csr_hz: u64,
    pub timebase_hz: u64,
    pub max_polls: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConfig,
    InvalidLayout,
    UnsupportedFifo,
    ConfigurationRejected,
    TimedOut,
    ResetFailed,
    StartFailed,
    NotReady,
}

/// Capability advertisement only, not proof of packet-level qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChecksumCapabilities {
    pub raw: u32,
    pub tx: bool,
    pub rx: bool,
}
impl ChecksumCapabilities {
    pub const fn from_feature0(raw: u32) -> Self {
        Self { raw, tx: raw & (1 << 14) != 0, rx: raw & (1 << 16) != 0 }
    }
}

/// Non-destructive queue-0 snapshots. Status bits are sticky events, not
/// packet counts; RX debug is instantaneous. Reading does not acknowledge IRQs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaDiagnostics {
    pub dma_status: u32,
    pub mtl_interrupt: u32,
    pub mtl_rx_debug: u32,
}

/// GMAC4 MMC TX counters. No reset/freeze/read-clear mode is changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmcTxCounters {
    pub control: u32,
    pub frames_good_bad: u32,
    pub frames_good: u32,
    pub underflow: u32,
    pub carrier_error: u32,
    pub pause: u32,
}

pub struct Controller<R: Io> {
    io: R,
    config: Config,
    reset_done: bool,
    configured: bool,
    running: bool,
    layout: Option<Layout>,
    rx_checksum: bool,
    rx_forward_errors: bool,
    symmetric_pause: bool,
    tso: bool,
    rx_watchdog: u8,
}
impl<R: Io> Controller<R> {
    /// Read counters only when the hardware advertises MMC and reads are
    /// non-destructive. Offsets match Linux stmmac mmc.h/mmc_core.c (GMAC4).
    pub fn mmc_tx_counters(&mut self) -> Option<MmcTxCounters> {
        if self.io.read(FEATURE0) & (1 << 8) == 0 { return None; }
        let control = self.io.read(0x700);
        // Reject reset, reset-on-read, freeze and preset modes. Stop-on-wrap
        // is safe to observe; callers must reject saturated counters.
        if control & 0x3d != 0 { return None; }
        Some(MmcTxCounters {
            control,
            frames_good_bad: self.io.read(0x718),
            frames_good: self.io.read(0x768),
            underflow: self.io.read(0x748),
            carrier_error: self.io.read(0x760),
            pause: self.io.read(0x770),
        })
    }
    pub fn new(io: R, config: Config) -> Result<Self, Error> {
        if config.mac == [0; 6]
            || config.mac[0] & 1 != 0
            || mdio::clock_range(config.csr_hz).is_err()
            || !(1..=1_000_000_000).contains(&config.timebase_hz)
            || !(1..=1_000_000).contains(&config.max_polls)
        {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            io,
            config,
            reset_done: false,
            configured: false,
            running: false,
            layout: None,
            rx_checksum: false,
            rx_forward_errors: false,
            symmetric_pause: false,
            tso: false,
            rx_watchdog: 0,
        })
    }
    /// Select the watchdog interval while stopped. Does not enable interrupts;
    /// handler registration and budgeted poll scheduling belong to the adapter.
    pub fn set_rx_watchdog(&mut self, microseconds: u32) -> Result<(), Error> {
        if self.running { return Err(Error::NotReady); }
        self.rx_watchdog = crate::rx_irq::watchdog_ticks(self.config.csr_hz, microseconds)
            .ok_or(Error::InvalidConfig)?;
        self.configured = false;
        Ok(())
    }
    pub fn checksum_capabilities(&mut self) -> ChecksumCapabilities {
        ChecksumCapabilities::from_feature0(self.io.read(FEATURE0))
    }
    /// Request segmentation only while stopped. Capability alone is not an
    /// active-mode guarantee; configure/start and register readback must succeed.
    pub fn set_tso(&mut self, enabled: bool) -> Result<(), Error> {
        if self.running { return Err(Error::NotReady); }
        if enabled && (self.io.read(FEATURE1) & (1 << 18) == 0
            || !self.checksum_capabilities().tx || !self.config.full_duplex) {
            return Err(Error::ConfigurationRejected);
        }
        self.tso = enabled;
        self.configured = false;
        Ok(())
    }
    pub fn tso_active(&self) -> bool { self.tso && self.configured && self.running }
    /// Select RX checksum observation while stopped. Consumers must still use
    /// software verification until per-packet metadata and fallback are qualified.
    pub fn set_rx_checksum(&mut self, enabled: bool) -> Result<(), Error> {
        if self.running { return Err(Error::NotReady); }
        if enabled && !self.checksum_capabilities().rx {
            return Err(Error::ConfigurationRejected);
        }
        self.rx_checksum = enabled;
        self.configured = false;
        Ok(())
    }
    /// Diagnostic mode: forward erroneous frames to DMA for rejection evidence.
    /// The ring must continue rejecting error-summary descriptors without copy.
    pub fn set_rx_error_forwarding(&mut self, enabled: bool) -> Result<(), Error> {
        if self.running { return Err(Error::NotReady); }
        self.rx_forward_errors = enabled;
        self.configured = false;
        Ok(())
    }
    /// Change the next configuration only while the controller is stopped.
    /// Invalidates any prior configuration; start requires configure again.
    pub fn set_link(&mut self, speed: Speed, full_duplex: bool) -> Result<(), Error> {
        if self.running {
            return Err(Error::NotReady);
        }
        self.config.speed = speed;
        self.config.full_duplex = full_duplex;
        self.configured = false;
        Ok(())
    }
    /// Apply the PHY's negotiated symmetric pause result while stopped.
    pub fn set_symmetric_pause(&mut self, enabled: bool) -> Result<(), Error> {
        if self.running { return Err(Error::NotReady); }
        self.symmetric_pause = enabled;
        self.configured = false;
        Ok(())
    }
    fn update(&mut self, offset: usize, clear: u32, set: u32) {
        let value = self.io.read(offset);
        self.io.write(offset, (value & !clear) | set);
    }
    fn wait_clear(&mut self, offset: usize, mask: u32) -> Result<(), Error> {
        let start = self.io.ticks();
        let budget = self.config.timebase_hz.div_ceil(10); // 100 ms; at least one tick.
        for _ in 0..self.config.max_polls {
            if self.io.read(offset) & mask == 0 {
                return Ok(());
            }
            if self.io.ticks().wrapping_sub(start) >= budget {
                break;
            }
            self.io.relax();
        }
        Err(Error::TimedOut)
    }
    /// SWR completion plus disabled DMA/MAC readback is the controller-level
    /// reset proof. Platform qualification must verify it on the actual SoC.
    pub fn reset(&mut self) -> Result<(), Error> {
        self.reset_done = false;
        self.configured = false;
        self.running = false;
        self.layout = None;
        self.io.write(IRQ_ENABLE, 0);
        self.update(TX, 1, 0);
        self.update(RX, 1, 0);
        self.update(MAC, 3, 0);
        self.io.write(DMA_MODE, SWR);
        self.wait_clear(DMA_MODE, SWR)?;
        if self.io.read(TX) & 1 != 0 || self.io.read(RX) & 1 != 0 || self.io.read(MAC) & 3 != 0 {
            return Err(Error::ResetFailed);
        }
        self.reset_done = true;
        Ok(())
    }
    pub fn configure(&mut self, layout: Layout) -> Result<(), Error> {
        if !self.reset_done || self.running {
            return Err(Error::NotReady);
        }
        self.configured = false;
        if self.tso && (self.io.read(FEATURE1) & (1 << 18) == 0
            || !self.checksum_capabilities().tx || !self.config.full_duplex) {
            return Err(Error::ConfigurationRejected);
        }

        self.layout = None;
        layout.validate().map_err(|_| Error::InvalidLayout)?;
        let feature = self.io.read(FEATURE1);
        let tx = (feature >> 6) & 31;
        let rx = feature & 31;
        // At least one full standard frame in each store-and-forward FIFO.
        if !(4..=10).contains(&tx) || !(4..=11).contains(&rx) {
            return Err(Error::UnsupportedFifo);
        }
        if self.symmetric_pause && !self.config.full_duplex {
            return Err(Error::ConfigurationRejected);
        }
        let tqs = (1u32 << (tx - 1)) - 1;
        let rqs = (1u32 << (rx - 1)) - 1;
        self.io.write(0xd00, tqs << 16 | 2 << 2 | 1 << 1);
        self.io.write(0xd18, 0x10);
        // DISTCPEF (6) disables checksum-error dropping; FEP (4) forwards
        // erroneous packets. Default remains discard-before-DMA.
        let error_forward = if self.rx_forward_errors { (1 << 6) | (1 << 4) } else { 0 };
        // Linux stmmac's automatic TX pause thresholds: >= 4 KiB FIFO only.
        // Smaller FIFOs can still honor received pause at the MAC; never
        // program unrepresentable automatic-generation thresholds for them.
        // 4 KiB: activate at 1.5 KiB free, release at 2.5 KiB free;
        // larger FIFOs: activate at 3 KiB free, release at 4.5 KiB free.
        let flow = if !self.symmetric_pause || rx < 5 { 0 }
            else if rx == 5 { 1 << 7 | 1 << 8 | 3 << 14 }
            else { 1 << 7 | 4 << 8 | 7 << 14 };
        self.io.write(0xd30, rqs << 20 | 1 << 5 | error_forward | flow);
        if self.io.read(0xd30) & 0x000f_ff80 != flow {
            return Err(Error::ConfigurationRejected);
        }
        if self.io.read(0xd30) & ((1 << 6) | (1 << 4)) != error_forward {
            return Err(Error::ConfigurationRejected);
        }
        self.io.write(0xa0, 2); // RX queue 0 in DCB mode.
        self.io.write(0xa4, 1 << 20); // Multicast/broadcast to queue 0.
        self.io.write(0x98, 0);
        self.io.write(0xa8, 0);
        self.io.write(FILTER, 0); // Own unicast and broadcast; no promiscuous mode.
        let tx_flow = if self.symmetric_pause { 0xffff_0002 } else { 0 };
        let rx_flow = u32::from(self.symmetric_pause);
        self.io.write(0x70, tx_flow);
        self.io.write(0x90, rx_flow);
        if self.io.read(0x70) & 0xffff_0002 != tx_flow || self.io.read(0x90) & 1 != rx_flow {
            return Err(Error::ConfigurationRejected);
        }
        let c = self.config;
        let speed = match c.speed {
            Speed::Mbps10 => 1 << 15,
            Speed::Mbps100 => (1 << 15) | (1 << 14),
            Speed::Mbps1000 => 0,
        };
        // FCS retained (ACS/CST=0), jumbo disabled, MAC still stopped.
        // Segmentation is selected separately in the DMA channel.
        // IPC only enables hardware observation; software acceptance is separate.
        self.io
            .write(MAC, speed | if c.full_duplex { 1 << 13 } else { 0 }
                | if self.rx_checksum { 1 << 27 } else { 0 });
        if (self.io.read(MAC) & (1 << 27) != 0) != self.rx_checksum {
            return Err(Error::ConfigurationRejected);
        }
        self.io.write(0xdc, (c.csr_hz / 1_000_000 - 1) as u32);
        self.io.write(
            0x300,
            1 << 31 | u32::from(c.mac[5]) << 8 | u32::from(c.mac[4]),
        );
        self.io.write(
            0x304,
            u32::from_le_bytes([c.mac[0], c.mac[1], c.mac[2], c.mac[3]]),
        );
        // 8 beats without PBLx8 fits even the smallest admitted FIFO.
        // Retain the measured baseline outstanding limits. Hardware may
        // implement fewer field bits than the generic register definition;
        // reject a configuration it cannot represent before starting DMA.
        let bus = 2 << 16 | 1 << 3 | 1 << 2 | 1 << 1;
        self.io.write(0x1004, bus);
        if self.io.read(0x1004) & 0x0f0f_080e != bus {
            return Err(Error::ConfigurationRejected);
        }
        self.io.write(
            0x1100,
            descriptor::skip_length(STRIDE, layout.axi_bytes).unwrap(),
        );
        let tx_mode = 8 << 16 | 1 << 4 | if self.tso { 1 << 12 } else { 0 };
        self.io.write(TX, tx_mode);
        if self.io.read(TX) & (1 << 12) != tx_mode & (1 << 12) {
            return Err(Error::ConfigurationRejected);
        }
        self.io.write(RX, 8 << 16 | (BUFFER as u32) << 1);
        self.io.write(0x1110, 0);
        self.io.write(0x1114, layout.tx_descriptors as u32);
        self.io.write(0x1118, 0);
        self.io.write(0x111c, layout.rx_descriptors as u32);
        self.io.write(0x112c, (layout.count - 1) as u32);
        self.io.write(0x1130, (layout.count - 1) as u32);
        self.io.write(IRQ_ENABLE, 0); // Polled frontend; interrupt policy added separately.
        self.io.write(crate::rx_irq::WATCHDOG, u32::from(self.rx_watchdog));
        if self.io.read(crate::rx_irq::WATCHDOG) & 0xff != u32::from(self.rx_watchdog) {
            return Err(Error::ConfigurationRejected);
        }
        self.layout = Some(layout);
        self.configured = true;
        Ok(())
    }
    pub fn start(&mut self) -> Result<(), Error> {
        if !self.configured || self.running {
            return Err(Error::NotReady);
        }
        self.running = true;
        self.reset_done = false;
        self.update(TX, 0, 1);
        self.update(RX, 0, 1);
        self.update(MAC, 0, 3);
        if self.io.read(TX) & 1 == 0 || self.io.read(RX) & 1 == 0 || self.io.read(MAC) & 3 != 3 {
            self.configured = false;
            self.layout = None;
            return Err(Error::StartFailed);
        }
        Ok(())
    }
    #[cfg(feature = "rx-stage-profile")]
    pub(crate) fn profile_ticks(&mut self) -> u64 { self.io.ticks() }

    pub fn tail(&mut self, rx: bool, address: u64) -> Result<(), Error> {
        let l = self.layout.ok_or(Error::NotReady)?;
        let base = if rx {
            l.rx_descriptors
        } else {
            l.tx_descriptors
        };
        if address < base
            || address >= base + (l.count * STRIDE) as u64
            || (address - base) % STRIDE as u64 != 0
        {
            return Err(Error::InvalidLayout);
        }
        self.io
            .write(if rx { 0x1128 } else { 0x1120 }, address as u32);
        Ok(())
    }
    /// Stopping ends in a reset handshake instead of inferring DMA quiescence
    /// from an empty MTL FIFO. A timeout cannot authorize pool reuse.
    pub fn stop(&mut self) -> Result<(), Error> {
        self.reset()
    }
    pub fn diagnostics(&mut self) -> DmaDiagnostics {
        // Linux stmmac dwmac4: channel-0 status, MTL queue-0 IRQ and RX debug.
        // Avoid read-to-clear missed-packet counters and all W1C writes.
        DmaDiagnostics {
            dma_status: self.io.read(0x1160),
            mtl_interrupt: self.io.read(0xd2c),
            mtl_rx_debug: self.io.read(0xd38),
        }
    }
    pub fn flow_diagnostics(&mut self) -> [u32; 4] {
        [self.io.read(FEATURE1), self.io.read(0xd30), self.io.read(0x70), self.io.read(0x90)]
    }
    pub fn dma_status(&mut self) -> u32 {
        self.io.read(0x1160)
    }
}

/// Ordered MMIO plus a firmware-supplied monotonic counter. No SoC cache ISA.
pub struct Mmio {
    base: usize,
    ticks: fn() -> u64,
}
impl Mmio {
    /// # Safety
    /// The complete register window must be mapped and exclusively assigned to
    /// this driver, with clocks/reset/pins prepared before any register access.
    pub unsafe fn new(base: usize, bytes: usize, ticks: fn() -> u64) -> Result<Self, Error> {
        if base % 4 != 0 || bytes < 0x1164 || base.checked_add(bytes).is_none() {
            return Err(Error::InvalidConfig);
        }
        Ok(Self { base, ticks })
    }
}
fn fence() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "riscv64"))]
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
impl Registers for Mmio {
    fn read(&mut self, offset: usize) -> u32 {
        assert!(offset <= 0x1160 && offset % 4 == 0);
        fence();
        let value = unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) };
        fence();
        value
    }
    fn write(&mut self, offset: usize, value: u32) {
        assert!(offset <= 0x1160 && offset % 4 == 0);
        fence();
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) };
        fence();
    }
}
unsafe impl Io for Mmio {
    fn ticks(&mut self) -> u64 {
        (self.ticks)()
    }
}
