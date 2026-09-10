//! GMAC4/5 single-queue register engine. Platform clocks/PHY/cache are separate.
use crate::{
    descriptor,
    mdio::{self, Registers},
    ring::{Layout, BUFFER, STRIDE},
};

const MAC: usize = 0;
const FILTER: usize = 8;
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
    TimedOut,
    ResetFailed,
    StartFailed,
    NotReady,
}

pub struct Controller<R: Io> {
    io: R,
    config: Config,
    reset_done: bool,
    configured: bool,
    running: bool,
    layout: Option<Layout>,
}
impl<R: Io> Controller<R> {
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
        })
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
        self.layout = None;
        layout.validate().map_err(|_| Error::InvalidLayout)?;
        let feature = self.io.read(FEATURE1);
        let tx = (feature >> 6) & 31;
        let rx = feature & 31;
        // At least one full standard frame in each store-and-forward FIFO.
        if !(4..=10).contains(&tx) || !(4..=11).contains(&rx) {
            return Err(Error::UnsupportedFifo);
        }
        let tqs = (1u32 << (tx - 1)) - 1;
        let rqs = (1u32 << (rx - 1)) - 1;
        self.io.write(0xd00, tqs << 16 | 2 << 2 | 1 << 1);
        self.io.write(0xd18, 0x10);
        self.io.write(0xd30, rqs << 20 | 1 << 5);
        self.io.write(0xa0, 2); // RX queue 0 in DCB mode.
        self.io.write(0xa4, 1 << 20); // Multicast/broadcast to queue 0.
        self.io.write(0x98, 0);
        self.io.write(0xa8, 0);
        self.io.write(FILTER, 0); // Own unicast and broadcast; no promiscuous mode.
        self.io.write(0x70, 0);
        self.io.write(0x90, 0); // Pause requires PHY negotiation.
        let c = self.config;
        let speed = match c.speed {
            Speed::Mbps10 => 1 << 15,
            Speed::Mbps100 => (1 << 15) | (1 << 14),
            Speed::Mbps1000 => 0,
        };
        // FCS retained (ACS/CST=0), checksum/TSO/jumbo disabled, MAC still stopped.
        self.io
            .write(MAC, speed | if c.full_duplex { 1 << 13 } else { 0 });
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
        self.io.write(0x1004, 2 << 16 | 1 << 3 | 1 << 2 | 1 << 1);
        self.io.write(
            0x1100,
            descriptor::skip_length(STRIDE, layout.axi_bytes).unwrap(),
        );
        self.io.write(TX, 8 << 16 | 1 << 4);
        self.io.write(RX, 8 << 16 | (BUFFER as u32) << 1);
        self.io.write(0x1110, 0);
        self.io.write(0x1114, layout.tx_descriptors as u32);
        self.io.write(0x1118, 0);
        self.io.write(0x111c, layout.rx_descriptors as u32);
        self.io.write(0x112c, (layout.count - 1) as u32);
        self.io.write(0x1130, (layout.count - 1) as u32);
        self.io.write(IRQ_ENABLE, 0); // Polled frontend; interrupt policy added separately.
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
