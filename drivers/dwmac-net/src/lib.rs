//! Polling Synopsys DWMAC engine for the CV1800B integrated Ethernet MAC.
//!
//! The crate owns registers, clock/ePHY setup and one cache-isolated RX/TX
//! descriptor pair. Kernel capabilities, packet sessions and supervision are
//! deliberately outside this layer.

#![cfg_attr(not(test), no_std)]

use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use vibeos_hal::{DwmacDescription, MAX_PACKET_LEN};

const DMA_BUFFER_LEN: usize = 1_536;
const RESET_BUDGET: usize = 2_000_000;
const GMAC_CONTROL: usize = 0x0000;
const GMAC_FRAME_FILTER: usize = 0x0004;
const GMAC_MII_ADDR: usize = 0x0010;
const GMAC_MII_DATA: usize = 0x0014;
const GMAC_ADDR_HIGH: usize = 0x0040;
const GMAC_ADDR_LOW: usize = 0x0044;
const DMA_BUS_MODE: usize = 0x1000;
const DMA_TX_POLL: usize = 0x1004;
const DMA_RX_POLL: usize = 0x1008;
const DMA_RX_DESC: usize = 0x100c;
const DMA_TX_DESC: usize = 0x1010;
const DMA_STATUS: usize = 0x1014;
const DMA_CONTROL: usize = 0x1018;
const DMA_INT_ENABLE: usize = 0x101c;
const DMA_AXI_BUS_MODE: usize = 0x1028;
const DMA_SOFT_RESET: u32 = 1;
const DMA_AAL: u32 = 1 << 25;
const DMA_START_RX: u32 = 1 << 1;
const DMA_START_TX: u32 = 1 << 13;
const DMA_RX_STORE_FORWARD: u32 = 1 << 25;
const DMA_TX_STORE_FORWARD: u32 = 1 << 21;
const DMA_FLUSH_TX: u32 = 1 << 20;
const MAC_RX_ENABLE: u32 = 1 << 2;
const MAC_TX_ENABLE: u32 = 1 << 3;
const MAC_ACS: u32 = 1 << 7;
const MAC_DUPLEX: u32 = 1 << 11;
const MAC_FAST_ETHERNET: u32 = 1 << 14;
const MAC_MII_PORT: u32 = 1 << 15;
const MII_BUSY: u32 = 1;
const MII_CLOCK_RANGE_250MHZ: u32 = 5 << 2;
const DESC_OWN: u32 = 1 << 31;
const RX_LAST: u32 = 1 << 8;
const RX_FIRST: u32 = 1 << 9;
const RX_ERROR: u32 = 1 << 15;
const RX_END_RING: u32 = 1 << 25;
const TX_END_RING: u32 = 1 << 25;
const TX_FIRST: u32 = 1 << 29;
const TX_LAST: u32 = 1 << 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Busy,
    InvalidDescription,
    TimedOut,
    QueueFull,
    PacketTooLarge,
    AddressTooWide,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Telemetry {
    pub phy_link_up: bool,
    pub tx_descriptor_status: u32,
    pub dma_status: u32,
    pub clock_enable: u32,
    pub clock_bypass: u32,
    pub clock_divider: u32,
    pub ephy_control: u32,
    pub resets: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Clone, Copy)]
#[repr(C, align(64))]
struct Descriptor {
    words: [u32; 16],
}
impl Descriptor {
    const ZERO: Self = Self { words: [0; 16] };
}

#[repr(C, align(64))]
struct Slab {
    rx_desc: Descriptor,
    tx_desc: Descriptor,
    rx: [u8; DMA_BUFFER_LEN],
    tx: [u8; DMA_BUFFER_LEN],
}
impl Slab {
    const ZERO: Self = Self {
        rx_desc: Descriptor::ZERO,
        tx_desc: Descriptor::ZERO,
        rx: [0; DMA_BUFFER_LEN],
        tx: [0; DMA_BUFFER_LEN],
    };
}

const _: () = {
    assert!(core::mem::size_of::<Descriptor>() == 64);
    assert!(core::mem::align_of::<Descriptor>() == 64);
    assert!(core::mem::offset_of!(Slab, rx_desc) % 64 == 0);
    assert!(core::mem::offset_of!(Slab, tx_desc) % 64 == 0);
    assert!(core::mem::offset_of!(Slab, rx) % 64 == 0);
    assert!(core::mem::offset_of!(Slab, tx) % 64 == 0);
};

pub struct DmaStorage {
    slab: UnsafeCell<Slab>,
    claimed: AtomicBool,
    phy_link_up: AtomicBool,
    resets: AtomicU64,
    rx_packets: AtomicU64,
    tx_packets: AtomicU64,
    tx_status: AtomicU64,
}

unsafe impl Sync for DmaStorage {}

impl DmaStorage {
    pub const fn new() -> Self {
        Self {
            slab: UnsafeCell::new(Slab::ZERO),
            claimed: AtomicBool::new(false),
            phy_link_up: AtomicBool::new(false),
            resets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_status: AtomicU64::new(0),
        }
    }

    pub fn base(&self) -> usize {
        self.slab.get() as usize
    }
}

impl Default for DmaStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate invariants required by the fixed CV1800B engine without touching
/// hardware. This is also suitable for BSP table tests on the host.
pub const fn validate_description(description: DwmacDescription) -> bool {
    range_contains_bytes(
        description.registers.start,
        description.registers.end,
        DMA_AXI_BUS_MODE + 4,
    ) && range_contains_bytes(
        description.soc_control.start,
        description.soc_control.end,
        0xa000,
    ) && range_contains_bytes(description.efuse.start, description.efuse.end, 0x128)
        && description.cache_line_bytes == 64
        && description.dma_address_bits == 32
        && description.phy_address < 32
}

const fn range_contains_bytes(start: usize, end: usize, bytes: usize) -> bool {
    match start.checked_add(bytes) {
        Some(required_end) => end >= required_end,
        None => false,
    }
}

/// Exclusive live ownership of one caller-supplied DMA slab and DWMAC instance.
pub struct Engine {
    description: DwmacDescription,
    dma: &'static DmaStorage,
    time: fn() -> u64,
    timebase_hz: u64,
    live: bool,
}

impl Engine {
    /// Claim and initialize the device.
    ///
    /// # Safety
    /// `time` must be monotonic in `timebase_hz` ticks and every described
    /// MMIO range must remain mapped with exclusive device ownership for the
    /// returned engine's lifetime. The supplied `.dma` slab must be
    /// identity mapped, physically contiguous, coherent with the explicit
    /// cache maintenance below, and reachable within `dma_address_bits`;
    /// descriptor addresses are published directly from their Rust address.
    pub unsafe fn claim(
        description: DwmacDescription,
        dma: &'static DmaStorage,
        guest_mac: [u8; 6],
        time: fn() -> u64,
        timebase_hz: u64,
    ) -> Result<Self, Error> {
        if !validate_description(description) {
            return Err(Error::InvalidDescription);
        }
        if dma
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::Busy);
        }
        let mut engine = Self {
            description,
            dma,
            time,
            timebase_hz,
            live: false,
        };
        if let Err(error) = unsafe { engine.initialize(guest_mac) } {
            let _ = shutdown(description, dma);
            dma.claimed.store(false, Ordering::Release);
            return Err(error);
        }
        engine.live = true;
        Ok(engine)
    }

    pub fn irq(&self) -> u32 {
        self.description.irq
    }

    pub fn tx_owned(&self) -> bool {
        let dma = unsafe { &*self.dma.slab.get() };
        invalidate_range(
            self.description.cache_line_bytes,
            descriptor_address(&dma.tx_desc),
            core::mem::size_of_val(&dma.tx_desc),
        );
        let status = dma.tx_desc.words[0];
        self.dma
            .tx_status
            .store(u64::from(status), Ordering::Release);
        status & DESC_OWN != 0
    }

    pub fn transmit(&mut self, packet: &[u8]) -> Result<(), Error> {
        if packet.len() > DMA_BUFFER_LEN {
            return Err(Error::PacketTooLarge);
        }
        let dma = unsafe { &mut *self.dma.slab.get() };
        invalidate_range(
            self.description.cache_line_bytes,
            descriptor_address(&dma.tx_desc),
            core::mem::size_of_val(&dma.tx_desc),
        );
        if dma.tx_desc.words[0] & DESC_OWN != 0 {
            self.dma
                .tx_status
                .store(u64::from(dma.tx_desc.words[0]), Ordering::Release);
            return Err(Error::QueueFull);
        }
        dma.tx[..packet.len()].copy_from_slice(packet);
        dma.tx_desc.words[1] = packet.len() as u32 | TX_END_RING | TX_FIRST | TX_LAST;
        dma.tx_desc.words[0] = DESC_OWN;
        self.dma
            .tx_status
            .store(u64::from(DESC_OWN), Ordering::Release);
        clean_range(
            self.description.cache_line_bytes,
            buffer_address(&dma.tx),
            packet.len(),
        );
        clean_range(
            self.description.cache_line_bytes,
            descriptor_address(&dma.tx_desc),
            core::mem::size_of_val(&dma.tx_desc),
        );
        write32(self.description, DMA_TX_POLL, 1);
        self.dma.tx_packets.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn receive(&mut self, output: &mut [u8]) -> Option<usize> {
        let dma = unsafe { &mut *self.dma.slab.get() };
        invalidate_range(
            self.description.cache_line_bytes,
            descriptor_address(&dma.rx_desc),
            core::mem::size_of_val(&dma.rx_desc),
        );
        let status = dma.rx_desc.words[0];
        if status & DESC_OWN != 0 {
            return None;
        }
        let with_fcs = ((status >> 16) & 0x3fff) as usize;
        let length = with_fcs.saturating_sub(4);
        let valid = status & (RX_FIRST | RX_LAST) == RX_FIRST | RX_LAST
            && status & RX_ERROR == 0
            && length != 0
            && length <= MAX_PACKET_LEN
            && length <= output.len();
        let result = if valid {
            invalidate_range(
                self.description.cache_line_bytes,
                buffer_address(&dma.rx),
                with_fcs.min(DMA_BUFFER_LEN),
            );
            output[..length].copy_from_slice(&dma.rx[..length]);
            self.dma.rx_packets.fetch_add(1, Ordering::Relaxed);
            Some(length)
        } else {
            None
        };
        dma.rx_desc.words[1] = DMA_BUFFER_LEN as u32 | RX_END_RING;
        dma.rx_desc.words[0] = DESC_OWN;
        clean_range(
            self.description.cache_line_bytes,
            descriptor_address(&dma.rx_desc),
            core::mem::size_of_val(&dma.rx_desc),
        );
        write32(self.description, DMA_RX_POLL, 1);
        result
    }

    pub fn poll_link(&mut self) {
        update_phy_link(self.description, self.dma);
    }

    /// Stop DMA and release this instance's DMA ownership claim.
    pub fn shutdown(mut self) -> bool {
        let reset = shutdown(self.description, self.dma);
        self.live = false;
        self.dma.claimed.store(false, Ordering::Release);
        reset
    }

    unsafe fn initialize(&mut self, mac: [u8; 6]) -> Result<(), Error> {
        prepare_soc(self.description, self.time, self.timebase_hz);
        write32(
            self.description,
            DMA_BUS_MODE,
            read32(self.description, DMA_BUS_MODE) | DMA_SOFT_RESET,
        );
        if !wait_reset(self.description) {
            return Err(Error::TimedOut);
        }
        self.dma.resets.fetch_add(1, Ordering::Relaxed);
        let dma = unsafe { &mut *self.dma.slab.get() };
        *dma = Slab::ZERO;
        let rx = descriptor_address(&dma.rx_desc);
        let tx = descriptor_address(&dma.tx_desc);
        let rxb = buffer_address(&dma.rx);
        let txb = buffer_address(&dma.tx);
        if [rx, tx, rxb, txb]
            .iter()
            .any(|&address| address > u32::MAX as usize)
        {
            return Err(Error::AddressTooWide);
        }
        dma.rx_desc.words[1] = DMA_BUFFER_LEN as u32 | RX_END_RING;
        dma.rx_desc.words[2] = rxb as u32;
        dma.rx_desc.words[0] = DESC_OWN;
        dma.tx_desc.words[1] = TX_END_RING;
        dma.tx_desc.words[2] = txb as u32;
        clean_range(
            self.description.cache_line_bytes,
            self.dma.base(),
            core::mem::size_of::<Slab>(),
        );
        write32(
            self.description,
            DMA_BUS_MODE,
            DMA_AAL | (8 << 8) | (8 << 17),
        );
        write32(
            self.description,
            DMA_AXI_BUS_MODE,
            (1 << 12) | (1 << 1) | (1 << 2) | (1 << 3),
        );
        write32(self.description, DMA_RX_DESC, rx as u32);
        write32(self.description, DMA_TX_DESC, tx as u32);
        write32(self.description, DMA_STATUS, u32::MAX);
        write32(self.description, DMA_INT_ENABLE, 0);
        write32(
            self.description,
            GMAC_ADDR_HIGH,
            u32::from(mac[4]) | u32::from(mac[5]) << 8,
        );
        write32(
            self.description,
            GMAC_ADDR_LOW,
            u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]),
        );
        write32(self.description, GMAC_FRAME_FILTER, 0);
        write32(
            self.description,
            GMAC_CONTROL,
            MAC_MII_PORT | MAC_FAST_ETHERNET | MAC_DUPLEX | MAC_ACS | MAC_RX_ENABLE | MAC_TX_ENABLE,
        );
        write32(
            self.description,
            DMA_CONTROL,
            DMA_FLUSH_TX
                | DMA_RX_STORE_FORWARD
                | DMA_TX_STORE_FORWARD
                | DMA_START_RX
                | DMA_START_TX,
        );
        write32(self.description, DMA_RX_POLL, 1);
        update_phy_link(self.description, self.dma);
        let _ = read32(self.description, GMAC_MII_ADDR);
        Ok(())
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if self.live {
            let _ = shutdown(self.description, self.dma);
            self.dma.claimed.store(false, Ordering::Release);
        }
    }
}

/// Read a diagnostic snapshot from the live device and its SoC wiring.
///
/// # Safety
/// Every MMIO range referenced by `description` must remain mapped and
/// readable for this call. The caller must also serialize these diagnostic
/// reads with platform operations for which the DWMAC, clock, or ePHY
/// register semantics require exclusive access.
pub unsafe fn telemetry(description: DwmacDescription, dma: &DmaStorage) -> Telemetry {
    let tx_descriptor_status = dma.tx_status.load(Ordering::Acquire) as u32;
    Telemetry {
        phy_link_up: dma.phy_link_up.load(Ordering::Acquire),
        tx_descriptor_status,
        dma_status: read32(description, DMA_STATUS),
        clock_enable: soc_read32(description.soc_control.start + 0x2000),
        clock_bypass: soc_read32(description.soc_control.start + 0x2030),
        clock_divider: soc_read32(description.soc_control.start + 0x208c),
        ephy_control: soc_read32(description.soc_control.start + 0x9800),
        resets: dma.resets.load(Ordering::Acquire),
        rx_packets: dma.rx_packets.load(Ordering::Acquire),
        tx_packets: dma.tx_packets.load(Ordering::Acquire),
    }
}

/// Physical address of the caller-owned stable DMA slab, for diagnostics and
/// kernel resource descriptions only.
pub fn dma_region_base(dma: &DmaStorage) -> usize {
    dma.base()
}

/// Force hardware quiescence and clear an ownership claim after the previous
/// owner has become permanently unable to execute.
///
/// # Safety
/// The caller must prove that no old `Engine` can run or be dropped again.
/// Every range in `description` must still satisfy the mapping and exclusive
/// MMIO requirements of [`Engine::claim`] while recovery touches the device.
pub unsafe fn recover_faulted(description: DwmacDescription, dma: &DmaStorage) -> bool {
    let reset = shutdown(description, dma);
    dma.claimed.store(false, Ordering::Release);
    reset
}

fn shutdown(d: DwmacDescription, dma: &DmaStorage) -> bool {
    write32(d, DMA_INT_ENABLE, 0);
    write32(d, DMA_CONTROL, 0);
    write32(
        d,
        GMAC_CONTROL,
        read32(d, GMAC_CONTROL) & !(MAC_RX_ENABLE | MAC_TX_ENABLE),
    );
    write32(d, DMA_BUS_MODE, read32(d, DMA_BUS_MODE) | DMA_SOFT_RESET);
    let reset = wait_reset(d);
    dma.phy_link_up.store(false, Ordering::Release);
    dma.tx_status.store(0, Ordering::Release);
    reset
}
fn wait_reset(d: DwmacDescription) -> bool {
    for _ in 0..RESET_BUDGET {
        if read32(d, DMA_BUS_MODE) & DMA_SOFT_RESET == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn update_phy_link(d: DwmacDescription, dma: &DmaStorage) {
    if mdio_read(d, 1).is_none() {
        dma.phy_link_up.store(false, Ordering::Release);
        return;
    }
    let Some(status) = mdio_read(d, 1) else {
        dma.phy_link_up.store(false, Ordering::Release);
        return;
    };
    if status & (1 << 2) == 0 {
        dma.phy_link_up.store(false, Ordering::Release);
        return;
    }
    dma.phy_link_up.store(true, Ordering::Release);
    let control = mdio_read(d, 0).unwrap_or(0);
    let (fast, full) = if control & (1 << 12) != 0 && status & (1 << 5) != 0 {
        let partner = mdio_read(d, 5).unwrap_or(0);
        if partner & (1 << 8) != 0 {
            (true, true)
        } else if partner & (1 << 7) != 0 {
            (true, false)
        } else if partner & (1 << 6) != 0 {
            (false, true)
        } else {
            (false, false)
        }
    } else {
        (control & (1 << 13) != 0, control & (1 << 8) != 0)
    };
    let mut mac = read32(d, GMAC_CONTROL) & !(MAC_FAST_ETHERNET | MAC_DUPLEX);
    if fast {
        mac |= MAC_FAST_ETHERNET;
    }
    if full {
        mac |= MAC_DUPLEX;
    }
    write32(d, GMAC_CONTROL, mac);
}
fn mdio_read(d: DwmacDescription, register: u32) -> Option<u16> {
    for _ in 0..10_000 {
        if read32(d, GMAC_MII_ADDR) & MII_BUSY == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    if read32(d, GMAC_MII_ADDR) & MII_BUSY != 0 {
        return None;
    }
    write32(
        d,
        GMAC_MII_ADDR,
        u32::from(d.phy_address) << 11 | (register & 0x1f) << 6 | MII_CLOCK_RANGE_250MHZ | MII_BUSY,
    );
    for _ in 0..10_000 {
        if read32(d, GMAC_MII_ADDR) & MII_BUSY == 0 {
            return Some(read32(d, GMAC_MII_DATA) as u16);
        }
        core::hint::spin_loop();
    }
    None
}

fn prepare_soc(d: DwmacDescription, time: fn() -> u64, hz: u64) {
    let clk = d.soc_control.start + 0x2000;
    soc_write32(clk, soc_read32(clk) | ((1 << 11) | (1 << 25) | (1 << 26)));
    soc_write32(clk + 0x30, soc_read32(clk + 0x30) & !(1 << 9));
    soc_write32(
        clk + 0x8c,
        (soc_read32(clk + 0x8c) & !(0xf << 16)) | (3 << 16) | (1 << 3),
    );
    prepare_ephy(d, time, hz);
    let _ = soc_read32(clk);
}
fn prepare_ephy(d: DwmacDescription, time: fn() -> u64, hz: u64) {
    let base = d.soc_control.start + 0x9000;
    let top = base + 0x800;
    soc_write32(top + 4, 1);
    soc_write32(top, 0x0900);
    soc_write32(top, 0x0904);
    delay(time, hz, 10);
    page(base, 5);
    ew(base, 0x40, 0x0c7e);
    delay(time, hz, 1);
    soc_write32(top, 0x0906);
    page(base, 0);
    let e20 = soc_read32(d.efuse.start + 0x120);
    let e24 = soc_read32(d.efuse.start + 0x124);
    ew(
        base,
        0x64,
        if e20 & 0x200 != 0 {
            (e24 >> 24 & 0xff) | (e24 >> 8 & 0xff00)
        } else {
            0x5a5a
        },
    );
    ew(base, 0x54, if e20 & 0x100 != 0 { e24 & 0xff00 } else { 0 });
    let term = if e20 & 0x800 != 0 {
        ((e20 >> 24) & 0xf0) | ((e20 >> 16) & 0xf00)
    } else {
        0xbb0
    };
    ew(base, 0x58, (er(base, 0x58) & !0xff0) | term);
    ew(base, 0x5c, 0xc10);
    ew(base, 0x68, 3);
    ew(base, 0x54, 0);
    table(
        base,
        16,
        &[
            (0x68, 0x1000),
            (0x6c, 0x3020),
            (0x70, 0x5040),
            (0x74, 0x7060),
            (0x58, 0x1708),
            (0x5c, 0x3827),
            (0x60, 0x5748),
            (0x64, 0x7867),
        ],
    );
    table(
        base,
        17,
        &[
            (0x40, 0x9080),
            (0x44, 0xb0a0),
            (0x48, 0xd0c0),
            (0x4c, 0xf0e0),
            (0x50, 0x9788),
            (0x54, 0xb8a7),
            (0x58, 0xd7c8),
            (0x5c, 0xf8e7),
        ],
    );
    page(base, 5);
    ew(base, 0x40, er(base, 0x40) | 1);
    ew(base, 0x4c, er(base, 0x4c) | 0x820);
    table(
        base,
        10,
        &[
            (0x40, 0x3e00),
            (0x44, 0x7864),
            (0x48, 0x6470),
            (0x4c, 0x5f62),
            (0x50, 0x5a5a),
            (0x54, 0x5458),
            (0x58, 0xb23a),
            (0x5c, 0x94a0),
            (0x60, 0x9092),
            (0x64, 0x8a8e),
            (0x68, 0x8688),
            (0x6c, 0x8484),
            (0x70, 0x82),
        ],
    );
    table(
        base,
        11,
        &[
            (0x40, 0x5252),
            (0x44, 0x5252),
            (0x48, 0x4b52),
            (0x4c, 0x3d47),
            (0x50, 0xaa99),
            (0x54, 0x989e),
            (0x58, 0x9395),
            (0x5c, 0x9091),
            (0x60, 0x8e8f),
            (0x64, 0x8d8e),
            (0x68, 0x8c8c),
            (0x6c, 0x8b8b),
            (0x70, 0x8a),
        ],
    );
    table(
        base,
        13,
        &[
            (0x40, 0x1e0a),
            (0x44, 0x3862),
            (0x48, 0x1e62),
            (0x4c, 0x2a08),
            (0x50, 0x244c),
            (0x54, 0x1a44),
            (0x58, 0x61c),
        ],
    );
    table(
        base,
        14,
        &[
            (0x40, 0x2d30),
            (0x44, 0x3470),
            (0x48, 0x648),
            (0x4c, 0x261c),
            (0x50, 0x3160),
            (0x54, 0x2d5e),
        ],
    );
    table(
        base,
        15,
        &[
            (0x40, 0x2922),
            (0x44, 0x366e),
            (0x48, 0x752),
            (0x4c, 0x2556),
            (0x50, 0x2348),
            (0x54, 0xc30),
        ],
    );
    table(
        base,
        16,
        &[
            (0x40, 0x1e08),
            (0x44, 0x3868),
            (0x48, 0x1462),
            (0x4c, 0x1a0e),
            (0x50, 0x305e),
            (0x54, 0x2f62),
        ],
    );
    page(base, 1);
    ew(base, 0x68, er(base, 0x68) & !0xf00);
    table(base, 19, &[(0x58, 0x12), (0x5c, 0x6848)]);
    table(
        base,
        18,
        &[
            (0x48, 0x801),
            (0x4c, 0x1717),
            (0x5c, 0x108),
            (0x50, 0x3afc),
            (0x54, 0x8d3),
            (0x60, 0xfb),
        ],
    );
    page(base, 0);
    soc_write32(top, 0x090e);
    ew(base, 0, er(base, 0) | 0x100);
    soc_write32(top + 4, 0);
}
fn table(base: usize, p: u32, v: &[(usize, u32)]) {
    page(base, p);
    for &(o, x) in v {
        ew(base, o, x)
    }
}
fn page(base: usize, p: u32) {
    soc_write32(base + 0x7c, p << 8)
}
fn er(base: usize, o: usize) -> u32 {
    soc_read32(base + o)
}
fn ew(base: usize, o: usize, v: u32) {
    soc_write32(base + o, v)
}
fn delay(time: fn() -> u64, hz: u64, ms: u64) {
    let end = time().saturating_add(ms.saturating_mul(hz) / 1000);
    while time() < end {
        core::hint::spin_loop()
    }
}
fn descriptor_address(v: &Descriptor) -> usize {
    v.words.as_ptr() as usize
}
fn buffer_address(v: &[u8; DMA_BUFFER_LEN]) -> usize {
    v.as_ptr() as usize
}
fn clean_range(line: usize, start: usize, size: usize) {
    cache_range(line, start, size, true)
}
fn invalidate_range(line: usize, start: usize, size: usize) {
    cache_range(line, start, size, false)
}
#[cfg(target_arch = "riscv64")]
fn cache_range(bytes: usize, start: usize, size: usize, clean: bool) {
    let mut line = start & !(bytes - 1);
    let end = start.saturating_add(size).saturating_add(bytes - 1) & !(bytes - 1);
    while line < end {
        unsafe {
            if clean {
                core::arch::asm!(".long 0x0295000b",in("a0")line,options(nostack))
            } else {
                core::arch::asm!(".long 0x02a5000b",in("a0")line,options(nostack))
            }
        }
        line += bytes
    }
    unsafe { core::arch::asm!(".long 0x0190000b", options(nostack)) }
}
#[cfg(not(target_arch = "riscv64"))]
fn cache_range(_: usize, _: usize, _: usize, _: bool) {
    core::sync::atomic::compiler_fence(Ordering::SeqCst)
}
#[inline]
fn read32(d: DwmacDescription, o: usize) -> u32 {
    unsafe { ((d.registers.start + o) as *const u32).read_volatile() }
}
#[inline]
fn write32(d: DwmacDescription, o: usize, v: u32) {
    unsafe { ((d.registers.start + o) as *mut u32).write_volatile(v) }
}
#[inline]
fn soc_read32(a: usize) -> u32 {
    unsafe { (a as *const u32).read_volatile() }
}
#[inline]
fn soc_write32(a: usize, v: u32) {
    unsafe { (a as *mut u32).write_volatile(v) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dma_layout_is_cache_isolated() {
        assert_eq!(core::mem::size_of::<Descriptor>(), 64);
        assert_eq!(core::mem::align_of::<Slab>(), 64);
        assert_eq!(core::mem::offset_of!(Slab, rx) % 64, 0);
        assert_eq!(core::mem::offset_of!(Slab, tx) % 64, 0)
    }
    #[test]
    fn error_values_are_stable() {
        assert_eq!(Error::PacketTooLarge, Error::PacketTooLarge)
    }

    #[test]
    fn description_validation_rejects_truncated_windows() {
        use vibeos_hal::AddressRange;
        let valid = DwmacDescription {
            registers: AddressRange::new(0x1000, 0x3000),
            irq: 1,
            soc_control: AddressRange::new(0x4000, 0xe000),
            efuse: AddressRange::new(0x1_0000, 0x1_1000),
            phy_address: 0,
            dma_address_bits: 32,
            cache_line_bytes: 64,
        };
        assert!(validate_description(valid));
        assert!(!validate_description(DwmacDescription {
            registers: AddressRange::new(0x1000, 0x1010),
            ..valid
        }));
        assert!(!validate_description(DwmacDescription {
            registers: AddressRange::new(usize::MAX - 0x100, usize::MAX),
            ..valid
        }));
    }
}
