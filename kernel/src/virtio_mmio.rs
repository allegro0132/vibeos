//! Modern virtio-mmio transport for platforms which expose QEMU-style slots.
//!
//! QEMU exposes eight 4 KiB transport windows; boards without this transport
//! select zero slots and probing becomes a no-op. Empty windows read as zero;
//! a live modern transport has the virtio magic, version 2, and a non-zero
//! device id. This module deliberately contains only volatile MMIO access and
//! transport sequencing. Queue ownership and descriptor safety live in the
//! supervised `virtio_blk` and `virtio_net` drivers.

use core::arch::asm;

pub const VIRTIO_MMIO_BASE: usize = 0x1000_1000;
pub const VIRTIO_MMIO_STRIDE: usize = 0x1000;
pub const VIRTIO_MMIO_SLOTS: usize = crate::platform::VIRTIO_MMIO_SLOTS;
pub const VIRTIO_MMIO_FIRST_IRQ: u32 = 1;

pub const VIRTIO_MAGIC: u32 = 0x7472_6976;
pub const VIRTIO_MODERN_VERSION: u32 = 2;
pub const VIRTIO_DEVICE_NETWORK: u32 = 1;
pub const VIRTIO_DEVICE_BLOCK: u32 = 2;

const MAGIC_VALUE: usize = 0x000;
const VERSION: usize = 0x004;
const DEVICE_ID: usize = 0x008;
const VENDOR_ID: usize = 0x00c;
const DEVICE_FEATURES: usize = 0x010;
const DEVICE_FEATURES_SEL: usize = 0x014;
const DRIVER_FEATURES: usize = 0x020;
const DRIVER_FEATURES_SEL: usize = 0x024;
const QUEUE_SEL: usize = 0x030;
const QUEUE_NUM_MAX: usize = 0x034;
const QUEUE_NUM: usize = 0x038;
const QUEUE_READY: usize = 0x044;
const QUEUE_NOTIFY: usize = 0x050;
const INTERRUPT_STATUS: usize = 0x060;
const INTERRUPT_ACK: usize = 0x064;
const STATUS: usize = 0x070;
const QUEUE_DESC_LOW: usize = 0x080;
const QUEUE_DESC_HIGH: usize = 0x084;
const QUEUE_DRIVER_LOW: usize = 0x090;
const QUEUE_DRIVER_HIGH: usize = 0x094;
const QUEUE_DEVICE_LOW: usize = 0x0a0;
const QUEUE_DEVICE_HIGH: usize = 0x0a4;
const CONFIG_GENERATION: usize = 0x0fc;
const CONFIG: usize = 0x100;
const CONFIG_READ_RETRY_BUDGET: usize = 32;

/// One QEMU `virtio-mmio` transport window.
///
/// Construction is restricted to the fixed QEMU platform table, so volatile
/// reads cannot be redirected to an arbitrary caller-supplied address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioTransport {
    base: usize,
    irq: u32,
    slot: u8,
}

impl MmioTransport {
    /// Inspect one of the selected platform's architected transport windows.
    pub fn probe_slot(slot: usize) -> Option<Self> {
        if slot >= VIRTIO_MMIO_SLOTS {
            return None;
        }
        let transport = Self {
            base: VIRTIO_MMIO_BASE + slot * VIRTIO_MMIO_STRIDE,
            irq: VIRTIO_MMIO_FIRST_IRQ + slot as u32,
            slot: slot as u8,
        };
        if transport.read(MAGIC_VALUE) != VIRTIO_MAGIC
            || transport.read(VERSION) != VIRTIO_MODERN_VERSION
            || transport.read(DEVICE_ID) == 0
        {
            return None;
        }
        Some(transport)
    }

    /// Find the first modern virtio block transport.  Other device types and
    /// legacy (version 1) transports are deliberately skipped.
    pub fn scan_block() -> Option<Self> {
        (0..VIRTIO_MMIO_SLOTS)
            .filter_map(Self::probe_slot)
            .find(|transport| transport.device_id() == VIRTIO_DEVICE_BLOCK)
    }

    /// Find the first modern virtio network transport. Other device types and
    /// legacy (version 1) transports are deliberately skipped.
    pub fn scan_network() -> Option<Self> {
        (0..VIRTIO_MMIO_SLOTS)
            .filter_map(Self::probe_slot)
            .find(|transport| transport.device_id() == VIRTIO_DEVICE_NETWORK)
    }

    pub const fn base(self) -> usize {
        self.base
    }

    pub const fn irq(self) -> u32 {
        self.irq
    }

    pub const fn slot(self) -> usize {
        self.slot as usize
    }

    pub fn device_id(self) -> u32 {
        self.read(DEVICE_ID)
    }

    pub fn vendor_id(self) -> u32 {
        self.read(VENDOR_ID)
    }

    pub fn status(self) -> u32 {
        self.read(STATUS)
    }

    /// Reset and synchronously confirm that the device observed status zero.
    /// A caller must quarantine every DMA address if this fails.
    pub fn reset(self, poll_budget: usize) -> bool {
        self.write(STATUS, 0);
        for _ in 0..poll_budget {
            if self.read(STATUS) == 0 {
                mmio_fence();
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    pub fn set_status(self, status: u32) {
        self.write(STATUS, status);
    }

    pub fn add_status(self, status: u32) {
        self.set_status(self.status() | status);
    }

    pub fn device_features(self) -> u64 {
        self.write(DEVICE_FEATURES_SEL, 0);
        let low = self.read(DEVICE_FEATURES) as u64;
        self.write(DEVICE_FEATURES_SEL, 1);
        let high = self.read(DEVICE_FEATURES) as u64;
        low | high << 32
    }

    pub fn set_driver_features(self, features: u64) {
        self.write(DRIVER_FEATURES_SEL, 0);
        self.write(DRIVER_FEATURES, features as u32);
        self.write(DRIVER_FEATURES_SEL, 1);
        self.write(DRIVER_FEATURES, (features >> 32) as u32);
    }

    pub fn select_queue(self, queue: u16) {
        self.write(QUEUE_SEL, u32::from(queue));
    }

    pub fn queue_num_max(self) -> u16 {
        self.read(QUEUE_NUM_MAX).min(u16::MAX as u32) as u16
    }

    pub fn queue_ready(self) -> bool {
        self.read(QUEUE_READY) != 0
    }

    /// Program the three split-ring areas for the selected queue.
    pub fn configure_queue(self, size: u16, descriptors: u64, driver_area: u64, device_area: u64) {
        self.write(QUEUE_NUM, u32::from(size));
        self.write_address(QUEUE_DESC_LOW, QUEUE_DESC_HIGH, descriptors);
        self.write_address(QUEUE_DRIVER_LOW, QUEUE_DRIVER_HIGH, driver_area);
        self.write_address(QUEUE_DEVICE_LOW, QUEUE_DEVICE_HIGH, device_area);
        self.write(QUEUE_READY, 1);
    }

    pub fn notify_queue(self, queue: u16) {
        mmio_fence();
        self.write(QUEUE_NOTIFY, u32::from(queue));
    }

    /// Acknowledge and return the raw interrupt cause.  This is the only MMIO
    /// work required in the IRQ top half.
    pub fn acknowledge_interrupt(self) -> u32 {
        let cause = crate::virtio::InterruptCauses::from_status(self.read(INTERRUPT_STATUS));
        if !cause.is_empty() {
            self.write(INTERRUPT_ACK, cause.ack_bits());
        }
        cause.ack_bits()
    }

    /// Read block capacity (512-byte sectors) using the config-generation
    /// retry protocol.  This avoids publishing a torn 64-bit config value on
    /// RV64 even though each MMIO transfer itself is 32 bits.
    pub fn block_capacity(self) -> Option<u64> {
        crate::virtio::consistent_config_u64(CONFIG_READ_RETRY_BUDGET, || {
            crate::virtio::ConfigU64Sample {
                generation_before: self.read(CONFIG_GENERATION),
                low: self.read(CONFIG),
                high: self.read(CONFIG + 4),
                generation_after: self.read(CONFIG_GENERATION),
            }
        })
    }

    #[inline]
    fn read(self, offset: usize) -> u32 {
        // Safety: `MmioTransport` can only name one of QEMU virt's eight
        // aligned 4 KiB transport windows and every register here is aligned.
        let value = unsafe { ((self.base + offset) as *const u32).read_volatile() };
        mmio_fence();
        value
    }

    #[inline]
    fn write(self, offset: usize, value: u32) {
        mmio_fence();
        // Safety: see `read`; all write offsets are transport registers.
        unsafe { ((self.base + offset) as *mut u32).write_volatile(value) };
        mmio_fence();
    }

    fn write_address(self, low: usize, high: usize, address: u64) {
        self.write(low, address as u32);
        self.write(high, (address >> 32) as u32);
    }
}

#[inline]
fn mmio_fence() {
    // Rust atomics do not order RISC-V I/O space; virtio requires explicit
    // device ordering around status, queue publication, and IRQ ACKs.
    unsafe { asm!("fence iorw, iorw", options(nostack, preserves_flags)) };
}
