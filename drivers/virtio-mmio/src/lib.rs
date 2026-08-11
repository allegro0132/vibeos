//! Virtio 1.2 MMIO transport independent of kernel composition and boards.
//!
//! A board or firmware package provides a
//! [`VirtioMmioDescription`](vibeos_hal::VirtioMmioDescription) from its
//! trusted hardware description. Device drivers then pass that description
//! to [`MmioTransport::scan_block`], [`MmioTransport::scan_network`], or
//! [`MmioTransport::scan_entropy`]. Queue ownership, DMA allocation,
//! capability publication, interrupt routing, and fault recovery remain the
//! responsibility of the caller.
//!
//! # Migration from the kernel module
//!
//! * `MmioTransport::scan_block()` becomes
//!   `MmioTransport::scan_block(description)` (and likewise for
//!   network/entropy).
//! * `MmioTransport::probe_slot(slot)` becomes
//!   `MmioTransport::probe_slot(description, slot)`.
//! * All other `MmioTransport` methods retain their names and behavior.

#![cfg_attr(not(test), no_std)]

use vibeos_core::virtio::{
    consistent_config_u64, ConfigU64Sample, InterruptCauses, DEVICE_ID_BLOCK, DEVICE_ID_ENTROPY,
    DEVICE_ID_NETWORK, MMIO_CONFIG_GENERATION_OFFSET, MMIO_CONFIG_OFFSET,
    MMIO_DEVICE_FEATURES_OFFSET, MMIO_DEVICE_FEATURES_SEL_OFFSET, MMIO_DEVICE_ID_OFFSET,
    MMIO_DRIVER_FEATURES_OFFSET, MMIO_DRIVER_FEATURES_SEL_OFFSET, MMIO_INTERRUPT_ACK_OFFSET,
    MMIO_INTERRUPT_STATUS_OFFSET, MMIO_MAGIC_VALUE, MMIO_MAGIC_VALUE_OFFSET,
    MMIO_QUEUE_DESC_HIGH_OFFSET, MMIO_QUEUE_DESC_LOW_OFFSET, MMIO_QUEUE_DEVICE_HIGH_OFFSET,
    MMIO_QUEUE_DEVICE_LOW_OFFSET, MMIO_QUEUE_DRIVER_HIGH_OFFSET, MMIO_QUEUE_DRIVER_LOW_OFFSET,
    MMIO_QUEUE_NOTIFY_OFFSET, MMIO_QUEUE_NUM_MAX_OFFSET, MMIO_QUEUE_NUM_OFFSET,
    MMIO_QUEUE_READY_OFFSET, MMIO_QUEUE_SEL_OFFSET, MMIO_STATUS_OFFSET, MMIO_VENDOR_ID_OFFSET,
    MMIO_VERSION_MODERN, MMIO_VERSION_OFFSET,
};
use vibeos_hal::VirtioMmioDescription;

/// Compatibility names retained for the former kernel-local transport API.
pub const VIRTIO_MAGIC: u32 = MMIO_MAGIC_VALUE;
pub const VIRTIO_MODERN_VERSION: u32 = MMIO_VERSION_MODERN;
pub const VIRTIO_DEVICE_NETWORK: u32 = DEVICE_ID_NETWORK;
pub const VIRTIO_DEVICE_BLOCK: u32 = DEVICE_ID_BLOCK;
pub const VIRTIO_DEVICE_ENTROPY: u32 = DEVICE_ID_ENTROPY;

const CONFIG_READ_RETRY_BUDGET: usize = 32;
const REQUIRED_WINDOW_BYTES: usize = MMIO_CONFIG_OFFSET + 8;

/// One resolved transport window and its interrupt line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioMmioSlot {
    base: usize,
    irq: u32,
    index: usize,
}

impl VirtioMmioSlot {
    pub const fn base(self) -> usize {
        self.base
    }

    pub const fn irq(self) -> u32 {
        self.irq
    }

    pub const fn index(self) -> usize {
        self.index
    }
}

/// Resolve a slot without touching hardware.
///
/// Returns `None` for an out-of-range slot or if its address/IRQ cannot be
/// represented. This pure calculation is useful to validate BSP tables on
/// the host.
pub const fn resolve_slot(
    description: VirtioMmioDescription,
    index: usize,
) -> Option<VirtioMmioSlot> {
    if index >= description.slots
        || description.registers.start % core::mem::align_of::<u32>() != 0
        || description.stride % core::mem::align_of::<u32>() != 0
        || (description.slots > 1 && description.stride < REQUIRED_WINDOW_BYTES)
    {
        return None;
    }
    let Some(offset) = index.checked_mul(description.stride) else {
        return None;
    };
    let Some(base) = description.registers.start.checked_add(offset) else {
        return None;
    };
    let Some(end) = base.checked_add(REQUIRED_WINDOW_BYTES) else {
        return None;
    };
    if end > description.registers.end {
        return None;
    }
    if index > u32::MAX as usize {
        return None;
    }
    let Some(irq) = description.first_irq.checked_add(index as u32) else {
        return None;
    };
    Some(VirtioMmioSlot { base, irq, index })
}

/// One live modern Virtio MMIO transport window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioTransport {
    slot: VirtioMmioSlot,
}

impl MmioTransport {
    /// Inspect one of the configured transport windows.
    ///
    /// # Safety
    ///
    /// Every described window must be mapped for volatile 32-bit MMIO access
    /// and contain the modern Virtio MMIO register layout through offset
    /// `0x107`.
    pub unsafe fn probe_slot(description: VirtioMmioDescription, slot: usize) -> Option<Self> {
        unsafe { Self::probe(resolve_slot(description, slot)?) }
    }

    /// Inspect a previously resolved transport window.
    ///
    /// # Safety
    ///
    /// `slot.base()` must name a mapped modern Virtio MMIO window.
    pub unsafe fn probe(slot: VirtioMmioSlot) -> Option<Self> {
        let transport = Self { slot };
        if transport.read(MMIO_MAGIC_VALUE_OFFSET) != VIRTIO_MAGIC
            || transport.read(MMIO_VERSION_OFFSET) != VIRTIO_MODERN_VERSION
            || transport.read(MMIO_DEVICE_ID_OFFSET) == 0
        {
            return None;
        }
        Some(transport)
    }

    /// # Safety
    ///
    /// The description must satisfy [`MmioTransport::probe_slot`]'s safety
    /// requirements.
    pub unsafe fn scan_block(description: VirtioMmioDescription) -> Option<Self> {
        unsafe { Self::scan_device(description, VIRTIO_DEVICE_BLOCK) }
    }

    /// # Safety
    ///
    /// The description must satisfy [`MmioTransport::probe_slot`]'s safety
    /// requirements.
    pub unsafe fn scan_network(description: VirtioMmioDescription) -> Option<Self> {
        unsafe { Self::scan_device(description, VIRTIO_DEVICE_NETWORK) }
    }

    /// # Safety
    ///
    /// The description must satisfy [`MmioTransport::probe_slot`]'s safety
    /// requirements.
    pub unsafe fn scan_entropy(description: VirtioMmioDescription) -> Option<Self> {
        unsafe { Self::scan_device(description, VIRTIO_DEVICE_ENTROPY) }
    }

    unsafe fn scan_device(description: VirtioMmioDescription, device_id: u32) -> Option<Self> {
        (0..description.slots)
            .filter_map(|slot| unsafe { Self::probe_slot(description, slot) })
            .find(|transport| transport.device_id() == device_id)
    }

    pub const fn base(self) -> usize {
        self.slot.base()
    }

    pub const fn irq(self) -> u32 {
        self.slot.irq()
    }

    pub const fn slot(self) -> usize {
        self.slot.index()
    }

    pub fn device_id(self) -> u32 {
        self.read(MMIO_DEVICE_ID_OFFSET)
    }

    pub fn vendor_id(self) -> u32 {
        self.read(MMIO_VENDOR_ID_OFFSET)
    }

    pub fn status(self) -> u32 {
        self.read(MMIO_STATUS_OFFSET)
    }

    /// Reset and synchronously confirm that the device observed status zero.
    /// A caller must quarantine every DMA address if this fails.
    pub fn reset(self, poll_budget: usize) -> bool {
        self.write(MMIO_STATUS_OFFSET, 0);
        for _ in 0..poll_budget {
            if self.read(MMIO_STATUS_OFFSET) == 0 {
                mmio_fence();
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    pub fn set_status(self, status: u32) {
        self.write(MMIO_STATUS_OFFSET, status);
    }

    pub fn add_status(self, status: u32) {
        self.set_status(self.status() | status);
    }

    pub fn device_features(self) -> u64 {
        self.write(MMIO_DEVICE_FEATURES_SEL_OFFSET, 0);
        let low = self.read(MMIO_DEVICE_FEATURES_OFFSET) as u64;
        self.write(MMIO_DEVICE_FEATURES_SEL_OFFSET, 1);
        let high = self.read(MMIO_DEVICE_FEATURES_OFFSET) as u64;
        low | high << 32
    }

    pub fn set_driver_features(self, features: u64) {
        self.write(MMIO_DRIVER_FEATURES_SEL_OFFSET, 0);
        self.write(MMIO_DRIVER_FEATURES_OFFSET, features as u32);
        self.write(MMIO_DRIVER_FEATURES_SEL_OFFSET, 1);
        self.write(MMIO_DRIVER_FEATURES_OFFSET, (features >> 32) as u32);
    }

    pub fn select_queue(self, queue: u16) {
        self.write(MMIO_QUEUE_SEL_OFFSET, u32::from(queue));
    }

    pub fn queue_num_max(self) -> u16 {
        self.read(MMIO_QUEUE_NUM_MAX_OFFSET).min(u16::MAX as u32) as u16
    }

    pub fn queue_ready(self) -> bool {
        self.read(MMIO_QUEUE_READY_OFFSET) != 0
    }

    pub fn configure_queue(self, size: u16, descriptors: u64, driver_area: u64, device_area: u64) {
        self.write(MMIO_QUEUE_NUM_OFFSET, u32::from(size));
        self.write_address(
            MMIO_QUEUE_DESC_LOW_OFFSET,
            MMIO_QUEUE_DESC_HIGH_OFFSET,
            descriptors,
        );
        self.write_address(
            MMIO_QUEUE_DRIVER_LOW_OFFSET,
            MMIO_QUEUE_DRIVER_HIGH_OFFSET,
            driver_area,
        );
        self.write_address(
            MMIO_QUEUE_DEVICE_LOW_OFFSET,
            MMIO_QUEUE_DEVICE_HIGH_OFFSET,
            device_area,
        );
        self.write(MMIO_QUEUE_READY_OFFSET, 1);
    }

    pub fn notify_queue(self, queue: u16) {
        mmio_fence();
        self.write(MMIO_QUEUE_NOTIFY_OFFSET, u32::from(queue));
    }

    pub fn acknowledge_interrupt(self) -> u32 {
        let cause = InterruptCauses::from_status(self.read(MMIO_INTERRUPT_STATUS_OFFSET));
        if !cause.is_empty() {
            self.write(MMIO_INTERRUPT_ACK_OFFSET, cause.ack_bits());
        }
        cause.ack_bits()
    }

    pub fn block_capacity(self) -> Option<u64> {
        consistent_config_u64(CONFIG_READ_RETRY_BUDGET, || ConfigU64Sample {
            generation_before: self.read(MMIO_CONFIG_GENERATION_OFFSET),
            low: self.read(MMIO_CONFIG_OFFSET),
            high: self.read(MMIO_CONFIG_OFFSET + 4),
            generation_after: self.read(MMIO_CONFIG_GENERATION_OFFSET),
        })
    }

    #[inline]
    fn read(self, offset: usize) -> u32 {
        // Safety: the probe contract guarantees a mapped Virtio MMIO aperture;
        // `resolve_slot` verifies alignment and all register offsets are
        // aligned.
        let value = unsafe { ((self.base() + offset) as *const u32).read_volatile() };
        mmio_fence();
        value
    }

    #[inline]
    fn write(self, offset: usize, value: u32) {
        mmio_fence();
        // Safety: see `read`; all write offsets are transport registers.
        unsafe { ((self.base() + offset) as *mut u32).write_volatile(value) };
        mmio_fence();
    }

    fn write_address(self, low: usize, high: usize, address: u64) {
        self.write(low, address as u32);
        self.write(high, (address >> 32) as u32);
    }
}

#[inline]
fn mmio_fence() {
    #[cfg(target_arch = "riscv64")]
    // Safety: this instruction only orders device access and does not touch
    // memory directly.
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack, preserves_flags));
    }

    #[cfg(not(target_arch = "riscv64"))]
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use vibeos_hal::AddressRange;

    const QEMU: VirtioMmioDescription = VirtioMmioDescription {
        registers: AddressRange::new(0x1000_1000, 0x1000_9000),
        stride: 0x1000,
        slots: 8,
        first_irq: 1,
    };

    #[test]
    fn resolves_first_and_last_slot() {
        assert_eq!(
            resolve_slot(QEMU, 0),
            Some(VirtioMmioSlot {
                base: 0x1000_1000,
                irq: 1,
                index: 0,
            })
        );
        assert_eq!(
            resolve_slot(QEMU, 7),
            Some(VirtioMmioSlot {
                base: 0x1000_8000,
                irq: 8,
                index: 7,
            })
        );
        assert_eq!(resolve_slot(QEMU, 8), None);
    }

    #[test]
    fn rejects_address_overflow() {
        let description = VirtioMmioDescription {
            registers: AddressRange::new(usize::MAX - 0xfff, usize::MAX),
            stride: 0x1000,
            slots: 2,
            first_irq: 1,
        };
        assert!(resolve_slot(description, 0).is_some());
        assert_eq!(resolve_slot(description, 1), None);
    }

    #[test]
    fn rejects_irq_overflow() {
        let description = VirtioMmioDescription {
            registers: AddressRange::new(0x1000, 0x3000),
            stride: 0x1000,
            slots: 2,
            first_irq: u32::MAX,
        };
        assert!(resolve_slot(description, 0).is_some());
        assert_eq!(resolve_slot(description, 1), None);
    }

    #[test]
    fn zero_slots_never_resolve() {
        let description = VirtioMmioDescription {
            registers: AddressRange::new(0x1000, 0x1000),
            stride: 0x1000,
            slots: 0,
            first_irq: 1,
        };
        assert_eq!(resolve_slot(description, 0), None);
    }

    #[test]
    fn rejects_slot_that_does_not_fit_register_aperture() {
        let description = VirtioMmioDescription {
            registers: AddressRange::new(0x1000, 0x2107),
            stride: 0x1000,
            slots: 2,
            first_irq: 1,
        };
        assert!(resolve_slot(description, 0).is_some());
        assert_eq!(resolve_slot(description, 1), None);
    }

    #[test]
    fn rejects_unaligned_or_overlapping_windows() {
        let unaligned = VirtioMmioDescription {
            registers: AddressRange::new(0x1002, 0x3000),
            stride: 0x1000,
            slots: 1,
            first_irq: 1,
        };
        assert_eq!(resolve_slot(unaligned, 0), None);

        let overlapping = VirtioMmioDescription {
            registers: AddressRange::new(0x1000, 0x3000),
            stride: REQUIRED_WINDOW_BYTES - 4,
            slots: 2,
            first_irq: 1,
        };
        assert_eq!(resolve_slot(overlapping, 0), None);
    }
}
