//! CV1800B platform bring-up for the integrated Synopsys DWC2 USB 2.0 OTG core.
//!
//! This first layer owns clocks, the SoC role override and the DWC2 host core.
//! USB transactions and class drivers intentionally live above this crate.

#![cfg_attr(not(test), no_std)]

use core::sync::atomic::{compiler_fence, AtomicBool, Ordering};
use vibeos_hal::Dwc2Description;

const TOP_USB_ROLE: usize = 0x48;
const CLKGEN_OFFSET: usize = 0x2000;
const CLK_ENABLE_1: usize = CLKGEN_OFFSET + 0x04;
const CLK_ENABLE_2: usize = CLKGEN_OFFSET + 0x08;
const USB_CLOCKS_ENABLE_1: u32 = 0xf000_0000;
const USB_CLOCKS_ENABLE_2: u32 = 1;
const USB_ROLE_MASK: u32 = 0xc0;
const USB_ROLE_HOST: u32 = 0x40;

const GAHBCFG: usize = 0x008;
const GUSBCFG: usize = 0x00c;
const GRSTCTL: usize = 0x010;
const GINTSTS: usize = 0x014;
const GINTMSK: usize = 0x018;
const GHWCFG2: usize = 0x048;
const GHWCFG3: usize = 0x04c;
const GHWCFG4: usize = 0x050;
const GSNPSID: usize = 0x040;
const HCFG: usize = 0x400;
const HPRT0: usize = 0x440;

const GAHBCFG_GLOBAL_INTERRUPT: u32 = 1;
const GUSBCFG_FORCE_HOST: u32 = 1 << 29;
const GUSBCFG_FORCE_DEVICE: u32 = 1 << 30;
const GRSTCTL_CORE_SOFT_RESET: u32 = 1;
const GRSTCTL_AHB_IDLE: u32 = 1 << 31;
const GINTSTS_CURRENT_MODE_HOST: u32 = 1;
const HPRT_CONNECT: u32 = 1;
const HPRT_CHANGE_BITS: u32 = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5);
const HPRT_POWER: u32 = 1 << 12;
const REGISTER_TIMEOUT_MS: u64 = 10;
const HOST_MODE_TIMEOUT_MS: u64 = 110;

static CLAIMED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Busy,
    InvalidDescription,
    CoreNotFound(u32),
    AhbIdleTimedOut,
    CoreResetTimedOut,
    HostModeTimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Info {
    pub core_id: u32,
    pub release: u16,
    pub irq: u32,
    pub host_channels: u8,
    pub dynamic_fifo: bool,
    pub dma_architecture: u8,
    pub fifo_depth_words: u16,
    pub dedicated_fifos: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Telemetry {
    pub clock_enable_1: u32,
    pub clock_enable_2: u32,
    pub role_override: u32,
    pub gusbcfg: u32,
    pub hprt0: u32,
    pub phy_utmi_control: u32,
}

/// Exclusive ownership of the fixed CV1800B DWC2 host instance.
pub struct Controller {
    description: Dwc2Description,
    info: Info,
}

impl Controller {
    /// Enable the CV1800B USB clocks, select host role, reset DWC2 and power
    /// its root port. No interrupt or DMA is enabled at this stage.
    ///
    /// # Safety
    /// All ranges in `description` must be identity-mapped, strongly ordered
    /// MMIO for the CV1800B and remain exclusively owned until `shutdown`.
    /// `time` must advance monotonically in `timebase_hz` ticks.
    pub unsafe fn initialize(
        description: Dwc2Description,
        timebase_hz: u64,
        time: fn() -> u64,
    ) -> Result<Self, Error> {
        if !validate_description(description) || timebase_hz == 0 {
            return Err(Error::InvalidDescription);
        }
        if CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::Busy);
        }

        let old_clocks_1 = unsafe { soc_read(description, CLK_ENABLE_1) };
        let old_clocks_2 = unsafe { soc_read(description, CLK_ENABLE_2) };
        let old_role = unsafe { soc_read(description, TOP_USB_ROLE) };
        unsafe {
            soc_write(
                description,
                CLK_ENABLE_1,
                old_clocks_1 | USB_CLOCKS_ENABLE_1,
            );
            soc_write(
                description,
                CLK_ENABLE_2,
                old_clocks_2 | USB_CLOCKS_ENABLE_2,
            );
            soc_write(
                description,
                TOP_USB_ROLE,
                (old_role & !USB_ROLE_MASK) | USB_ROLE_HOST,
            );
        }
        compiler_fence(Ordering::SeqCst);

        let result = unsafe { Self::initialize_core(description, timebase_hz, time) };
        match result {
            Ok(controller) => Ok(controller),
            Err(error) => {
                unsafe {
                    soc_write(description, TOP_USB_ROLE, old_role);
                    soc_write(description, CLK_ENABLE_2, old_clocks_2);
                    soc_write(description, CLK_ENABLE_1, old_clocks_1);
                }
                CLAIMED.store(false, Ordering::Release);
                Err(error)
            }
        }
    }

    unsafe fn initialize_core(
        description: Dwc2Description,
        timebase_hz: u64,
        time: fn() -> u64,
    ) -> Result<Self, Error> {
        let core_id = unsafe { core_read(description, GSNPSID) };
        if !is_dwc2_core_id(core_id) {
            return Err(Error::CoreNotFound(core_id));
        }

        unsafe {
            core_write(description, GINTMSK, 0);
            let ahbcfg = core_read(description, GAHBCFG) & !GAHBCFG_GLOBAL_INTERRUPT;
            core_write(description, GAHBCFG, ahbcfg);
        }
        wait_for(
            description,
            GRSTCTL,
            GRSTCTL_AHB_IDLE,
            true,
            REGISTER_TIMEOUT_MS,
            timebase_hz,
            time,
        )
        .map_err(|_| Error::AhbIdleTimedOut)?;

        let usb_config = unsafe { core_read(description, GUSBCFG) };
        unsafe {
            core_write(
                description,
                GUSBCFG,
                (usb_config & !GUSBCFG_FORCE_DEVICE) | GUSBCFG_FORCE_HOST,
            );
            core_write(description, GRSTCTL, GRSTCTL_CORE_SOFT_RESET);
        }
        wait_for(
            description,
            GRSTCTL,
            GRSTCTL_CORE_SOFT_RESET,
            false,
            REGISTER_TIMEOUT_MS,
            timebase_hz,
            time,
        )
        .map_err(|_| Error::CoreResetTimedOut)?;
        wait_for(
            description,
            GRSTCTL,
            GRSTCTL_AHB_IDLE,
            true,
            REGISTER_TIMEOUT_MS,
            timebase_hz,
            time,
        )
        .map_err(|_| Error::AhbIdleTimedOut)?;
        wait_for(
            description,
            GINTSTS,
            GINTSTS_CURRENT_MODE_HOST,
            true,
            HOST_MODE_TIMEOUT_MS,
            timebase_hz,
            time,
        )
        .map_err(|_| Error::HostModeTimedOut)?;

        unsafe {
            // UTMI+ at 30/60 MHz uses HCFG.FSLSPClkSel = 0.
            core_write(description, HCFG, core_read(description, HCFG) & !0x3);
            core_write(description, GINTSTS, u32::MAX);
            let port = core_read(description, HPRT0);
            core_write(description, HPRT0, (port & !HPRT_CHANGE_BITS) | HPRT_POWER);
        }

        let hwcfg2 = unsafe { core_read(description, GHWCFG2) };
        let hwcfg3 = unsafe { core_read(description, GHWCFG3) };
        let hwcfg4 = unsafe { core_read(description, GHWCFG4) };
        Ok(Self {
            description,
            info: Info {
                core_id,
                release: core_id as u16,
                irq: description.irq,
                host_channels: host_channel_count(hwcfg2),
                dynamic_fifo: hwcfg2 & (1 << 19) != 0,
                dma_architecture: ((hwcfg2 >> 3) & 0x3) as u8,
                fifo_depth_words: (hwcfg3 >> 16) as u16,
                dedicated_fifos: hwcfg4 & (1 << 25) != 0,
            },
        })
    }

    pub const fn info(&self) -> Info {
        self.info
    }

    pub fn connected(&self) -> bool {
        unsafe { core_read(self.description, HPRT0) & HPRT_CONNECT != 0 }
    }

    pub fn telemetry(&self) -> Telemetry {
        Telemetry {
            clock_enable_1: unsafe { soc_read(self.description, CLK_ENABLE_1) },
            clock_enable_2: unsafe { soc_read(self.description, CLK_ENABLE_2) },
            role_override: unsafe { soc_read(self.description, TOP_USB_ROLE) },
            gusbcfg: unsafe { core_read(self.description, GUSBCFG) },
            hprt0: unsafe { core_read(self.description, HPRT0) },
            phy_utmi_control: unsafe { phy_read(self.description, 0x14) },
        }
    }

    /// Quiesce the host core and release software ownership. Clock gates stay
    /// enabled because other firmware may subsequently take over the OTG port.
    pub fn shutdown(self) {
        unsafe {
            core_write(self.description, GINTMSK, 0);
            let ahbcfg = core_read(self.description, GAHBCFG) & !GAHBCFG_GLOBAL_INTERRUPT;
            core_write(self.description, GAHBCFG, ahbcfg);
            let port = core_read(self.description, HPRT0);
            core_write(
                self.description,
                HPRT0,
                port & !(HPRT_CHANGE_BITS | HPRT_POWER),
            );
        }
        CLAIMED.store(false, Ordering::Release);
        core::mem::forget(self);
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        CLAIMED.store(false, Ordering::Release);
    }
}

pub const fn validate_description(description: Dwc2Description) -> bool {
    range_contains(
        description.registers.start,
        description.registers.end,
        HPRT0 + 4,
    ) && range_contains(description.phy.start, description.phy.end, 0x18)
        && range_contains(
            description.soc_control.start,
            description.soc_control.end,
            CLK_ENABLE_2 + 4,
        )
        && description.irq != 0
        && description.dma_address_bits == 32
}

const fn range_contains(start: usize, end: usize, bytes: usize) -> bool {
    match start.checked_add(bytes) {
        Some(required_end) => end >= required_end,
        None => false,
    }
}

const fn is_dwc2_core_id(id: u32) -> bool {
    id & 0xffff_0000 == 0x4f54_0000
}

const fn host_channel_count(hwcfg2: u32) -> u8 {
    (((hwcfg2 >> 14) & 0xf) + 1) as u8
}

fn wait_for(
    description: Dwc2Description,
    register: usize,
    mask: u32,
    asserted: bool,
    timeout_ms: u64,
    timebase_hz: u64,
    time: fn() -> u64,
) -> Result<(), ()> {
    let timeout_ticks = (timebase_hz.saturating_mul(timeout_ms).saturating_add(999) / 1_000).max(1);
    let started = time();
    loop {
        if (unsafe { core_read(description, register) } & mask != 0) == asserted {
            return Ok(());
        }
        if time().wrapping_sub(started) >= timeout_ticks {
            return Err(());
        }
        core::hint::spin_loop();
    }
}

unsafe fn core_read(description: Dwc2Description, offset: usize) -> u32 {
    unsafe { read32(description.registers.start + offset) }
}

unsafe fn core_write(description: Dwc2Description, offset: usize, value: u32) {
    unsafe { write32(description.registers.start + offset, value) }
}

unsafe fn phy_read(description: Dwc2Description, offset: usize) -> u32 {
    unsafe { read32(description.phy.start + offset) }
}

unsafe fn soc_read(description: Dwc2Description, offset: usize) -> u32 {
    unsafe { read32(description.soc_control.start + offset) }
}

unsafe fn soc_write(description: Dwc2Description, offset: usize, value: u32) {
    unsafe { write32(description.soc_control.start + offset, value) }
}

unsafe fn read32(address: usize) -> u32 {
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

unsafe fn write32(address: usize, value: u32) {
    unsafe { core::ptr::write_volatile(address as *mut u32, value) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vibeos_hal::AddressRange;

    const VALID: Dwc2Description = Dwc2Description {
        registers: AddressRange::new(0x0434_0000, 0x0435_0000),
        phy: AddressRange::new(0x0300_6000, 0x0300_6058),
        irq: 30,
        soc_control: AddressRange::new(0x0300_0000, 0x0300_a000),
        dma_address_bits: 32,
    };

    #[test]
    fn cv1800b_description_covers_every_register() {
        assert!(validate_description(VALID));
        let mut short = VALID;
        short.registers.end = short.registers.start + HPRT0;
        assert!(!validate_description(short));
        short = VALID;
        short.phy.end = short.phy.start + 0x14;
        assert!(!validate_description(short));
    }

    #[test]
    fn recognizes_synopsys_otg_ids_and_decodes_channels() {
        assert!(is_dwc2_core_id(0x4f54_280a));
        assert!(!is_dwc2_core_id(0x5533_0000));
        assert_eq!(host_channel_count(0), 1);
        assert_eq!(host_channel_count(15 << 14), 16);
    }
}
