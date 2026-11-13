//! GICv3 Group-1 physical timer interrupt setup for one boot CPU.
//! No global distributor reset: preserve secure firmware-owned interrupts.
use crate::bare;
use core::{
    arch::asm,
    ptr::{read_volatile, write_volatile},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Timeout,
    RedistributorNotFound,
    SystemRegistersUnavailable,
    InvalidRange,
}

unsafe fn read(base: usize, offset: usize) -> u32 {
    unsafe { read_volatile((base + offset) as *const u32) }
}
unsafe fn write(base: usize, offset: usize, value: u32) {
    unsafe { write_volatile((base + offset) as *mut u32, value) }
}
unsafe fn wait_clear(base: usize, offset: usize, bits: u32) -> Result<(), Error> {
    let start = bare::counter();
    let timeout = bare::counter_frequency() / 10;
    loop {
        if unsafe { read(base, offset) } & bits == 0 {
            return Ok(());
        }
        if bare::counter().wrapping_sub(start) > timeout {
            return Err(Error::Timeout);
        }
        core::hint::spin_loop();
    }
}

/// # Safety
/// IRQs must be masked, caller owns this CPU's PPI30 configuration. Both
/// apertures must be mapped Device-nGnRnE and described by the selected BSP.
/// Firmware must permit EL1 GIC system registers (ICC_SRE_EL2/EL3).
pub unsafe fn init_timer(
    distributor: usize,
    redistributors: usize,
    end: usize,
) -> Result<usize, Error> {
    if distributor & 0xffff != 0 || redistributors & 0xffff != 0 || end <= redistributors {
        return Err(Error::InvalidRange);
    }
    let mpidr = bare::mpidr();
    let affinity = ((mpidr >> 8) & 0xff00_0000) | (mpidr & 0x00ff_ffff);
    let mut redist = redistributors;
    loop {
        if redist.checked_add(0x20000).filter(|v| *v <= end).is_none() {
            return Err(Error::RedistributorNotFound);
        }
        let typer = unsafe { read_volatile((redist + 8) as *const u64) };
        if typer >> 32 == affinity {
            break;
        }
        if typer & (1 << 4) != 0 {
            return Err(Error::RedistributorNotFound);
        }
        redist += if typer & 2 != 0 { 0x40000 } else { 0x20000 };
    }
    unsafe {
        write(redist, 0x14, read(redist, 0x14) & !(1 << 1));
        wait_clear(redist, 0x14, 1 << 2)?;
        // Enable Group 1 with affinity routing. In the single-security-state
        // (DS=1) view Group 1 uses bit 1; the NS alias also has G1/G1A
        // enables. Preserve firmware state and enable both NS aliases.
        write(distributor, 0, read(distributor, 0) | (1 << 4) | 3);
        wait_clear(distributor, 0, 1 << 31)?;
        let sgi = redist + 0x10000;
        write(sgi, 0x180, 1 << 30); // ICENABLER0
        wait_clear(redist, 0, 1 << 3)?;
        write(sgi, 0x80, read(sgi, 0x80) | (1 << 30)); // IGROUPR0
        write(sgi, 0x280, 1 << 30); // ICPENDR0
        write(sgi, 0x380, 1 << 30); // ICACTIVER0
                                    // Timer PPI is level-sensitive; preserve other PPI configuration.
        write(sgi, 0xc04, read(sgi, 0xc04) & !(3 << 28));
        write_volatile((sgi + 0x400 + 30) as *mut u8, 0x80);
        let sre: u64;
        asm!("mrs {0}, ICC_SRE_EL1", "orr {0}, {0}, #1", "msr ICC_SRE_EL1, {0}", "isb",
            "mrs {0}, ICC_SRE_EL1", out(reg) sre, options(nostack));
        if sre & 1 == 0 {
            return Err(Error::SystemRegistersUnavailable);
        }
        // EOImode=0: EOI drops priority and deactivates the interrupt.
        let mut control: u64;
        asm!("mrs {}, ICC_CTLR_EL1", out(reg) control, options(nostack));
        control &= !(1 << 1);
        asm!("msr ICC_CTLR_EL1, {control}", "msr ICC_PMR_EL1, {pmr}",
            "msr ICC_BPR1_EL1, xzr", "msr ICC_IGRPEN1_EL1, {one}", "isb",
            control = in(reg) control, pmr = in(reg) 0xffu64, one = in(reg) 1u64, options(nostack));
        write(sgi, 0x100, 1 << 30); // ISENABLER0
        wait_clear(redist, 0, 1 << 3)?;
        asm!("dsb sy", "isb", options(nostack));
    }
    Ok(redist)
}
/// Acknowledge on this CPU. 1020..1023 are special IDs, never EOI them.
pub fn acknowledge() -> u32 {
    let id: u64;
    unsafe {
        asm!("mrs {}, ICC_IAR1_EL1", "dsb sy", out(reg) id, options(nostack));
    }
    id as u32
}
/// # Safety
/// `id` must be the non-special INTID just acknowledged on this CPU, and its
/// interrupt source must have been serviced before deactivation.
pub unsafe fn eoi(id: u32) {
    unsafe {
        asm!("dsb sy", "msr ICC_EOIR1_EL1, {}", "isb", in(reg) id as u64, options(nostack));
    }
}

/// Route one level-sensitive Group-1 SPI to the current CPU.
///
/// # Safety
/// IRQs must be masked. The caller exclusively owns this interrupt and its
/// source must be quiescent. `distributor` is a mapped 64 KiB Device aperture
/// already initialized by init_timer; firmware must make this SPI non-secure.
pub unsafe fn enable_level_spi(distributor: usize, id: u32) -> Result<(), Error> {
    if distributor & 0xffff != 0 || !(32..1020).contains(&id) {
        return Err(Error::InvalidRange);
    }
    unsafe {
        let count = ((read(distributor, 4) & 31) + 1) * 32;
        if id >= count {
            return Err(Error::InvalidRange);
        }
        let word = id as usize / 32 * 4;
        let bit = 1 << (id % 32);
        write(distributor, 0x180 + word, bit);
        wait_clear(distributor, 0, 1 << 31)?;
        write(
            distributor,
            0x80 + word,
            read(distributor, 0x80 + word) | bit,
        );
        write(distributor, 0x280 + word, bit);
        write(distributor, 0x380 + word, bit);
        let cfg = 0xc00 + id as usize / 16 * 4;
        write(
            distributor,
            cfg,
            read(distributor, cfg) & !(3 << ((id % 16) * 2)),
        );
        write_volatile((distributor + 0x400 + id as usize) as *mut u8, 0x80);
        // IROUTER holds Aff3 at [39:32], Aff2:Aff0 at [23:0], IRM=0.
        let route = bare::mpidr() & 0xff00_ffffff;
        write_volatile((distributor + 0x6000 + id as usize * 8) as *mut u64, route);
        asm!("dsb sy", options(nostack));
        write(distributor, 0x100 + word, bit);
        wait_clear(distributor, 0, 1 << 31)?;
        asm!("dsb sy", "isb", options(nostack));
    }
    Ok(())
}
