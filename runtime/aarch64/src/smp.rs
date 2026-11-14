//! PSCI CPU_ON and checked GICv3 affinity encoding.
//!
//! Arm DEN0022 (PSCI) and IHI0069 (GICv3): only Aff0 0..15 is admitted;
//! RangeSelector support is not assumed by this qualified four-CPU platform.
pub const IPI_INTID: u8 = 1;

pub const fn sgi_target(mpidr: u64, intid: u8) -> Option<u64> {
    if mpidr & !0xff00_ffffff != 0 || mpidr & 0xff >= 16 || intid >= 16 {
        return None;
    }
    Some(((mpidr >> 32) & 0xff) << 48
        | ((mpidr >> 16) & 0xff) << 32
        | (intid as u64) << 24
        | ((mpidr >> 8) & 0xff) << 16
        | 1u64 << (mpidr & 0xff))
}

#[derive(Clone, Copy)]
pub enum Conduit { Smc, Hvc }

/// Start one stopped CPU at a physical identity-mapped entry point.
/// # Safety
/// Entry/context must remain valid permanently. All memory read before the
/// secondary enables caches must be cleaned to PoC before this call. The
/// target must own a separate stack and must not repeat global initialization.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn cpu_on(conduit: Conduit, mpidr: usize, entry: usize, context: usize) -> Result<(), i64> {
    use core::arch::asm;
    let mut result = 0xc400_0003u64;
    unsafe {
        match conduit {
            Conduit::Smc => asm!("smc #0", inout("x0") result, inout("x1") mpidr => _,
                inout("x2") entry => _, inout("x3") context => _, clobber_abi("C"), options(nostack)),
            Conduit::Hvc => asm!("hvc #0", inout("x0") result, inout("x1") mpidr => _,
                inout("x2") entry => _, inout("x3") context => _, clobber_abi("C"), options(nostack)),
        }
    }
    if result == 0 { Ok(()) } else { Err(result as i64) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_one_cpu_in_each_affinity_level() {
        assert_eq!(sgi_target(0, 1), Some(0x0100_0001));
        assert_eq!(sgi_target(3, 1), Some(0x0100_0008));
        assert_eq!(sgi_target(0x1200_34560f, 7), Some(0x0012_0034_0756_8000));
    }
    #[test]
    fn reject_unrepresentable_targets_instead_of_broadcasting() {
        for mpidr in [16, 255, 1 << 24, 1 << 40, u64::MAX] {
            assert_eq!(sgi_target(mpidr, 1), None);
        }
        assert_eq!(sgi_target(0, 16), None);
    }
}
