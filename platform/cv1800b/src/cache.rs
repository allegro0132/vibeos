//! CV1800B C906 cache maintenance. These opcodes are never used on JH7110.
#[cfg(not(target_arch = "riscv64"))]
use core::sync::atomic::Ordering;
use vibeos_hal::memory::{DmaConstraints, DmaDirection, DmaOps, DmaRegion};
/// Identity-mapped, cache-isolated DMA pool below 4 GiB.
/// # Safety
/// Callers supply owned RAM ranges and observe controller ownership rules.
/// The pool must satisfy `constraints`; individual sync spans may be partial
/// cache lines only where the enclosing line belongs to the same DMA buffer.
pub static DMA: DmaOps = DmaOps {
    constraints: DmaConstraints {
        address_bits: 32,
        alignment: 64,
        cache_line: 64,
    },
    sync_for_device: |r, _direction| unsafe { sync(r, true) },
    sync_for_cpu: |r, direction| unsafe { sync(r, matches!(direction, DmaDirection::ToDevice)) },
};
unsafe fn sync(r: DmaRegion, clean: bool) {
    assert!(r.physical <= usize::MAX as u64);
    assert!(r
        .physical
        .checked_add(r.bytes as u64)
        .is_some_and(|end| end <= 1u64 << 32));
    cache_range(64, r.physical as usize, r.bytes, clean);
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

#[cfg(all(test, not(target_arch = "riscv64")))]
mod tests {
    use super::*;
    // Host synchronization is a compiler fence only; no hardware coherence claim.
    #[test]
    fn entire_pool_must_be_cache_isolated_and_below_four_gib() {
        assert!(DMA
            .constraints
            .validate(DmaRegion {
                physical: 0xffff_ffc0,
                bytes: 64
            })
            .is_ok());
        assert!(DMA
            .constraints
            .validate(DmaRegion {
                physical: 0xffff_ffc0,
                bytes: 128
            })
            .is_err());
        assert!(DMA
            .constraints
            .validate(DmaRegion {
                physical: 0x8000_0020,
                bytes: 64
            })
            .is_err());
        assert!(DMA
            .constraints
            .validate(DmaRegion {
                physical: 0x8000_0000,
                bytes: 63
            })
            .is_err());
        for direction in [
            DmaDirection::ToDevice,
            DmaDirection::FromDevice,
            DmaDirection::Bidirectional,
        ] {
            unsafe {
                (DMA.sync_for_device)(
                    DmaRegion {
                        physical: 0xffff_ffc0,
                        bytes: 64,
                    },
                    direction,
                );
                (DMA.sync_for_cpu)(
                    DmaRegion {
                        physical: 0xffff_ffc0,
                        bytes: 64,
                    },
                    direction,
                );
            }
        }
    }
    #[test]
    #[should_panic]
    fn synchronization_rejects_out_of_reach_span() {
        unsafe {
            (DMA.sync_for_device)(
                DmaRegion {
                    physical: 0xffff_ffc0,
                    bytes: 65,
                },
                DmaDirection::Bidirectional,
            );
        }
    }
}
