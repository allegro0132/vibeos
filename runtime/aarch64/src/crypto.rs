//! Architectural crypto inventory, deliberately separate from permission to
//! execute SIMD. Presence does not establish exception/context-switch safety.
//! ID_AA64ISAR0_EL1.AES[7:4]: 1=AES, 2=AES+PMULL (Arm architecture manual).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub isar0: u64,
    pub pfr0: u64,
    pub cpacr: u64,
}
impl Capabilities {
    pub const fn aes(self) -> bool {
        matches!((self.isar0 >> 4) & 15, 1 | 2)
    }
    pub const fn pmull(self) -> bool {
        (self.isar0 >> 4) & 15 == 2
    }
    pub const fn simd(self) -> bool {
        matches!((self.pfr0 >> 20) & 15, 0 | 1)
    }
    pub const fn fp(self) -> bool {
        matches!((self.pfr0 >> 16) & 15, 0 | 1)
    }
    pub const fn el1_simd_enabled(self) -> bool {
        (self.cpacr >> 20) & 1 != 0
    }
    /// Hardware prerequisites only; the caller must separately protect state.
    pub const fn aes_gcm_instructions(self) -> bool {
        self.aes() && self.pmull() && self.simd() && self.fp()
    }
}

/// Read-only EL1 inventory. This does not enable FP/SIMD or select a backend.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn read() -> Capabilities {
    let (isar0, pfr0, cpacr);
    unsafe {
        core::arch::asm!(
        "mrs {isar0}, id_aa64isar0_el1", "mrs {pfr0}, id_aa64pfr0_el1", "mrs {cpacr}, cpacr_el1",
        isar0 = out(reg) isar0, pfr0 = out(reg) pfr0, cpacr = out(reg) cpacr,
        options(nomem, nostack, preserves_flags));
    }
    Capabilities { isar0, pfr0, cpacr }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capability_does_not_imply_simd_permission() {
        let c = Capabilities {
            isar0: 2 << 4,
            pfr0: 0,
            cpacr: 0,
        };
        assert!(c.aes_gcm_instructions());
        assert!(!c.el1_simd_enabled());
        for fpen in 0..4 {
            assert_eq!(
                Capabilities {
                    cpacr: fpen << 20,
                    ..c
                }
                .el1_simd_enabled(),
                fpen & 1 != 0
            );
        }
    }
    #[test]
    fn absent_reserved_or_aes_without_pmull_cannot_select_full_acceleration() {
        for field in 0..16 {
            let c = Capabilities {
                isar0: field << 4,
                pfr0: 0,
                cpacr: 3 << 20,
            };
            assert_eq!(c.aes_gcm_instructions(), field == 2);
        }
        for shift in [16, 20] {
            let c = Capabilities {
                isar0: 2 << 4,
                pfr0: 15 << shift,
                cpacr: 3 << 20,
            };
            assert!(!c.aes_gcm_instructions());
        }
    }
}
