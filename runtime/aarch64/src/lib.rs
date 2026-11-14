//! AArch64 EL1 architecture mechanisms. No board addresses or image policy.
#![no_std]

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub mod bare;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub mod gic;
pub mod mmu;
pub mod crypto;
pub mod smp;

/// Integer prefix is stable; crypto images append complete SIMD/FP state.
#[repr(C)]
pub struct ExceptionFrame {
    pub x: [u64; 31],
    pub elr: u64,
    pub spsr: u64,
    pub reserved: u64,
    #[cfg(feature = "crypto-simd-frame")]
    pub simd: [[u64; 2]; 32],
    #[cfg(feature = "crypto-simd-frame")]
    pub fpcr: u64,
    #[cfg(feature = "crypto-simd-frame")]
    pub fpsr: u64,
}
#[cfg(not(feature = "crypto-simd-frame"))]
const _: () = assert!(core::mem::size_of::<ExceptionFrame>() == 272);
#[cfg(feature = "crypto-simd-frame")]
const _: () = {
    assert!(core::mem::size_of::<ExceptionFrame>() == 800);
    assert!(core::mem::offset_of!(ExceptionFrame, simd) == 272);
    assert!(core::mem::offset_of!(ExceptionFrame, fpcr) == 784);
    assert!(core::mem::offset_of!(ExceptionFrame, fpsr) == 792);
};

const _: () = {
    assert!(core::mem::offset_of!(ExceptionFrame, elr) == 248);
    assert!(core::mem::offset_of!(ExceptionFrame, spsr) == 256);
};
