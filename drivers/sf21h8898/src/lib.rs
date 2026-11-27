//! SF21H8898 peripherals and DMA memory layout used on the BPI-RV2.
#![no_std]
#![cfg(target_arch = "riscv64")]
use core::{
    arch::asm,
    fmt::{self, Write},
    ptr,
};
mod acl;
pub mod crypto;
pub mod ethernet;
pub mod hnat;
#[cfg(feature = "wrap-memcpy")]
mod packet_copy;
pub mod wan;

const UART: usize = 0x0c301000;
pub struct Console;
impl Console {
    pub fn read_byte(&mut self) -> Option<u8> {
        unsafe {
            (ptr::read_volatile((UART + 0x18) as *const u32) & 0x10 == 0)
                .then(|| ptr::read_volatile(UART as *const u32) as u8)
        }
    }
}
impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            unsafe {
                while ptr::read_volatile((UART + 0x18) as *const u32) & 0x20 != 0 {}
                ptr::write_volatile(UART as *mut u32, byte.into());
            }
        }
        Ok(())
    }
}

pub fn ticks() -> u64 {
    let v;
    unsafe { asm!("rdtime {}",out(reg)v,options(nomem,nostack)) };
    v
}
