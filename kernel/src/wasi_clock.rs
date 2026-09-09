//! Shared Preview 1 clock source for both execution engines.
#[cfg(feature = "qemu-virt")]
static RTC_LOCK: crate::sync::SpinLock<()> = crate::sync::SpinLock::new(());
pub fn time(id: u32, _precision: u64) -> Result<u64, i32> {
    match id {
        #[cfg(feature = "qemu-virt")]
        0 => {
            let _lock = RTC_LOCK.lock();
            // The low-register read latches the high register globally. All
            // WASI engines must use the same lock for this pair of MMIO reads.
            let ns = unsafe {
                let low = core::ptr::read_volatile(crate::platform::RTC_BASE as *const u32);
                let high = core::ptr::read_volatile((crate::platform::RTC_BASE + 4) as *const u32);
                (u64::from(high) << 32) | u64::from(low)
            };
            Ok(ns)
        }
        1 => u64::try_from(
            u128::from(crate::sbi::time()) * 1_000_000_000
                / u128::from(vibeos_core::exec::timebase_hz()),
        )
        .map_err(|_| 29),
        _ => Err(52),
    }
}
pub fn resolution(id: u32) -> Result<u64, i32> {
    match id {
        #[cfg(feature = "qemu-virt")]
        0 => Ok(1),
        1 => Ok(1_000_000_000u64.div_ceil(vibeos_core::exec::timebase_hz())),
        _ => Err(52),
    }
}
