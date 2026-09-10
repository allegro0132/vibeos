//! SiFive composable L2 cache operations used by the pinned JH7110 SDK.
//! FLUSH64 uses a full physical address, not the uncached alias or a shifted PPN.
use vibeos_hal::{
    memory::{DmaCache, DmaConstraints, DmaDirection, DmaRegion, MemoryError},
    AddressRange,
};
pub const CONTROL: AddressRange = AddressRange::new(0x02010000, 0x02014000);
const FLUSH64: usize = 0x200;
const LINE: usize = 64;

/// # Safety
/// Accesses must faithfully reach the admitted, live cache controller (or its
/// test model). Each 64-bit command and following full barrier must complete
/// the SDK-defined flush/invalidate operation before returning. Other cores
/// must obey the caller's DMA ownership and cache-line isolation protocol.
pub unsafe trait Registers {
    fn read32(&mut self, offset: usize) -> u32;
    fn write64(&mut self, offset: usize, value: u64);
    fn barrier(&mut self);
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Resources,
    Geometry,
}
pub struct Cache<R: Registers> {
    registers: R,
}
impl<R: Registers> Cache<R> {
    pub fn new(mut registers: R) -> Result<Self, Error> {
        let config = registers.read32(0);
        let banks = config & 255;
        let ways = (config >> 8) & 255;
        let block = config >> 24;
        let enabled = registers.read32(8);
        if banks == 0 || ways == 0 || ways > 32 || block != 6 || enabled >= ways {
            return Err(Error::Geometry);
        }
        Ok(Self { registers })
    }
    pub fn validate_region(region: DmaRegion) -> Result<(), MemoryError> {
        DmaConstraints {
            address_bits: 64,
            alignment: LINE,
            cache_line: LINE,
        }
        .validate(region)?;
        let end = region
            .physical
            .checked_add(region.bytes as u64)
            .ok_or(MemoryError::AddressOverflow)?;
        if region.physical < 0x40200000 || end > 0x140000000 {
            return Err(MemoryError::NotAddressable);
        }
        Ok(())
    }
    pub fn flush(&mut self, region: DmaRegion) -> Result<(), MemoryError> {
        Self::validate_region(region)?;
        self.registers.barrier();
        for offset in (0..region.bytes).step_by(LINE) {
            self.registers
                .write64(FLUSH64, region.physical + offset as u64);
            self.registers.barrier();
        }
        Ok(())
    }
}
// The SDK uses the same clean/invalidate FLUSH64 sequence for both directions.
// It is safe only with dedicated lines and exclusive CPU/device ownership.
unsafe impl<R: Registers> DmaCache for Cache<R> {
    fn validate(&self, r: DmaRegion) -> Result<(), MemoryError> {
        Self::validate_region(r)
    }
    fn for_device(&mut self, r: DmaRegion, _: DmaDirection) {
        self.flush(r).expect("unadmitted JH7110 cache span");
    }
    fn for_cpu(&mut self, r: DmaRegion, _: DmaDirection) {
        self.flush(r).expect("unadmitted JH7110 cache span");
    }
    fn barrier(&mut self) {
        self.registers.barrier();
    }
}

pub struct Mmio {
    base: usize,
}
impl Mmio {
    /// # Safety
    /// The DTB-admitted control window must be mapped for S-mode, with cache
    /// controller access permitted by PMP. The caller owns the service lifetime.
    pub unsafe fn new(control: AddressRange) -> Result<Self, Error> {
        if control != CONTROL {
            return Err(Error::Resources);
        }
        Ok(Self {
            base: control.start,
        })
    }
}
unsafe impl Registers for Mmio {
    fn read32(&mut self, offset: usize) -> u32 {
        assert!(matches!(offset, 0 | 8));
        self.barrier();
        let v = unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) };
        self.barrier();
        v
    }
    fn write64(&mut self, offset: usize, value: u64) {
        assert_eq!(offset, FLUSH64);
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u64, value) };
    }
    fn barrier(&mut self) {
        #[cfg(target_arch = "riscv64")]
        unsafe {
            core::arch::asm!("fence iorw, iorw", options(nostack, preserves_flags));
        }
        #[cfg(not(target_arch = "riscv64"))]
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
