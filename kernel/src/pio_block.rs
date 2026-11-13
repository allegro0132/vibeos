//! Exclusive invocation token for the firmware's synchronous block instance.
use vibeos_hal::block::{pio_device, Diagnostics, Error};
pub struct Info {
    pub capacity_sectors: u64,
}
pub struct FirmwareCard {
    capacity: u64,
    verify: bool,
    _exclusive: core::marker::PhantomData<core::cell::Cell<()>>,
}
impl FirmwareCard {
    /// # Safety
    /// The storage service must exclude every earlier incarnation/operation.
    pub unsafe fn initialize(
        hz: u64,
        time: fn() -> u64,
        log: fn(core::fmt::Arguments<'_>),
    ) -> Result<Self, Error> {
        let capacity = (pio_device().initialize)(hz, time, log)?;
        Ok(Self {
            capacity,
            verify: true,
            _exclusive: core::marker::PhantomData,
        })
    }
    pub fn info(&self) -> Info {
        Info {
            capacity_sectors: self.capacity,
        }
    }
    fn diagnostics(&self) -> Diagnostics {
        unsafe { (pio_device().diagnostics)() }
    }
    pub fn last_command(&self) -> u8 {
        self.diagnostics().command
    }
    pub fn last_interrupt_status(&self) -> u32 {
        self.diagnostics().interrupt_status
    }
    pub fn present_state(&self) -> u32 {
        self.diagnostics().present_state
    }
    pub fn set_write_readback(&mut self, enabled: bool) {
        self.verify = enabled;
    }
    pub fn read_blocks(&mut self, first: u64, out: &mut [u8]) -> Result<(), Error> {
        unsafe { (pio_device().read)(first, out) }
    }
    pub fn read_sector(&mut self, sector: u64) -> Result<[u8; 512], Error> {
        let mut out = [0; 512];
        self.read_blocks(sector, &mut out)?;
        Ok(out)
    }
    pub fn write_blocks_tracked(
        &mut self,
        first: u64,
        data: &[u8],
        published: impl FnOnce(),
    ) -> Result<(), Error> {
        let mut published = Some(published);
        unsafe {
            (pio_device().write)(first, data, self.verify, &mut || {
                if let Some(hook) = published.take() {
                    hook();
                }
            })
        }
    }
    pub fn write_sector_tracked(
        &mut self,
        first: u64,
        data: &[u8; 512],
        published: impl FnOnce(),
    ) -> Result<(), Error> {
        self.write_blocks_tracked(first, data, published)
    }
    pub fn flush_tracked(&mut self, published: impl FnOnce()) -> Result<(), Error> {
        let mut published = Some(published);
        unsafe {
            (pio_device().flush)(&mut || {
                if let Some(hook) = published.take() {
                    hook();
                }
            })
        }
    }
    pub fn diagnostic_probe_multiblock_read(
        &mut self,
        sector: u64,
        output: &mut [u8],
        budget: usize,
    ) -> (usize, Result<(), Error>) {
        match pio_device().probe_read {
            Some(probe) => unsafe { probe(sector, output, budget) },
            None => (0, Err(Error::Unsupported)),
        }
    }
}
