//! Firmware boundary: every address-bearing operation is translated before
//! the controller sees it. No raw diagnostic escape is exported to the kernel.
use vibeos_hal::block::{BlockWindow, Diagnostics, Error, MAX_TRANSFER_BLOCKS};
pub trait BlockIo {
    fn read(&mut self, sector: u64, output: &mut [u8]) -> Result<(), Error>;
    fn write(
        &mut self,
        sector: u64,
        data: &[u8],
        verify: bool,
        published: &mut dyn FnMut(),
    ) -> Result<(), Error>;
    fn flush(&mut self, published: &mut dyn FnMut()) -> Result<(), Error>;
    fn diagnostics(&self) -> Diagnostics;
}
pub struct Partition<B> {
    hardware: B,
    window: BlockWindow,
    sectors: u64,
}
impl<B: BlockIo> Partition<B> {
    pub fn new(hardware: B, capacity: u64, first: u64, sectors: u64) -> Result<Self, Error> {
        Ok(Self {
            hardware,
            window: BlockWindow::new(capacity, first, sectors)?,
            sectors,
        })
    }
    pub fn sectors(&self) -> u64 {
        self.sectors
    }
    fn address(&self, sector: u64, bytes: usize) -> Result<u64, Error> {
        if bytes > MAX_TRANSFER_BLOCKS as usize * 512 {
            return Err(Error::OutOfRange);
        }
        self.window.translate(sector, bytes)
    }
    pub fn read(&mut self, sector: u64, output: &mut [u8]) -> Result<(), Error> {
        let physical = self.address(sector, output.len())?;
        self.hardware.read(physical, output)
    }
    pub fn write(
        &mut self,
        sector: u64,
        data: &[u8],
        verify: bool,
        published: &mut dyn FnMut(),
    ) -> Result<(), Error> {
        let physical = self.address(sector, data.len())?;
        self.hardware.write(physical, data, verify, published)
    }
    pub fn flush(&mut self, published: &mut dyn FnMut()) -> Result<(), Error> {
        self.hardware.flush(published)
    }
    pub fn diagnostics(&self) -> Diagnostics {
        self.hardware.diagnostics()
    }
}
impl<R: vibeos_driver_dw_mshc::Registers> BlockIo for vibeos_driver_dw_mshc::Card<R> {
    fn read(&mut self, sector: u64, output: &mut [u8]) -> Result<(), Error> {
        self.read_blocks(sector, output).map_err(Into::into)
    }
    fn write(
        &mut self,
        sector: u64,
        data: &[u8],
        verify: bool,
        published: &mut dyn FnMut(),
    ) -> Result<(), Error> {
        self.write_blocks_tracked(sector, data, verify, published)
            .map_err(Into::into)
    }
    fn flush(&mut self, published: &mut dyn FnMut()) -> Result<(), Error> {
        self.flush_tracked(published).map_err(Into::into)
    }
    fn diagnostics(&self) -> Diagnostics {
        self.diagnostics()
    }
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{cell::RefCell, rc::Rc, vec::Vec};
    struct Model(Rc<RefCell<Vec<u64>>>);
    impl BlockIo for Model {
        fn read(&mut self, s: u64, out: &mut [u8]) -> Result<(), Error> {
            self.0.borrow_mut().push(s);
            out.fill(0x5a);
            Ok(())
        }
        fn write(
            &mut self,
            s: u64,
            _: &[u8],
            verify: bool,
            p: &mut dyn FnMut(),
        ) -> Result<(), Error> {
            assert!(verify);
            self.0.borrow_mut().push(s);
            p();
            Err(Error::TimedOut)
        }
        fn flush(&mut self, p: &mut dyn FnMut()) -> Result<(), Error> {
            p();
            Ok(())
        }
        fn diagnostics(&self) -> Diagnostics {
            Diagnostics::default()
        }
    }
    #[test]
    fn validates_whole_requests_before_any_io_or_publication() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut p = Partition::new(Model(calls.clone()), 1024, 128, 512).unwrap();
        let mut out = [0; 1024];
        let mut published = 0;
        for sector in [511, 512, u64::MAX] {
            assert_eq!(p.read(sector, &mut out), Err(Error::OutOfRange));
            assert_eq!(
                p.write(sector, &out, true, &mut || published += 1),
                Err(Error::OutOfRange)
            );
        }
        assert!(calls.borrow().is_empty());
        assert_eq!(published, 0);
        assert_eq!(p.read(0, &mut []), Err(Error::Protocol));
        assert_eq!(p.read(0, &mut out[..513]), Err(Error::Protocol));
        p.read(0, &mut out).unwrap();
        assert_eq!(out, [0x5a; 1024]);
        assert_eq!(&*calls.borrow(), &[128]);
        assert_eq!(
            p.write(510, &out, true, &mut || published += 1),
            Err(Error::TimedOut)
        );
        assert_eq!(&*calls.borrow(), &[128, 638]);
        assert_eq!(published, 1);
        p.flush(&mut || published += 1).unwrap();
        assert_eq!(published, 2);
        assert_eq!(p.sectors(), 512);
    }
    #[test]
    fn rejects_small_media_and_oversized_transfers() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        assert!(Partition::new(Model(calls.clone()), 639, 128, 512).is_err());
        let mut p = Partition::new(Model(calls.clone()), 1024, 128, 512).unwrap();
        let mut output = std::vec![0;257*512];
        assert_eq!(p.read(0, &mut output), Err(Error::OutOfRange));
        assert!(calls.borrow().is_empty());
    }
}
