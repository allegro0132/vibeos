//! Execute Mars policy and partition translation on RV64; no Mars MMIO.
use vibeos_firmware_milkv_mars::{
    admit,
    partition::{BlockIo, Partition},
    SbiExtensions,
};
use vibeos_hal::{
    block::{Diagnostics, Error},
    boot::BootRequest,
    AddressRange,
};
struct Model {
    next: u64,
}
impl BlockIo for Model {
    fn read(&mut self, sector: u64, output: &mut [u8]) -> Result<(), Error> {
        assert_eq!(sector, self.next);
        output.fill(0x5a);
        Ok(())
    }
    fn write(
        &mut self,
        sector: u64,
        _: &[u8],
        verify: bool,
        p: &mut dyn FnMut(),
    ) -> Result<(), Error> {
        assert_eq!(sector, self.next);
        assert!(verify);
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
pub fn run() {
    let request = BootRequest {
        physical_hart: 4,
        dtb_address: 0x48000000,
        ram: AddressRange::new(0x40200000, 0x140000000),
        static_memory: AddressRange::new(0x40200000, 0x42000000),
        heap_envelope: AddressRange::new(0x42000000, 0x140000000),
    };
    let capabilities = SbiExtensions {
        hsm: true,
        ipi: true,
        rfence: true,
        time: true,
    };
    let fixture = include_bytes!("../../../boards/milkv-mars/tests/fixtures/trng.dtb");
    let admitted = admit(fixture, &request, capabilities).unwrap();
    #[cfg(feature = "mars-ethernet-device-test")]
    assert_eq!(admitted.network.unwrap().mac, AddressRange::new(0x16030000, 0x16040000));
    assert_eq!(admitted.harts.ids(), &[4, 1, 2, 3]);
    assert!(admit(
        fixture,
        &request,
        SbiExtensions {
            hsm: false,
            ..capabilities
        }
    )
    .is_err());
    let mut data = Partition::new(Model { next: 128 }, 1024, 128, 512).unwrap();
    let mut output = [0; 1024];
    assert_eq!(data.read(511, &mut output), Err(Error::OutOfRange));
    data.read(0, &mut output).unwrap();
    assert_eq!(output, [0x5a; 1024]);
    let mut published = 0;
    assert_eq!(
        data.write(512, &output, true, &mut || published += 1),
        Err(Error::OutOfRange)
    );
    assert_eq!(published, 0);
    assert_eq!(
        data.write(0, &output, true, &mut || published += 1),
        Err(Error::TimedOut)
    );
    assert_eq!(published, 1);
}
