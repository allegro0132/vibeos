#![no_std]
//! Mars composition policy. Host tests exercise admission and data-only block
//! translation; only the binary performs SBI calls or real device accesses.
pub mod partition;
#[cfg(feature = "entropy-device")]
pub mod entropy_instance;
#[cfg(feature = "ethernet-device")]
pub mod packet;
use vibeos_bsp_milkv_mars as mars;
use vibeos_hal::{
    boot::{BootError, BootRequest},
    memory::BootMemory,
};
pub const DATA_FIRST_SECTOR: u64 = 262_144;
pub const DATA_SECTOR_COUNT: u64 = 1_048_576;
#[derive(Clone, Copy, Debug)]
pub struct SbiExtensions {
    pub hsm: bool,
    pub ipi: bool,
    pub rfence: bool,
    pub time: bool,
}
#[derive(Clone, Copy, Debug)]
pub struct Admission {
    pub harts: mars::harts::BootHarts,
    pub resources: mars::resources::Resources,
    pub heap: BootMemory<16>,
    pub network: Option<mars::network_resources::Resources>,
    pub trng: Option<mars::trng_resources::Resources>,
}
/// The caller associates `dtb` with the handoff's physical DTB address.
/// SBI bits are extension probes, not proof of successful four-hart startup.
pub fn admit(
    dtb: &[u8],
    request: &BootRequest,
    sbi: SbiExtensions,
) -> Result<Admission, BootError> {
    if !(sbi.hsm && sbi.ipi && sbi.rfence && sbi.time) {
        return Err(BootError::UnsupportedFirmware);
    }
    if request.ram.start != mars::KERNEL_LOAD_ADDRESS || request.ram.end != mars::RAM.end {
        return Err(BootError::InvalidMemory);
    }
    let harts =
        mars::harts::admit(dtb, request.physical_hart, false).map_err(|_| BootError::InvalidCpu)?;
    if !harts.is_four_core() {
        return Err(BootError::InvalidCpu);
    }
    let resources = mars::resources::admit(dtb).map_err(|_| BootError::InvalidDtb)?;
    let memory = mars::usable_memory::<16>(dtb, request.dtb_address)
        .map_err(|_| BootError::InvalidMemory)?;
    let heap = request.usable_heap(&memory)?;
    #[cfg(feature = "ethernet-device")]
    let network = Some(mars::network_resources::admit(dtb).map_err(|_| BootError::InvalidDtb)?);
    #[cfg(not(feature = "ethernet-device"))]
    let network = None;
    #[cfg(feature = "entropy-device")]
    let trng = Some(mars::trng_resources::admit(dtb).map_err(|_| BootError::InvalidDtb)?);
    #[cfg(not(feature = "entropy-device"))]
    let trng = None;
    Ok(Admission {
        harts,
        resources,
        heap,
        network,
        trng,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use vibeos_hal::AddressRange;
    const DTB: &[u8] = include_bytes!("../../../boards/milkv-mars/tests/fixtures/trng.dtb");
    #[test]
    fn four_hart_admission_requires_sbi_and_preserves_reserved_dtb_pages() {
        let mut request = BootRequest {
            physical_hart: 4,
            dtb_address: 0x48000000,
            ram: AddressRange::new(mars::KERNEL_LOAD_ADDRESS, mars::RAM.end),
            static_memory: AddressRange::new(mars::KERNEL_LOAD_ADDRESS, 0x42000000),
            heap_envelope: AddressRange::new(0x42000000, mars::RAM.end),
        };
        let all = SbiExtensions {
            hsm: true,
            ipi: true,
            rfence: true,
            time: true,
        };
        let result = admit(DTB, &request, all).unwrap();
        #[cfg(feature = "ethernet-device")]
        assert_eq!(result.network.unwrap().mac, AddressRange::new(0x16030000, 0x16040000));
        #[cfg(not(feature = "ethernet-device"))]
        assert!(result.network.is_none());
        #[cfg(feature = "entropy-device")]
        {
            assert_eq!(result.trng.unwrap().registers, mars::TRNG_REGISTERS);
            let without_trng = include_bytes!("../../../boards/milkv-mars/tests/fixtures/network.dtb");
            assert!(matches!(admit(without_trng, &request, all), Err(BootError::InvalidDtb)));
        }
        #[cfg(not(feature = "entropy-device"))]
        assert!(result.trng.is_none());
        assert_eq!(result.harts.ids(), &[4, 1, 2, 3]);
        assert_eq!(result.heap.ranges().last().unwrap().end, mars::RAM.end);
        assert!(!result
            .heap
            .contains(AddressRange::new(0x48000000, 0x48001000)));
        for bits in [
            SbiExtensions { hsm: false, ..all },
            SbiExtensions { ipi: false, ..all },
            SbiExtensions {
                rfence: false,
                ..all
            },
            SbiExtensions { time: false, ..all },
        ] {
            assert!(matches!(
                admit(DTB, &request, bits),
                Err(BootError::UnsupportedFirmware)
            ));
        }
        request.physical_hart = 0;
        assert!(matches!(
            admit(DTB, &request, all),
            Err(BootError::InvalidCpu)
        ));
        request.physical_hart = 4;
        request.static_memory.end = 0x48001000;
        request.heap_envelope.start = request.static_memory.end;
        assert!(matches!(
            admit(DTB, &request, all),
            Err(BootError::InvalidMemory)
        ));
    }
}
