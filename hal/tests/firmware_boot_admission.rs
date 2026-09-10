//! Run the test firmware's actual pre-MMU callback with owned host bytes.
//! Host atomics and QEMU boot do not qualify Mars cache visibility.
use vibeos_hal::{
    boot::{BootError, BootRequest},
    AddressRange,
};
struct Board;
struct Info {
    timebase_hz: u64,
}
impl Board {
    const HART_IDS: &'static [usize] = &[0, 1, 2, 3];
    const INFO: Info = Info {
        timebase_hz: 10_000_000,
    };
}
#[allow(unused_imports)]
#[path = "../../firmware/qemu-hal-test/src/boot_admission.rs"]
mod admission;
#[test]
fn validates_before_publication_and_never_replaces_published_metadata() {
    assert!(std::panic::catch_unwind(admission::hart_ids).is_err());
    assert!(std::panic::catch_unwind(admission::timebase_hz).is_err());
    let blob = include_bytes!("fixtures/boot-admission.dtb");
    let mut storage = vec![0u64; blob.len().div_ceil(8)];
    let base = storage.as_mut_ptr() as usize;
    unsafe { core::ptr::copy_nonoverlapping(blob.as_ptr(), base as *mut u8, blob.len()) };
    let mut request = BootRequest {
        physical_hart: 3,
        dtb_address: base,
        ram: AddressRange::new(base, base + blob.len()),
        static_memory: AddressRange::new(0x80200000, 0x80400000),
        heap_envelope: AddressRange::new(0x80400000, 0x88000000),
    };
    request.physical_hart = 4;
    assert_eq!(
        unsafe { admission::admit(request) },
        Err(BootError::InvalidCpu)
    );
    request.physical_hart = 3;
    request.static_memory.end = 0x88000001;
    assert_eq!(
        unsafe { admission::admit(request) },
        Err(BootError::InvalidMemory)
    );
    request.static_memory.end = 0x80400000;
    let time = blob
        .windows(4)
        .position(|s| s == 10_000_000u32.to_be_bytes())
        .unwrap();
    unsafe { *((base + time) as *mut u8) ^= 1 };
    assert_eq!(
        unsafe { admission::admit(request) },
        Err(BootError::InvalidTimebase)
    );
    unsafe { *((base + time) as *mut u8) ^= 1 };
    let status = blob.windows(5).position(|s| s == b"okay\0").unwrap();
    unsafe { *((base + status) as *mut u8) = b'x' };
    assert_eq!(
        unsafe { admission::admit(request) },
        Err(BootError::InvalidCpu)
    );
    unsafe { *((base + status) as *mut u8) = b'o' };
    assert!(std::panic::catch_unwind(admission::hart_ids).is_err());
    assert_eq!(unsafe { admission::admit(request) }, Ok(()));
    assert_eq!(admission::hart_ids(), &[3, 0, 1, 2]);
    assert_eq!(admission::timebase_hz(), 10_000_000);
    request.physical_hart = 1;
    assert_eq!(
        unsafe { admission::admit(request) },
        Err(BootError::AlreadyInitialized)
    );
    assert_eq!(admission::hart_ids(), &[3, 0, 1, 2]);
}
