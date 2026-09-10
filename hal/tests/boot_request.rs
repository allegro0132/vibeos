//! Physical readability is a firmware obligation. These tests use owned host
//! RAM and cannot verify a machine's physical address decoding or cache state.
use vibeos_hal::{
    boot::{BootError, BootRequest},
    AddressRange,
};
const BLOB: &[u8] = include_bytes!("fixtures/cpus.dtb");
fn fixture() -> (Vec<u64>, BootRequest) {
    let mut storage = vec![0u64; BLOB.len().div_ceil(8)];
    let base = storage.as_mut_ptr() as usize;
    unsafe { core::ptr::copy_nonoverlapping(BLOB.as_ptr(), base as *mut u8, BLOB.len()) };
    let range = AddressRange::new(base, base + BLOB.len());
    (
        storage,
        BootRequest {
            physical_hart: 0,
            dtb_address: base,
            ram: range,
            static_memory: range,
            heap_envelope: range,
        },
    )
}
#[test]
fn accepts_complete_tree_and_rejects_header_and_body_truncation() {
    let (_storage, mut request) = fixture();
    assert_eq!(unsafe { request.dtb() }.unwrap(), BLOB);
    request.ram.end -= 1;
    assert_eq!(unsafe { request.dtb() }, Err(BootError::InvalidDtb));
    request.ram.end = request.ram.start + 39;
    assert_eq!(unsafe { request.dtb() }, Err(BootError::InvalidDtb));
}
#[test]
fn rejects_unaligned_outside_and_wrapping_addresses_before_reading() {
    let (_storage, mut request) = fixture();
    for address in [0, request.ram.start + 1, request.ram.end, usize::MAX - 7] {
        request.dtb_address = address;
        assert_eq!(unsafe { request.dtb() }, Err(BootError::InvalidDtb));
    }
}
#[test]
fn rejects_corrupted_header_without_reading_unadvertised_storage() {
    let (_storage, request) = fixture();
    let header = unsafe { core::slice::from_raw_parts_mut(request.dtb_address as *mut u8, 40) };
    for size in [0u32, 39, 1024 * 1024 + 1, u32::MAX] {
        header[4..8].copy_from_slice(&size.to_be_bytes());
        assert_eq!(unsafe { request.dtb() }, Err(BootError::InvalidDtb));
    }
    header[4..8].copy_from_slice(&(BLOB.len() as u32).to_be_bytes());
    header[0] = 0;
    assert_eq!(unsafe { request.dtb() }, Err(BootError::InvalidDtb));
}
