use vibeos_bsp_milkv_mars::usable_memory;
use vibeos_hal::AddressRange;

#[test]
fn dtc_blob_reserves_firmware_coprocessor_reservation_table_and_dtb() {
    let bytes = include_bytes!("fixtures/memory.dtb");
    let memory = usable_memory::<16>(bytes, 0x4800_0000).unwrap();
    assert!(!memory.contains(AddressRange::new(0x4000_0000, 0x4020_0000)));
    assert!(!memory.contains(AddressRange::new(0x4100_0000, 0x4100_1000)));
    assert!(!memory.contains(AddressRange::new(0x69c0_0000, 0x6cc0_1000)));
    assert!(!memory.contains(AddressRange::new(0x4800_0000, 0x4800_0000 + bytes.len())));
    assert!(memory.contains(AddressRange::new(0x1_0000_0000, 0x1_4000_0000)));
    assert!(memory.contains(AddressRange::new(0x4020_0000, 0x4100_0000)));
}

#[test]
fn incompatible_board_cannot_supply_mars_memory() {
    let mut bytes = *include_bytes!("fixtures/memory.dtb");
    let position = bytes.windows(11).position(|x| x == b"milk-v,mars").unwrap();
    bytes[position + 7] = b'x';
    assert!(usable_memory::<16>(&bytes, 0x4800_0000).is_err());
}
