use vibeos_bsp_milkv_mars::{self as mars, network_resources::admit};
use vibeos_hal::fdt::{Event, Fdt};
const BLOB: &[u8] = include_bytes!("fixtures/network.dtb");
fn property(blob: &[u8], node: &str, property: &str) -> (usize, usize) {
    let mut active = None;
    for event in Fdt::new(blob).unwrap().events() {
        match event.unwrap() {
            Event::Begin { depth, name } if name == node => active = Some(depth),
            Event::End { depth } if active == Some(depth) => active = None,
            Event::Property { depth, name, value } if active == Some(depth) && name == property => {
                return (
                    value.as_ptr() as usize - blob.as_ptr() as usize,
                    value.len(),
                );
            }
            _ => (),
        }
    }
    panic!("missing {node}/{property}");
}
fn patch(node: &str, name: &str, word: usize, value: u32) -> Vec<u8> {
    let mut blob = BLOB.to_vec();
    let (at, len) = property(&blob, node, name);
    assert!(word * 4 + 4 <= len);
    blob[at + word * 4..at + word * 4 + 4].copy_from_slice(&value.to_be_bytes());
    blob
}
#[test]
fn pinned_wiring_is_admitted_without_inventing_phy_address_or_coherence() {
    let r = admit(BLOB).unwrap();
    assert_eq!(r.mac, mars::GMAC0_REGISTERS);
    assert_eq!(r.irq, 7);
    assert_eq!(r.cache, mars::L2_CACHE);
    assert_eq!(r.aon_crg.end, r.aon_syscon.start);
    assert_eq!(r.phy.drive, [0, 3, 6]);
    assert!(!r.phy.rxc_delay_enabled);
    assert_eq!(r.phy.tx_delay_fe, 5);
    assert_eq!(r.phy.tx_inverted, [true; 3]);
    // A generic serial/SD tree cannot silently enable Ethernet.
    assert!(admit(include_bytes!("fixtures/resources.dtb")).is_err());
}
#[test]
fn rejects_provider_substitution_indices_and_cache_geometry() {
    for (node, key, at, value) in [
        ("ethernet@16030000", "reg", 1, 0x16040000),
        ("spare-serial@10010000", "reg", 1, 0x16030000),
        ("ethernet@16030000", "reg", 3, 0x1000),
        ("ethernet@16030000", "interrupts", 0, 78),
        ("ethernet@16030000", "clocks", 0, 100),
        ("ethernet@16030000", "clocks", 3, 225),
        ("ethernet@16030000", "resets", 0, 200),
        ("ethernet@16030000", "resets", 1, 160),
        ("ethernet@16030000", "rx-fifo-depth", 0, 1024),
        ("ethernet@16030000", "#size-cells", 0, 1),
        ("clock-controller", "reg", 9, 0x17020000),
        ("clock-controller", "#clock-cells", 0, 2),
        ("reset-controller", "reg", 9, 0x17020000),
        ("reset-controller", "#reset-cells", 0, 2),
        ("aon_syscon@17010000", "reg", 3, 0x10000),
        ("cache-controller@2010000", "reg", 1, 0x2014000),
        ("cache-controller@2010000", "cache-block-size", 0, 32),
        ("cache-controller@2010000", "cache-level", 0, 1),
        ("cache-controller@2010000", "cache-sets", 0, 1024),
        ("cache-controller@2010000", "cache-size", 0, 1048576),
        ("ethernet-phy@0", "rx_delay_sel", 0, 0),
        ("ethernet-phy@0", "tx_inverted_1000", 0, 0),
    ] {
        assert!(
            admit(&patch(node, key, at, value)).is_err(),
            "{node}/{key}/{at}"
        );
    }
}
#[test]
fn rejects_disabled_devices_wrong_modes_and_string_ordering() {
    for (node, key, bytes) in [
        ("ethernet@16030000", "status", b"fail\0".as_slice()),
        ("ethernet@16030000", "phy-mode", b"rgmii-rx\0"),
        ("ethernet@16030000", "reset-names", b"stmmaceth\0ahb\0"),
        ("clock-controller", "reg-names", b"aon\0stg\0sys\0"),
    ] {
        let mut blob = BLOB.to_vec();
        let (at, len) = property(&blob, node, key);
        assert_eq!(len, bytes.len());
        blob[at..at + len].copy_from_slice(bytes);
        assert!(admit(&blob).is_err(), "{node}/{key}");
    }
}
#[test]
fn rejects_duplicate_provider_handles_outside_soc() {
    let mut blob = patch("spare", "phandle", 0, 200);
    let (at, _) = property(&blob, "spare", "linux,phandle");
    blob[at..at + 4].copy_from_slice(&200u32.to_be_bytes());
    assert!(admit(&blob).is_err());
}
#[test]
fn rejects_duplicate_network_properties_in_valid_dtb() {
    let mut blob = BLOB.to_vec();
    let (at, len) = property(&blob, "ethernet@16030000", "clocks");
    let encoded = blob[at - 12..at + len.next_multiple_of(4)].to_vec();
    blob.splice(at - 12..at - 12, encoded.iter().copied());
    // Insertion in the structure shifts strings and grows structure/total size.
    for index in [4, 12, 36] {
        let old = u32::from_be_bytes(blob[index..index + 4].try_into().unwrap());
        blob[index..index + 4].copy_from_slice(&(old + encoded.len() as u32).to_be_bytes());
    }
    assert!(Fdt::new(&blob).is_ok());
    assert!(admit(&blob).is_err());
}
