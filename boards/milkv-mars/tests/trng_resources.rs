use vibeos_bsp_milkv_mars::{
    self as mars,
    trng_resources::{admit, ResetScope},
};
use vibeos_hal::fdt::{Event, Fdt};
const BLOB: &[u8] = include_bytes!("fixtures/trng.dtb");
const TRNG: &str = "trng@1600C000";
fn property(blob: &[u8], node: &str, key: &str) -> (usize, usize) {
    let mut active = None;
    for event in Fdt::new(blob).unwrap().events() {
        match event.unwrap() {
            Event::Begin { depth, name } if name == node => active = Some(depth),
            Event::End { depth } if active == Some(depth) => active = None,
            Event::Property { depth, name, value } if active == Some(depth) && name == key => {
                return (
                    value.as_ptr() as usize - blob.as_ptr() as usize,
                    value.len(),
                )
            }
            _ => (),
        }
    }
    panic!("missing {node}/{key}")
}
fn set(blob: &mut [u8], node: &str, key: &str, word: usize, value: u32) {
    let (at, len) = property(blob, node, key);
    assert!(word * 4 + 4 <= len);
    blob[at + word * 4..at + word * 4 + 4].copy_from_slice(&value.to_be_bytes());
}
fn insert(blob: &mut Vec<u8>, at: usize, encoded: &[u8]) {
    blob.splice(at..at, encoded.iter().copied());
    for i in [4, 12, 36] {
        let old = u32::from_be_bytes(blob[i..i + 4].try_into().unwrap());
        blob[i..i + 4].copy_from_slice(&(old + encoded.len() as u32).to_be_bytes());
    }
    assert!(Fdt::new(blob).is_ok());
}
fn end() -> usize {
    let (at, len) = property(BLOB, TRNG, "interrupts");
    at + len.next_multiple_of(4)
}

#[test]
fn pinned_node_retains_shared_reset_scope_and_exact_resources() {
    let r = admit(BLOB).unwrap();
    assert_eq!(r.registers, mars::TRNG_REGISTERS);
    assert_eq!(r.irq, 30);
    assert_eq!(r.sys_crg, mars::SYS_CRG);
    assert_eq!(r.clock_ids, [205, 206]);
    assert_eq!(r.reset_id, 131);
    assert_eq!(r.reset_scope, ResetScope::SharedSecuritySubsystem);
    assert!(admit(include_bytes!("fixtures/network.dtb")).is_err());
}
#[test]
fn resource_provider_or_interrupt_substitution_is_rejected() {
    for (node, key, word, value) in [
        (TRNG, "reg", 1, 0x16008000),
        (TRNG, "reg", 3, 0x8000),
        (TRNG, "interrupts", 0, 31),
        (TRNG, "clocks", 0, 201),
        (TRNG, "clocks", 1, 206),
        (TRNG, "clocks", 3, 205),
        (TRNG, "resets", 0, 200),
        (TRNG, "resets", 1, 130),
        ("clock-controller", "#clock-cells", 0, 2),
        ("clock-controller", "reg", 1, 0x10230000),
        ("reset-controller", "#reset-cells", 0, 2),
        ("reset-controller", "reg", 3, 0x1000),
    ] {
        let mut b = BLOB.to_vec();
        set(&mut b, node, key, word, value);
        assert!(admit(&b).is_err(), "{node}/{key}/{word}");
    }
}
#[test]
fn disabled_wrong_binding_and_clock_order_are_rejected() {
    for (key, bytes) in [
        ("status", b"fail\0".as_slice()),
        ("clock-names", b"ahb\0hclk\0"),
    ] {
        let mut b = BLOB.to_vec();
        let (at, len) = property(&b, TRNG, key);
        assert_eq!(len, bytes.len());
        b[at..at + len].copy_from_slice(bytes);
        assert!(admit(&b).is_err());
    }
    let mut b = BLOB.to_vec();
    let (at, _) = property(&b, TRNG, "compatible");
    b[at] = b'x';
    assert!(admit(&b).is_err());
}
#[test]
fn provider_handles_cannot_alias_elsewhere_in_the_tree() {
    for id in [200, 201] {
        let mut b = BLOB.to_vec();
        set(&mut b, "spare", "phandle", 0, id);
        set(&mut b, "spare", "linux,phandle", 0, id);
        assert!(admit(&b).is_err());
    }
}
#[test]
fn partial_overlapping_aliases_rejected_but_adjacent_regions_allowed() {
    for (start, size, rejected) in [
        (0x1600b000, 0x2000, true),
        (0x1600f000, 0x1000, true),
        (0x1600c000, 0x4000, true),
        (0x16008000, 0x4000, false),
        (0x16010000, 0x1000, false),
    ] {
        let mut b = BLOB.to_vec();
        set(&mut b, "spare-serial@10010000", "reg", 1, start);
        set(&mut b, "spare-serial@10010000", "reg", 3, size);
        assert_eq!(admit(&b).is_err(), rejected, "{start:x}/{size:x}");
    }
}
#[test]
fn duplicate_properties_nodes_and_unrecognized_children_rejected() {
    let mut b = BLOB.to_vec();
    let (at, len) = property(&b, TRNG, "clocks");
    let encoded = b[at - 12..at + len.next_multiple_of(4)].to_vec();
    insert(&mut b, at - 12, &encoded);
    assert!(admit(&b).is_err());
    let mut b = BLOB.to_vec();
    let start = b
        .windows(TRNG.len())
        .position(|w| w == TRNG.as_bytes())
        .unwrap()
        - 4;
    let encoded = b[start..end() + 4].to_vec();
    insert(&mut b, start, &encoded);
    assert!(admit(&b).is_err());
    let mut b = BLOB.to_vec();
    let mut empty = 1u32.to_be_bytes().to_vec();
    empty.extend(TRNG.as_bytes());
    empty.push(0);
    empty.resize(empty.len().next_multiple_of(4), 0);
    empty.extend(2u32.to_be_bytes());
    insert(&mut b, start, &empty);
    assert!(admit(&b).is_err());
    let mut b = BLOB.to_vec();
    insert(&mut b, end(), &[0, 0, 0, 1, b't', 0, 0, 0, 0, 0, 0, 2]);
    assert!(admit(&b).is_err());
}
#[test]
fn explicit_matching_interrupt_parent_allowed_but_rerouting_rejected() {
    let (at, len) = property(BLOB, "soc", "interrupt-parent");
    let encoded = BLOB[at - 12..at + len].to_vec();
    let mut b = BLOB.to_vec();
    insert(&mut b, end(), &encoded);
    assert!(admit(&b).is_ok());
    set(&mut b, TRNG, "interrupt-parent", 0, 100);
    assert!(admit(&b).is_err());
    let (at, len) = property(BLOB, "plic@c000000", "interrupts-extended");
    let encoded = BLOB[at - 12..at + len].to_vec();
    let mut b = BLOB.to_vec();
    insert(&mut b, end(), &encoded);
    assert!(admit(&b).is_err());
}
