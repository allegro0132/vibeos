use vibeos_bsp_milkv_mars::harts::admit;
use vibeos_hal::fdt::{Event, Fdt};
const BLOB: &[u8] = include_bytes!("../../../hal/tests/fixtures/cpus.dtb");
fn replace(hart: usize, name: &str, change: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut bytes = BLOB.to_vec();
    let mut current = None;
    let mut range = None;
    for event in Fdt::new(&bytes).unwrap().events() {
        match event.unwrap() {
            Event::Begin { depth: 2, name } => {
                current = name.strip_prefix("cpu@").and_then(|s| s.parse().ok())
            }
            Event::Property {
                depth: 2,
                name: n,
                value,
            } if current == Some(hart) && n == name => {
                let at = value.as_ptr() as usize - bytes.as_ptr() as usize;
                range = Some(at..at + value.len());
            }
            _ => (),
        }
    }
    change(&mut bytes[range.unwrap()]);
    bytes
}
#[test]
fn every_application_hart_can_be_boot_with_stable_logical_order() {
    for boot in 1..=4 {
        let selected = admit(BLOB, boot, true).unwrap();
        let mut expected = vec![boot];
        expected.extend((1..=4).filter(|&id| id != boot));
        assert_eq!(selected.ids(), expected);
        assert!(selected.is_four_core());
        assert_eq!(selected.timebase_hz, 4_000_000);
    }
    for boot in [0, 5, usize::MAX] {
        assert!(admit(BLOB, boot, true).is_err());
    }
}
#[test]
fn bad_secondary_is_excluded_but_bad_boot_is_fatal() {
    for (name, index, value) in [
        ("status", 0, b'n'),
        ("mmu-type", 9, b'8'),
        ("compatible", 7, b'x'),
        ("riscv,isa", 6, b'b'),
    ] {
        let bytes = replace(2, name, |s| s[index] = value);
        assert_eq!(admit(&bytes, 3, true).unwrap().ids(), &[3, 1, 4], "{name}");
        assert!(!admit(&bytes, 3, true).unwrap().is_four_core());
        assert!(admit(&bytes, 2, true).is_err(), "{name}");
    }
}
#[test]
fn float_requirement_is_image_specific_and_monitor_is_always_excluded() {
    let bytes = replace(2, "riscv,isa", |s| {
        s[7] = b'b';
        s[8] = b'u';
    });
    assert!(admit(&bytes, 2, false).unwrap().is_four_core());
    assert!(admit(&bytes, 2, true).is_err());
    let bytes = include_bytes!("../../../hal/tests/fixtures/cpus-monitor-enabled.dtb");
    assert_eq!(admit(bytes, 4, true).unwrap().ids(), &[4, 1, 2, 3]);
    assert!(admit(bytes, 0, false).is_err());
}
#[test]
fn incompatible_board_and_wrong_timebase_are_fatal() {
    let mut bytes = BLOB.to_vec();
    let at = bytes.windows(11).position(|s| s == b"milk-v,mars").unwrap();
    bytes[at] = b'x';
    assert!(admit(&bytes, 1, true).is_err());
    let mut bytes = BLOB.to_vec();
    let at = bytes
        .windows(4)
        .position(|s| s == 4_000_000u32.to_be_bytes())
        .unwrap();
    bytes[at..at + 4].copy_from_slice(&1_000_000u32.to_be_bytes());
    assert!(admit(&bytes, 1, true).is_err());
}
