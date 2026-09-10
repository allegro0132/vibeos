use vibeos_hal::fdt::{Event, Fdt};
const BLOB: &[u8] = include_bytes!("fixtures/cpus.dtb");
fn property(bytes: &[u8], hart: Option<usize>, name: &str) -> core::ops::Range<usize> {
    let mut current = None;
    for event in Fdt::new(bytes).unwrap().events() {
        match event.unwrap() {
            Event::Begin { depth: 2, name } => {
                current = name.strip_prefix("cpu@").and_then(|s| s.parse().ok())
            }
            Event::Property {
                depth,
                name: n,
                value,
            } if n == name
                && ((depth == 1 && hart.is_none()) || (depth == 2 && hart == current)) =>
            {
                let offset = value.as_ptr() as usize - bytes.as_ptr() as usize;
                return offset..offset + value.len();
            }
            _ => (),
        }
    }
    panic!("missing property");
}
#[test]
fn inventory_retains_disabled_monitor_and_ignores_interrupt_children() {
    let tree = Fdt::new(BLOB).unwrap();
    let topology = tree.cpus::<5>().unwrap();
    assert_eq!(topology.timebase_hz, 4_000_000);
    assert_eq!(topology.entries().len(), 5);
    assert!(!topology.entries()[0].enabled);
    assert!(topology.entries()[0].compatible_with("sifive,s7"));
    for cpu in &topology.entries()[1..] {
        assert!(cpu.enabled && cpu.compatible_with("sifive,u74-mc"));
        assert_eq!(cpu.mmu, "riscv,sv39");
        assert_eq!(cpu.isa, "rv64imafdc_zba_zbb");
    }
    assert!(tree.cpus::<4>().is_err());
    assert!(tree.cpus::<0>().is_err());
}
#[test]
fn duplicate_id_bad_cells_and_zero_timebase_are_rejected() {
    for (hart, name, replacement) in [
        (Some(4), "reg", 3u32),
        (None, "#address-cells", 3),
        (None, "#size-cells", 1),
        (None, "timebase-frequency", 0),
    ] {
        let mut bytes = BLOB.to_vec();
        let at = property(&bytes, hart, name);
        bytes[at].copy_from_slice(&replacement.to_be_bytes());
        assert!(Fdt::new(&bytes).unwrap().cpus::<8>().is_err(), "{name}");
    }
}
#[test]
fn duplicate_properties_and_unterminated_strings_are_rejected() {
    let mut bytes = BLOB.to_vec();
    let at = property(&bytes, Some(1), "status");
    bytes[at.end - 1] = b'x';
    assert!(Fdt::new(&bytes).unwrap().cpus::<8>().is_err());
    let mut bytes = BLOB.to_vec();
    let reg = property(&bytes, Some(1), "reg");
    let kind = property(&bytes, Some(1), "device_type");
    let reg_name = bytes[reg.start - 4..reg.start].to_vec();
    bytes[kind.start - 4..kind.start].copy_from_slice(&reg_name);
    assert!(Fdt::new(&bytes).unwrap().cpus::<8>().is_err());
}
#[test]
fn every_single_bit_mutation_and_truncation_is_bounded() {
    for n in 0..BLOB.len() {
        assert!(Fdt::new(&BLOB[..n]).is_err());
    }
    for n in 0..BLOB.len() {
        for bit in 0..8 {
            let mut bytes = BLOB.to_vec();
            bytes[n] ^= 1 << bit;
            if let Ok(tree) = Fdt::new(&bytes) {
                let _ = tree.cpus::<8>();
            }
        }
    }
}

#[test]
fn larger_sv_modes_also_admit_sv39() {
    for mmu in [
        b"riscv,sv39\0",
        b"riscv,sv48\0",
        b"riscv,sv57\0",
        b"riscv,sv32\0",
    ] {
        let mut bytes = BLOB.to_vec();
        let at = property(&bytes, Some(1), "mmu-type");
        bytes[at].copy_from_slice(mmu);
        let tree = Fdt::new(&bytes).unwrap();
        let cpus = tree.cpus::<8>().unwrap();
        assert_eq!(cpus.entries()[1].supports_sv39(), mmu != b"riscv,sv32\0");
    }
}

#[test]
fn two_cell_hart_ids_are_not_truncated_to_32_bits() {
    let tree = Fdt::new(include_bytes!("fixtures/cpus-two-cells.dtb")).unwrap();
    let cpus = tree.cpus::<8>().unwrap();
    assert_eq!(cpus.entries()[0].hart, 0x1_0000_0000);
    assert_eq!(cpus.entries()[4].hart, 0x1_0000_0004);
}
