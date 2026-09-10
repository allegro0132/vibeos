//! Pure DTB tests do not establish real MMIO decoding or firmware clock state.
use vibeos_bsp_milkv_mars::{self as mars, resources::admit};
use vibeos_hal::fdt::{Event, Fdt};
const BLOB: &[u8] = include_bytes!("fixtures/resources.dtb");
fn property(blob: &[u8], node: &str, name: &str) -> (usize, usize) {
    let tree = Fdt::new(blob).unwrap();
    let mut active = None;
    for event in tree.events() {
        match event.unwrap() {
            Event::Begin { depth, name } if name == node => active = Some(depth),
            Event::End { depth } if active == Some(depth) => active = None,
            Event::Property {
                depth,
                name: actual,
                value,
            } if active == Some(depth) && name == actual => {
                return (
                    value.as_ptr() as usize - blob.as_ptr() as usize,
                    value.len(),
                )
            }
            _ => (),
        }
    }
    panic!("missing {node}/{name}");
}
fn patch(node: &str, name: &str, word: usize, value: u32) -> Vec<u8> {
    let mut blob = BLOB.to_vec();
    let (offset, bytes) = property(&blob, node, name);
    assert!(word * 4 + 4 <= bytes);
    blob[offset + word * 4..offset + word * 4 + 4].copy_from_slice(&value.to_be_bytes());
    blob
}
#[test]
fn admits_pinned_resources_and_all_nonzero_application_boot_harts() {
    let resources = admit(BLOB).unwrap();
    assert_eq!(resources.uart, mars::UART_REGISTERS);
    assert_eq!(resources.plic, mars::PLIC.registers);
    assert_eq!(resources.sd, mars::SD_REGISTERS);
    assert_eq!(resources.crg, mars::SYS_CRG);
    assert_eq!(resources.syscon.len(), 0x1000);
    assert_eq!(resources.pins, mars::SYS_PINCTRL);
    for hart in 1..=4 {
        assert_eq!(
            mars::harts::admit(BLOB, hart, false).unwrap().ids()[0],
            hart
        );
    }
}
#[test]
fn rejects_resource_geometry_irq_and_controller_configuration_changes() {
    for (node, name, at, value) in [
        ("serial@10000000", "reg", 1, 0x10010000),
        ("serial@10000000", "reg", 3, 0x1000),
        ("serial@10000000", "interrupts", 0, 33),
        ("serial@10000000", "reg-io-width", 0, 1),
        ("serial@10000000", "reg-shift", 0, 0),
        ("sdio1@16020000", "fifo-depth", 0, 16),
        ("sdio1@16020000", "bus-width", 0, 8),
        ("sdio1@16020000", "interrupts", 0, 74),
        ("sys_syscon@13030000", "reg", 3, 0x10000),
        ("clock-controller", "reg", 1, 0x13010000),
        ("gpio@13040000", "reg", 1, 0x13050000),
        ("plic@c000000", "riscv,ndev", 0, 137),
        ("plic@c000000", "#interrupt-cells", 0, 2),
        ("soc", "#address-cells", 0, 1),
        ("soc", "interrupt-parent", 0, 0xdead),
    ] {
        assert!(
            admit(&patch(node, name, at, value)).is_err(),
            "{node}/{name}"
        );
    }
    let mut disabled = BLOB.to_vec();
    let (at, _) = property(&disabled, "sdio1@16020000", "status");
    disabled[at..at + 4].copy_from_slice(b"fail");
    assert!(admit(&disabled).is_err());
}
#[test]
fn accepts_opensbi_masked_machine_contexts_but_rejects_supervisor_changes() {
    let mut blob = BLOB.to_vec();
    let (at, _) = property(&blob, "plic@c000000", "interrupts-extended");
    for index in [0, 1, 3, 5, 7] {
        blob[at + index * 8 + 4..at + index * 8 + 8].copy_from_slice(&u32::MAX.to_be_bytes());
    }
    assert!(admit(&blob).is_ok());
    for index in [2, 4, 6, 8] {
        assert!(admit(&patch(
            "plic@c000000",
            "interrupts-extended",
            index * 2 + 1,
            11
        ))
        .is_err());
    }
    // Routing the final S context to hart 1 would silently break hart 4 IRQs.
    let (at, _) = property(BLOB, "plic@c000000", "interrupts-extended");
    let hart1 = u32::from_be_bytes(BLOB[at + 8..at + 12].try_into().unwrap());
    assert!(admit(&patch("plic@c000000", "interrupts-extended", 16, hart1)).is_err());
}

#[test]
fn rejects_ambiguous_phandles_aliases_and_duplicate_resource_instances() {
    let (at, _) = property(BLOB, "plic@c000000", "phandle");
    let plic = u32::from_be_bytes(BLOB[at..at + 4].try_into().unwrap());
    let mut blob = patch("spare", "phandle", 0, plic);
    let (at, _) = property(&blob, "spare", "linux,phandle");
    blob[at..at + 4].copy_from_slice(&plic.to_be_bytes());
    assert!(
        admit(&blob).is_err(),
        "duplicate handle outside /soc must be rejected"
    );
    assert!(admit(&patch("spare", "linux,phandle", 0, 101)).is_err());
    let mut duplicate = patch("spare-serial@10010000", "reg", 1, 0x10000000);
    let (at, _) = property(&duplicate, "spare-serial@10010000", "interrupts");
    duplicate[at..at + 4].copy_from_slice(&32u32.to_be_bytes());
    assert!(admit(&duplicate).is_err());
}

#[test]
fn composition_uses_standard_attributes_and_complete_ram_table_storage() {
    use vibeos_hal::{boot::ram_page_table_pages, Board, MemoryAttributes};
    let mmu = mars::Board::MMU;
    assert_eq!(mmu.ram.end, 0x140000000);
    assert_eq!(ram_page_table_pages(mmu.ram), 2051);
    assert_eq!(mmu.ram_attributes, MemoryAttributes::Standard);
    assert_eq!(mmu.mmio_attributes, MemoryAttributes::Standard);
    assert!(mars::Board::INFO.sdhci.is_none());
    assert!(mars::Board::INFO.dwmac.is_none());
    let mut windows = vec![
        mars::PLIC.registers.start / (2 << 20),
        (mars::PLIC.registers.start + 0x200000) / (2 << 20),
    ];
    for mapping in mmu.identity_mappings {
        assert_eq!(mapping.range.start % 4096, 0);
        assert_eq!(mapping.range.end % 4096, 0);
        for window in mapping.range.start / (2 << 20)..=(mapping.range.end - 1) / (2 << 20) {
            if !windows.contains(&window) {
                windows.push(window);
            }
        }
    }
    assert_eq!(windows.len(), mmu.device_level0_tables);
    assert!(windows.iter().all(|&w| w * (2 << 20) < 1 << 30));
}

#[test]
fn rejects_non_identity_soc_ranges_without_guessing_translation() {
    let mut blob = BLOB.to_vec();
    let (at, len) = property(&blob, "soc", "ranges");
    assert_eq!(len, 0);
    // Replace the empty property with one complete two-cell translation tuple.
    let data = [0, 0x10000000u32, 0, 0x20000000, 0, 0x10000]
        .into_iter().flat_map(u32::to_be_bytes).collect::<Vec<_>>();
    blob.splice(at..at, data.iter().copied());
    blob[at - 8..at - 4].copy_from_slice(&(data.len() as u32).to_be_bytes());
    for index in [4, 8, 12, 16, 36] {
        let value = u32::from_be_bytes(blob[index..index + 4].try_into().unwrap());
        if index == 4 || index == 36 || value as usize >= at {
            blob[index..index + 4].copy_from_slice(&(value + data.len() as u32).to_be_bytes());
        }
    }
    assert!(Fdt::new(&blob).is_ok(), "mutation must remain a structurally valid DTB");
    assert!(admit(&blob).is_err());
}
