//! Board map arithmetic, not physical bus probing or a device-access grant.
use std::collections::BTreeSet;
use vibeos_bsp_milkv_mars as mars;
use vibeos_hal::{Board, MappingGranularity, MemoryKind};

fn device_pages() -> BTreeSet<usize> {
    let mut pages = BTreeSet::new();
    for m in mars::MMIO_MAPPINGS {
        assert_eq!(m.granularity, MappingGranularity::Page4K);
        assert_eq!(m.range.start % 4096, 0);
        assert_eq!(m.range.end % 4096, 0);
        assert!(!m.range.is_empty());
        for page in (m.range.start..m.range.end).step_by(4096) {
            assert!(pages.insert(page), "overlapping mapping at {page:x}");
        }
    }
    // Sparse PLIC control, enables and supervisor contexts for every U74.
    pages.insert(mars::PLIC.registers.start);
    pages.insert(mars::PLIC.registers.start + 0x2000);
    for hart in mars::HART_IDS {
        pages.insert(
            mars::PLIC.registers.start + 0x200000 + mars::plic_s_context(*hart).unwrap() * 4096,
        );
    }
    pages
}

#[test]
fn exact_page_table_capacity_covers_security_and_all_plic_contexts() {
    let pages = device_pages();
    let roots: BTreeSet<_> = pages.iter().map(|p| p >> 30).collect();
    let windows: BTreeSet<_> = pages.iter().map(|p| p >> 21).collect();
    assert_eq!(roots.len(), mars::Board::MMU.device_level1_tables);
    assert_eq!(windows.len(), mars::Board::MMU.device_level0_tables);
    assert_eq!(windows.len(), 8);
    assert!(windows.len() <= vibeos_hal::boot::MAX_DEVICE_LEVEL0_TABLES);
}

#[test]
fn security_apertures_are_exact_and_do_not_map_crypto_or_security_dma() {
    let pages = device_pages();
    for range in [mars::STG_CRG, mars::TRNG_REGISTERS] {
        assert_eq!(
            mars::MMIO_MAPPINGS
                .iter()
                .filter(|m| m.range == range)
                .count(),
            1
        );
        assert!(mars::MEMORY_MAP
            .iter()
            .any(|m| m.kind == MemoryKind::Mmio && m.range == range));
        for page in (range.start..range.end).step_by(4096) {
            assert!(pages.contains(&page));
        }
        assert!(!pages.contains(&(range.start - 4096)));
        assert!(!pages.contains(&range.end));
    }
    for page in (0x16000000..0x1600c000).step_by(4096) {
        assert!(!pages.contains(&page));
    }
    assert!(!pages.contains(&0x16010000));
    assert!(pages.contains(&mars::SD_REGISTERS.start));
    assert!(pages.contains(&mars::GMAC0_REGISTERS.start));
}
