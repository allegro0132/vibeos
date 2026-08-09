use vibeos_core::mmu::{
    is_canonical_virtual_address, satp, vpn_index, PagePermissions, PageTableEntry, PteError,
    ENTRIES_PER_TABLE, PAGE_SIZE, SATP_MODE_SV39,
};

#[test]
fn sv39_indices_select_all_three_levels() {
    let address = 0x0000_003f_ffff_f000usize;
    assert_eq!(vpn_index(address, 0), ENTRIES_PER_TABLE - 1);
    assert_eq!(vpn_index(address, 1), ENTRIES_PER_TABLE - 1);
    assert_eq!(vpn_index(address, 2), 0xff);
}

#[test]
fn table_entry_round_trips_a_page_address() {
    let physical = 0x0000_0000_8020_0000usize;
    let entry = PageTableEntry::table(physical).unwrap();
    assert_eq!(entry.bits(), 0x2008_0001, "known Sv39 table PTE");
    assert!(entry.is_valid());
    assert!(!entry.is_leaf());
    assert_eq!(entry.physical_address(), physical);
    assert_eq!(entry.permissions(), PagePermissions::NONE);
}

#[test]
fn leaf_entry_encodes_permissions_and_eager_ad_bits() {
    let permissions = PagePermissions::READ
        .union(PagePermissions::WRITE)
        .union(PagePermissions::EXECUTE);
    let entry = PageTableEntry::leaf(0x87ff_f000, permissions).unwrap();
    assert!(entry.is_valid());
    assert!(entry.is_leaf());
    assert_eq!(entry.physical_address(), 0x87ff_f000);
    assert_eq!(entry.permissions(), permissions);
    assert_ne!(entry.bits() & (1 << 6), 0, "accessed bit");
    assert_ne!(entry.bits() & (1 << 7), 0, "dirty bit");
    assert_eq!(
        PageTableEntry::leaf(0x8020_0000, permissions)
            .unwrap()
            .bits(),
        0x2008_00cf,
        "known Sv39 RWX leaf PTE"
    );
}

#[test]
fn invalid_leaf_encodings_fail_closed() {
    assert_eq!(
        PageTableEntry::leaf(0x8020_0000, PagePermissions::WRITE),
        Err(PteError::WriteWithoutRead)
    );
    assert_eq!(
        PageTableEntry::leaf(0x8020_0000, PagePermissions::NONE),
        Err(PteError::EmptyLeaf)
    );
    assert_eq!(
        PageTableEntry::leaf(0x8020_0001, PagePermissions::READ),
        Err(PteError::Unaligned)
    );
    assert_eq!(
        PageTableEntry::leaf(1usize << 56, PagePermissions::READ),
        Err(PteError::PhysicalAddressTooLarge)
    );
    assert_eq!(
        PageTableEntry::leaf(0x8040_0000, PagePermissions::EXECUTE)
            .unwrap()
            .permissions(),
        PagePermissions::EXECUTE,
        "execute-only is a valid Sv39 leaf"
    );
}

#[test]
fn satp_uses_sv39_mode_and_root_ppn() {
    let root = 0x8040_0000usize;
    let value = satp(root).unwrap();
    assert_eq!(value, 0x8000_0000_0008_0400, "known Sv39 satp word");
    assert_eq!(value >> 60, SATP_MODE_SV39);
    assert_eq!(value & ((1usize << 44) - 1), root / PAGE_SIZE);
    assert_eq!(satp(root + 1), Err(PteError::Unaligned));
}

#[test]
fn canonical_virtual_addresses_match_sv39_sign_extension() {
    assert!(is_canonical_virtual_address(0));
    assert!(is_canonical_virtual_address((1usize << 38) - 1));
    assert!(is_canonical_virtual_address(usize::MAX << 38));
    assert!(!is_canonical_virtual_address(1usize << 39));
    assert!(!is_canonical_virtual_address(1usize << 38));
}
