//! Pure Sv39 page-table encodings shared by the kernel and host tests.
//!
//! The kernel owns the page-table storage and TLB shootdown policy.  This
//! module only defines the architectural bit layout and address validation, so
//! malformed writable-without-readable leaves or truncated physical addresses
//! are rejected before they reach a hardware walker.

pub const PAGE_SHIFT: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
pub const ENTRIES_PER_TABLE: usize = 512;
pub const SV39_LEVELS: usize = 3;
pub const SATP_MODE_SV39: usize = 8;

const PTE_VALID: u64 = 1 << 0;
const PTE_READ: u64 = 1 << 1;
const PTE_WRITE: u64 = 1 << 2;
const PTE_EXECUTE: u64 = 1 << 3;
const PTE_USER: u64 = 1 << 4;
const PTE_GLOBAL: u64 = 1 << 5;
const PTE_ACCESSED: u64 = 1 << 6;
const PTE_DIRTY: u64 = 1 << 7;
const PTE_PERMISSION_MASK: u64 = PTE_READ | PTE_WRITE | PTE_EXECUTE | PTE_USER | PTE_GLOBAL;
const PTE_PPN_MASK: u64 = ((1u64 << 44) - 1) << 10;
const MAX_PHYSICAL_ADDRESS: usize = 1usize << 56;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PteError {
    Unaligned,
    PhysicalAddressTooLarge,
    WriteWithoutRead,
    EmptyLeaf,
}

/// Permission bits accepted for an Sv39 leaf PTE.
///
/// Accessed and dirty are set eagerly by [`PageTableEntry::leaf`].  VibeOS
/// does not currently use page-fault-driven A/D emulation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagePermissions(u64);

impl PagePermissions {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(PTE_READ);
    pub const WRITE: Self = Self(PTE_WRITE);
    pub const EXECUTE: Self = Self(PTE_EXECUTE);
    pub const USER: Self = Self(PTE_USER);
    pub const GLOBAL: Self = Self(PTE_GLOBAL);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn bits(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    pub const EMPTY: Self = Self(0);

    pub fn table(next_level_physical: usize) -> Result<Self, PteError> {
        validate_physical_page(next_level_physical)?;
        Ok(Self(ppn_bits(next_level_physical) | PTE_VALID))
    }

    pub fn leaf(physical: usize, permissions: PagePermissions) -> Result<Self, PteError> {
        validate_physical_page(physical)?;
        if permissions.contains(PagePermissions::WRITE)
            && !permissions.contains(PagePermissions::READ)
        {
            return Err(PteError::WriteWithoutRead);
        }
        if !permissions.contains(PagePermissions::READ)
            && !permissions.contains(PagePermissions::EXECUTE)
        {
            return Err(PteError::EmptyLeaf);
        }
        Ok(Self(
            ppn_bits(physical) | PTE_VALID | permissions.bits() | PTE_ACCESSED | PTE_DIRTY,
        ))
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn is_valid(self) -> bool {
        self.0 & PTE_VALID != 0
    }

    pub const fn is_leaf(self) -> bool {
        self.0 & (PTE_READ | PTE_WRITE | PTE_EXECUTE) != 0
    }

    pub const fn physical_address(self) -> usize {
        (((self.0 & PTE_PPN_MASK) >> 10) as usize) << PAGE_SHIFT
    }

    pub const fn permissions(self) -> PagePermissions {
        PagePermissions(self.0 & PTE_PERMISSION_MASK)
    }
}

/// Return one of the three VPN indices, where level 0 is the 4 KiB leaf level.
pub const fn vpn_index(virtual_address: usize, level: usize) -> usize {
    debug_assert!(level < SV39_LEVELS);
    (virtual_address >> (PAGE_SHIFT + level * 9)) & (ENTRIES_PER_TABLE - 1)
}

/// Sv39 virtual addresses have bits 63:39 equal to bit 38.
pub const fn is_canonical_virtual_address(virtual_address: usize) -> bool {
    let upper = virtual_address >> 39;
    if virtual_address & (1usize << 38) == 0 {
        upper == 0
    } else {
        upper == usize::MAX >> 39
    }
}

/// Construct an ASID-zero `satp` value for one page-aligned Sv39 root.
pub fn satp(root_physical: usize) -> Result<usize, PteError> {
    validate_physical_page(root_physical)?;
    Ok(SATP_MODE_SV39 << 60 | root_physical >> PAGE_SHIFT)
}

fn validate_physical_page(physical: usize) -> Result<(), PteError> {
    if physical & (PAGE_SIZE - 1) != 0 {
        return Err(PteError::Unaligned);
    }
    if physical >= MAX_PHYSICAL_ADDRESS {
        return Err(PteError::PhysicalAddressTooLarge);
    }
    Ok(())
}

const fn ppn_bits(physical: usize) -> u64 {
    ((physical >> PAGE_SHIFT) as u64) << 10
}
