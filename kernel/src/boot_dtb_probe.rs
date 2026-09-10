//! Opt-in live handoff probe. No DTB borrow survives heap initialization.
//! A successful probe proves parsing of firmware data, not Mars hardware support.
pub struct Report {
    pub boot: usize,
    pub count: usize,
    pub hz: u32,
}
/// # Safety
/// Called once before paging/heap initialization. The firmware must supply
/// readable, immutable physical RAM at `address`; bounds constrain that trust.
pub unsafe fn capture(address: usize, boot: usize) -> Result<Report, &'static str> {
    let ram = crate::platform::mmu().ram;
    if address % 8 != 0
        || address < ram.start
        || address
            .checked_add(40)
            .filter(|&end| end <= ram.end)
            .is_none()
    {
        return Err("DTB header outside firmware RAM envelope");
    }
    let header = unsafe { core::slice::from_raw_parts(address as *const u8, 40) };
    let length = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
    if !(40..=1024 * 1024).contains(&length)
        || address
            .checked_add(length)
            .filter(|&end| end <= ram.end)
            .is_none()
    {
        return Err("DTB body outside firmware RAM envelope");
    }
    let bytes = unsafe { core::slice::from_raw_parts(address as *const u8, length) };
    let tree = vibeos_hal::fdt::Fdt::new(bytes).map_err(|_| "invalid DTB")?;
    let cpus = tree.cpus::<16>().map_err(|_| "invalid CPU inventory")?;
    if cpus.timebase_hz as u64 != crate::platform::timebase_hz() {
        return Err("DTB timebase mismatch");
    }
    if !crate::platform::hart_ids().contains(&boot) {
        return Err("unexpected boot hart");
    }
    for &hart in crate::platform::hart_ids() {
        if !cpus
            .entries()
            .iter()
            .any(|cpu| cpu.hart == hart && cpu.enabled && cpu.supports_sv39())
        {
            return Err("scheduled hart absent or incompatible in DTB");
        }
    }
    Ok(Report {
        boot,
        count: crate::platform::hart_ids().len(),
        hz: cpus.timebase_hz,
    })
}
