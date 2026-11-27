//! EN8811H upload over the board's MAC0 MDIO bus and MAC4 2500BASE-X PCS.
use crate::ticks;
use core::ptr;
const MGMT: usize = 0x08000200;
const PHY: u8 = 15;
type Result<T> = core::result::Result<T, &'static str>;
fn read(a: usize) -> u32 {
    unsafe { ptr::read_volatile(a as *const u32) }
}
fn write(a: usize, v: u32) {
    unsafe { ptr::write_volatile(a as *mut u32, v) }
}
fn idle() -> Result<u16> {
    for _ in 0..100_000 {
        let v = read(MGMT + 4);
        if v & (1 << 22) == 0 {
            return Ok(v as u16);
        }
    }
    Err("MDIO timeout")
}
fn mdio(phy: u8, reg: u16, value: Option<u16>) -> Result<u16> {
    idle()?;
    write(MGMT + 0x20, read(MGMT + 0x20) | (1 << phy));
    write(MGMT, (u32::from(phy) << 16) | u32::from(reg));
    let command = if value.is_some() { 1 } else { 3 };
    write(
        MGMT + 4,
        (1 << 22) | (command << 16) | u32::from(value.unwrap_or(0)),
    );
    idle()
}
fn reg(r: u16, v: u16) -> Result<()> {
    mdio(PHY, r, Some(v)).map(|_| ())
}
fn buck(addr: u32, value: Option<u32>) -> Result<u32> {
    reg(31, 4)?;
    reg(16, 0)?;
    let r = if value.is_some() { 17 } else { 21 };
    reg(r, (addr >> 16) as u16)?;
    reg(r + 1, addr as u16)?;
    let val = if let Some(v) = value {
        reg(19, (v >> 16) as u16)?;
        reg(20, v as u16)?;
        v
    } else {
        (u32::from(mdio(PHY, 23, None)?) << 16) | u32::from(mdio(PHY, 24, None)?)
    };
    reg(31, 0)?;
    Ok(val)
}
fn upload(addr: u32, data: &[u8], kick: fn()) -> Result<()> {
    reg(31, 4)?;
    reg(16, 0x8000)?;
    reg(17, (addr >> 16) as u16)?;
    reg(18, addr as u16)?;
    for word in data.chunks_exact(4) {
        reg(19, u16::from_le_bytes([word[2], word[3]]))?;
        reg(20, u16::from_le_bytes([word[0], word[1]]))?;
        kick();
    }
    reg(31, 0)
}
fn mmd(r: u16, v: Option<u16>) -> Result<u16> {
    reg(13, 30)?;
    reg(14, r)?;
    reg(13, 0x401e)?;
    mdio(PHY, 14, v)
}
fn pcs_addr(reg: usize) -> *mut u16 {
    (0x09000000 + ((31 << 16) | reg) * 4) as *mut u16
}
fn pcs(reg: usize) -> u16 {
    unsafe { ptr::read_volatile(pcs_addr(reg)) }
}
fn set_pcs(reg: usize, val: u16) {
    unsafe { ptr::write_volatile(pcs_addr(reg), val) }
}
fn power(value: u16, state: u16) -> Result<()> {
    set_pcs(0, value);
    let start = ticks();
    while (pcs(0x8010) >> 2) & 7 != state {
        if ticks() - start > 125_000_000 {
            use core::fmt::Write;
            let _ = writeln!(
                crate::Console,
                "XPCS desired {state} status {:x} BMCR {:x}\r",
                pcs(0x8010),
                pcs(0)
            );
            return Err("XPCS power transition");
        }
    }
    Ok(())
}
/// BMSR link status is latch-low. The second read reports current carrier.
pub fn carrier() -> Result<bool> {
    mdio(PHY, 1, None)?;
    Ok(mdio(PHY, 1, None)? & 4 != 0)
}

pub fn start_lan_phy() -> Result<()> {
    if mdio(6, 2, None)? != 0xadb4 || mdio(6, 3, None)? != 0x0412 {
        return Err("SF1211F ID");
    }
    mdio(6, 0x16, Some(0))?;
    let ext = |a: u16, v: u16| -> Result<()> {
        mdio(6, 0x0e, Some(a))?;
        mdio(6, 0x0d, Some(v))?;
        Ok(())
    };
    if mdio(6, 0x11, None)? & 4 == 0 {
        ext(0x1e0c, 0x17)?;
        ext(0x1e58, 0)?;
    }
    for (a, v) in [
        (0x281, 0x40),
        (0x149, 0x84),
        (0x14a, 0x86),
        (0x23c, 0x81),
        (0x184, 0x85),
        (0x185, 0x86),
        (0x186, 0x85),
        (0x187, 0x86),
        (0x272, 9),
    ] {
        ext(a, v)?
    }
    Ok(())
}
pub fn start(dm: &[u8], dsp: &[u8], kick: fn()) -> Result<()> {
    if mdio(PHY, 2, None)? != 0x03a2 || mdio(PHY, 3, None)? != 0xa411 {
        return Err("EN8811H ID");
    }
    // The board boots this PHY in download mode. Its SRAM is volatile.
    mdio(PHY + 8, 31, Some((0xcf928u32 >> 6) as u16))?;
    mdio(PHY + 8, 10, Some(0))?;
    mdio(PHY + 8, 16, Some(0))?;
    buck(0x1e00d0, Some(15))?;
    buck(0x1e0228, Some(0xf0))?;
    buck(0xf0018, Some(0))?;
    let control = buck(0x800000, None)?;
    buck(0x800000, Some(control | 1 << 11))?;
    upload(0, dm, kick)?;
    upload(0x100000, dsp, kick)?;
    buck(0x800000, Some(control & !(1 << 11)))?;
    buck(0xf0018, Some(1))?;
    let start = ticks();
    while mmd(0x8009, None)? != 2 {
        kick();
        if ticks() - start > 6_250_000_000 {
            return Err("EN8811H firmware ready timeout");
        }
    }
    for (r, v) in [(0x800c, 0), (0x800d, 0), (0x800e, 0x1101), (0x800f, 2)] {
        mmd(r, Some(v))?;
    }
    let _ = mdio(PHY, 0, Some(0x1200))?;
    let polarity = buck(0xca0f8, None)?;
    buck(0xca0f8, Some((polarity & !3) | 1))?;
    // The second XPCS reference is PCIe PLL output 2 (clock ID 6).
    write(0x0ce0044c, read(0x0ce0044c) | (1 << 31));
    write(0x0ce00500, 16);
    write(0x0ce00500, 0);
    let lock = ticks();
    while read(0x0ce004d4) & 1 == 0 {
        if ticks() - lock > 125_000_000 {
            return Err("reference PLL lock timeout");
        }
    }
    write(0x0ce00450, read(0x0ce00450) | (1 << 30));
    write(0x0ce00500, 16);
    write(0x0ce00500, 0);
    write(0x0ce01888, read(0x0ce01888) | (1 << 6));
    write(0x0ce01870, 0x601);
    set_pcs(0, 0x8000);
    let reset = ticks();
    while pcs(0) & 0x8000 != 0 {
        if ticks() - reset > 125_000_000 {
            return Err("XPCS reset timeout");
        }
    }
    set_pcs(0x8006, pcs(0x8006) | 3);
    power(0, 4)?;
    set_pcs(0, pcs(0) & !0x1000);
    set_pcs(0x8001, 0);
    set_pcs(0x8079, 0x32);
    set_pcs(0x8078, pcs(0x8078) | 2);
    set_pcs(0x8058, pcs(0x8058) | 16);
    set_pcs(0x809a, 5);
    set_pcs(0x800a, 0x2faf);
    set_pcs(0x8000, pcs(0x8000) | 12);
    power(0x800, 6)?;
    power(0, 4)?;
    set_pcs(4, 0x20);
    set_pcs(0, 0x140);
    let mac = 0x08010000;
    write(mac + 8, 1);
    write(mac, 0x40000101);
    write(mac + 4, 0x207);
    write(0x0ce018d4, read(0x0ce018d4) & !(1 << 4));
    Ok(())
}
