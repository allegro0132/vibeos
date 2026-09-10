//! Mars application-hart admission, independent of physical startup and SBI.
use vibeos_hal::fdt::{Error, Fdt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootHarts {
    ids: [usize; 4],
    count: usize,
    pub timebase_hz: u32,
}
impl BootHarts {
    /// Boot hart is always logical slot zero; remaining IDs are ascending.
    pub fn ids(&self) -> &[usize] {
        &self.ids[..self.count]
    }
    pub fn is_four_core(&self) -> bool {
        self.count == 4
    }
}

/// Select enabled U74 application harts with the image's base ISA and Sv39.
/// Unknown/non-application cores are not scheduling candidates. A rejected
/// boot hart is fatal; rejected secondary harts produce a reduced inventory,
/// which must not be reported as successful four-core acceptance.
///
/// This is DTB evidence only: the final firmware must additionally probe SBI
/// HSM/IPI/RFENCE/TIME and obtain real startup completion from each selected hart.
pub fn admit(dtb: &[u8], boot_hart: usize, require_float: bool) -> Result<BootHarts, Error> {
    let tree = Fdt::new(dtb)?;
    super::validate_board(&tree)?;
    let topology = tree.cpus::<8>()?;
    if u64::from(topology.timebase_hz) != super::TIMEBASE_HZ {
        return Err(Error::InvalidRange);
    }
    let mut selected = [false; 5];
    for cpu in topology.entries() {
        if super::HART_IDS.contains(&cpu.hart)
            && cpu.enabled
            && cpu.compatible_with("sifive,u74-mc")
            && cpu.mmu == "riscv,sv39"
            && supports_image(cpu.isa, require_float)
        {
            selected[cpu.hart] = true;
        }
    }
    if !selected.get(boot_hart).copied().unwrap_or(false) {
        return Err(Error::InvalidRange);
    }
    let mut result = BootHarts {
        ids: [boot_hart; 4],
        count: 1,
        timebase_hz: topology.timebase_hz,
    };
    for &hart in super::HART_IDS {
        if hart != boot_hart && selected[hart] {
            result.ids[result.count] = hart;
            result.count += 1;
        }
    }
    Ok(result)
}

/// Pinned SDK uses the legacy riscv,isa string. Parse only its single-letter
/// extension section; letters inside z*/s*/x* names cannot grant base features.
/// Versions are accepted, but malformed or repeated single extensions fail.
/// Legacy SDK 'sux' suffixes are tolerated without granting any capability.
fn supports_image(isa: &str, require_float: bool) -> bool {
    let Some(body) = isa.strip_prefix("rv64") else {
        return false;
    };
    let mut sections = body.split('_');
    let base = sections.next().unwrap_or("").as_bytes();
    if !matches!(base.first(), Some(b'i' | b'g')) {
        return false;
    }
    let mut flags = 0u32;
    let mut at = 0;
    while at < base.len() {
        let letter = base[at];
        if !letter.is_ascii_lowercase() {
            return false;
        }
        let bit = 1u32 << (letter - b'a');
        if flags & bit != 0 {
            return false;
        }
        flags |= bit;
        at += 1;
        let start = at;
        while at < base.len() && base[at].is_ascii_digit() {
            at += 1;
        }
        if at < base.len() && base[at] == b'p' && at > start {
            at += 1;
            let minor = at;
            while at < base.len() && base[at].is_ascii_digit() {
                at += 1;
            }
            if at == minor {
                return false;
            }
        }
    }
    for ext in sections {
        if ext.len() < 2
            || !matches!(ext.as_bytes()[0], b'z' | b's' | b'x')
            || !ext
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return false;
        }
    }
    let bit = |letter: u8| 1u32 << (letter - b'a');
    if flags & bit(b'e') != 0 {
        return false;
    }
    if flags & bit(b'g') != 0 {
        if flags & (bit(b'i') | bit(b'm') | bit(b'a') | bit(b'f') | bit(b'd')) != 0 {
            return false;
        }
        flags |= bit(b'i') | bit(b'm') | bit(b'a') | bit(b'f') | bit(b'd');
    }
    if flags & bit(b'd') != 0 && flags & bit(b'f') == 0 {
        return false;
    }
    let mut required = bit(b'i') | bit(b'm') | bit(b'a') | bit(b'c');
    if require_float {
        required |= bit(b'f') | bit(b'd');
    }
    flags & required == required
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn isa_extensions_do_not_borrow_letters_from_named_extensions() {
        for isa in [
            "rv64imafdc_zba_zbb",
            "rv64imafdcbsux_zba_zbb",
            "rv64gc",
            "rv64i2p1m2p0a2p1f2p2d2p2c2p0",
        ] {
            assert!(supports_image(isa, true), "{isa}");
        }
        assert!(supports_image("rv64imac_zba_zbb", false));
        for isa in [
            "rv64imac_zfake_zdouble",
            "rv32imafdc",
            "rv64imafdc_",
            "rv64imafdcc",
            "rv64i2pmac",
            "rv64emafdc",
            "rv64iemafdc",
            "rv64gimafdc",
            "rv64imafd",
        ] {
            assert!(!supports_image(isa, true), "{isa}");
        }
        assert!(!supports_image("rv64i_zmac", false));
        assert!(!supports_image("rv64imadc", false));
    }
}
