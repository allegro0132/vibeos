//! Allocation-free CPU inventory. This parses declarations, not SBI availability;
//! firmware must still probe HSM and only start harts admitted by board policy.
use super::{wide, word, Error, Event, Fdt};

#[derive(Clone, Copy, Debug)]
pub struct Cpu<'a> {
    pub hart: usize,
    pub enabled: bool,
    pub compatible: &'a [u8],
    pub isa: &'a str,
    pub mmu: &'a str,
}
impl Cpu<'_> {
    /// The privileged ISA requires Sv48 to support Sv39 and Sv57 to support
    /// Sv48. DTB mmu-type names the highest mode, not its only supported mode.
    pub fn supports_sv39(&self) -> bool {
        matches!(self.mmu, "riscv,sv39" | "riscv,sv48" | "riscv,sv57")
    }
    pub fn compatible_with(&self, name: &str) -> bool {
        self.compatible
            .split(|&b| b == 0)
            .any(|s| s == name.as_bytes())
    }
}
const EMPTY: Cpu<'static> = Cpu {
    hart: 0,
    enabled: false,
    compatible: &[],
    isa: "",
    mmu: "",
};
#[derive(Debug)]
pub struct Cpus<'a, const N: usize> {
    entries: [Cpu<'a>; N],
    count: usize,
    pub timebase_hz: u32,
}
impl<'a, const N: usize> Cpus<'a, N> {
    pub fn entries(&self) -> &[Cpu<'a>] {
        &self.entries[..self.count]
    }
}
fn text(value: &[u8]) -> Result<&str, Error> {
    let value = value.strip_suffix(&[0]).ok_or(Error::InvalidString)?;
    if value.is_empty() || value.contains(&0) {
        return Err(Error::InvalidString);
    }
    core::str::from_utf8(value).map_err(|_| Error::InvalidString)
}
fn list(value: &[u8]) -> Result<&[u8], Error> {
    let inner = value.strip_suffix(&[0]).ok_or(Error::InvalidString)?;
    for entry in inner.split(|&b| b == 0) {
        if entry.is_empty() || core::str::from_utf8(entry).is_err() {
            return Err(Error::InvalidString);
        }
    }
    Ok(value)
}
fn set<'a>(slot: &mut Option<&'a [u8]>, value: &'a [u8]) -> Result<(), Error> {
    if slot.replace(value).is_some() {
        return Err(Error::InvalidStructure);
    }
    Ok(())
}
#[derive(Default)]
struct Node<'a> {
    candidate: bool,
    reg: Option<&'a [u8]>,
    kind: Option<&'a [u8]>,
    status: Option<&'a [u8]>,
    compatible: Option<&'a [u8]>,
    isa: Option<&'a [u8]>,
    mmu: Option<&'a [u8]>,
}
impl<'a> Fdt<'a> {
    /// Read the unique root `/cpus` node with explicit address/size cells.
    /// Duplicate IDs (including disabled CPUs) or ambiguous properties fail
    /// closed. Disabled entries remain visible for board-specific diagnostics.
    pub fn cpus<const N: usize>(&self) -> Result<Cpus<'a, N>, Error> {
        let mut result = Cpus {
            entries: [EMPTY; N],
            count: 0,
            timebase_hz: 0,
        };
        let (mut inside, mut seen) = (false, false);
        let (mut address, mut size, mut time, mut status) = (None, None, None, None);
        let mut node = Node::default();
        for event in self.events() {
            match event? {
                Event::Begin {
                    depth: 1,
                    name: "cpus",
                } => {
                    if seen {
                        return Err(Error::InvalidStructure);
                    }
                    seen = true;
                    inside = true;
                }
                Event::Begin { depth: 2, name } if inside => {
                    node = Node {
                        candidate: name == "cpu" || name.starts_with("cpu@"),
                        ..Node::default()
                    };
                }
                Event::Property {
                    depth: 1,
                    name,
                    value,
                } if inside => match name {
                    "#address-cells" => set(&mut address, value)?,
                    "#size-cells" => set(&mut size, value)?,
                    "timebase-frequency" => set(&mut time, value)?,
                    "status" => set(&mut status, value)?,
                    _ => (),
                },
                Event::Property {
                    depth: 2,
                    name,
                    value,
                } if inside => match name {
                    "reg" => set(&mut node.reg, value)?,
                    "device_type" => set(&mut node.kind, value)?,
                    "status" => set(&mut node.status, value)?,
                    "compatible" => set(&mut node.compatible, value)?,
                    "riscv,isa" => set(&mut node.isa, value)?,
                    "mmu-type" => set(&mut node.mmu, value)?,
                    _ => (),
                },
                Event::End { depth: 2 }
                    if inside && (node.candidate || node.kind == Some(b"cpu\0")) =>
                {
                    if node.kind != Some(b"cpu\0") {
                        return Err(Error::InvalidStructure);
                    }
                    let cells = address.ok_or(Error::UnsupportedCells)?;
                    if cells.len() != 4 {
                        return Err(Error::UnsupportedCells);
                    }
                    let cells = word(cells, 0)?;
                    if !(1..=2).contains(&cells) || size != Some(&[0, 0, 0, 0][..]) {
                        return Err(Error::UnsupportedCells);
                    }
                    let reg = node.reg.ok_or(Error::InvalidRange)?;
                    if reg.len() != cells as usize * 4 {
                        return Err(Error::InvalidRange);
                    }
                    let hart = if cells == 1 {
                        u64::from(word(reg, 0)?)
                    } else {
                        wide(reg, 0)?
                    };
                    let hart = usize::try_from(hart).map_err(|_| Error::InvalidRange)?;
                    if result.entries().iter().any(|cpu| cpu.hart == hart) {
                        return Err(Error::InvalidStructure);
                    }
                    let cpu = Cpu {
                        hart,
                        enabled: match node.status {
                            None => true,
                            Some(s) => matches!(text(s)?, "ok" | "okay"),
                        },
                        compatible: node.compatible.map(list).transpose()?.unwrap_or(&[]),
                        isa: node.isa.map(text).transpose()?.unwrap_or(""),
                        mmu: node.mmu.map(text).transpose()?.unwrap_or(""),
                    };
                    *result
                        .entries
                        .get_mut(result.count)
                        .ok_or(Error::InvalidStructure)? = cpu;
                    result.count += 1;
                }
                Event::End { depth: 1 } if inside => {
                    inside = false;
                }
                _ => (),
            }
        }
        if !seen || result.count == 0 {
            return Err(Error::InvalidStructure);
        }
        if let Some(s) = status {
            if !matches!(text(s)?, "ok" | "okay") {
                return Err(Error::InvalidStructure);
            }
        }
        let time = time.ok_or(Error::InvalidRange)?;
        if time.len() != 4 {
            return Err(Error::InvalidRange);
        }
        result.timebase_hz = word(time, 0)?;
        if result.timebase_hz == 0 {
            return Err(Error::InvalidRange);
        }
        Ok(result)
    }
}
