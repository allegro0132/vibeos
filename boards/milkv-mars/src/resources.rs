//! Pinned SDK resource admission for the first Mars console/SD composition.
//! Only root /soc with identity ranges is supported; no implicit bus address
//! translation, IRQ-controller substitution or unbounded phandle allocation.
use vibeos_hal::{
    fdt::{Error, Event, Fdt},
    AddressRange,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resources {
    pub uart: AddressRange,
    pub plic: AddressRange,
    pub sd: AddressRange,
    pub crg: AddressRange,
    pub syscon: AddressRange,
    pub pins: AddressRange,
}
fn word(bytes: &[u8]) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        bytes.try_into().map_err(|_| Error::InvalidStructure)?,
    ))
}
fn scalar(value: Option<&[u8]>) -> Result<u32, Error> {
    word(value.ok_or(Error::InvalidStructure)?)
}
fn list(bytes: &[u8], wanted: &[u8]) -> Result<bool, Error> {
    let body = bytes.strip_suffix(&[0]).ok_or(Error::InvalidString)?;
    if body
        .split(|&b| b == 0)
        .any(|s| s.is_empty() || core::str::from_utf8(s).is_err())
    {
        return Err(Error::InvalidString);
    }
    Ok(body.split(|&b| b == 0).any(|s| s == wanted))
}
fn enabled(status: Option<&[u8]>) -> bool {
    matches!(status, None | Some(b"okay\0") | Some(b"ok\0"))
}
fn set<'a>(slot: &mut Option<&'a [u8]>, value: &'a [u8]) -> Result<(), Error> {
    if slot.replace(value).is_some() {
        return Err(Error::InvalidStructure);
    }
    Ok(())
}
#[derive(Default)]
struct Node<'a> {
    compatible: Option<&'a [u8]>,
    reg: Option<&'a [u8]>,
    status: Option<&'a [u8]>,
    parent: Option<&'a [u8]>,
    interrupts: Option<&'a [u8]>,
    extended: Option<&'a [u8]>,
    phandle: Option<&'a [u8]>,
    linux_phandle: Option<&'a [u8]>,
    controller: Option<&'a [u8]>,
    cells: Option<&'a [u8]>,
    sources: Option<&'a [u8]>,
    shift: Option<&'a [u8]>,
    width: Option<&'a [u8]>,
    fifo: Option<&'a [u8]>,
    bus_width: Option<&'a [u8]>,
}
impl<'a> Node<'a> {
    fn property(&mut self, name: &str, value: &'a [u8]) -> Result<(), Error> {
        let slot = match name {
            "compatible" => &mut self.compatible,
            "reg" => &mut self.reg,
            "status" => &mut self.status,
            "interrupt-parent" => &mut self.parent,
            "interrupts" => &mut self.interrupts,
            "interrupts-extended" => &mut self.extended,
            "phandle" => &mut self.phandle,
            "linux,phandle" => &mut self.linux_phandle,
            "interrupt-controller" => &mut self.controller,
            "#interrupt-cells" => &mut self.cells,
            "riscv,ndev" => &mut self.sources,
            "reg-shift" => &mut self.shift,
            "reg-io-width" => &mut self.width,
            "fifo-depth" => &mut self.fifo,
            "bus-width" => &mut self.bus_width,
            _ => return Ok(()),
        };
        set(slot, value)
    }
    fn phandle(&self) -> Result<u32, Error> {
        let value = scalar(self.phandle.or(self.linux_phandle))?;
        if value == 0
            || value == u32::MAX
            || self.linux_phandle.is_some_and(|p| word(p) != Ok(value))
        {
            return Err(Error::InvalidStructure);
        }
        Ok(value)
    }
}
fn first_range(reg: &[u8]) -> Result<AddressRange, Error> {
    if reg.is_empty() || reg.len() % 16 != 0 {
        return Err(Error::InvalidRange);
    }
    let start = u64::from_be_bytes(reg[..8].try_into().unwrap());
    let size = u64::from_be_bytes(reg[8..16].try_into().unwrap());
    let end = start.checked_add(size).ok_or(Error::InvalidRange)?;
    let range = AddressRange::new(
        usize::try_from(start).map_err(|_| Error::InvalidRange)?,
        usize::try_from(end).map_err(|_| Error::InvalidRange)?,
    );
    if range.is_empty() {
        return Err(Error::InvalidRange);
    }
    Ok(range)
}

/// Require all six pinned console/SD resources and the physical PLIC context
/// sequence. Returned apertures come from the DTB, including the 4 KiB SYSCON.
/// This does not validate GMAC/PHY/DMA resources or qualify running clocks.
pub fn admit(dtb: &[u8]) -> Result<Resources, Error> {
    let tree = Fdt::new(dtb)?;
    super::validate_board(&tree)?;
    // Also rejects duplicate physical CPU IDs and malformed /cpus declarations.
    tree.cpus::<8>()?;
    let (mut soc, mut seen_soc) = (false, false);
    let (mut address, mut size, mut ranges, mut parent, mut status, mut compatible) =
        (None, None, None, None, None, None);
    for event in tree.events() {
        match event? {
            Event::Begin {
                depth: 1,
                name: "soc",
            } => {
                if seen_soc {
                    return Err(Error::InvalidStructure);
                }
                soc = true;
                seen_soc = true;
            }
            Event::End { depth: 1 } => soc = false,
            Event::Property {
                depth: 1,
                name,
                value,
            } if soc => match name {
                "#address-cells" => set(&mut address, value)?,
                "#size-cells" => set(&mut size, value)?,
                "ranges" => set(&mut ranges, value)?,
                "interrupt-parent" => set(&mut parent, value)?,
                "status" => set(&mut status, value)?,
                "compatible" => set(&mut compatible, value)?,
                _ => (),
            },
            _ => (),
        }
    }
    if !seen_soc
        || scalar(address)? != 2
        || scalar(size)? != 2
        || ranges != Some(&[][..])
        || !enabled(status)
        || !list(compatible.ok_or(Error::InvalidStructure)?, b"simple-bus")?
    {
        return Err(Error::InvalidStructure);
    }
    let parent = scalar(parent)?;
    let cpu_interrupts = cpu_interrupts(&tree)?;
    unique_handles(
        &tree,
        [
            cpu_interrupts[0],
            cpu_interrupts[1],
            cpu_interrupts[2],
            cpu_interrupts[3],
            cpu_interrupts[4],
            parent,
        ],
    )?;
    let mut found = [None; 6];
    let mut node = Node::default();
    for event in tree.events() {
        match event? {
            Event::Begin { depth: 1, name } => soc = name == "soc",
            Event::End { depth: 1 } => soc = false,
            Event::Begin { depth: 2, .. } if soc => node = Node::default(),
            Event::Property {
                depth: 2,
                name,
                value,
            } if soc => node.property(name, value)?,
            Event::End { depth: 2 } if soc => {
                let (Some(reg), Some(compatible)) = (node.reg, node.compatible) else {
                    continue;
                };
                // Other devices may use different register tuple conventions.
                // Only a matching compatible makes this node a candidate.
                let candidates = [
                    b"snps,dw-apb-uart".as_slice(),
                    b"riscv,plic0",
                    b"starfive,jh7110-sdio",
                    b"starfive,jh7110-clkgen",
                    b"syscon",
                    b"starfive,jh7110-sys-pinctrl",
                ];
                for (index, name) in candidates.iter().enumerate() {
                    if !list(compatible, name)? {
                        continue;
                    }
                    let range = first_range(reg)?;
                    let expected = [
                        super::UART_REGISTERS,
                        super::PLIC.registers,
                        super::SD_REGISTERS,
                        super::SYS_CRG,
                        AddressRange::new(
                            super::SYS_SYSCON.start,
                            super::SYS_SYSCON.start + 0x1000,
                        ),
                        super::SYS_PINCTRL,
                    ][index];
                    if range.start != expected.start {
                        continue;
                    }
                    if range != expected
                        || !enabled(node.status)
                        || found[index].replace(range).is_some()
                    {
                        return Err(Error::InvalidRange);
                    }
                    if index == 0 || index == 2 {
                        let irq = if index == 0 {
                            super::UART_IRQ
                        } else {
                            super::SD_IRQ
                        };
                        if scalar(node.interrupts)? != irq
                            || node.extended.is_some()
                            || node.parent.map(word).transpose()?.unwrap_or(parent) != parent
                        {
                            return Err(Error::InvalidStructure);
                        }
                    }
                    match index {
                        0 if scalar(node.shift)? != 2 || scalar(node.width)? != 4 => {
                            return Err(Error::InvalidStructure)
                        }
                        1 => {
                            if node.phandle()? != parent
                                || scalar(node.cells)? != 1
                                || node.controller != Some(&[][..])
                                || scalar(node.sources)? != super::PLIC.max_irq
                            {
                                return Err(Error::InvalidStructure);
                            }
                            validate_contexts(
                                node.extended.ok_or(Error::InvalidStructure)?,
                                cpu_interrupts,
                            )?;
                        }
                        2 if scalar(node.fifo)? != 32 || scalar(node.bus_width)? != 4 => {
                            return Err(Error::InvalidStructure)
                        }
                        _ => (),
                    }
                }
            }
            _ => (),
        }
    }
    let [Some(uart), Some(plic), Some(sd), Some(crg), Some(syscon), Some(pins)] = found else {
        return Err(Error::InvalidStructure);
    };
    Ok(Resources {
        uart,
        plic,
        sd,
        crg,
        syscon,
        pins,
    })
}

fn cpu_interrupts(tree: &Fdt<'_>) -> Result<[u32; 5], Error> {
    let mut result = [0; 5];
    let (mut cpus, mut hart) = (false, None);
    let mut intc = Node::default();
    for event in tree.events() {
        match event? {
            Event::Begin { depth: 1, name } => cpus = name == "cpus",
            Event::End { depth: 1 } => cpus = false,
            Event::Begin { depth: 2, .. } if cpus => hart = None,
            Event::Property {
                depth: 2,
                name: "reg",
                value,
            } if cpus => {
                let id = match value.len() {
                    4 => u64::from(word(value)?),
                    8 => u64::from_be_bytes(value.try_into().unwrap()),
                    _ => return Err(Error::InvalidRange),
                };
                hart = Some(usize::try_from(id).map_err(|_| Error::InvalidRange)?);
            }
            Event::Begin { depth: 3, .. } if cpus => intc = Node::default(),
            Event::Property {
                depth: 3,
                name,
                value,
            } if cpus => intc.property(name, value)?,
            Event::End { depth: 3 } if cpus => {
                if intc
                    .compatible
                    .is_some_and(|s| list(s, b"riscv,cpu-intc") == Ok(true))
                {
                    let id = hart.ok_or(Error::InvalidStructure)?;
                    if id >= 5
                        || result[id] != 0
                        || scalar(intc.cells)? != 1
                        || intc.controller != Some(&[][..])
                        || !enabled(intc.status)
                    {
                        return Err(Error::InvalidStructure);
                    }
                    let handle = intc.phandle()?;
                    if result.contains(&handle) {
                        return Err(Error::InvalidStructure);
                    }
                    result[id] = handle;
                }
            }
            _ => (),
        }
    }
    if result.contains(&0) {
        return Err(Error::InvalidStructure);
    }
    Ok(result)
}
fn validate_contexts(bytes: &[u8], intc: [u32; 5]) -> Result<(), Error> {
    if bytes.len() != 9 * 8 {
        return Err(Error::InvalidStructure);
    }
    for (index, pair) in bytes.chunks_exact(8).enumerate() {
        let hart = if index == 0 { 0 } else { index.div_ceil(2) };
        let irq = word(&pair[4..])?;
        // OpenSBI may mask machine contexts with -1 without removing their
        // slots. Supervisor contexts must retain external interrupt ID 9.
        let irq_ok = if index == 0 || index % 2 == 1 {
            irq == 11 || irq == u32::MAX
        } else {
            irq == 9
        };
        if word(&pair[..4])? != intc[hart] || !irq_ok {
            return Err(Error::InvalidStructure);
        }
    }
    Ok(())
}

// Only handles used by this admission policy need global resolution. Count
// their definitions across the whole tree, including unrelated/nested nodes.
pub(super) fn unique_handles<const N: usize>(tree: &Fdt<'_>, targets: [u32; N]) -> Result<(), Error> {
    if targets
        .iter()
        .enumerate()
        .any(|(i, &v)| v == 0 || v == u32::MAX || targets[..i].contains(&v))
    {
        return Err(Error::InvalidStructure);
    }
    let mut handles = [0; 32];
    let mut properties = [0u8; 32];
    let mut counts = [0usize; N];
    for event in tree.events() {
        match event? {
            Event::Begin { depth, .. } => {
                *handles.get_mut(depth).ok_or(Error::InvalidStructure)? = 0;
                properties[depth] = 0;
            }
            Event::Property { depth, name, value }
                if matches!(name, "phandle" | "linux,phandle") =>
            {
                let value = word(value)?;
                let flag = if name == "phandle" { 1 } else { 2 };
                let old = handles.get_mut(depth).ok_or(Error::InvalidStructure)?;
                if value == 0
                    || value == u32::MAX
                    || properties[depth] & flag != 0
                    || (*old != 0 && *old != value)
                {
                    return Err(Error::InvalidStructure);
                }
                *old = value;
                properties[depth] |= flag;
            }
            Event::End { depth } => {
                if let Some(index) = targets.iter().position(|v| *v == handles[depth]) {
                    counts[index] += 1;
                }
            }
            _ => (),
        }
    }
    if counts != [1; N] {
        return Err(Error::InvalidStructure);
    }
    Ok(())
}
