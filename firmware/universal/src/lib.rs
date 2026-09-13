#![no_std]
//! Allocation-free DTB identification, independently testable on the host.
use vibeos_hal::{
    fdt::{Event, Fdt},
    runtime_platform::BoardId,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidDtb,
    UnknownBoard,
    ConflictingIdentity,
    MissingEarlyDevices,
}
fn list(bytes: &[u8], item: &[u8]) -> bool {
    bytes.split(|b| *b == 0).any(|v| v == item)
}
pub fn identify(bytes: &[u8]) -> Result<BoardId, Error> {
    let fdt = Fdt::new(bytes).map_err(|_| Error::InvalidDtb)?;
    let mut compatible = None;
    let mut marker = None;
    for event in fdt.events() {
        match event.map_err(|_| Error::InvalidDtb)? {
            Event::Property {
                depth: 0,
                name: "compatible",
                value,
            } => {
                if compatible.replace(value).is_some() {
                    return Err(Error::ConflictingIdentity);
                }
            }
            Event::Property {
                depth: 0,
                name: "vibeos,board-id",
                value,
            } => {
                if marker.replace(value).is_some() {
                    return Err(Error::ConflictingIdentity);
                }
            }
            _ => {}
        }
    }
    let compatible = compatible.ok_or(Error::UnknownBoard)?;
    if compatible.last() != Some(&0) {
        return Err(Error::InvalidDtb);
    }
    let qemu = list(compatible, b"riscv-virtio") || list(compatible, b"qemu,virt");
    let duo = list(compatible, b"milk-v,duo")
        || list(compatible, b"cvitek,cv1800b")
        || list(compatible, b"cvitek,cv180x");
    let mars = list(compatible, b"milk-v,mars") && list(compatible, b"starfive,jh7110");
    if u8::from(qemu) + u8::from(duo) + u8::from(mars) != 1 {
        return Err(Error::UnknownBoard);
    }
    let (board, id) = if qemu {
        (BoardId::QemuVirt, b"qemu-virt\0".as_slice())
    } else if duo {
        (BoardId::MilkvDuo, b"milkv-duo\0".as_slice())
    } else {
        (BoardId::MilkvMars, b"milkv-mars\0".as_slice())
    };
    if marker.is_some_and(|m| m != id) {
        return Err(Error::ConflictingIdentity);
    }
    // A generic CV180x string alone also describes other, incompatible boards.
    if duo && marker.is_none() && !list(compatible, b"milk-v,duo") {
        return Err(Error::UnknownBoard);
    }
    Ok(board)
}

/// Require the kernel's baseline ISA on every admitted scheduler hart.
pub fn supports_isa(isa: &str, floating_point: bool) -> bool {
    let Some(base) = isa.strip_prefix("rv64").and_then(|s| s.split('_').next()) else {
        return false;
    };
    let integer = base.contains('g') || ['i', 'm', 'a'].iter().all(|c| base.contains(*c));
    integer
        && base.contains('c')
        && (!floating_point || base.contains('g') || (base.contains('f') && base.contains('d')))
}

/// Check enabled early controllers in identity-mapped buses before MMIO access.
pub fn early_resources(bytes: &[u8], uart: usize, plic: usize) -> Result<(), Error> {
    #[derive(Clone, Copy)]
    struct Node<'a> {
        address: u32,
        size: u32,
        parent_address: u32,
        parent_size: u32,
        disabled: bool,
        translated: bool,
        reg: Option<&'a [u8]>,
        compatible: Option<&'a [u8]>,
    }
    const EMPTY: Node<'_> = Node {
        address: 2,
        size: 1,
        parent_address: 2,
        parent_size: 1,
        disabled: false,
        translated: false,
        reg: None,
        compatible: None,
    };
    let fdt = Fdt::new(bytes).map_err(|_| Error::InvalidDtb)?;
    let mut nodes = [EMPTY; 32];
    let mut found_uart = false;
    let mut found_plic = false;
    for event in fdt.events() {
        match event.map_err(|_| Error::InvalidDtb)? {
            Event::Begin { depth, .. } => {
                if depth >= nodes.len() {
                    return Err(Error::InvalidDtb);
                }
                let parent = if depth == 0 { EMPTY } else { nodes[depth - 1] };
                nodes[depth] = Node {
                    parent_address: parent.address,
                    parent_size: parent.size,
                    disabled: parent.disabled,
                    translated: parent.translated,
                    ..EMPTY
                };
            }
            Event::Property { depth, name, value } => {
                let n = nodes.get_mut(depth).ok_or(Error::InvalidDtb)?;
                match name {
                    "#address-cells" | "#size-cells" => {
                        let cells =
                            u32::from_be_bytes(value.try_into().map_err(|_| Error::InvalidDtb)?);
                        if name == "#address-cells" {
                            n.address = cells;
                        } else {
                            n.size = cells;
                        }
                    }
                    "status" => n.disabled |= value != b"okay\0" && value != b"ok\0",
                    "ranges" => n.translated |= !value.is_empty(),
                    "reg" => {
                        if n.reg.replace(value).is_some() {
                            return Err(Error::InvalidDtb);
                        }
                    }
                    "compatible" => {
                        if n.compatible.replace(value).is_some() {
                            return Err(Error::InvalidDtb);
                        }
                    }
                    _ => {}
                }
            }
            Event::End { depth } => {
                let n = nodes.get(depth).ok_or(Error::InvalidDtb)?;
                if n.disabled || n.translated {
                    continue;
                }
                let (Some(reg), Some(compatible)) = (n.reg, n.compatible) else {
                    continue;
                };
                if !(1..=2).contains(&n.parent_address) || !(1..=2).contains(&n.parent_size) {
                    continue;
                }
                let stride = (n.parent_address + n.parent_size) as usize * 4;
                if reg.len() < stride || reg.len() % stride != 0 {
                    return Err(Error::InvalidDtb);
                }
                let address_bytes = n.parent_address as usize * 4;
                let address = reg[..address_bytes]
                    .iter()
                    .fold(0u64, |a, b| (a << 8) | u64::from(*b));
                let size = reg[address_bytes..stride]
                    .iter()
                    .fold(0u64, |a, b| (a << 8) | u64::from(*b));
                if size == 0 {
                    continue;
                }
                if address == uart as u64
                    && (list(compatible, b"ns16550a") || list(compatible, b"snps,dw-apb-uart"))
                {
                    if found_uart {
                        return Err(Error::InvalidDtb);
                    }
                    found_uart = true;
                }
                if address == plic as u64
                    && (list(compatible, b"riscv,plic0")
                        || list(compatible, b"sifive,plic-1.0.0")
                        || list(compatible, b"thead,c900-plic"))
                {
                    if found_plic {
                        return Err(Error::InvalidDtb);
                    }
                    found_plic = true;
                }
            }
        }
    }
    if found_uart && found_plic {
        Ok(())
    } else {
        Err(Error::MissingEarlyDevices)
    }
}
