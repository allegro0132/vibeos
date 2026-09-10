//! Bounded, allocation-free FDT v17 reader for firmware handoff data.
//! This module accepts an already readable byte slice; converting a firmware
//! physical pointer to that slice is the architecture entry's responsibility.
pub mod cpus;

use crate::{
    memory::{BootMemory, MemoryError},
    AddressRange,
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    InvalidHeader,
    InvalidStructure,
    InvalidString,
    UnsupportedCells,
    InvalidRange,
    TooDeep,
    Memory(MemoryError),
}
impl From<MemoryError> for Error {
    fn from(e: MemoryError) -> Self {
        Self::Memory(e)
    }
}
fn word(bytes: &[u8], at: usize) -> Result<u32, Error> {
    let end = at.checked_add(4).ok_or(Error::Truncated)?;
    Ok(u32::from_be_bytes(
        bytes
            .get(at..end)
            .ok_or(Error::Truncated)?
            .try_into()
            .unwrap(),
    ))
}
fn wide(bytes: &[u8], at: usize) -> Result<u64, Error> {
    Ok((u64::from(word(bytes, at)?) << 32)
        | u64::from(word(bytes, at.checked_add(4).ok_or(Error::Truncated)?)?))
}
fn aligned(value: usize) -> Result<usize, Error> {
    Ok(value.checked_add(3).ok_or(Error::Truncated)? & !3)
}
fn string(bytes: &[u8]) -> Result<&str, Error> {
    let end = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or(Error::InvalidString)?;
    core::str::from_utf8(&bytes[..end]).map_err(|_| Error::InvalidString)
}
#[derive(Clone, Copy)]
pub struct Fdt<'a> {
    bytes: &'a [u8],
    structure: &'a [u8],
    strings: &'a [u8],
    reserve_start: usize,
    reserve_end: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event<'a> {
    Begin {
        depth: usize,
        name: &'a str,
    },
    Property {
        depth: usize,
        name: &'a str,
        value: &'a [u8],
    },
    End {
        depth: usize,
    },
}
pub struct Events<'a> {
    structure: &'a [u8],
    strings: &'a [u8],
    cursor: usize,
    depth: usize,
    roots: usize,
    ended: bool,
    children: [bool; 32],
}
impl<'a> Iterator for Events<'a> {
    type Item = Result<Event<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.ended {
            return None;
        }
        let result = (|| loop {
            let token = word(self.structure, self.cursor)?;
            self.cursor += 4;
            match token {
                1 => {
                    if self.depth == 32 {
                        return Err(Error::TooDeep);
                    }
                    let name = string(self.structure.get(self.cursor..).ok_or(Error::Truncated)?)?;
                    self.cursor = aligned(self.cursor + name.len() + 1)?;
                    if self.cursor > self.structure.len() {
                        return Err(Error::Truncated);
                    }
                    if self.depth == 0 {
                        if self.roots != 0 || !name.is_empty() {
                            return Err(Error::InvalidStructure);
                        }
                        self.roots += 1;
                    }
                    if self.depth != 0 {
                        self.children[self.depth - 1] = true;
                    }
                    self.children[self.depth] = false;
                    let depth = self.depth;
                    self.depth += 1;
                    return Ok(Some(Event::Begin { depth, name }));
                }
                2 => {
                    self.depth = self.depth.checked_sub(1).ok_or(Error::InvalidStructure)?;
                    return Ok(Some(Event::End { depth: self.depth }));
                }
                3 => {
                    if self.depth == 0 || self.children[self.depth - 1] {
                        return Err(Error::InvalidStructure);
                    }
                    let size = word(self.structure, self.cursor)? as usize;
                    let name_at = word(self.structure, self.cursor + 4)? as usize;
                    self.cursor += 8;
                    let end = self.cursor.checked_add(size).ok_or(Error::Truncated)?;
                    let value = self
                        .structure
                        .get(self.cursor..end)
                        .ok_or(Error::Truncated)?;
                    let name = string(self.strings.get(name_at..).ok_or(Error::InvalidString)?)?;
                    self.cursor = aligned(end)?;
                    if self.cursor > self.structure.len() {
                        return Err(Error::Truncated);
                    }
                    return Ok(Some(Event::Property {
                        depth: self.depth - 1,
                        name,
                        value,
                    }));
                }
                4 => {}
                9 => {
                    if self.depth != 0 || self.roots != 1 {
                        return Err(Error::InvalidStructure);
                    }
                    if self.structure[self.cursor..].iter().any(|&b| b != 0) {
                        return Err(Error::InvalidStructure);
                    }
                    return Ok(None);
                }
                _ => return Err(Error::InvalidStructure),
            }
        })();
        match result {
            Ok(Some(event)) => Some(Ok(event)),
            Ok(None) => {
                self.ended = true;
                None
            }
            Err(e) => {
                self.ended = true;
                Some(Err(e))
            }
        }
    }
}
impl<'a> Fdt<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        if word(bytes, 0)? != 0xd00dfeed || word(bytes, 20)? != 17 || word(bytes, 24)? > 17 {
            return Err(Error::InvalidHeader);
        }
        let size = word(bytes, 4)? as usize;
        if !(40..=1024 * 1024).contains(&size) {
            return Err(Error::InvalidHeader);
        }
        let bytes = bytes.get(..size).ok_or(Error::Truncated)?;
        let struct_start = word(bytes, 8)? as usize;
        let strings_start = word(bytes, 12)? as usize;
        let reserve_start = word(bytes, 16)? as usize;
        let struct_end = struct_start
            .checked_add(word(bytes, 36)? as usize)
            .ok_or(Error::InvalidHeader)?;
        let strings_end = strings_start
            .checked_add(word(bytes, 32)? as usize)
            .ok_or(Error::InvalidHeader)?;
        if struct_start < 40
            || strings_start < 40
            || reserve_start < 40
            || struct_start % 4 != 0
            || reserve_start % 8 != 0
            || struct_end > size
            || strings_end > size
            || (struct_start < strings_end && strings_start < struct_end)
        {
            return Err(Error::InvalidHeader);
        }
        let mut reserve_end = reserve_start;
        loop {
            let address = wide(bytes, reserve_end)?;
            let length = wide(bytes, reserve_end + 8)?;
            reserve_end = reserve_end.checked_add(16).ok_or(Error::InvalidHeader)?;
            if address == 0 && length == 0 {
                break;
            }
            address.checked_add(length).ok_or(Error::InvalidRange)?;
            if length == 0 {
                return Err(Error::InvalidRange);
            }
        }
        if (reserve_start < struct_end && struct_start < reserve_end)
            || (reserve_start < strings_end && strings_start < reserve_end)
        {
            return Err(Error::InvalidHeader);
        }
        let tree = Self {
            bytes,
            structure: &bytes[struct_start..struct_end],
            strings: &bytes[strings_start..strings_end],
            reserve_start,
            reserve_end,
        };
        for event in tree.events() {
            event?;
        }
        Ok(tree)
    }
    pub fn size(&self) -> usize {
        self.bytes.len()
    }
    pub fn events(&self) -> Events<'a> {
        Events {
            structure: self.structure,
            strings: self.strings,
            cursor: 0,
            depth: 0,
            roots: 0,
            ended: false,
            children: [false; 32],
        }
    }
    /// Admit memory nodes and subtract fixed reserved-memory nodes, the FDT
    /// reservation table and the FDT itself. Firmware/image reservations are
    /// subtracted by the caller before publishing the resulting map.
    pub fn memory<const N: usize>(&self, physical_address: usize) -> Result<BootMemory<N>, Error> {
        #[derive(Clone, Copy)]
        struct Node<'a> {
            address_cells: u32,
            size_cells: u32,
            parent_address: u32,
            parent_size: u32,
            memory: bool,
            reserved_root: bool,
            reserved_child: bool,
            disabled: bool,
            reg: Option<&'a [u8]>,
        }
        const EMPTY: Node<'static> = Node {
            address_cells: 2,
            size_cells: 1,
            parent_address: 2,
            parent_size: 1,
            memory: false,
            reserved_root: false,
            reserved_child: false,
            disabled: false,
            reg: None,
        };
        let mut nodes = [EMPTY; 32];
        let mut memory = BootMemory::<N>::new();
        // Keep raw reservations separately: overlapping firmware reservations
        // are legal, so apply a second pass rather than insert them as RAM.
        for pass in 0..2 {
            for event in self.events() {
                match event? {
                    Event::Begin { depth, name } => {
                        let parent = if depth == 0 { EMPTY } else { nodes[depth - 1] };
                        nodes[depth] = Node {
                            parent_address: parent.address_cells,
                            parent_size: parent.size_cells,
                            memory: depth == 1 && (name == "memory" || name.starts_with("memory@")),
                            reserved_root: depth == 1 && name == "reserved-memory",
                            reserved_child: depth == 2 && parent.reserved_root,
                            disabled: parent.disabled,
                            ..EMPTY
                        };
                    }
                    Event::Property { depth, name, value } => {
                        let n = &mut nodes[depth];
                        match name {
                            "#address-cells" => {
                                if value.len() != 4 {
                                    return Err(Error::UnsupportedCells);
                                }
                                n.address_cells = word(value, 0)?;
                            }
                            "#size-cells" => {
                                if value.len() != 4 {
                                    return Err(Error::UnsupportedCells);
                                }
                                n.size_cells = word(value, 0)?;
                            }
                            "reg" => {
                                if n.reg.replace(value).is_some() {
                                    return Err(Error::InvalidStructure);
                                }
                            }
                            "status" => n.disabled |= value != b"okay\0" && value != b"ok\0",
                            "ranges" if n.reserved_root && !value.is_empty() => {
                                return Err(Error::UnsupportedCells)
                            }
                            "device_type" if depth == 1 && value == b"memory\0" => n.memory = true,
                            _ => {}
                        }
                    }
                    Event::End { depth } => {
                        let n = nodes[depth];
                        if n.disabled || !(n.memory && pass == 0 || n.reserved_child && pass == 1) {
                            continue;
                        }
                        let Some(reg) = n.reg else {
                            if n.memory {
                                return Err(Error::InvalidRange);
                            } else {
                                continue;
                            }
                        };
                        if !(1..=2).contains(&n.parent_address) || !(1..=2).contains(&n.parent_size)
                        {
                            return Err(Error::UnsupportedCells);
                        }
                        let stride = (n.parent_address + n.parent_size) as usize * 4;
                        if reg.is_empty() || reg.len() % stride != 0 {
                            return Err(Error::InvalidRange);
                        }
                        for entry in reg.chunks_exact(stride) {
                            let address = if n.parent_address == 2 {
                                wide(entry, 0)?
                            } else {
                                u64::from(word(entry, 0)?)
                            };
                            let at = n.parent_address as usize * 4;
                            let length = if n.parent_size == 2 {
                                wide(entry, at)?
                            } else {
                                u64::from(word(entry, at)?)
                            };
                            let end = address.checked_add(length).ok_or(Error::InvalidRange)?;
                            let range = AddressRange::new(
                                usize::try_from(address).map_err(|_| Error::InvalidRange)?,
                                usize::try_from(end).map_err(|_| Error::InvalidRange)?,
                            );
                            if pass == 0 {
                                memory.add_ram(range)?;
                            } else {
                                memory.reserve(range)?;
                            }
                        }
                    }
                }
            }
        }
        for at in (self.reserve_start..self.reserve_end - 16).step_by(16) {
            let start = usize::try_from(wide(self.bytes, at)?).map_err(|_| Error::InvalidRange)?;
            let length =
                usize::try_from(wide(self.bytes, at + 8)?).map_err(|_| Error::InvalidRange)?;
            memory.reserve(AddressRange::new(
                start,
                start.checked_add(length).ok_or(Error::InvalidRange)?,
            ))?;
        }
        // An FDT outside RAM remains valid, but cannot subtract unrelated RAM.
        memory.reserve(AddressRange::new(
            physical_address,
            physical_address
                .checked_add(self.size())
                .ok_or(Error::InvalidRange)?,
        ))?;
        Ok(memory)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;
    fn push(v: &mut Vec<u8>, x: u32) {
        v.extend(x.to_be_bytes());
    }
    fn begin(v: &mut Vec<u8>, name: &[u8]) {
        push(v, 1);
        v.extend(name);
        v.push(0);
        while v.len() % 4 != 0 {
            v.push(0);
        }
    }
    fn property(v: &mut Vec<u8>, name: u32, value: &[u8]) {
        push(v, 3);
        push(v, value.len() as u32);
        push(v, name);
        v.extend(value);
        while v.len() % 4 != 0 {
            v.push(0);
        }
    }
    fn fixture() -> Vec<u8> {
        let names = b"#address-cells\0#size-cells\0reg\0";
        let mut s = Vec::new();
        begin(&mut s, b"");
        property(&mut s, 0, &2u32.to_be_bytes());
        property(&mut s, 15, &2u32.to_be_bytes());
        begin(&mut s, b"memory@40000000");
        let mut reg = Vec::new();
        reg.extend(0x40000000u64.to_be_bytes());
        reg.extend(0x100000000u64.to_be_bytes());
        property(&mut s, 27, &reg);
        push(&mut s, 2);
        begin(&mut s, b"reserved-memory");
        property(&mut s, 0, &2u32.to_be_bytes());
        property(&mut s, 15, &2u32.to_be_bytes());
        begin(&mut s, b"firmware@40000000");
        let mut reg = Vec::new();
        reg.extend(0x40000000u64.to_be_bytes());
        reg.extend(0x200000u64.to_be_bytes());
        property(&mut s, 27, &reg);
        push(&mut s, 2);
        push(&mut s, 2);
        push(&mut s, 2);
        push(&mut s, 9);
        let mut out = std::vec![0u8;56];
        let values = [
            0xd00dfeed,
            (56 + s.len() + names.len()) as u32,
            56,
            (56 + s.len()) as u32,
            40,
            17,
            16,
            1,
            names.len() as u32,
            s.len() as u32,
        ];
        for (i, v) in values.into_iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }
        out.extend(s);
        out.extend(names);
        out
    }
    #[test]
    fn reads_four_gib_and_subtracts_firmware_and_dtb() {
        let bytes = fixture();
        let f = Fdt::new(&bytes).unwrap();
        let m = f.memory::<8>(0x48000000).unwrap();
        assert_eq!(m.ranges()[0], AddressRange::new(0x40200000, 0x48000000));
        assert_eq!(
            m.ranges()[1],
            AddressRange::new(0x48000000 + bytes.len(), 0x140000000)
        );
    }
    #[test]
    fn mutated_handoff_data_never_panics() {
        let original = fixture();
        for index in 0..original.len() {
            for bit in 0..8 {
                let mut bytes = original.clone();
                bytes[index] ^= 1 << bit;
                if let Ok(tree) = Fdt::new(&bytes) {
                    let _ = tree.memory::<8>(0x48000000);
                }
            }
        }
    }
    #[test]
    fn every_truncation_is_rejected() {
        let bytes = fixture();
        for n in 0..bytes.len() {
            assert!(Fdt::new(&bytes[..n]).is_err(), "truncation {n}");
        }
    }
    #[test]
    fn rejects_overlap_unbalanced_structure_and_bad_property_name() {
        let mut bytes = fixture();
        bytes[12..16].copy_from_slice(&56u32.to_be_bytes());
        assert!(Fdt::new(&bytes).is_err());
        let mut bytes = fixture();
        bytes[56..60].copy_from_slice(&2u32.to_be_bytes());
        assert!(Fdt::new(&bytes).is_err());
        let mut bytes = fixture();
        bytes[72..76].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(Fdt::new(&bytes).is_err());
    }
}
