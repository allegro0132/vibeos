//! Shared strict parsing of pinned Mars provider descriptions. No MMIO.
use vibeos_hal::fdt::{Error, Event, Fdt};

pub(crate) struct Node<'a> {
    properties: [Option<(&'a str, &'a [u8])>; 48],
    count: usize,
}
impl<'a> Node<'a> {
    pub(crate) fn get(&self, name: &str) -> Option<&'a [u8]> {
        self.properties[..self.count]
            .iter()
            .flatten()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| *value)
    }
    pub(crate) fn require(&self, name: &str) -> Result<&'a [u8], Error> {
        self.get(name).ok_or(Error::InvalidStructure)
    }
    pub(crate) fn cells(&self, name: &str, expected: &[u32]) -> Result<(), Error> {
        let bytes = self.require(name)?;
        check(
            bytes.len() == expected.len() * 4
                && bytes
                    .chunks_exact(4)
                    .zip(expected)
                    .all(|(b, &v)| b == v.to_be_bytes()),
        )
    }
    pub(crate) fn strings(&self, name: &str, expected: &[u8]) -> Result<(), Error> {
        check(self.require(name)? == expected)
    }
    pub(crate) fn enabled(&self) -> Result<(), Error> {
        check(matches!(
            self.get("status"),
            None | Some(b"okay\0") | Some(b"ok\0")
        ))
    }
    pub(crate) fn handle(&self) -> Result<u32, Error> {
        let bytes = self
            .get("phandle")
            .or(self.get("linux,phandle"))
            .ok_or(Error::InvalidStructure)?;
        let value = u32::from_be_bytes(bytes.try_into().map_err(|_| Error::InvalidStructure)?);
        check(value != 0 && value != u32::MAX)?;
        if let Some(alias) = self.get("linux,phandle") {
            check(alias == bytes)?;
        }
        Ok(value)
    }
}
pub(crate) fn check(ok: bool) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidStructure)
    }
}

// Exact paths are a deliberate pinned-board policy. Duplicate nodes/properties
// are rejected; arbitrary firmware-supplied register windows are never trusted.
pub(crate) fn node<'a>(tree: &Fdt<'a>, path: &[&str]) -> Result<Node<'a>, Error> {
    let mut names = [""; 32];
    let mut found = false;
    let mut result = Node {
        properties: [None; 48],
        count: 0,
    };
    for event in tree.events() {
        match event? {
            Event::Begin { depth, name } => {
                *names.get_mut(depth).ok_or(Error::InvalidStructure)? = name;
                if depth == path.len() && names[1..=depth] == *path {
                    check(!found)?;
                    found = true;
                }
            }
            Event::End { depth } => names[depth] = "",
            Event::Property { depth, name, value }
                if depth == path.len() && names[1..=depth] == *path =>
            {
                check(result.get(name).is_none() && result.count < result.properties.len())?;
                result.properties[result.count] = Some((name, value));
                result.count += 1;
            }
            _ => (),
        }
    }
    check(found)?;
    result.enabled()?;
    Ok(result)
}

pub(crate) fn providers(tree: &Fdt<'_>) -> Result<(u32, u32), Error> {
    let clock = {
        let n = node(tree, &["soc", "clock-controller"])?;
        n.strings("compatible", b"starfive,jh7110-clkgen\0")?;
        n.strings("reg-names", b"sys\0stg\0aon\0")?;
        n.cells(
            "reg",
            &[
                0, 0x13020000, 0, 0x10000, 0, 0x10230000, 0, 0x10000, 0, 0x17000000, 0, 0x10000,
            ],
        )?;
        n.cells("#clock-cells", &[1])?;
        n.handle()?
    };
    let reset = {
        let n = node(tree, &["soc", "reset-controller"])?;
        n.strings("compatible", b"starfive,jh7110-reset\0")?;
        n.strings("reg-names", b"syscrg\0stgcrg\0aoncrg\0ispcrg\0voutcrg\0")?;
        n.cells(
            "reg",
            &[
                0, 0x13020000, 0, 0x10000, 0, 0x10230000, 0, 0x10000, 0, 0x17000000, 0, 0x10000, 0,
                0x19810000, 0, 0x10000, 0, 0x295c0000, 0, 0x10000,
            ],
        )?;
        n.cells("#reset-cells", &[1])?;
        n.handle()?
    };
    super::resources::unique_handles(tree, [clock, reset])?;
    Ok((clock, reset))
}
