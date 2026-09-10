//! Strict admission of the pinned vendor GMAC0 wiring. This admits resources,
//! not link readiness or DMA coherence. In particular, the vendor PHY tuning
//! node has no MDIO `reg`: a later probe must discover and identify the PHY.
use vibeos_hal::{
    fdt::{Error, Event, Fdt},
    AddressRange,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resources {
    pub mac: AddressRange,
    pub irq: u32,
    pub cache: AddressRange,
    pub sys_crg: AddressRange,
    pub aon_crg: AddressRange,
    pub aon_syscon: AddressRange,
    pub phy: PhyTuning,
}

/// Vendor Motorcomm tuning values, not a discovered PHY identity or address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhyTuning {
    pub drive: [u32; 3],
    pub rxc_delay_enabled: bool,
    pub rx_delay: u32,
    pub tx_delay_fe: u32,
    pub tx_delay: u32,
    pub tx_inverted: [bool; 3],
}

struct Node<'a> {
    properties: [Option<(&'a str, &'a [u8])>; 48],
    count: usize,
}
impl<'a> Node<'a> {
    fn get(&self, name: &str) -> Option<&'a [u8]> {
        self.properties[..self.count]
            .iter()
            .flatten()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| *value)
    }
    fn require(&self, name: &str) -> Result<&'a [u8], Error> {
        self.get(name).ok_or(Error::InvalidStructure)
    }
    fn cells(&self, name: &str, expected: &[u32]) -> Result<(), Error> {
        let bytes = self.require(name)?;
        check(
            bytes.len() == expected.len() * 4
                && bytes
                    .chunks_exact(4)
                    .zip(expected)
                    .all(|(b, &v)| b == v.to_be_bytes()),
        )
    }
    fn strings(&self, name: &str, expected: &[u8]) -> Result<(), Error> {
        check(self.require(name)? == expected)
    }
    fn enabled(&self) -> Result<(), Error> {
        check(matches!(
            self.get("status"),
            None | Some(b"okay\0") | Some(b"ok\0")
        ))
    }
    fn handle(&self) -> Result<u32, Error> {
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
fn check(ok: bool) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidStructure)
    }
}

// Exact paths are a deliberate pinned-board policy. Duplicate nodes/properties
// are rejected; arbitrary firmware-supplied register windows are never trusted.
fn node<'a>(tree: &Fdt<'a>, path: &[&str]) -> Result<Node<'a>, Error> {
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

/// Admit the official SDK topology, including providers and their ordering.
/// Does not consume `dma-coherent` as proof: the composed driver must still use
/// the platform cache service and a validated, controller-reachable DMA pool.
pub fn admit(dtb: &[u8]) -> Result<Resources, Error> {
    super::resources::admit(dtb)?; // Also validates identity /soc and PLIC routing.
    let tree = Fdt::new(dtb)?;
    let clock = {
        let n = node(&tree, &["soc", "clock-controller"])?;
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
        let n = node(&tree, &["soc", "reset-controller"])?;
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
    super::resources::unique_handles(&tree, [clock, reset])?;
    {
        let n = node(&tree, &["soc", "aon_syscon@17010000"])?;
        n.strings("compatible", b"syscon\0")?;
        n.cells("reg", &[0, 0x17010000, 0, 0x1000])?;
    }
    {
        let n = node(&tree, &["soc", "cache-controller@2010000"])?;
        n.strings("compatible", b"sifive,fu740-c000-ccache\0cache\0")?;
        n.strings("reg-names", b"control\0sideband\0")?;
        n.cells(
            "reg",
            &[0, 0x2010000, 0, 0x4000, 0, 0x8000000, 0, 0x2000000],
        )?;
        n.cells("cache-block-size", &[64])?;
        n.cells("cache-level", &[2])?;
        n.cells("cache-sets", &[2048])?;
        n.cells("cache-size", &[2097152])?;
        n.strings("cache-unified", b"")?;
    }
    let parent = node(&tree, &["soc"])?;
    {
        let n = node(&tree, &["soc", "ethernet@16030000"])?;
        n.strings("compatible", b"starfive,dwmac\0snps,dwmac-5.10a\0")?;
        n.cells("reg", &[0, 0x16030000, 0, 0x10000])?;
        n.cells("interrupts", &[7, 6, 5])?;
        n.strings("interrupt-names", b"macirq\0eth_wake_irq\0eth_lpi\0")?;
        check(n.get("interrupts-extended").is_none())?;
        if let Some(p) = n.get("interrupt-parent") {
            check(p == parent.require("interrupt-parent")?)?;
        }
        n.strings(
            "clock-names",
            b"gtx\0tx\0ptp_ref\0stmmaceth\0pclk\0gtxc\0rmii_rtx\0",
        )?;
        n.cells(
            "clocks",
            &[
                clock, 108, clock, 224, clock, 109, clock, 221, clock, 222, clock, 111, clock, 223,
            ],
        )?;
        n.strings("reset-names", b"ahb\0stmmaceth\0")?;
        n.cells("resets", &[reset, 161, reset, 160])?;
        n.strings("phy-mode", b"rgmii-id\0")?;
        n.cells("rx-fifo-depth", &[2048])?;
        n.cells("tx-fifo-depth", &[2048])?;
        n.cells("#address-cells", &[1])?;
        n.cells("#size-cells", &[0])?;
        // A fixed-link or PHY substitution needs a separately reviewed profile.
        check(n.get("phy-handle").is_none() && n.get("fixed-link").is_none())?;
    }
    let phy = {
        let n = node(&tree, &["soc", "ethernet@16030000", "ethernet-phy@0"])?;
        check(n.get("reg").is_none())?;
        for (name, value) in [
            ("rgmii_sw_dr_2", 0),
            ("rgmii_sw_dr", 3),
            ("rgmii_sw_dr_rxc", 6),
            ("rxc_dly_en", 0),
            ("rx_delay_sel", 10),
            ("tx_delay_sel_fe", 5),
            ("tx_delay_sel", 10),
            ("tx_inverted_10", 1),
            ("tx_inverted_100", 1),
            ("tx_inverted_1000", 1),
        ] {
            n.cells(name, &[value])?;
        }
        PhyTuning {
            drive: [0, 3, 6],
            rxc_delay_enabled: false,
            rx_delay: 10,
            tx_delay_fe: 5,
            tx_delay: 10,
            tx_inverted: [true; 3],
        }
    };
    // This pinned binding has one direct tuning child, no nested MDIO bus or
    // fixed-link alternative. Reject additions even when marked disabled.
    let (mut soc, mut mac) = (false, false);
    let mut device_name = "";
    for event in tree.events() {
        match event? {
            Event::Begin { depth: 1, name } => soc = name == "soc",
            Event::End { depth: 1 } => soc = false,
            Event::Begin { depth: 2, name } if soc => {
                device_name = name;
                mac = name == "ethernet@16030000";
            }
            Event::End { depth: 2 } => mac = false,
            Event::Property {
                depth: 2,
                name: "reg",
                value,
            } if soc => {
                if value.len() % 16 == 0 {
                    for tuple in value.chunks_exact(16) {
                        let address = u64::from_be_bytes(tuple[..8].try_into().unwrap());
                        for (base, expected) in [
                            (0x16030000, "ethernet@16030000"),
                            (0x2010000, "cache-controller@2010000"),
                            (0x17010000, "aon_syscon@17010000"),
                        ] {
                            check(address != base || device_name == expected)?;
                        }
                    }
                }
            }
            Event::Begin { depth, name } if soc && mac && depth >= 3 => {
                check(depth == 3 && name == "ethernet-phy@0")?;
            }
            _ => (),
        }
    }
    Ok(Resources {
        mac: super::GMAC0_REGISTERS,
        irq: super::GMAC0_IRQ,
        cache: super::L2_CACHE,
        sys_crg: super::SYS_CRG,
        aon_crg: super::AON_CRG,
        aon_syscon: super::AON_SYSCON,
        phy,
    })
}
