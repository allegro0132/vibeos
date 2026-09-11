//! Admit the enabled TRNG node of the pinned Mars DTB. This is not a clock,
//! reset, mapping or entropy-quality grant. SEC reset is shared with crypto/DMA.
use super::dtb::{check, node, providers};
use vibeos_hal::{
    fdt::{Error, Event, Fdt},
    AddressRange,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResetScope {
    SharedSecuritySubsystem,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resources {
    pub registers: AddressRange,
    pub irq: u32,
    pub sys_crg: AddressRange,
    pub stg_crg: AddressRange,
    pub clock_ids: [u32; 2],
    pub reset_id: u32,
    pub reset_scope: ResetScope,
}

pub fn admit(dtb: &[u8]) -> Result<Resources, Error> {
    super::resources::admit(dtb)?;
    let tree = Fdt::new(dtb)?;
    let (clock, reset) = providers(&tree)?;
    let parent = node(&tree, &["soc"])?;
    let n = node(&tree, &["soc", "trng@1600C000"])?;
    n.strings("compatible", b"starfive,jh7110-trng\0")?;
    n.cells("reg", &[0, 0x1600c000, 0, 0x4000])?;
    n.strings("clock-names", b"hclk\0ahb\0")?;
    n.cells("clocks", &[clock, 205, clock, 206])?;
    n.cells("resets", &[reset, 131])?;
    n.cells("interrupts", &[30])?;
    check(n.get("interrupts-extended").is_none())?;
    if let Some(p) = n.get("interrupt-parent") {
        check(p == parent.require("interrupt-parent")?)?;
    }
    // /soc has identity addressing, validated by resources::admit. Reject any
    // other direct child's reg tuple overlapping this controller, including
    // partial overlaps and disabled aliases. Child nodes are not this binding.
    let (mut soc, mut owner, mut name) = (false, false, "");
    for event in tree.events() {
        match event? {
            Event::Begin { depth: 1, name: n } => soc = n == "soc",
            Event::End { depth: 1 } => soc = false,
            Event::Begin { depth: 2, name: n } if soc => {
                name = n;
                owner = n == "trng@1600C000";
            }
            Event::End { depth: 2 } => owner = false,
            Event::Begin { depth, .. } if soc && owner && depth > 2 => {
                return Err(Error::InvalidStructure)
            }
            Event::Property {
                depth: 2,
                name: "reg",
                value,
            } if soc => {
                check(value.len() % 16 == 0)?;
                for tuple in value.chunks_exact(16) {
                    let start = u64::from_be_bytes(tuple[..8].try_into().unwrap());
                    let size = u64::from_be_bytes(tuple[8..].try_into().unwrap());
                    let end = start.checked_add(size).ok_or(Error::InvalidRange)?;
                    if start < super::TRNG_REGISTERS.end as u64
                        && end > super::TRNG_REGISTERS.start as u64
                    {
                        check(name == "trng@1600C000")?;
                    }
                }
            }
            _ => (),
        }
    }
    Ok(Resources {
        registers: super::TRNG_REGISTERS,
        irq: super::TRNG_IRQ,
        sys_crg: super::SYS_CRG,
        stg_crg: super::STG_CRG,
        clock_ids: [205, 206],
        reset_id: 131,
        reset_scope: ResetScope::SharedSecuritySubsystem,
    })
}
