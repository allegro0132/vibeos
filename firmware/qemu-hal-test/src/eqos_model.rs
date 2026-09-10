//! Run the actual EQoS codecs on RV64 with a register model. No Mars DMA/MMIO.
use vibeos_eqos_net::{
    descriptor as d,
    mdio::{Port, Registers},
};
struct Model {
    writes: [(usize, u32); 3],
    count: usize,
}
impl Registers for Model {
    fn read(&mut self, offset: usize) -> u32 {
        match offset {
            0x200 => 0,
            0x204 => 0x24,
            _ => panic!("EQoS model read"),
        }
    }
    fn write(&mut self, offset: usize, value: u32) {
        self.writes[self.count] = (offset, value);
        self.count += 1;
    }
}
pub fn run() {
    let mut port = Port::new(
        Model {
            writes: [(0, 0); 3],
            count: 0,
        },
        125_000_000,
    )
    .unwrap();
    let status = vibeos_ethernet::status(&mut port, 0, 4).unwrap();
    assert!(status.link_up() && status.autoneg_complete());
    assert_eq!(port.into_inner().writes[..2], [(0x200, 0x1010d); 2]);
    let address = core::hint::black_box(0xffff_ffc4u64);
    let mut tx = d::tx(address, 60).unwrap();
    assert_eq!(tx, [0xffff_ffc4, 0, 60, 0x3000003c]);
    tx[3] |= d::OWN;
    assert_eq!(d::tx_complete(tx), Ok(false));
    tx[3] &= !d::OWN;
    assert_eq!(d::tx_complete(tx), Ok(true));
    assert_eq!(d::tx(address + 1, 60), Err(d::Error::AddressTooWide));
    assert_eq!(d::rx_complete([0, 0, 0, 0x30000040], 1536), Ok(Some(60)));
    assert_eq!(
        d::rx_complete([0, 0, 0, 0x30008040], 1536),
        Err(d::Error::Hardware)
    );
    assert_eq!(d::skip_length(64, 8), Ok(6 << 18));
}
