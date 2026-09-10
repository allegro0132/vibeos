//! Host register/descriptor models do not execute DMA or establish coherence.
use vibeos_eqos_net::{
    descriptor as d,
    mdio::{self, Port, Registers},
};

#[derive(Default)]
struct Regs {
    writes: Vec<(usize, u32)>,
}
impl Registers for Regs {
    fn read(&mut self, offset: usize) -> u32 {
        match offset {
            mdio::ADDRESS => 0,
            mdio::DATA => 0xcafe,
            _ => panic!("unexpected offset"),
        }
    }
    fn write(&mut self, offset: usize, value: u32) {
        self.writes.push((offset, value));
    }
}

#[test]
fn mdio_uses_eqos_offsets_fields_and_data_before_write() {
    let mut p = Port::new(Regs::default(), 125_000_000).unwrap();
    assert_eq!(vibeos_ethernet::read(&mut p, 3, 17, 2), Ok(0xcafe));
    vibeos_ethernet::write(&mut p, 3, 17, 0xabcd, 2).unwrap();
    assert_eq!(
        p.into_inner().writes,
        [(0x200, 0x0071_010d), (0x204, 0xabcd), (0x200, 0x0071_0105)]
    );
}

#[test]
fn csr_clock_boundaries() {
    for (hz, code) in [
        (20_000_000, 2),
        (34_999_999, 2),
        (35_000_000, 3),
        (59_999_999, 3),
        (60_000_000, 0),
        (99_999_999, 0),
        (100_000_000, 1),
        (149_999_999, 1),
        (150_000_000, 4),
        (249_999_999, 4),
        (250_000_000, 5),
        (300_000_000, 5),
    ] {
        assert_eq!(mdio::clock_range(hz), Ok(code));
    }
    for hz in [0, 19_999_999, 300_000_001, u64::MAX] {
        assert!(mdio::clock_range(hz).is_err());
    }
}

#[test]
fn prepared_descriptors_do_not_transfer_ownership() {
    assert_eq!(d::tx(0x42001000, 60), Ok([0x42001000, 0, 60, 0x3000003c]));
    assert_eq!(d::rx(0x42002000, 1536), Ok([0x42002000, 0, 0, 0x01000000]));
}

#[test]
fn complete_dma_span_must_fit_32_bits() {
    assert!(d::tx(0xffff_ffc4, 60).is_ok());
    assert_eq!(d::tx(0xffff_ffc5, 60), Err(d::Error::AddressTooWide));
    assert_eq!(d::rx(0xffff_fa01, 1536), Err(d::Error::AddressTooWide));
    assert_eq!(d::tx(u64::MAX, 60), Err(d::Error::AddressTooWide));
    for n in [0, 13, 1519, usize::MAX] {
        assert_eq!(d::tx(0x42000000, n), Err(d::Error::InvalidLength));
    }
    for n in [0, 1521, 16384] {
        assert_eq!(d::rx(0x42000000, n), Err(d::Error::InvalidLength));
    }
}

#[test]
fn rx_waits_for_cpu_ownership_strips_fcs_and_rejects_bad_frames() {
    assert_eq!(d::rx_complete([0, 0, 0, 0xffff_ffff], 1536), Ok(None));
    assert_eq!(
        d::rx_complete([u32::MAX, 0, 0, 0x30000040], 1536),
        Ok(Some(60))
    );
    for (word, error) in [
        (0x70000040, d::Error::Context),
        (0x30008040, d::Error::Hardware),
        (0x10000040, d::Error::Fragmented),
        (0x20000040, d::Error::Fragmented),
        (0x30000011, d::Error::InvalidLength),
        (0x300005f3, d::Error::InvalidLength),
    ] {
        assert_eq!(d::rx_complete([0, 0, 0, word], 1536), Err(error));
    }
    assert_eq!(
        d::rx_complete([0, 0, 0, 0x30000040], 63),
        Err(d::Error::InvalidLength)
    );
}

#[test]
fn tx_completion_preserves_errors_and_busy_state() {
    assert_eq!(d::tx_complete([0, 0, 0, 0xb0008000]), Ok(false));
    assert_eq!(
        d::tx_complete([0, 0, 0, 0x30008000]),
        Err(d::Error::Hardware)
    );
    assert_eq!(
        d::tx_complete([0, 0, 0, 0x70000000]),
        Err(d::Error::Context)
    );
    assert_eq!(d::tx_complete([0, 0, 0, 0]), Err(d::Error::Fragmented));
    assert_eq!(d::tx_complete([0, 0, 0, 0x30000000]), Ok(true));
}

#[test]
fn cache_line_stride_uses_axi_width_not_word_count() {
    assert_eq!(d::skip_length(64, 8), Ok(6 << 18));
    assert_eq!(d::skip_length(64, 16), Ok(3 << 18));
    assert_eq!(d::skip_length(16, 4), Ok(0));
    for (stride, axi) in [(64, 4), (128, 8), (15, 8), (48, 8), (64, 0), (64, 3)] {
        assert_eq!(d::skip_length(stride, axi), Err(d::Error::InvalidLayout));
    }
}
