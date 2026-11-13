use vibeos_platform_jh7110::clock::{stg_axiahb_hz, Bank, UnsupportedClock};

fn decode(values: [u32; 6]) -> Result<u32, UnsupportedClock> {
    stg_axiahb_hz(|b, o| match (b, o) {
        (Bank::SysCrg, 0x14) => values[0],
        (Bank::SysCrg, 0x1c) => values[1],
        (Bank::SysCrg, 0x20) => values[2],
        (Bank::Syscon, 0x2c) => values[3],
        (Bank::Syscon, 0x30) => values[4],
        (Bank::Syscon, 0x34) => values[5],
        _ => panic!("unrelated clock accessed"),
    })
}
const PLL: [u32; 6] = [1 << 24, 3, 2, (3 << 15) | (99 << 17), 0, 2];

#[test]
fn bus_snapshot_needs_no_gmac_or_security_registers() {
    assert_eq!(decode(PLL), Ok(198_000_000));
    let mut post = PLL;
    post[4] = 1 << 28;
    assert_eq!(decode(post), Ok(99_000_000));
    let mut high_bits = PLL;
    high_bits[1] |= 0xff00_0000;
    high_bits[2] |= 0xff00_0000;
    assert_eq!(decode(high_bits), Ok(198_000_000));
}

#[test]
fn oscillator_path_never_reads_disabled_pll() {
    let mut reads = Vec::new();
    assert_eq!(
        stg_axiahb_hz(|b, o| {
            assert_eq!(b, Bank::SysCrg);
            reads.push(o);
            match o {
                0x14 => 0,
                0x1c | 0x20 => 1,
                _ => panic!("wrong root"),
            }
        }),
        Ok(24_000_000)
    );
    assert_eq!(reads, [0x14, 0x1c, 0x20]);
}

#[test]
fn malformed_roots_are_rejected_instead_of_rounded() {
    for (index, value) in [
        (1, 0),
        (1, 4),
        (2, 0),
        (2, 3),
        (3, 99 << 17),
        (3, (3 << 15) | (7 << 17)),
        (4, 1 << 27),
        (5, 0),
        (5, 7),
    ] {
        let mut values = PLL;
        values[index] = value;
        assert_eq!(
            decode(values),
            Err(UnsupportedClock),
            "index={index} value={value}"
        );
    }
    let mut too_fast = PLL;
    too_fast[1] = 1;
    assert_eq!(decode(too_fast), Err(UnsupportedClock));
    assert_eq!(decode([0, 2, 1, 0, 0, 0]), Err(UnsupportedClock));
}
