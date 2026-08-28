#![cfg(feature = "c88-f2-acceptance")]

use softfloat_core::softfloat as sf;

const F32_NAN: u32 = 0x7fc0_0000;
const F64_NAN: u64 = 0x7ff8_0000_0000_0000;
const CASES: usize = 50_000;

fn next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn canonical32(value: f32) -> u32 {
    if value.is_nan() {
        F32_NAN
    } else {
        value.to_bits()
    }
}

fn canonical64(value: f64) -> u64 {
    if value.is_nan() {
        F64_NAN
    } else {
        value.to_bits()
    }
}

fn mix(digest: &mut u64, value: u64) {
    *digest ^= value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    *digest = digest.rotate_left(27).wrapping_mul(0x94d0_49bb_1331_11eb);
}

#[test]
fn fixed_seed_non_nan_differential_corpus_matches_host_ieee_results() {
    let mut state = 0xc88f_2000_d15c_a11e;
    let mut digest = 0xcbf2_9ce4_8422_2325;
    for index in 0..CASES {
        let a32 = next(&mut state) as u32;
        let b32 = next(&mut state) as u32;
        let a64 = next(&mut state);
        let b64 = next(&mut state);
        let af32 = f32::from_bits(a32);
        let bf32 = f32::from_bits(b32);
        let af64 = f64::from_bits(a64);
        let bf64 = f64::from_bits(b64);

        let actual32 = [
            sf::f32_add_bits(a32, b32),
            sf::f32_sub_bits(a32, b32),
            sf::f32_mul_bits(a32, b32),
            sf::f32_div_bits(a32, b32),
            sf::f32_sqrt_bits(a32),
            sf::f32_ceil_bits(a32),
            sf::f32_floor_bits(a32),
            sf::f32_trunc_bits(a32),
            sf::f32_nearest_bits(a32),
        ];
        let expected32 = [
            canonical32(af32 + bf32),
            canonical32(af32 - bf32),
            canonical32(af32 * bf32),
            canonical32(af32 / bf32),
            canonical32(af32.sqrt()),
            canonical32(af32.ceil()),
            canonical32(af32.floor()),
            canonical32(af32.trunc()),
            canonical32(af32.round_ties_even()),
        ];
        assert_eq!(
            actual32, expected32,
            "f32 corpus index {index}: {a32:08x}/{b32:08x}"
        );

        let actual64 = [
            sf::f64_add_bits(a64, b64),
            sf::f64_sub_bits(a64, b64),
            sf::f64_mul_bits(a64, b64),
            sf::f64_div_bits(a64, b64),
            sf::f64_sqrt_bits(a64),
            sf::f64_ceil_bits(a64),
            sf::f64_floor_bits(a64),
            sf::f64_trunc_bits(a64),
            sf::f64_nearest_bits(a64),
        ];
        let expected64 = [
            canonical64(af64 + bf64),
            canonical64(af64 - bf64),
            canonical64(af64 * bf64),
            canonical64(af64 / bf64),
            canonical64(af64.sqrt()),
            canonical64(af64.ceil()),
            canonical64(af64.floor()),
            canonical64(af64.trunc()),
            canonical64(af64.round_ties_even()),
        ];
        assert_eq!(
            actual64, expected64,
            "f64 corpus index {index}: {a64:016x}/{b64:016x}"
        );

        assert_eq!(sf::f64_promote_f32_bits(a32), canonical64(f64::from(af32)));
        assert_eq!(sf::f32_demote_f64_bits(a64), canonical32(af64 as f32));
        assert_eq!(sf::f32_eq_bits(a32, b32), af32 == bf32);
        assert_eq!(sf::f32_ne_bits(a32, b32), af32 != bf32);
        assert_eq!(sf::f32_lt_bits(a32, b32), af32 < bf32);
        assert_eq!(sf::f32_le_bits(a32, b32), af32 <= bf32);
        assert_eq!(sf::f64_eq_bits(a64, b64), af64 == bf64);
        assert_eq!(sf::f64_ne_bits(a64, b64), af64 != bf64);
        assert_eq!(sf::f64_lt_bits(a64, b64), af64 < bf64);
        assert_eq!(sf::f64_le_bits(a64, b64), af64 <= bf64);

        for value in actual32 {
            mix(&mut digest, u64::from(value));
        }
        for value in actual64 {
            mix(&mut digest, value);
        }
    }
    assert_eq!(digest, 0x05e1_fa8e_3d77_9f53, "fixed corpus digest changed");
}

#[test]
fn boundary_corpus_covers_subnormal_zero_halfway_overflow_and_nan_classes() {
    let f32_values = [
        0x0000_0000,
        0x8000_0000,
        0x0000_0001,
        0x007f_ffff,
        0x0080_0000,
        0x3f00_0000,
        0x3f00_0001,
        0x3f80_0000,
        0x7f7f_ffff,
        0x7f80_0000,
        0xff80_0000,
        0x7f80_0001,
        0x7fc0_0000,
        0xffc1_2345,
    ];
    let f64_values = [
        0x0000_0000_0000_0000,
        0x8000_0000_0000_0000,
        0x0000_0000_0000_0001,
        0x000f_ffff_ffff_ffff,
        0x0010_0000_0000_0000,
        0x3fe0_0000_0000_0000,
        0x3fe0_0000_0000_0001,
        0x3ff0_0000_0000_0000,
        0x7fef_ffff_ffff_ffff,
        0x7ff0_0000_0000_0000,
        0xfff0_0000_0000_0000,
        0x7ff0_0000_0000_0001,
        0x7ff8_0000_0000_0000,
        0xfff8_0000_0001_2345,
    ];
    for &bits in &f32_values {
        let value = f32::from_bits(bits);
        assert_eq!(
            sf::f32_sqrt_bits(bits),
            canonical32(value.sqrt()),
            "sqrt32 {bits:08x}"
        );
        assert_eq!(
            sf::f32_nearest_bits(bits),
            canonical32(value.round_ties_even()),
            "nearest32 {bits:08x}"
        );
    }
    for &bits in &f64_values {
        let value = f64::from_bits(bits);
        assert_eq!(
            sf::f64_sqrt_bits(bits),
            canonical64(value.sqrt()),
            "sqrt64 {bits:016x}"
        );
        assert_eq!(
            sf::f64_nearest_bits(bits),
            canonical64(value.round_ties_even()),
            "nearest64 {bits:016x}"
        );
    }
    assert_eq!(sf::f32_min_bits(0x8000_0000, 0), 0x8000_0000);
    assert_eq!(sf::f32_max_bits(0x8000_0000, 0), 0);
    assert_eq!(
        sf::f64_min_bits(0x8000_0000_0000_0000, 0),
        0x8000_0000_0000_0000
    );
    assert_eq!(sf::f64_max_bits(0x8000_0000_0000_0000, 0), 0);
}
