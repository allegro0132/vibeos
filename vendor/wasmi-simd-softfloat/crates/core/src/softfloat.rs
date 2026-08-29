//! Deterministic IEEE-754 operations for the C8.10-S2 fixed-SIMD candidate.
//!
//! Arithmetic and conversions use `rustc_apfloat`, which performs no host
//! floating-point operations. Square root uses a fixed 24/53-round restoring
//! integer square root and an exact midpoint comparison. Primitive `f32` and
//! `f64` values appear only as bit containers at the Wasmi API boundary.

use crate::TrapCode;
use core::cmp::Ordering;
use rustc_apfloat::{
    ieee::{Double, Single},
    Float as ApFloat, FloatConvert, Round, Status,
};

pub const F32_CANONICAL_NAN: u32 = 0x7fc0_0000;
pub const F64_CANONICAL_NAN: u64 = 0x7ff8_0000_0000_0000;

const F32_SIGN: u32 = 1 << 31;
const F64_SIGN: u64 = 1 << 63;
const F32_ABS: u32 = !F32_SIGN;
const F64_ABS: u64 = !F64_SIGN;
const F32_EXP: u32 = 0x7f80_0000;
const F64_EXP: u64 = 0x7ff0_0000_0000_0000;
const F32_FRAC: u32 = 0x007f_ffff;
const F64_FRAC: u64 = 0x000f_ffff_ffff_ffff;

// Keep the bit classifier out of primitive-float ABI wrappers.  LLVM can
// otherwise recognize an inlined `f32::to_bits` plus this mask as an unordered
// floating-point comparison and reintroduce a target `__unordsf2` helper on
// soft-float RISC-V. The non-inlined integer ABI is part of the S2 audit
// boundary, not a performance hint.
#[inline(never)]
pub fn f32_is_nan(bits: u32) -> bool {
    bits & F32_EXP == F32_EXP && bits & F32_FRAC != 0
}

#[inline(never)]
pub fn f64_is_nan(bits: u64) -> bool {
    bits & F64_EXP == F64_EXP && bits & F64_FRAC != 0
}

#[inline]
fn canonical_f32(bits: u32) -> u32 {
    if f32_is_nan(bits) {
        F32_CANONICAL_NAN
    } else {
        bits
    }
}

#[inline]
fn canonical_f64(bits: u64) -> u64 {
    if f64_is_nan(bits) {
        F64_CANONICAL_NAN
    } else {
        bits
    }
}

#[inline]
fn single(bits: u32) -> Single {
    Single::from_bits(u128::from(bits))
}

#[inline]
fn double(bits: u64) -> Double {
    Double::from_bits(u128::from(bits))
}

#[inline]
fn single_bits(value: Single) -> u32 {
    canonical_f32(value.to_bits() as u32)
}

#[inline]
fn double_bits(value: Double) -> u64 {
    canonical_f64(value.to_bits() as u64)
}

macro_rules! binary_apfloat {
    ($name32:ident, $name64:ident, $method:ident) => {
        #[inline]
        pub fn $name32(lhs: u32, rhs: u32) -> u32 {
            if f32_is_nan(lhs) || f32_is_nan(rhs) {
                return F32_CANONICAL_NAN;
            }
            single_bits(
                single(lhs)
                    .$method(single(rhs), Round::NearestTiesToEven)
                    .value,
            )
        }

        #[inline]
        pub fn $name64(lhs: u64, rhs: u64) -> u64 {
            if f64_is_nan(lhs) || f64_is_nan(rhs) {
                return F64_CANONICAL_NAN;
            }
            double_bits(
                double(lhs)
                    .$method(double(rhs), Round::NearestTiesToEven)
                    .value,
            )
        }
    };
}

binary_apfloat!(f32_add_bits, f64_add_bits, add_r);
binary_apfloat!(f32_sub_bits, f64_sub_bits, sub_r);
binary_apfloat!(f32_mul_bits, f64_mul_bits, mul_r);
binary_apfloat!(f32_div_bits, f64_div_bits, div_r);

macro_rules! round_apfloat {
    ($name32:ident, $name64:ident, $round:expr) => {
        #[inline]
        pub fn $name32(value: u32) -> u32 {
            if f32_is_nan(value) {
                return F32_CANONICAL_NAN;
            }
            single_bits(single(value).round_to_integral($round).value)
        }

        #[inline]
        pub fn $name64(value: u64) -> u64 {
            if f64_is_nan(value) {
                return F64_CANONICAL_NAN;
            }
            double_bits(double(value).round_to_integral($round).value)
        }
    };
}

round_apfloat!(f32_ceil_bits, f64_ceil_bits, Round::TowardPositive);
round_apfloat!(f32_floor_bits, f64_floor_bits, Round::TowardNegative);
round_apfloat!(f32_trunc_bits, f64_trunc_bits, Round::TowardZero);
round_apfloat!(f32_nearest_bits, f64_nearest_bits, Round::NearestTiesToEven);

#[inline]
pub const fn f32_abs_bits(value: u32) -> u32 {
    value & F32_ABS
}

#[inline]
pub const fn f64_abs_bits(value: u64) -> u64 {
    value & F64_ABS
}

#[inline]
pub const fn f32_neg_bits(value: u32) -> u32 {
    value ^ F32_SIGN
}

#[inline]
pub const fn f64_neg_bits(value: u64) -> u64 {
    value ^ F64_SIGN
}

#[inline]
pub const fn f32_copysign_bits(lhs: u32, rhs: u32) -> u32 {
    (lhs & F32_ABS) | (rhs & F32_SIGN)
}

#[inline]
pub const fn f64_copysign_bits(lhs: u64, rhs: u64) -> u64 {
    (lhs & F64_ABS) | (rhs & F64_SIGN)
}

#[inline]
fn f32_order_key(bits: u32) -> u32 {
    if bits & F32_SIGN != 0 {
        !bits
    } else {
        bits | F32_SIGN
    }
}

#[inline]
fn f64_order_key(bits: u64) -> u64 {
    if bits & F64_SIGN != 0 {
        !bits
    } else {
        bits | F64_SIGN
    }
}

#[inline]
pub fn f32_partial_cmp_bits(lhs: u32, rhs: u32) -> Option<Ordering> {
    if f32_is_nan(lhs) || f32_is_nan(rhs) {
        return None;
    }
    if lhs & F32_ABS == 0 && rhs & F32_ABS == 0 {
        return Some(Ordering::Equal);
    }
    Some(f32_order_key(lhs).cmp(&f32_order_key(rhs)))
}

#[inline]
pub fn f64_partial_cmp_bits(lhs: u64, rhs: u64) -> Option<Ordering> {
    if f64_is_nan(lhs) || f64_is_nan(rhs) {
        return None;
    }
    if lhs & F64_ABS == 0 && rhs & F64_ABS == 0 {
        return Some(Ordering::Equal);
    }
    Some(f64_order_key(lhs).cmp(&f64_order_key(rhs)))
}

macro_rules! comparisons {
    ($eq:ident, $ne:ident, $lt:ident, $le:ident, $gt:ident, $ge:ident, $cmp:ident, $bits:ty) => {
        #[inline]
        pub fn $eq(lhs: $bits, rhs: $bits) -> bool {
            $cmp(lhs, rhs) == Some(Ordering::Equal)
        }
        #[inline]
        pub fn $ne(lhs: $bits, rhs: $bits) -> bool {
            $cmp(lhs, rhs) != Some(Ordering::Equal)
        }
        #[inline]
        pub fn $lt(lhs: $bits, rhs: $bits) -> bool {
            $cmp(lhs, rhs) == Some(Ordering::Less)
        }
        #[inline]
        pub fn $le(lhs: $bits, rhs: $bits) -> bool {
            matches!($cmp(lhs, rhs), Some(Ordering::Less | Ordering::Equal))
        }
        #[inline]
        pub fn $gt(lhs: $bits, rhs: $bits) -> bool {
            $cmp(lhs, rhs) == Some(Ordering::Greater)
        }
        #[inline]
        pub fn $ge(lhs: $bits, rhs: $bits) -> bool {
            matches!($cmp(lhs, rhs), Some(Ordering::Greater | Ordering::Equal))
        }
    };
}

comparisons!(
    f32_eq_bits,
    f32_ne_bits,
    f32_lt_bits,
    f32_le_bits,
    f32_gt_bits,
    f32_ge_bits,
    f32_partial_cmp_bits,
    u32
);
comparisons!(
    f64_eq_bits,
    f64_ne_bits,
    f64_lt_bits,
    f64_le_bits,
    f64_gt_bits,
    f64_ge_bits,
    f64_partial_cmp_bits,
    u64
);

#[inline]
pub fn f32_min_bits(lhs: u32, rhs: u32) -> u32 {
    match f32_partial_cmp_bits(lhs, rhs) {
        None => F32_CANONICAL_NAN,
        Some(Ordering::Less) => lhs,
        Some(Ordering::Greater) => rhs,
        Some(Ordering::Equal) => lhs | rhs,
    }
}

#[inline]
pub fn f32_max_bits(lhs: u32, rhs: u32) -> u32 {
    match f32_partial_cmp_bits(lhs, rhs) {
        None => F32_CANONICAL_NAN,
        Some(Ordering::Less) => rhs,
        Some(Ordering::Greater) => lhs,
        Some(Ordering::Equal) => lhs & rhs,
    }
}

#[inline]
pub fn f64_min_bits(lhs: u64, rhs: u64) -> u64 {
    match f64_partial_cmp_bits(lhs, rhs) {
        None => F64_CANONICAL_NAN,
        Some(Ordering::Less) => lhs,
        Some(Ordering::Greater) => rhs,
        Some(Ordering::Equal) => lhs | rhs,
    }
}

#[inline]
pub fn f64_max_bits(lhs: u64, rhs: u64) -> u64 {
    match f64_partial_cmp_bits(lhs, rhs) {
        None => F64_CANONICAL_NAN,
        Some(Ordering::Less) => rhs,
        Some(Ordering::Greater) => lhs,
        Some(Ordering::Equal) => lhs & rhs,
    }
}

/// Returns `floor(sqrt(value))` in exactly `rounds` restoring rounds.
fn isqrt_u128(value: u128, rounds: u32) -> u128 {
    let rounds = rounds.max(1).min(64);
    let mut remainder = value;
    let mut root = 0_u128;
    let mut bit = 1_u128 << ((rounds - 1) * 2);
    for _ in 0..rounds {
        let candidate = root + bit;
        if remainder >= candidate {
            remainder -= candidate;
            root = (root >> 1) + bit;
        } else {
            root >>= 1;
        }
        bit >>= 2;
    }
    root
}

/// Correctly rounds a positive, finite binary float significand to nearest,
/// ties-to-even. The exact square-root midpoint cannot be a half integer when
/// `radicand` is integral, but the even guard is retained in the proof-shaped
/// comparison.
fn rounded_sqrt_significand(radicand: u128, rounds: u32) -> u128 {
    let root = isqrt_u128(radicand, rounds);
    let twice_plus_one = root * 2 + 1;
    let midpoint_square = twice_plus_one * twice_plus_one;
    let four_radicand = radicand * 4;
    if four_radicand > midpoint_square || (four_radicand == midpoint_square && root & 1 != 0) {
        root + 1
    } else {
        root
    }
}

fn sqrt_bits(
    bits: u64,
    sign_mask: u64,
    exponent_mask: u64,
    fraction_mask: u64,
    exponent_shift: u32,
    precision: u32,
    bias: i32,
    canonical_nan: u64,
) -> u64 {
    let abs = bits & !sign_mask;
    if abs == 0 {
        return bits;
    }
    if bits & exponent_mask == exponent_mask {
        if bits & fraction_mask == 0 && bits & sign_mask == 0 {
            return bits;
        }
        return canonical_nan;
    }
    if bits & sign_mask != 0 {
        return canonical_nan;
    }

    let encoded_exp = ((bits & exponent_mask) >> exponent_shift) as i32;
    let fraction = bits & fraction_mask;
    let (significand, exponent) = if encoded_exp == 0 {
        let leading = 63 - fraction.leading_zeros();
        let shift = (precision - 1) - leading;
        (fraction << shift, 1 - bias - shift as i32)
    } else {
        (fraction | (1_u64 << (precision - 1)), encoded_exp - bias)
    };
    let odd = exponent.rem_euclid(2) as u32;
    let mut result_exp = (exponent - odd as i32) / 2;
    let radicand = u128::from(significand) << (precision - 1 + odd);
    let mut result_significand = rounded_sqrt_significand(radicand, precision);
    if result_significand == 1_u128 << precision {
        result_significand >>= 1;
        result_exp += 1;
    }
    let encoded_result_exp = (result_exp + bias) as u64;
    if encoded_result_exp == 0 || encoded_result_exp >= exponent_mask >> exponent_shift {
        // This is unreachable for a positive finite IEEE-754 input, but the
        // candidate backend remains panic-free if its decoder is changed.
        return canonical_nan;
    }
    (encoded_result_exp << exponent_shift) | result_significand as u64 & fraction_mask
}

#[inline]
pub fn f32_sqrt_bits(value: u32) -> u32 {
    sqrt_bits(
        u64::from(value),
        u64::from(F32_SIGN),
        u64::from(F32_EXP),
        u64::from(F32_FRAC),
        23,
        24,
        127,
        u64::from(F32_CANONICAL_NAN),
    ) as u32
}

#[inline]
pub fn f64_sqrt_bits(value: u64) -> u64 {
    sqrt_bits(
        value,
        F64_SIGN,
        F64_EXP,
        F64_FRAC,
        52,
        53,
        1023,
        F64_CANONICAL_NAN,
    )
}

#[inline]
pub fn f32_demote_f64_bits(value: u64) -> u32 {
    if f64_is_nan(value) {
        return F32_CANONICAL_NAN;
    }
    let mut loses_info = false;
    let converted = <Double as FloatConvert<Single>>::convert_r(
        double(value),
        Round::NearestTiesToEven,
        &mut loses_info,
    );
    single_bits(converted.value)
}

#[inline]
pub fn f64_promote_f32_bits(value: u32) -> u64 {
    if f32_is_nan(value) {
        return F64_CANONICAL_NAN;
    }
    let mut loses_info = false;
    let converted = <Single as FloatConvert<Double>>::convert_r(
        single(value),
        Round::NearestTiesToEven,
        &mut loses_info,
    );
    double_bits(converted.value)
}

#[inline]
fn invalid_conversion(status: Status) -> Result<(), TrapCode> {
    if status.intersects(Status::INVALID_OP) {
        Err(TrapCode::IntegerOverflow)
    } else {
        Ok(())
    }
}

macro_rules! trunc_signed {
    ($name:ident, $ap:ident, $nan:ident, $input:ty, $output:ty, $width:expr) => {
        #[inline]
        pub fn $name(value: $input) -> Result<$output, TrapCode> {
            if $nan(value) {
                return Err(TrapCode::BadConversionToInteger);
            }
            let mut exact = false;
            let converted = $ap(value).to_i128_r($width, Round::TowardZero, &mut exact);
            invalid_conversion(converted.status)?;
            Ok(converted.value as $output)
        }
    };
}

macro_rules! trunc_unsigned {
    ($name:ident, $ap:ident, $nan:ident, $input:ty, $output:ty, $width:expr) => {
        #[inline]
        pub fn $name(value: $input) -> Result<$output, TrapCode> {
            if $nan(value) {
                return Err(TrapCode::BadConversionToInteger);
            }
            let mut exact = false;
            let converted = $ap(value).to_u128_r($width, Round::TowardZero, &mut exact);
            invalid_conversion(converted.status)?;
            Ok(converted.value as $output)
        }
    };
}

trunc_signed!(i32_trunc_f32_s_bits, single, f32_is_nan, u32, i32, 32);
trunc_signed!(i64_trunc_f32_s_bits, single, f32_is_nan, u32, i64, 64);
trunc_unsigned!(i32_trunc_f32_u_bits, single, f32_is_nan, u32, u32, 32);
trunc_unsigned!(i64_trunc_f32_u_bits, single, f32_is_nan, u32, u64, 64);
trunc_signed!(i32_trunc_f64_s_bits, double, f64_is_nan, u64, i32, 32);
trunc_signed!(i64_trunc_f64_s_bits, double, f64_is_nan, u64, i64, 64);
trunc_unsigned!(i32_trunc_f64_u_bits, double, f64_is_nan, u64, u32, 32);
trunc_unsigned!(i64_trunc_f64_u_bits, double, f64_is_nan, u64, u64, 64);

macro_rules! trunc_saturating_signed {
    ($name:ident, $trunc:ident, $nan:ident, $input:ty, $output:ty, $sign:expr) => {
        #[inline]
        pub fn $name(value: $input) -> $output {
            if $nan(value) {
                return 0;
            }
            match $trunc(value) {
                Ok(value) => value,
                Err(_) if value & $sign != 0 => <$output>::MIN,
                Err(_) => <$output>::MAX,
            }
        }
    };
}

macro_rules! trunc_saturating_unsigned {
    ($name:ident, $trunc:ident, $nan:ident, $input:ty, $output:ty, $sign:expr) => {
        #[inline]
        pub fn $name(value: $input) -> $output {
            if $nan(value) {
                return 0;
            }
            match $trunc(value) {
                Ok(value) => value,
                Err(_) if value & $sign != 0 => 0,
                Err(_) => <$output>::MAX,
            }
        }
    };
}

trunc_saturating_signed!(
    i32_trunc_sat_f32_s_bits,
    i32_trunc_f32_s_bits,
    f32_is_nan,
    u32,
    i32,
    F32_SIGN
);
trunc_saturating_unsigned!(
    i32_trunc_sat_f32_u_bits,
    i32_trunc_f32_u_bits,
    f32_is_nan,
    u32,
    u32,
    F32_SIGN
);
trunc_saturating_signed!(
    i64_trunc_sat_f32_s_bits,
    i64_trunc_f32_s_bits,
    f32_is_nan,
    u32,
    i64,
    F32_SIGN
);
trunc_saturating_unsigned!(
    i64_trunc_sat_f32_u_bits,
    i64_trunc_f32_u_bits,
    f32_is_nan,
    u32,
    u64,
    F32_SIGN
);
trunc_saturating_signed!(
    i32_trunc_sat_f64_s_bits,
    i32_trunc_f64_s_bits,
    f64_is_nan,
    u64,
    i32,
    F64_SIGN
);
trunc_saturating_unsigned!(
    i32_trunc_sat_f64_u_bits,
    i32_trunc_f64_u_bits,
    f64_is_nan,
    u64,
    u32,
    F64_SIGN
);
trunc_saturating_signed!(
    i64_trunc_sat_f64_s_bits,
    i64_trunc_f64_s_bits,
    f64_is_nan,
    u64,
    i64,
    F64_SIGN
);
trunc_saturating_unsigned!(
    i64_trunc_sat_f64_u_bits,
    i64_trunc_f64_u_bits,
    f64_is_nan,
    u64,
    u64,
    F64_SIGN
);

macro_rules! int_to_float {
    ($name:ident, $ap:ty, $method:ident, $input:ty, $output:ty) => {
        #[inline]
        pub fn $name(value: $input) -> $output {
            <$ap>::$method(value as _, Round::NearestTiesToEven)
                .value
                .to_bits() as $output
        }
    };
}

int_to_float!(f32_convert_i32_s_bits, Single, from_i128_r, i32, u32);
int_to_float!(f32_convert_i32_u_bits, Single, from_u128_r, u32, u32);
int_to_float!(f32_convert_i64_s_bits, Single, from_i128_r, i64, u32);
int_to_float!(f32_convert_i64_u_bits, Single, from_u128_r, u64, u32);
int_to_float!(f64_convert_i32_s_bits, Double, from_i128_r, i32, u64);
int_to_float!(f64_convert_i32_u_bits, Double, from_u128_r, u32, u64);
int_to_float!(f64_convert_i64_s_bits, Double, from_i128_r, i64, u64);
int_to_float!(f64_convert_i64_u_bits, Double, from_u128_r, u64, u64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_sqrt_rounding_covers_boundaries() {
        assert_eq!(isqrt_u128(0, 64), 0);
        assert_eq!(isqrt_u128(1, 64), 1);
        assert_eq!(isqrt_u128(2, 64), 1);
        assert_eq!(isqrt_u128(3, 64), 1);
        assert_eq!(isqrt_u128(4, 64), 2);
        assert_eq!(isqrt_u128(u128::MAX, 64), u64::MAX as u128);
    }

    #[test]
    fn exact_sqrt_special_cases_and_known_values() {
        assert_eq!(f32_sqrt_bits(0), 0);
        assert_eq!(f32_sqrt_bits(F32_SIGN), F32_SIGN);
        assert_eq!(f32_sqrt_bits(0x4080_0000), 0x4000_0000);
        assert_eq!(f32_sqrt_bits(0x4000_0000), 0x3fb5_04f3);
        assert_eq!(f32_sqrt_bits(1), 0x1a35_04f3);
        assert_eq!(f32_sqrt_bits(0xbf80_0000), F32_CANONICAL_NAN);
        assert_eq!(f64_sqrt_bits(0x4010_0000_0000_0000), 0x4000_0000_0000_0000);
        assert_eq!(f64_sqrt_bits(0x4000_0000_0000_0000), 0x3ff6_a09e_667f_3bcd);
        assert_eq!(f64_sqrt_bits(1), 0x1e60_0000_0000_0000);
        assert_eq!(f64_sqrt_bits(0xbff0_0000_0000_0000), F64_CANONICAL_NAN);
    }

    #[test]
    fn canonical_and_sign_only_nan_rules_are_disjoint() {
        let f32_nan = 0xff81_2345;
        let f64_nan = 0xfff0_0000_0001_2345;
        assert_eq!(f32_add_bits(f32_nan, 0), F32_CANONICAL_NAN);
        assert_eq!(f64_add_bits(f64_nan, 0), F64_CANONICAL_NAN);
        assert_eq!(f32_abs_bits(f32_nan), 0x7f81_2345);
        assert_eq!(f64_neg_bits(f64_nan), 0x7ff0_0000_0001_2345);
        assert_eq!(f32_copysign_bits(f32_nan, 0), 0x7f81_2345);
    }
}
