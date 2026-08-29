use crate::{hint::unlikely, TrapCode};

/// Type of a value.
///
/// See [`Val`] for details.
///
/// [`Val`]: enum.Value.html
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValType {
    /// 32-bit signed or unsigned integer.
    I32,
    /// 64-bit signed or unsigned integer.
    I64,
    /// 32-bit IEEE 754-2008 floating point number.
    F32,
    /// 64-bit IEEE 754-2008 floating point number.
    F64,
    /// A 128-bit Wasm `simd` proposal vector.
    V128,
    /// A nullable function reference.
    FuncRef,
    /// A nullable external reference.
    ExternRef,
}

impl ValType {
    /// Returns `true` if [`ValType`] is a Wasm numeric type.
    ///
    /// This is `true` for [`ValType::I32`], [`ValType::I64`],
    /// [`ValType::F32`] and [`ValType::F64`].
    pub fn is_num(&self) -> bool {
        matches!(self, Self::I32 | Self::I64 | Self::F32 | Self::F64)
    }

    /// Returns `true` if [`ValType`] is a Wasm reference type.
    ///
    /// This is `true` for [`ValType::FuncRef`] and [`ValType::ExternRef`].
    pub fn is_ref(&self) -> bool {
        matches!(self, Self::ExternRef | Self::FuncRef)
    }
}

/// Sign-extends `Self` integer type from `T` integer type.
pub trait SignExtendFrom<T> {
    /// Convert one type to another by extending with leading zeroes.
    fn sign_extend_from(self) -> Self;
}

/// Integer value.
pub trait Integer: Sized + Unsigned {
    /// Returns `true` if `self` is zero.
    #[allow(clippy::wrong_self_convention)]
    fn is_zero(self) -> bool;
    /// Counts leading zeros in the bitwise representation of the value.
    fn leading_zeros(self) -> Self;
    /// Counts trailing zeros in the bitwise representation of the value.
    fn trailing_zeros(self) -> Self;
    /// Counts 1-bits in the bitwise representation of the value.
    fn count_ones(self) -> Self;
    /// Shift-left `self` by `other`.
    fn shl(lhs: Self, rhs: Self) -> Self;
    /// Signed shift-right `self` by `other`.
    fn shr_s(lhs: Self, rhs: Self) -> Self;
    /// Unsigned shift-right `self` by `other`.
    fn shr_u(lhs: Self, rhs: Self) -> Self;
    /// Get left bit rotation result.
    fn rotl(lhs: Self, rhs: Self) -> Self;
    /// Get right bit rotation result.
    fn rotr(lhs: Self, rhs: Self) -> Self;
    /// Signed integer division.
    ///
    /// # Errors
    ///
    /// If `other` is equal to zero.
    fn div_s(lhs: Self, rhs: Self) -> Result<Self, TrapCode>;
    /// Unsigned integer division.
    ///
    /// # Errors
    ///
    /// If `other` is equal to zero.
    fn div_u(lhs: Self::Uint, rhs: Self::Uint) -> Result<Self::Uint, TrapCode>;
    /// Signed integer remainder.
    ///
    /// # Errors
    ///
    /// If `other` is equal to zero.
    fn rem_s(lhs: Self, rhs: Self) -> Result<Self, TrapCode>;
    /// Unsigned integer remainder.
    ///
    /// # Errors
    ///
    /// If `other` is equal to zero.
    fn rem_u(lhs: Self::Uint, rhs: Self::Uint) -> Result<Self::Uint, TrapCode>;
}

/// Integer types that have an unsigned mirroring type.
pub trait Unsigned {
    /// The unsigned type.
    type Uint;

    /// Converts `self` losslessly to the unsigned type.
    fn to_unsigned(self) -> Self::Uint;
}

impl Unsigned for i32 {
    type Uint = u32;
    #[inline]
    fn to_unsigned(self) -> Self::Uint {
        self as _
    }
}

impl Unsigned for i64 {
    type Uint = u64;
    #[inline]
    fn to_unsigned(self) -> Self::Uint {
        self as _
    }
}

macro_rules! impl_sign_extend_from {
    ( $( impl SignExtendFrom<$from_type:ty> for $for_type:ty; )* ) => {
        $(
            impl SignExtendFrom<$from_type> for $for_type {
                #[inline]
                #[allow(clippy::cast_lossless)]
                fn sign_extend_from(self) -> Self {
                    (self as $from_type) as Self
                }
            }
        )*
    };
}
impl_sign_extend_from! {
    impl SignExtendFrom<i8> for i32;
    impl SignExtendFrom<i16> for i32;
    impl SignExtendFrom<i8> for i64;
    impl SignExtendFrom<i16> for i64;
    impl SignExtendFrom<i32> for i64;
}

macro_rules! impl_integer {
    ($ty:ty) => {
        impl Integer for $ty {
            #[inline]
            fn is_zero(self) -> bool {
                self == 0
            }
            #[inline]
            #[allow(clippy::cast_lossless)]
            fn leading_zeros(self) -> Self {
                self.leading_zeros() as _
            }
            #[inline]
            #[allow(clippy::cast_lossless)]
            fn trailing_zeros(self) -> Self {
                self.trailing_zeros() as _
            }
            #[inline]
            #[allow(clippy::cast_lossless)]
            fn count_ones(self) -> Self {
                self.count_ones() as _
            }
            #[inline]
            fn shl(lhs: Self, rhs: Self) -> Self {
                lhs.wrapping_shl(rhs as u32)
            }
            #[inline]
            fn shr_s(lhs: Self, rhs: Self) -> Self {
                lhs.wrapping_shr(rhs as u32)
            }
            #[inline]
            fn shr_u(lhs: Self, rhs: Self) -> Self {
                lhs.to_unsigned().wrapping_shr(rhs as u32) as _
            }
            #[inline]
            fn rotl(lhs: Self, rhs: Self) -> Self {
                lhs.rotate_left(rhs as u32)
            }
            #[inline]
            fn rotr(lhs: Self, rhs: Self) -> Self {
                lhs.rotate_right(rhs as u32)
            }
            #[inline]
            fn div_s(lhs: Self, rhs: Self) -> Result<Self, TrapCode> {
                if unlikely(rhs == 0) {
                    return Err(TrapCode::IntegerDivisionByZero);
                }
                let (result, overflow) = lhs.overflowing_div(rhs);
                if unlikely(overflow) {
                    return Err(TrapCode::IntegerOverflow);
                }
                Ok(result)
            }
            #[inline]
            fn div_u(lhs: Self::Uint, rhs: Self::Uint) -> Result<Self::Uint, TrapCode> {
                if unlikely(rhs == 0) {
                    return Err(TrapCode::IntegerDivisionByZero);
                }
                let (result, overflow) = lhs.overflowing_div(rhs);
                if unlikely(overflow) {
                    return Err(TrapCode::IntegerOverflow);
                }
                Ok(result)
            }
            #[inline]
            fn rem_s(lhs: Self, rhs: Self) -> Result<Self, TrapCode> {
                if unlikely(rhs == 0) {
                    return Err(TrapCode::IntegerDivisionByZero);
                }
                Ok(lhs.wrapping_rem(rhs))
            }
            #[inline]
            fn rem_u(lhs: Self::Uint, rhs: Self::Uint) -> Result<Self::Uint, TrapCode> {
                if unlikely(rhs == 0) {
                    return Err(TrapCode::IntegerDivisionByZero);
                }
                Ok(lhs.wrapping_rem(rhs))
            }
        }
    };
}
impl_integer!(i32);
impl_integer!(i64);

/// The Wasm `simd` proposal's `v128` type.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct V128([u8; 16]);

impl From<u128> for V128 {
    fn from(value: u128) -> Self {
        Self(value.to_le_bytes())
    }
}

impl V128 {
    /// Returns the `self` as a 128-bit Rust integer.
    pub fn as_u128(&self) -> u128 {
        u128::from_le_bytes(self.0)
    }
}
