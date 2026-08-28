#![cfg(feature = "c88-f3-acceptance")]

use std::panic::{catch_unwind, AssertUnwindSafe};

use vibeos_component_runtime::{
    abi_value::float_candidate::{
        lift_flat_values, lift_value, lower_parameters, lower_value, CandidateFlatValue,
        CandidateLoweredParameters, CodecError, PayloadAllocator, RejectResources,
    },
    memory::{GuestMemory, VecMemory},
    value::{CanonicalF32, CanonicalF64, CanonicalValue, ValuePosition, ValueType},
};

const CASES: usize = 4_096;
const EXPECTED_SCALAR_DIGEST: u64 = 0x8ebf_9db2_d447_2f51;
const EXPECTED_HOSTILE_DIGEST: u64 = 0x93ce_1dbf_abf6_b333;

#[derive(Clone, Copy)]
struct XorShift64(u64);

impl XorShift64 {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }
}

#[derive(Clone, Copy)]
struct Fnv64(u64);

impl Fnv64 {
    const fn new(domain: &[u8]) -> Self {
        let mut hash = Self(0xcbf2_9ce4_8422_2325);
        let mut index = 0;
        while index < domain.len() {
            hash.0 ^= domain[index] as u64;
            hash.0 = hash.0.wrapping_mul(0x0000_0100_0000_01b3);
            index += 1;
        }
        hash
    }

    fn byte(&mut self, value: u8) {
        self.0 ^= u64::from(value);
        self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
    }

    fn u16(&mut self, value: u16) {
        for byte in value.to_le_bytes() {
            self.byte(byte);
        }
    }

    fn u32(&mut self, value: u32) {
        for byte in value.to_le_bytes() {
            self.byte(byte);
        }
    }

    fn u64(&mut self, value: u64) {
        for byte in value.to_le_bytes() {
            self.byte(byte);
        }
    }

    const fn finish(self) -> u64 {
        self.0
    }
}

struct NoPayloadAllocation;

impl PayloadAllocator<VecMemory> for NoPayloadAllocation {
    fn allocate(
        &mut self,
        _memory: &mut VecMemory,
        _size: u32,
        _alignment: u32,
    ) -> Result<u32, CodecError> {
        Err(CodecError::Allocation)
    }
}

const fn oracle_f32(bits: u32) -> u32 {
    if bits & 0x7f80_0000 == 0x7f80_0000 && bits & 0x007f_ffff != 0 {
        0x7fc0_0000
    } else {
        bits
    }
}

const fn oracle_f64(bits: u64) -> u64 {
    if bits & 0x7ff0_0000_0000_0000 == 0x7ff0_0000_0000_0000 && bits & 0x000f_ffff_ffff_ffff != 0 {
        0x7ff8_0000_0000_0000
    } else {
        bits
    }
}

fn assert_f32(value: &CanonicalValue, expected: u32) {
    let CanonicalValue::F32(value) = value else {
        panic!("expected f32 candidate value")
    };
    assert_eq!(value.to_bits(), expected);
}

fn assert_f64(value: &CanonicalValue, expected: u64) {
    let CanonicalValue::F64(value) = value else {
        panic!("expected f64 candidate value")
    };
    assert_eq!(value.to_bits(), expected);
}

#[test]
fn fixed_seed_scalar_bits_are_panic_free_and_match_an_independent_oracle() {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut rng = XorShift64(0x6a09_e667_f3bc_c909);
        let mut hash = Fnv64::new(b"vibeos-c88-f3-scalar-bits-v1");
        let mut memory = VecMemory::new(128, 128).unwrap();
        let mut allocator = NoPayloadAllocation;
        for _ in 0..CASES {
            let raw32 = rng.next() as u32;
            let raw64 = rng.next();
            let expected32 = oracle_f32(raw32);
            let expected64 = oracle_f64(raw64);

            let wrapped32 = CanonicalF32::from_bits(raw32);
            let wrapped64 = CanonicalF64::from_bits(raw64);
            assert_eq!(wrapped32.to_bits(), expected32);
            assert_eq!(wrapped64.to_bits(), expected64);

            let (flat_lifted, _) = lift_flat_values(
                &memory,
                &RejectResources,
                &[ValueType::F32, ValueType::F64],
                &[
                    CandidateFlatValue::F32Bits(raw32),
                    CandidateFlatValue::F64Bits(raw64),
                ],
                ValuePosition::Parameter,
            )
            .unwrap();
            assert_f32(&flat_lifted[0], expected32);
            assert_f64(&flat_lifted[1], expected64);

            let CandidateLoweredParameters::Flat { values, usage } = lower_parameters(
                &mut memory,
                &mut allocator,
                &[ValueType::F32, ValueType::F64],
                &[
                    CanonicalValue::F32(wrapped32),
                    CanonicalValue::F64(wrapped64),
                ],
            )
            .unwrap() else {
                panic!("two scalar parameters must remain flat")
            };
            assert_eq!(
                values,
                vec![
                    CandidateFlatValue::F32Bits(expected32),
                    CandidateFlatValue::F64Bits(expected64),
                ]
            );
            assert_eq!(usage.allocations, 0);

            memory.write_exact(32, &raw32.to_le_bytes()).unwrap();
            memory.write_exact(40, &raw64.to_le_bytes()).unwrap();
            let (memory32, _) = lift_value(
                &memory,
                &RejectResources,
                &ValueType::F32,
                32,
                ValuePosition::Parameter,
            )
            .unwrap();
            let (memory64, _) = lift_value(
                &memory,
                &RejectResources,
                &ValueType::F64,
                40,
                ValuePosition::Parameter,
            )
            .unwrap();
            assert_f32(&memory32, expected32);
            assert_f64(&memory64, expected64);
            lower_value(
                &mut memory,
                &mut allocator,
                &ValueType::F32,
                &memory32,
                48,
                ValuePosition::Result,
            )
            .unwrap();
            lower_value(
                &mut memory,
                &mut allocator,
                &ValueType::F64,
                &memory64,
                56,
                ValuePosition::Result,
            )
            .unwrap();
            let mut lowered32 = [0; 4];
            let mut lowered64 = [0; 8];
            memory.read_exact(48, &mut lowered32).unwrap();
            memory.read_exact(56, &mut lowered64).unwrap();
            assert_eq!(u32::from_le_bytes(lowered32), expected32);
            assert_eq!(u64::from_le_bytes(lowered64), expected64);

            hash.u32(raw32);
            hash.u64(raw64);
            hash.u32(expected32);
            hash.u64(expected64);
        }
        hash.finish()
    }));
    assert!(outcome.is_ok(), "the scalar bit corpus must never panic");
    assert_eq!(outcome.unwrap(), EXPECTED_SCALAR_DIGEST);
}

#[test]
fn fixed_seed_nested_hostile_memory_has_stable_classification() {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let ty = ValueType::Variant(vec![
            Some(ValueType::List(Box::new(ValueType::F32))),
            Some(ValueType::F64),
            None,
        ]);
        let mut rng = XorShift64(0xbb67_ae85_84ca_a73b);
        let mut hash = Fnv64::new(b"vibeos-c88-f3-hostile-memory-v1");
        for _ in 0..CASES {
            let raw32 = rng.next() as u32;
            let raw64 = rng.next();
            let scenario = (rng.next() & 7) as u8;
            let mut memory = VecMemory::new(256, 256).unwrap();
            let mut root = 64;
            let expected_error = match scenario {
                0 => {
                    memory.write_exact(64, &[0]).unwrap();
                    memory.write_exact(72, &128_u32.to_le_bytes()).unwrap();
                    memory.write_exact(76, &1_u32.to_le_bytes()).unwrap();
                    memory.write_exact(128, &raw32.to_le_bytes()).unwrap();
                    None
                }
                1 => {
                    memory.write_exact(64, &[1]).unwrap();
                    memory.write_exact(72, &raw64.to_le_bytes()).unwrap();
                    None
                }
                2 => {
                    memory.write_exact(64, &[2]).unwrap();
                    None
                }
                3 => {
                    memory.write_exact(64, &[3]).unwrap();
                    Some(CodecError::InvalidDiscriminant)
                }
                4 => {
                    memory.write_exact(64, &[0]).unwrap();
                    memory.write_exact(72, &130_u32.to_le_bytes()).unwrap();
                    memory.write_exact(76, &1_u32.to_le_bytes()).unwrap();
                    Some(CodecError::Misaligned)
                }
                5 => {
                    memory.write_exact(64, &[0]).unwrap();
                    memory.write_exact(72, &128_u32.to_le_bytes()).unwrap();
                    memory.write_exact(76, &4_097_u32.to_le_bytes()).unwrap();
                    Some(CodecError::ElementLimit)
                }
                6 => {
                    memory.write_exact(64, &[0]).unwrap();
                    memory
                        .write_exact(72, &0xffff_fffc_u32.to_le_bytes())
                        .unwrap();
                    memory.write_exact(76, &2_u32.to_le_bytes()).unwrap();
                    Some(CodecError::OutOfBounds)
                }
                7 => {
                    root = 66;
                    Some(CodecError::Misaligned)
                }
                _ => unreachable!(),
            };

            let result = lift_value(
                &memory,
                &RejectResources,
                &ty,
                root,
                ValuePosition::Parameter,
            );
            hash.byte(scenario);
            match (scenario, result, expected_error) {
                (0, Ok((CanonicalValue::Variant { case: 0, payload }, usage)), None) => {
                    let Some(payload) = payload else {
                        panic!("list case has a payload")
                    };
                    let CanonicalValue::List(values) = payload.as_ref() else {
                        panic!("case zero is list<f32>")
                    };
                    assert_eq!(values.len(), 1);
                    assert_f32(&values[0], oracle_f32(raw32));
                    hash.u32(oracle_f32(raw32));
                    hash.u32(usage.list_elements);
                }
                (1, Ok((CanonicalValue::Variant { case: 1, payload }, usage)), None) => {
                    let Some(payload) = payload else {
                        panic!("f64 case has a payload")
                    };
                    assert_f64(payload.as_ref(), oracle_f64(raw64));
                    hash.u64(oracle_f64(raw64));
                    hash.u32(usage.nodes);
                }
                (
                    2,
                    Ok((
                        CanonicalValue::Variant {
                            case: 2,
                            payload: None,
                        },
                        usage,
                    )),
                    None,
                ) => {
                    hash.u32(usage.nodes);
                }
                (_, Err(actual), Some(expected)) => {
                    assert_eq!(actual, expected);
                    hash.u16(actual.code());
                }
                (_, other, expected) => {
                    panic!("unexpected hostile classification: {other:?}, expected {expected:?}")
                }
            }
        }
        hash.finish()
    }));
    assert!(
        outcome.is_ok(),
        "the hostile nested corpus must never panic"
    );
    assert_eq!(outcome.unwrap(), EXPECTED_HOSTILE_DIGEST);
}
