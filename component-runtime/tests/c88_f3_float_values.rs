#![cfg(feature = "c88-f3-acceptance")]

use vibeos_component_runtime::{
    abi_value::float_candidate::{
        flat_signature, lift_flat_values, lift_parameters, lift_results, lift_value,
        lower_flat_results_prepared, lower_parameters, lower_results, lower_value,
        CandidateFlatKind, CandidateFlatValue, CandidateLoweredParameters, CandidateLoweredResults,
        CandidatePreparedFlatResults, CodecError, PayloadAllocator, RejectResources,
    },
    memory::{GuestMemory, VecMemory},
    value::{validate_type, CanonicalF32, CanonicalF64, CanonicalValue, ValuePosition, ValueType},
};

#[derive(Default)]
struct Bump {
    next: u32,
    requests: Vec<(u32, u32, u32)>,
}

impl Bump {
    fn at(next: u32) -> Self {
        Self {
            next,
            requests: Vec::new(),
        }
    }
}

impl PayloadAllocator<VecMemory> for Bump {
    fn allocate(
        &mut self,
        memory: &mut VecMemory,
        size: u32,
        alignment: u32,
    ) -> Result<u32, CodecError> {
        let mask = alignment.checked_sub(1).ok_or(CodecError::Misaligned)?;
        let pointer = self.next.checked_add(mask).ok_or(CodecError::Overflow)? & !mask;
        let end = pointer.checked_add(size).ok_or(CodecError::Overflow)?;
        memory.grow_to(end as usize).map_err(CodecError::from)?;
        self.next = end.max(pointer.saturating_add(1));
        self.requests.push((size, alignment, pointer));
        Ok(pointer)
    }
}

fn memory() -> VecMemory {
    VecMemory::new(256, 128 * 1024).unwrap()
}

fn f32v(bits: u32) -> CanonicalValue {
    CanonicalValue::F32(CanonicalF32::from_bits(bits))
}

fn f64v(bits: u64) -> CanonicalValue {
    CanonicalValue::F64(CanonicalF64::from_bits(bits))
}

#[test]
fn scalar_layout_memory_and_nan_policy_are_exact() {
    assert_eq!(validate_type(&ValueType::F32).unwrap().layout.size, 4);
    assert_eq!(validate_type(&ValueType::F32).unwrap().layout.alignment, 4);
    assert_eq!(validate_type(&ValueType::F64).unwrap().layout.size, 8);
    assert_eq!(validate_type(&ValueType::F64).unwrap().layout.alignment, 8);

    let f32_cases: [u32; 12] = [
        0x0000_0000,
        0x8000_0000,
        0x0000_0001,
        0x007f_ffff,
        0x0080_0000,
        0x7f7f_ffff,
        0x7f80_0000,
        0xff80_0000,
        0x7fc0_0000,
        0x7f80_0001,
        0xff80_0001,
        0xffff_ffff,
    ];
    let f64_cases: [u64; 12] = [
        0x0000_0000_0000_0000,
        0x8000_0000_0000_0000,
        0x0000_0000_0000_0001,
        0x000f_ffff_ffff_ffff,
        0x0010_0000_0000_0000,
        0x7fef_ffff_ffff_ffff,
        0x7ff0_0000_0000_0000,
        0xfff0_0000_0000_0000,
        0x7ff8_0000_0000_0000,
        0x7ff0_0000_0000_0001,
        0xfff0_0000_0000_0001,
        0xffff_ffff_ffff_ffff,
    ];
    let mut memory = memory();
    let mut allocator = Bump::at(4096);
    for bits in f32_cases {
        memory.write_exact(64, &bits.to_le_bytes()).unwrap();
        let (lifted, _) = lift_value(
            &memory,
            &RejectResources,
            &ValueType::F32,
            64,
            ValuePosition::Parameter,
        )
        .unwrap();
        let CanonicalValue::F32(value) = lifted else {
            panic!("expected f32")
        };
        lower_value(
            &mut memory,
            &mut allocator,
            &ValueType::F32,
            &CanonicalValue::F32(value),
            68,
            ValuePosition::Result,
        )
        .unwrap();
        let mut lowered = [0; 4];
        memory.read_exact(68, &mut lowered).unwrap();
        assert_eq!(
            u32::from_le_bytes(lowered),
            CanonicalF32::from_bits(bits).to_bits()
        );
    }
    for bits in f64_cases {
        memory.write_exact(80, &bits.to_le_bytes()).unwrap();
        let (lifted, _) = lift_value(
            &memory,
            &RejectResources,
            &ValueType::F64,
            80,
            ValuePosition::Parameter,
        )
        .unwrap();
        let CanonicalValue::F64(value) = lifted else {
            panic!("expected f64")
        };
        lower_value(
            &mut memory,
            &mut allocator,
            &ValueType::F64,
            &CanonicalValue::F64(value),
            88,
            ValuePosition::Result,
        )
        .unwrap();
        let mut lowered = [0; 8];
        memory.read_exact(88, &mut lowered).unwrap();
        assert_eq!(
            u64::from_le_bytes(lowered),
            CanonicalF64::from_bits(bits).to_bits()
        );
    }

    assert_eq!(
        lift_value(
            &memory,
            &RejectResources,
            &ValueType::F32,
            2,
            ValuePosition::Parameter
        ),
        Err(CodecError::Misaligned)
    );
    assert_eq!(
        lift_value(
            &memory,
            &RejectResources,
            &ValueType::F64,
            252,
            ValuePosition::Parameter
        ),
        Err(CodecError::Misaligned)
    );
    assert_eq!(
        lift_value(
            &memory,
            &RejectResources,
            &ValueType::F64,
            256,
            ValuePosition::Parameter
        ),
        Err(CodecError::OutOfBounds)
    );
}

#[test]
fn flat_signatures_calling_conventions_and_prepared_results_are_exact() {
    assert_eq!(
        flat_signature(&[ValueType::F32, ValueType::F64]).unwrap(),
        vec![CandidateFlatKind::F32, CandidateFlatKind::F64]
    );
    let mut memory = memory();
    let mut allocator = Bump::at(4096);
    let (lifted, _) = lift_flat_values(
        &memory,
        &RejectResources,
        &[ValueType::F32, ValueType::F64],
        &[
            CandidateFlatValue::F32Bits(0xff80_0001),
            CandidateFlatValue::F64Bits(0xfff0_0000_0000_0001),
        ],
        ValuePosition::Parameter,
    )
    .unwrap();
    assert_eq!(lifted, vec![f32v(0x7fc0_0000), f64v(0x7ff8_0000_0000_0000)]);
    assert_eq!(
        lift_flat_values(
            &memory,
            &RejectResources,
            &[ValueType::F32],
            &[CandidateFlatValue::I32(0)],
            ValuePosition::Parameter,
        ),
        Err(CodecError::TypeMismatch)
    );

    let sixteen_types: Vec<_> = (0..16).map(|_| ValueType::F32).collect();
    let sixteen_values: Vec<_> = (0..16).map(f32v).collect();
    assert!(matches!(
        lower_parameters(
            &mut memory,
            &mut allocator,
            &sixteen_types,
            &sixteen_values
        )
        .unwrap(),
        CandidateLoweredParameters::Flat { values, .. } if values.len() == 16
    ));

    let seventeen_types: Vec<_> = (0..17).map(|_| ValueType::F32).collect();
    let seventeen_values: Vec<_> = (0..17).map(f32v).collect();
    let indirect = lower_parameters(
        &mut memory,
        &mut allocator,
        &seventeen_types,
        &seventeen_values,
    )
    .unwrap();
    let CandidateLoweredParameters::Indirect {
        pointer, arguments, ..
    } = indirect
    else {
        panic!("17 flat values must be indirect")
    };
    assert_eq!(arguments, [CandidateFlatValue::I32(pointer as i32)]);
    assert!(allocator.requests.contains(&(68, 4, pointer)));
    let (round_trip, _) =
        lift_parameters(&memory, &RejectResources, &seventeen_types, &arguments).unwrap();
    assert_eq!(round_trip, seventeen_values);

    let results = lower_results(
        &mut memory,
        &mut allocator,
        &[ValueType::F32, ValueType::F64],
        &[f32v(0x8000_0000), f64v(0x7ff0_0000_0000_0000)],
    )
    .unwrap();
    let CandidateLoweredResults::Retptr { pointer, .. } = results else {
        panic!("two results must use retptr")
    };
    assert!(allocator.requests.contains(&(16, 8, pointer)));
    let (round_trip, _) = lift_results(
        &memory,
        &RejectResources,
        &[ValueType::F32, ValueType::F64],
        &[CandidateFlatValue::I32(pointer as i32)],
    )
    .unwrap();
    assert_eq!(
        round_trip,
        vec![f32v(0x8000_0000), f64v(0x7ff0_0000_0000_0000)]
    );

    let mut prepared = CandidatePreparedFlatResults::try_new(&[ValueType::F32]).unwrap();
    assert_eq!(prepared.signature(), &[CandidateFlatKind::F32]);
    let (flat, _) = lower_flat_results_prepared(
        &mut memory,
        &mut allocator,
        &[ValueType::F32],
        &[f32v(0xff80_0001)],
        &mut prepared,
    )
    .unwrap();
    assert_eq!(flat, vec![CandidateFlatValue::F32Bits(0x7fc0_0000)]);
}

#[test]
fn variant_join_coercion_and_unselected_zeroes_are_exact() {
    let signatures = [
        (
            ValueType::Variant(vec![Some(ValueType::F32), Some(ValueType::S32)]),
            CandidateFlatKind::I32,
        ),
        (
            ValueType::Variant(vec![Some(ValueType::F64), Some(ValueType::S64)]),
            CandidateFlatKind::I64,
        ),
        (
            ValueType::Variant(vec![Some(ValueType::F32), Some(ValueType::F64)]),
            CandidateFlatKind::I64,
        ),
        (
            ValueType::Variant(vec![Some(ValueType::F32), Some(ValueType::S64)]),
            CandidateFlatKind::I64,
        ),
        (
            ValueType::Variant(vec![Some(ValueType::F64), Some(ValueType::S32)]),
            CandidateFlatKind::I64,
        ),
    ];
    for (ty, joined) in signatures {
        assert_eq!(
            flat_signature(&[ty]).unwrap(),
            vec![CandidateFlatKind::I32, joined]
        );
    }
    assert_eq!(
        flat_signature(&[ValueType::Option(Box::new(ValueType::F32))]).unwrap(),
        vec![CandidateFlatKind::I32, CandidateFlatKind::F32]
    );

    let ty = ValueType::Variant(vec![Some(ValueType::F32), Some(ValueType::F64), None]);
    let mut memory = memory();
    let mut allocator = Bump::at(4096);
    let CandidateLoweredParameters::Flat { values, .. } = lower_parameters(
        &mut memory,
        &mut allocator,
        core::slice::from_ref(&ty),
        &[CanonicalValue::Variant {
            case: 0,
            payload: Some(Box::new(f32v(0x8000_0000))),
        }],
    )
    .unwrap() else {
        panic!("variant is flat")
    };
    assert_eq!(
        values,
        vec![
            CandidateFlatValue::I32(0),
            CandidateFlatValue::I64(0x8000_0000)
        ]
    );
    let (lifted, _) = lift_parameters(
        &memory,
        &RejectResources,
        core::slice::from_ref(&ty),
        &values,
    )
    .unwrap();
    assert_eq!(
        lifted,
        vec![CanonicalValue::Variant {
            case: 0,
            payload: Some(Box::new(f32v(0x8000_0000))),
        }]
    );

    let CandidateLoweredParameters::Flat { values, .. } = lower_parameters(
        &mut memory,
        &mut allocator,
        core::slice::from_ref(&ty),
        &[CanonicalValue::Variant {
            case: 2,
            payload: None,
        }],
    )
    .unwrap() else {
        panic!("variant is flat")
    };
    assert_eq!(
        values,
        vec![CandidateFlatValue::I32(2), CandidateFlatValue::I64(0)]
    );

    let (lifted, _) = lift_parameters(
        &memory,
        &RejectResources,
        core::slice::from_ref(&ty),
        &[
            CandidateFlatValue::I32(0),
            CandidateFlatValue::I64(0xff80_0001),
        ],
    )
    .unwrap();
    assert_eq!(
        lifted,
        vec![CanonicalValue::Variant {
            case: 0,
            payload: Some(Box::new(f32v(0x7fc0_0000))),
        }]
    );
}

#[test]
fn nested_lists_canonicalize_every_leaf_and_reject_hostile_memory() {
    let ty = ValueType::Record(vec![
        ValueType::F32,
        ValueType::List(Box::new(ValueType::F64)),
        ValueType::Result {
            ok: Some(Box::new(ValueType::List(Box::new(ValueType::F32)))),
            error: Some(Box::new(ValueType::F64)),
        },
    ]);
    let value = CanonicalValue::Record(vec![
        f32v(0xff80_0001),
        CanonicalValue::List(vec![f64v(1), f64v(0xfff0_0000_0000_0001)]),
        CanonicalValue::Result(Ok(Some(Box::new(CanonicalValue::List(vec![
            f32v(0x8000_0000),
            f32v(0x7f80_0001),
        ]))))),
    ]);
    let mut memory = memory();
    let mut allocator = Bump::at(4096);
    lower_value(
        &mut memory,
        &mut allocator,
        &ty,
        &value,
        64,
        ValuePosition::Parameter,
    )
    .unwrap();
    assert!(allocator
        .requests
        .iter()
        .any(|(size, alignment, _)| *size == 16 && *alignment == 8));
    assert!(allocator
        .requests
        .iter()
        .any(|(size, alignment, _)| *size == 8 && *alignment == 4));
    let (lifted, _) =
        lift_value(&memory, &RejectResources, &ty, 64, ValuePosition::Parameter).unwrap();
    assert_eq!(lifted, value);

    let list = ValueType::List(Box::new(ValueType::F32));
    let mut hostile = VecMemory::new(256, 256).unwrap();
    hostile.write_exact(0, &240_u32.to_le_bytes()).unwrap();
    hostile.write_exact(4, &5_u32.to_le_bytes()).unwrap();
    assert_eq!(
        lift_value(
            &hostile,
            &RejectResources,
            &list,
            0,
            ValuePosition::Parameter
        ),
        Err(CodecError::OutOfBounds)
    );
    hostile.write_exact(0, &242_u32.to_le_bytes()).unwrap();
    hostile.write_exact(4, &0_u32.to_le_bytes()).unwrap();
    assert_eq!(
        lift_value(
            &hostile,
            &RejectResources,
            &list,
            0,
            ValuePosition::Parameter
        ),
        Err(CodecError::Misaligned)
    );
    hostile
        .write_exact(0, &0xffff_fffc_u32.to_le_bytes())
        .unwrap();
    hostile.write_exact(4, &2_u32.to_le_bytes()).unwrap();
    assert_eq!(
        lift_value(
            &hostile,
            &RejectResources,
            &list,
            0,
            ValuePosition::Parameter
        ),
        Err(CodecError::OutOfBounds)
    );
}
