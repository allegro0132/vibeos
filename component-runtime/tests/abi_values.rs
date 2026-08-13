use vibeos_component_runtime::abi_value::{
    flat_signature, lift_flat_values, lift_parameters, lift_results, lift_value, lower_parameters,
    lower_results, lower_value, CodecError, CodecUsage, FlatKind, LoweredParameters,
    LoweredResults, PayloadAllocator, RejectResources, MAX_FLAT_PARAMS,
};
use vibeos_component_runtime::memory::{AbiError, GuestMemory, VecMemory};
use vibeos_component_runtime::resource::{ResourceTable, ResourceTypeId};
use vibeos_component_runtime::value::{
    CanonicalValue, ResourceOwnership, ValuePosition, ValueType,
};
use vibeos_wasm_runtime::CoreValue;

struct Bump {
    next: u32,
    allocations: u32,
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
        self.next = pointer.checked_add(size).ok_or(CodecError::Overflow)?;
        memory
            .grow_to(self.next as usize)
            .map_err(CodecError::from)?;
        self.allocations += 1;
        Ok(pointer)
    }
}

fn memory_and_allocator() -> (VecMemory, Bump) {
    (
        VecMemory::new(256, 128 * 1024).unwrap(),
        Bump {
            next: 4096,
            allocations: 0,
        },
    )
}

#[test]
fn every_rich_value_shape_round_trips_through_guest_memory() {
    let resource_type = ResourceTypeId(5);
    let mut table = ResourceTable::new(71, 1).unwrap();
    let token = table.insert_owned(resource_type, 0x55_u32).unwrap();
    let ty = ValueType::Record(vec![
        ValueType::Bool,
        ValueType::U8,
        ValueType::U16,
        ValueType::U32,
        ValueType::U64,
        ValueType::S8,
        ValueType::S16,
        ValueType::S32,
        ValueType::S64,
        ValueType::Char,
        ValueType::String,
        ValueType::List(Box::new(ValueType::Tuple(vec![
            ValueType::U8,
            ValueType::String,
        ]))),
        ValueType::Flags(35),
        ValueType::Enum(3),
        ValueType::Option(Box::new(ValueType::U64)),
        ValueType::Result {
            ok: Some(Box::new(ValueType::String)),
            error: Some(Box::new(ValueType::U16)),
        },
        ValueType::Variant(vec![
            None,
            Some(ValueType::Record(vec![ValueType::String, ValueType::U32])),
        ]),
        ValueType::Resource {
            resource_type,
            ownership: ResourceOwnership::Borrow,
        },
    ]);
    let value = CanonicalValue::Record(vec![
        CanonicalValue::Bool(true),
        CanonicalValue::U8(250),
        CanonicalValue::U16(50_000),
        CanonicalValue::U32(3_000_000_000),
        CanonicalValue::U64(0xfedc_ba98_7654_3210),
        CanonicalValue::S8(-100),
        CanonicalValue::S16(-20_000),
        CanonicalValue::S32(-1_000_000),
        CanonicalValue::S64(-9_000_000_000),
        CanonicalValue::Char('界'),
        CanonicalValue::String(String::from("Vibe λ")),
        CanonicalValue::List(vec![
            CanonicalValue::Tuple(vec![
                CanonicalValue::U8(1),
                CanonicalValue::String(String::from("one")),
            ]),
            CanonicalValue::Tuple(vec![
                CanonicalValue::U8(2),
                CanonicalValue::String(String::from("two")),
            ]),
        ]),
        CanonicalValue::Flags(vec![0x8000_0001, 0b101]),
        CanonicalValue::Enum(2),
        CanonicalValue::Option(Some(Box::new(CanonicalValue::U64(42)))),
        CanonicalValue::Result(Ok(Some(Box::new(CanonicalValue::String(String::from(
            "ok",
        )))))),
        CanonicalValue::Variant {
            case: 1,
            payload: Some(Box::new(CanonicalValue::Record(vec![
                CanonicalValue::String(String::from("accepted")),
                CanonicalValue::U32(9),
            ]))),
        },
        CanonicalValue::Resource(token),
    ]);
    let (mut memory, mut allocator) = memory_and_allocator();
    let lower = lower_value(
        &mut memory,
        &mut allocator,
        &ty,
        &value,
        64,
        ValuePosition::Parameter,
    )
    .unwrap();
    assert!(lower.bytes > 100);
    assert_eq!(lower.allocations, 6);
    let binder = |index, expected, ownership, position| {
        assert_eq!(expected, resource_type);
        assert_eq!(ownership, ResourceOwnership::Borrow);
        assert_eq!(position, ValuePosition::Parameter);
        let token = table.token_from_guest_index(index);
        table
            .contains(token, resource_type)
            .map(|_| token)
            .map_err(|_| CodecError::ResourceBinding)
    };
    let (lifted, usage) = lift_value(&memory, &binder, &ty, 64, ValuePosition::Parameter).unwrap();
    assert_eq!(lifted, value);
    assert_eq!(usage.bytes, lower.bytes);
}

#[test]
fn padding_and_variant_union_are_zeroed_and_round_trip() {
    let ty = ValueType::Tuple(vec![
        ValueType::U8,
        ValueType::U64,
        ValueType::Variant(vec![Some(ValueType::U8), Some(ValueType::U64)]),
    ]);
    let value = CanonicalValue::Tuple(vec![
        CanonicalValue::U8(7),
        CanonicalValue::U64(9),
        CanonicalValue::Variant {
            case: 0,
            payload: Some(Box::new(CanonicalValue::U8(3))),
        },
    ]);
    let (mut memory, mut allocator) = memory_and_allocator();
    lower_value(
        &mut memory,
        &mut allocator,
        &ty,
        &value,
        64,
        ValuePosition::Result,
    )
    .unwrap();
    let mut raw = [0xff; 32];
    memory.read_exact(64, &mut raw).unwrap();
    assert_eq!(&raw[1..8], &[0; 7]);
    assert_eq!(&raw[17..24], &[0; 7]);
    assert_eq!(&raw[25..32], &[0; 7]);
    let (lifted, _) =
        lift_value(&memory, &RejectResources, &ty, 64, ValuePosition::Result).unwrap();
    assert_eq!(lifted, value);
}

#[test]
fn hostile_memory_is_rejected_without_panicking() {
    let ty = ValueType::Record(vec![
        ValueType::Bool,
        ValueType::Char,
        ValueType::String,
        ValueType::Flags(3),
        ValueType::Variant(vec![None, Some(ValueType::U32)]),
    ]);
    let (mut memory, _) = memory_and_allocator();

    // bool at 64, char at 68, string at 72, flags at 80, variant at 84.
    memory.write_exact(64, &[2]).unwrap();
    assert_eq!(
        lift_value(&memory, &RejectResources, &ty, 64, ValuePosition::Parameter),
        Err(CodecError::InvalidBool)
    );
    memory.write_exact(64, &[1]).unwrap();
    memory.write_exact(68, &0xd800_u32.to_le_bytes()).unwrap();
    assert_eq!(
        lift_value(&memory, &RejectResources, &ty, 64, ValuePosition::Parameter),
        Err(CodecError::InvalidChar)
    );
    memory.write_exact(68, &('a' as u32).to_le_bytes()).unwrap();
    memory
        .write_exact(72, &0xffff_fff0_u32.to_le_bytes())
        .unwrap();
    memory.write_exact(76, &32_u32.to_le_bytes()).unwrap();
    assert_eq!(
        lift_value(&memory, &RejectResources, &ty, 64, ValuePosition::Parameter),
        Err(CodecError::OutOfBounds)
    );

    memory.write_exact(72, &128_u32.to_le_bytes()).unwrap();
    memory.write_exact(76, &2_u32.to_le_bytes()).unwrap();
    memory.write_exact(128, &[0xff, 0xff]).unwrap();
    assert_eq!(
        lift_value(&memory, &RejectResources, &ty, 64, ValuePosition::Parameter),
        Err(CodecError::InvalidUtf8)
    );

    memory.write_exact(128, b"ok").unwrap();
    memory.write_exact(80, &[0b1000]).unwrap();
    assert_eq!(
        lift_value(&memory, &RejectResources, &ty, 64, ValuePosition::Parameter),
        Err(CodecError::InvalidFlags)
    );
    memory.write_exact(80, &[0b0101]).unwrap();
    memory.write_exact(84, &[2]).unwrap();
    assert_eq!(
        lift_value(&memory, &RejectResources, &ty, 64, ValuePosition::Parameter),
        Err(CodecError::InvalidDiscriminant)
    );
    assert_eq!(
        lift_value(
            &memory,
            &RejectResources,
            &ValueType::U64,
            65,
            ValuePosition::Parameter
        ),
        Err(CodecError::Misaligned)
    );
}

#[test]
fn resource_binding_and_position_are_strict() {
    let resource_type = ResourceTypeId(9);
    let mut table = ResourceTable::new(72, 1).unwrap();
    let token = table.insert_owned(resource_type, ()).unwrap();
    let ty = ValueType::Resource {
        resource_type,
        ownership: ResourceOwnership::Borrow,
    };
    let (mut memory, mut allocator) = memory_and_allocator();
    lower_value(
        &mut memory,
        &mut allocator,
        &ty,
        &CanonicalValue::Resource(token),
        64,
        ValuePosition::Parameter,
    )
    .unwrap();
    assert_eq!(
        lift_value(&memory, &RejectResources, &ty, 64, ValuePosition::Parameter),
        Err(CodecError::ResourceBinding)
    );
    assert_eq!(
        lower_value(
            &mut memory,
            &mut allocator,
            &ty,
            &CanonicalValue::Resource(token),
            64,
            ValuePosition::Result
        ),
        Err(CodecError::BorrowEscape)
    );
}

#[test]
fn flat_signature_and_calling_conventions_are_bounded() {
    assert_eq!(
        flat_signature(&[
            ValueType::U8,
            ValueType::U64,
            ValueType::String,
            ValueType::Tuple(vec![ValueType::S32, ValueType::S64]),
        ])
        .unwrap(),
        vec![
            FlatKind::I32,
            FlatKind::I64,
            FlatKind::I32,
            FlatKind::I32,
            FlatKind::I32,
            FlatKind::I64,
        ]
    );
    let (mut memory, mut allocator) = memory_and_allocator();
    assert_eq!(
        lower_parameters(
            &mut memory,
            &mut allocator,
            &[ValueType::U32, ValueType::U64],
            &[CanonicalValue::U32(7), CanonicalValue::U64(8)]
        )
        .unwrap(),
        LoweredParameters::Flat {
            values: vec![CoreValue::I32(7), CoreValue::I64(8)],
            usage: CodecUsage {
                nodes: 2,
                max_depth: 1,
                work: 2,
                ..CodecUsage::default()
            },
        }
    );

    let many_types: Vec<ValueType> = (0..=MAX_FLAT_PARAMS).map(|_| ValueType::U32).collect();
    let many_values: Vec<CanonicalValue> = (0..=MAX_FLAT_PARAMS)
        .map(|index| CanonicalValue::U32(index as u32))
        .collect();
    assert!(matches!(
        lower_parameters(&mut memory, &mut allocator, &many_types, &many_values).unwrap(),
        LoweredParameters::Indirect { pointer, arguments: [CoreValue::I32(argument)], usage }
            if pointer != 0 && argument as u32 == pointer && usage.bytes >= 68
    ));
    assert_eq!(
        lower_results(
            &mut memory,
            &mut allocator,
            &[ValueType::U32],
            &[CanonicalValue::U32(9)]
        )
        .unwrap(),
        LoweredResults::Flat {
            values: vec![CoreValue::I32(9)],
            usage: CodecUsage {
                nodes: 1,
                max_depth: 1,
                work: 1,
                ..CodecUsage::default()
            },
        }
    );
    assert!(matches!(
        lower_results(
            &mut memory,
            &mut allocator,
            &[ValueType::U32, ValueType::U64],
            &[CanonicalValue::U32(1), CanonicalValue::U64(2)]
        )
        .unwrap(),
        LoweredResults::Retptr { pointer, usage } if pointer != 0 && usage.bytes >= 16
    ));
}

#[test]
fn flat_and_indirect_calling_conventions_lift_back_exactly() {
    let (mut memory, mut allocator) = memory_and_allocator();

    let flat_types = vec![
        ValueType::String,
        ValueType::Option(Box::new(ValueType::U64)),
        ValueType::Variant(vec![Some(ValueType::U32), Some(ValueType::U64)]),
        ValueType::Flags(35),
    ];
    let flat_values = vec![
        CanonicalValue::String(String::from("flat")),
        CanonicalValue::Option(Some(Box::new(CanonicalValue::U64(0xfedc_ba98_7654_3210)))),
        CanonicalValue::Variant {
            case: 0,
            payload: Some(Box::new(CanonicalValue::U32(u32::MAX))),
        },
        CanonicalValue::Flags(vec![0x8000_0001, 0b101]),
    ];
    let flat =
        match lower_parameters(&mut memory, &mut allocator, &flat_types, &flat_values).unwrap() {
            LoweredParameters::Flat { values, .. } => values,
            LoweredParameters::Indirect { .. } => panic!("signature should remain flat"),
        };
    let (lifted, usage) = lift_parameters(&memory, &RejectResources, &flat_types, &flat).unwrap();
    assert_eq!(lifted, flat_values);
    assert_eq!(usage.nodes, 6);

    let many_types: Vec<ValueType> = (0..=MAX_FLAT_PARAMS).map(|_| ValueType::U32).collect();
    let many_values: Vec<CanonicalValue> = (0..=MAX_FLAT_PARAMS)
        .map(|index| CanonicalValue::U32(index as u32))
        .collect();
    let arguments =
        match lower_parameters(&mut memory, &mut allocator, &many_types, &many_values).unwrap() {
            LoweredParameters::Indirect { arguments, .. } => arguments,
            LoweredParameters::Flat { .. } => panic!("signature should be indirect"),
        };
    let (lifted, _) = lift_parameters(&memory, &RejectResources, &many_types, &arguments).unwrap();
    assert_eq!(lifted, many_values);

    let result_types = vec![
        ValueType::String,
        ValueType::Option(Box::new(ValueType::U32)),
    ];
    let result_values = vec![
        CanonicalValue::String(String::from("retptr")),
        CanonicalValue::Option(None),
    ];
    let pointer =
        match lower_results(&mut memory, &mut allocator, &result_types, &result_values).unwrap() {
            LoweredResults::Retptr { pointer, .. } => pointer,
            LoweredResults::Flat { .. } => panic!("result signature should use a retptr"),
        };
    let (lifted, _) = lift_results(
        &memory,
        &RejectResources,
        &result_types,
        &[CoreValue::I32(pointer as i32)],
    )
    .unwrap();
    assert_eq!(lifted, result_values);

    let scalar_types = [ValueType::S32];
    let scalar_values = [CanonicalValue::S32(-7)];
    let scalar =
        match lower_results(&mut memory, &mut allocator, &scalar_types, &scalar_values).unwrap() {
            LoweredResults::Flat { values, .. } => values,
            LoweredResults::Retptr { .. } => panic!("scalar result should remain flat"),
        };
    assert_eq!(
        lift_results(&memory, &RejectResources, &scalar_types, &scalar)
            .unwrap()
            .0,
        scalar_values
    );
}

#[test]
fn flat_lift_rejects_noncanonical_values_and_binds_exact_resources() {
    let (memory, _) = memory_and_allocator();
    assert_eq!(
        lift_flat_values(
            &memory,
            &RejectResources,
            &[ValueType::Bool],
            &[CoreValue::I32(2)],
            ValuePosition::Parameter,
        ),
        Err(CodecError::InvalidBool)
    );
    assert_eq!(
        lift_flat_values(
            &memory,
            &RejectResources,
            &[ValueType::Char],
            &[CoreValue::I32(0xd800)],
            ValuePosition::Parameter,
        ),
        Err(CodecError::InvalidChar)
    );
    assert_eq!(
        lift_flat_values(
            &memory,
            &RejectResources,
            &[ValueType::Flags(3)],
            &[CoreValue::I32(0b1000)],
            ValuePosition::Parameter,
        ),
        Err(CodecError::InvalidFlags)
    );
    assert_eq!(
        lift_flat_values(
            &memory,
            &RejectResources,
            &[ValueType::Enum(2)],
            &[CoreValue::I32(2)],
            ValuePosition::Parameter,
        ),
        Err(CodecError::InvalidDiscriminant)
    );
    assert_eq!(
        lift_flat_values(
            &memory,
            &RejectResources,
            &[ValueType::Variant(vec![None, Some(ValueType::U64)])],
            &[CoreValue::I32(2), CoreValue::I64(0)],
            ValuePosition::Parameter,
        ),
        Err(CodecError::InvalidDiscriminant)
    );
    assert_eq!(
        lift_parameters(
            &memory,
            &RejectResources,
            &[ValueType::U64],
            &[CoreValue::I32(1)],
        ),
        Err(CodecError::TypeMismatch)
    );
    assert_eq!(
        lift_parameters(
            &memory,
            &RejectResources,
            &[ValueType::U32],
            &[CoreValue::I32(1), CoreValue::I32(2)],
        ),
        Err(CodecError::FlatLimit)
    );
    assert_eq!(
        lift_results(
            &memory,
            &RejectResources,
            &[ValueType::String],
            &[CoreValue::I32(3)],
        ),
        Err(CodecError::Misaligned)
    );
    assert_eq!(
        lift_results(
            &memory,
            &RejectResources,
            &[ValueType::String],
            &[CoreValue::I32(8), CoreValue::I32(0)],
        ),
        Err(CodecError::FlatLimit)
    );

    let resource_type = ResourceTypeId(77);
    let mut table = ResourceTable::new(99, 1).unwrap();
    let token = table.insert_owned(resource_type, ()).unwrap();
    let resource_ty = ValueType::Resource {
        resource_type,
        ownership: ResourceOwnership::Borrow,
    };
    let binder = |index, expected, ownership, position| {
        if expected != resource_type
            || ownership != ResourceOwnership::Borrow
            || position != ValuePosition::Parameter
        {
            return Err(CodecError::ResourceBinding);
        }
        let rebound = table.token_from_guest_index(index);
        table
            .contains(rebound, expected)
            .map(|_| rebound)
            .map_err(|_| CodecError::ResourceBinding)
    };
    assert_eq!(
        lift_parameters(
            &memory,
            &binder,
            &[resource_ty],
            &[CoreValue::I32(token.guest_index() as i32)],
        )
        .unwrap()
        .0,
        vec![CanonicalValue::Resource(token)]
    );

    let borrowed_result = ValueType::Resource {
        resource_type,
        ownership: ResourceOwnership::Borrow,
    };
    assert_eq!(
        lift_results(
            &memory,
            &binder,
            &[borrowed_result],
            &[CoreValue::I32(token.guest_index() as i32)],
        ),
        Err(CodecError::BorrowEscape)
    );
}

#[test]
fn limits_and_allocator_failures_are_stable() {
    struct Failing;
    impl PayloadAllocator<VecMemory> for Failing {
        fn allocate(
            &mut self,
            _memory: &mut VecMemory,
            _size: u32,
            _alignment: u32,
        ) -> Result<u32, CodecError> {
            Err(CodecError::Allocation)
        }
    }

    let mut memory = VecMemory::new(128, 128).unwrap();
    assert_eq!(
        lower_value(
            &mut memory,
            &mut Failing,
            &ValueType::String,
            &CanonicalValue::String(String::from("x")),
            64,
            ValuePosition::Parameter
        ),
        Err(CodecError::Allocation)
    );

    // All arguments are validated before the first guest allocation. The bad
    // second argument therefore wins over the allocator failure from the first.
    assert_eq!(
        lower_parameters(
            &mut memory,
            &mut Failing,
            &[ValueType::String, ValueType::U32],
            &[
                CanonicalValue::String(String::from("would allocate")),
                CanonicalValue::Bool(false),
            ]
        ),
        Err(CodecError::TypeMismatch)
    );

    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for _ in 0..2_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let pointer = state as u32;
        let result = std::panic::catch_unwind(|| {
            lift_value(
                &memory,
                &RejectResources,
                &ValueType::List(Box::new(ValueType::U64)),
                pointer,
                ValuePosition::Parameter,
            )
        });
        assert!(result.is_ok());
    }
}

#[test]
fn allocator_bad_spans_are_rejected() {
    struct Bad;
    impl PayloadAllocator<VecMemory> for Bad {
        fn allocate(
            &mut self,
            _memory: &mut VecMemory,
            _size: u32,
            _alignment: u32,
        ) -> Result<u32, CodecError> {
            Ok(3)
        }
    }
    let mut memory = VecMemory::new(128, 128).unwrap();
    assert_eq!(
        lower_value(
            &mut memory,
            &mut Bad,
            &ValueType::List(Box::new(ValueType::U64)),
            &CanonicalValue::List(vec![CanonicalValue::U64(1)]),
            64,
            ValuePosition::Parameter
        ),
        Err(CodecError::Misaligned)
    );
}

#[test]
fn zero_length_payload_still_requires_a_current_aligned_pointer() {
    let memory = VecMemory::new(128, 128).unwrap();
    let mut encoded = [0_u8; 8];
    encoded[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut hostile = VecMemory::new(128, 128).unwrap();
    hostile.write_exact(64, &encoded).unwrap();
    assert_eq!(
        lift_value(
            &hostile,
            &RejectResources,
            &ValueType::String,
            64,
            ValuePosition::Parameter,
        ),
        Err(CodecError::OutOfBounds)
    );
    assert_eq!(
        lift_flat_values(
            &memory,
            &RejectResources,
            &[ValueType::List(Box::new(ValueType::Tuple(vec![])))],
            &[CoreValue::I32(-1), CoreValue::I32(1)],
            ValuePosition::Parameter,
        ),
        Err(CodecError::OutOfBounds)
    );
}

#[test]
fn allocator_cannot_alias_root_or_another_payload() {
    struct Fixed(u32);
    impl PayloadAllocator<VecMemory> for Fixed {
        fn allocate(
            &mut self,
            _memory: &mut VecMemory,
            _size: u32,
            _alignment: u32,
        ) -> Result<u32, CodecError> {
            Ok(self.0)
        }
    }

    let ty = ValueType::Record(vec![ValueType::String, ValueType::String]);
    let value = CanonicalValue::Record(vec![
        CanonicalValue::String(String::from("first")),
        CanonicalValue::String(String::from("other")),
    ]);
    let mut memory = VecMemory::new(256, 256).unwrap();

    assert_eq!(
        lower_value(
            &mut memory,
            &mut Fixed(64),
            &ty,
            &value,
            64,
            ValuePosition::Parameter,
        ),
        Err(CodecError::Allocation)
    );
    assert_eq!(
        lower_value(
            &mut memory,
            &mut Fixed(128),
            &ty,
            &value,
            64,
            ValuePosition::Parameter,
        ),
        Err(CodecError::Allocation)
    );
}

#[test]
fn abi_error_mapping_is_stable() {
    assert_eq!(CodecError::TypeMismatch.code(), 2);
    assert_eq!(
        CodecError::from(AbiError::OutOfBounds),
        CodecError::OutOfBounds
    );
    assert_eq!(CodecError::from(AbiError::Overflow), CodecError::Overflow);
}
