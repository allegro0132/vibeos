use std::panic::{catch_unwind, AssertUnwindSafe};

use vibeos_component_runtime::{
    abi_value::{
        lift_value, lower_value, CodecError, CodecUsage, PayloadAllocator, RejectResources,
    },
    memory::{GuestMemory, VecMemory},
    value::{validate_type, validate_value, CanonicalValue, ValuePosition, ValueType},
};

const SEED: u64 = 0x243f_6a88_85a3_08d3;
const VALID_CASES: usize = 512;
const FAMILY_COUNT: usize = 19;
const LEAF_FAMILY_COUNT: usize = 11;
const ALL_FAMILIES: u32 = (1 << FAMILY_COUNT) - 1;
const MAX_GENERATED_DEPTH: u32 = 6;
const ROOT_POINTER: u32 = 64;
const PAYLOAD_BASE: u32 = 4_096;
const MEMORY_LIMIT: usize = 128 * 1024;

const EXPECTED_TYPE_NODES: u64 = 799;
const EXPECTED_VALUE_NODES: u64 = 772;
const EXPECTED_DYNAMIC_BYTES: u64 = 1_026;
const EXPECTED_LIST_ELEMENTS: u64 = 88;
const EXPECTED_LOWER_ALLOCATIONS: u64 = 65;
const EXPECTED_MAX_TYPE_DEPTH: u32 = 6;
const EXPECTED_MAX_VALUE_DEPTH: u32 = 5;
const EXPECTED_CORPUS_DIGEST: u64 = 0xbf10_e036_e775_0d0b;
const EXPECTED_MISMATCH_DIGEST: u64 = 0x4cc0_bcd2_afdc_82bc;
const EXPECTED_TARGETED_REJECTIONS: u64 = 32;
const EXPECTED_REJECTION_DIGEST: u64 = 0x9740_17fe_ed8c_1e42;

#[derive(Clone, Copy)]
struct DeterministicRng(u64);

impl DeterministicRng {
    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn choose(&mut self, upper: usize) -> usize {
        assert!(upper != 0);
        (self.next_u64() % upper as u64) as usize
    }

    fn coin(&mut self) -> bool {
        self.next_u64() & 1 != 0
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

    fn bytes(&mut self, values: &[u8]) {
        self.u64(values.len() as u64);
        for value in values {
            self.byte(*value);
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

struct Bump {
    next: u32,
    calls: u32,
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
        self.next = end;
        self.calls = self
            .calls
            .checked_add(1)
            .ok_or(CodecError::AllocationLimit)?;
        Ok(pointer)
    }
}

fn memory_and_allocator() -> (VecMemory, Bump) {
    (
        VecMemory::new(PAYLOAD_BASE as usize, MEMORY_LIMIT).unwrap(),
        Bump {
            next: PAYLOAD_BASE,
            calls: 0,
        },
    )
}

fn random_type(rng: &mut DeterministicRng, depth: u32) -> ValueType {
    let families = if depth >= MAX_GENERATED_DEPTH {
        LEAF_FAMILY_COUNT
    } else {
        FAMILY_COUNT
    };
    let family = rng.choose(families);
    generated_type(rng, family, depth)
}

fn generated_type(rng: &mut DeterministicRng, family: usize, depth: u32) -> ValueType {
    match family {
        0 => ValueType::Bool,
        1 => ValueType::U8,
        2 => ValueType::U16,
        3 => ValueType::U32,
        4 => ValueType::U64,
        5 => ValueType::S8,
        6 => ValueType::S16,
        7 => ValueType::S32,
        8 => ValueType::S64,
        9 => ValueType::Char,
        10 => ValueType::String,
        11 => ValueType::List(Box::new(random_type(rng, depth + 1))),
        12 | 13 => {
            let count = rng.choose(4);
            let mut fields = Vec::with_capacity(count);
            for _ in 0..count {
                fields.push(random_type(rng, depth + 1));
            }
            if family == 12 {
                ValueType::Tuple(fields)
            } else {
                ValueType::Record(fields)
            }
        }
        14 => {
            const COUNTS: [u32; 14] = [1, 2, 7, 8, 9, 16, 17, 31, 32, 33, 63, 64, 65, 96];
            ValueType::Flags(COUNTS[rng.choose(COUNTS.len())])
        }
        15 => {
            const CASES: [u32; 8] = [1, 2, 3, 255, 256, 257, 1_024, 4_096];
            ValueType::Enum(CASES[rng.choose(CASES.len())])
        }
        16 => ValueType::Option(Box::new(random_type(rng, depth + 1))),
        17 => {
            let ok = rng.coin().then(|| Box::new(random_type(rng, depth + 1)));
            let error = rng.coin().then(|| Box::new(random_type(rng, depth + 1)));
            ValueType::Result { ok, error }
        }
        18 => {
            let count = 1 + rng.choose(4);
            let mut cases = Vec::with_capacity(count);
            for _ in 0..count {
                cases.push(rng.coin().then(|| random_type(rng, depth + 1)));
            }
            ValueType::Variant(cases)
        }
        _ => unreachable!("family is bounded by FAMILY_COUNT"),
    }
}

fn generated_value(rng: &mut DeterministicRng, ty: &ValueType) -> CanonicalValue {
    match ty {
        ValueType::Bool => CanonicalValue::Bool(rng.coin()),
        ValueType::U8 => CanonicalValue::U8(rng.next_u64() as u8),
        ValueType::U16 => CanonicalValue::U16(rng.next_u64() as u16),
        ValueType::U32 => CanonicalValue::U32(rng.next_u64() as u32),
        ValueType::U64 => CanonicalValue::U64(rng.next_u64()),
        ValueType::S8 => CanonicalValue::S8(rng.next_u64() as i8),
        ValueType::S16 => CanonicalValue::S16(rng.next_u64() as i16),
        ValueType::S32 => CanonicalValue::S32(rng.next_u64() as i32),
        ValueType::S64 => CanonicalValue::S64(rng.next_u64() as i64),
        ValueType::Char => {
            const CHARS: [char; 8] = ['\0', 'a', '\u{7f}', '\u{80}', 'é', '界', '💻', '\u{10ffff}'];
            CanonicalValue::Char(CHARS[rng.choose(CHARS.len())])
        }
        ValueType::String => {
            const CHARS: [char; 7] = ['a', '\0', 'é', 'λ', '界', '💻', '\u{10ffff}'];
            let count = rng.choose(13);
            let mut value = String::new();
            for _ in 0..count {
                value.push(CHARS[rng.choose(CHARS.len())]);
            }
            CanonicalValue::String(value)
        }
        ValueType::List(item) => {
            let count = rng.choose(5);
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(generated_value(rng, item));
            }
            CanonicalValue::List(values)
        }
        ValueType::Tuple(types) => {
            CanonicalValue::Tuple(types.iter().map(|ty| generated_value(rng, ty)).collect())
        }
        ValueType::Record(types) => {
            CanonicalValue::Record(types.iter().map(|ty| generated_value(rng, ty)).collect())
        }
        ValueType::Flags(count) => {
            let word_count = count.div_ceil(32);
            let mut words: Vec<u32> = (0..word_count).map(|_| rng.next_u64() as u32).collect();
            let used = count % 32;
            if used != 0 {
                *words.last_mut().unwrap() &= (1_u32 << used) - 1;
            }
            CanonicalValue::Flags(words)
        }
        ValueType::Enum(cases) => CanonicalValue::Enum(rng.choose(*cases as usize) as u32),
        ValueType::Option(inner) => {
            CanonicalValue::Option(rng.coin().then(|| Box::new(generated_value(rng, inner))))
        }
        ValueType::Result { ok, error } => {
            if rng.coin() {
                CanonicalValue::Result(Ok(ok
                    .as_deref()
                    .map(|ty| Box::new(generated_value(rng, ty)))))
            } else {
                CanonicalValue::Result(Err(error
                    .as_deref()
                    .map(|ty| Box::new(generated_value(rng, ty)))))
            }
        }
        ValueType::Variant(cases) => {
            let case = rng.choose(cases.len());
            CanonicalValue::Variant {
                case: case as u32,
                payload: cases[case]
                    .as_ref()
                    .map(|ty| Box::new(generated_value(rng, ty))),
            }
        }
        #[cfg(feature = "c88-f3-acceptance")]
        ValueType::F32 | ValueType::F64 => {
            unreachable!("the frozen C2.7 integer corpus excludes scalar floats")
        }
        ValueType::Resource { .. } | ValueType::Stream { .. } | ValueType::Future { .. } => {
            unreachable!("the C2.7 corpus excludes resource and endpoint handles")
        }
    }
}

fn family_mask(ty: &ValueType) -> u32 {
    let (family, children): (usize, Vec<&ValueType>) = match ty {
        ValueType::Bool => (0, vec![]),
        ValueType::U8 => (1, vec![]),
        ValueType::U16 => (2, vec![]),
        ValueType::U32 => (3, vec![]),
        ValueType::U64 => (4, vec![]),
        ValueType::S8 => (5, vec![]),
        ValueType::S16 => (6, vec![]),
        ValueType::S32 => (7, vec![]),
        ValueType::S64 => (8, vec![]),
        ValueType::Char => (9, vec![]),
        ValueType::String => (10, vec![]),
        ValueType::List(item) => (11, vec![item]),
        ValueType::Tuple(types) => (12, types.iter().collect()),
        ValueType::Record(types) => (13, types.iter().collect()),
        ValueType::Flags(_) => (14, vec![]),
        ValueType::Enum(_) => (15, vec![]),
        ValueType::Option(inner) => (16, vec![inner]),
        ValueType::Result { ok, error } => {
            let mut children = Vec::with_capacity(2);
            children.extend(ok.as_deref());
            children.extend(error.as_deref());
            (17, children)
        }
        ValueType::Variant(cases) => (18, cases.iter().flatten().collect()),
        #[cfg(feature = "c88-f3-acceptance")]
        ValueType::F32 | ValueType::F64 => {
            panic!("the frozen C2.7 integer corpus excludes scalar floats")
        }
        ValueType::Resource { .. } | ValueType::Stream { .. } | ValueType::Future { .. } => {
            panic!("resource and endpoint families are not part of this corpus")
        }
    };
    children
        .into_iter()
        .fold(1_u32 << family, |mask, child| mask | family_mask(child))
}

fn hash_type(hash: &mut Fnv64, ty: &ValueType) {
    match ty {
        ValueType::Bool => hash.byte(0),
        ValueType::U8 => hash.byte(1),
        ValueType::U16 => hash.byte(2),
        ValueType::U32 => hash.byte(3),
        ValueType::U64 => hash.byte(4),
        ValueType::S8 => hash.byte(5),
        ValueType::S16 => hash.byte(6),
        ValueType::S32 => hash.byte(7),
        ValueType::S64 => hash.byte(8),
        ValueType::Char => hash.byte(9),
        ValueType::String => hash.byte(10),
        ValueType::List(item) => {
            hash.byte(11);
            hash_type(hash, item);
        }
        ValueType::Tuple(types) | ValueType::Record(types) => {
            hash.byte(if matches!(ty, ValueType::Tuple(_)) {
                12
            } else {
                13
            });
            hash.u32(types.len() as u32);
            for ty in types {
                hash_type(hash, ty);
            }
        }
        ValueType::Flags(count) => {
            hash.byte(14);
            hash.u32(*count);
        }
        ValueType::Enum(cases) => {
            hash.byte(15);
            hash.u32(*cases);
        }
        ValueType::Option(inner) => {
            hash.byte(16);
            hash_type(hash, inner);
        }
        ValueType::Result { ok, error } => {
            hash.byte(17);
            hash_optional_type(hash, ok.as_deref());
            hash_optional_type(hash, error.as_deref());
        }
        ValueType::Variant(cases) => {
            hash.byte(18);
            hash.u32(cases.len() as u32);
            for case in cases {
                hash_optional_type(hash, case.as_ref());
            }
        }
        #[cfg(feature = "c88-f3-acceptance")]
        ValueType::F32 | ValueType::F64 => {
            panic!("the frozen C2.7 integer corpus excludes scalar floats")
        }
        ValueType::Resource { .. } | ValueType::Stream { .. } | ValueType::Future { .. } => {
            panic!("resource and endpoint families are not part of this corpus")
        }
    }
}

fn hash_optional_type(hash: &mut Fnv64, ty: Option<&ValueType>) {
    match ty {
        Some(ty) => {
            hash.byte(1);
            hash_type(hash, ty);
        }
        None => hash.byte(0),
    }
}

fn hash_value(hash: &mut Fnv64, value: &CanonicalValue) {
    match value {
        CanonicalValue::Bool(value) => {
            hash.byte(0);
            hash.byte(u8::from(*value));
        }
        CanonicalValue::U8(value) => {
            hash.byte(1);
            hash.byte(*value);
        }
        CanonicalValue::U16(value) => {
            hash.byte(2);
            for byte in value.to_le_bytes() {
                hash.byte(byte);
            }
        }
        CanonicalValue::U32(value) => {
            hash.byte(3);
            hash.u32(*value);
        }
        CanonicalValue::U64(value) => {
            hash.byte(4);
            hash.u64(*value);
        }
        CanonicalValue::S8(value) => {
            hash.byte(5);
            hash.byte(*value as u8);
        }
        CanonicalValue::S16(value) => {
            hash.byte(6);
            for byte in value.to_le_bytes() {
                hash.byte(byte);
            }
        }
        CanonicalValue::S32(value) => {
            hash.byte(7);
            hash.u32(*value as u32);
        }
        CanonicalValue::S64(value) => {
            hash.byte(8);
            hash.u64(*value as u64);
        }
        CanonicalValue::Char(value) => {
            hash.byte(9);
            hash.u32(*value as u32);
        }
        CanonicalValue::String(value) => {
            hash.byte(10);
            hash.bytes(value.as_bytes());
        }
        CanonicalValue::List(values)
        | CanonicalValue::Tuple(values)
        | CanonicalValue::Record(values) => {
            hash.byte(match value {
                CanonicalValue::List(_) => 11,
                CanonicalValue::Tuple(_) => 12,
                CanonicalValue::Record(_) => 13,
                _ => unreachable!(),
            });
            hash.u32(values.len() as u32);
            for value in values {
                hash_value(hash, value);
            }
        }
        CanonicalValue::Flags(words) => {
            hash.byte(14);
            hash.u32(words.len() as u32);
            for word in words {
                hash.u32(*word);
            }
        }
        CanonicalValue::Enum(case) => {
            hash.byte(15);
            hash.u32(*case);
        }
        CanonicalValue::Option(value) => {
            hash.byte(16);
            hash_optional_value(hash, value.as_deref());
        }
        CanonicalValue::Result(value) => {
            hash.byte(17);
            match value {
                Ok(value) => {
                    hash.byte(0);
                    hash_optional_value(hash, value.as_deref());
                }
                Err(value) => {
                    hash.byte(1);
                    hash_optional_value(hash, value.as_deref());
                }
            }
        }
        CanonicalValue::Variant { case, payload } => {
            hash.byte(18);
            hash.u32(*case);
            hash_optional_value(hash, payload.as_deref());
        }
        #[cfg(feature = "c88-f3-acceptance")]
        CanonicalValue::F32(_) | CanonicalValue::F64(_) => {
            panic!("the frozen C2.7 integer corpus excludes scalar floats")
        }
        CanonicalValue::Resource(_) | CanonicalValue::Stream(_) | CanonicalValue::Future(_) => {
            panic!("resource and endpoint values are not part of this corpus")
        }
    }
}

fn hash_optional_value(hash: &mut Fnv64, value: Option<&CanonicalValue>) {
    match value {
        Some(value) => {
            hash.byte(1);
            hash_value(hash, value);
        }
        None => hash.byte(0),
    }
}

fn assert_usage_matches_account(
    usage: CodecUsage,
    account: vibeos_component_runtime::value::ValueAccount,
) {
    assert_eq!(usage.nodes, account.nodes);
    assert_eq!(usage.bytes, account.bytes);
    assert_eq!(usage.list_elements, account.list_elements);
    assert_eq!(usage.max_depth, account.max_depth);
    assert_eq!(usage.work, account.work);
}

#[test]
fn deterministic_bounded_values_round_trip_every_non_resource_family() {
    let mut rng = DeterministicRng(SEED);
    let mut digest = Fnv64::new(b"vibeos.c2.7.canonical-values.v1\0");
    let mut mismatch_digest = Fnv64::new(b"vibeos.c2.7.canonical-mismatches.v1\0");
    let mut coverage = 0_u32;
    let mut type_nodes = 0_u64;
    let mut value_nodes = 0_u64;
    let mut dynamic_bytes = 0_u64;
    let mut list_elements = 0_u64;
    let mut lower_allocations = 0_u64;
    let mut max_type_depth = 0_u32;
    let mut max_value_depth = 0_u32;
    let mut mismatches = 0_u64;

    digest.u64(SEED);
    digest.u64(VALID_CASES as u64);
    for index in 0..VALID_CASES {
        let root_family = index % FAMILY_COUNT;
        let ty = generated_type(&mut rng, root_family, 1);
        let value = generated_value(&mut rng, &ty);
        let type_account = validate_type(&ty).unwrap();
        let value_account = validate_value(&ty, &value).unwrap();
        coverage |= family_mask(&ty);
        type_nodes += u64::from(type_account.nodes);
        value_nodes += u64::from(value_account.nodes);
        dynamic_bytes += (value_account.bytes - type_account.layout.size) as u64;
        list_elements += u64::from(value_account.list_elements);
        max_type_depth = max_type_depth.max(type_account.max_depth);
        max_value_depth = max_value_depth.max(value_account.max_depth);

        digest.u64(index as u64);
        digest.byte(root_family as u8);
        hash_type(&mut digest, &ty);
        hash_value(&mut digest, &value);

        let position = if index & 1 == 0 {
            ValuePosition::Parameter
        } else {
            ValuePosition::Result
        };
        digest.byte(u8::from(position == ValuePosition::Result));

        let round_trip = catch_unwind(AssertUnwindSafe(|| {
            let (mut memory, mut allocator) = memory_and_allocator();
            let lowered = lower_value(
                &mut memory,
                &mut allocator,
                &ty,
                &value,
                ROOT_POINTER,
                position,
            )?;
            let (lifted, lifted_usage) =
                lift_value(&memory, &RejectResources, &ty, ROOT_POINTER, position)?;
            let mut encoded = vec![0; memory.len() as usize];
            memory
                .read_exact(0, &mut encoded)
                .map_err(CodecError::from)?;
            Ok::<_, CodecError>((lowered, lifted_usage, lifted, encoded, allocator.calls))
        }));
        let (lowered, lifted_usage, lifted, encoded, allocation_calls) = match round_trip {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => panic!("valid case {index} was rejected: {error:?}"),
            Err(_) => panic!("valid case {index} panicked"),
        };
        assert_eq!(lifted, value, "case {index} changed across memory");
        assert_usage_matches_account(lowered, value_account);
        assert_usage_matches_account(lifted_usage, value_account);
        assert_eq!(allocation_calls, lowered.allocations);
        lower_allocations += u64::from(lowered.allocations);
        digest.u64(lowered.work);
        digest.u64(lowered.allocations.into());
        digest.bytes(&encoded);

        let wrong = if matches!(ty, ValueType::Bool) {
            CanonicalValue::U8(0)
        } else {
            CanonicalValue::Bool(false)
        };
        let mismatch = catch_unwind(AssertUnwindSafe(|| {
            let (mut memory, mut allocator) = memory_and_allocator();
            lower_value(
                &mut memory,
                &mut allocator,
                &ty,
                &wrong,
                ROOT_POINTER,
                position,
            )
        }));
        match mismatch {
            Ok(Err(CodecError::TypeMismatch)) => {}
            Ok(other) => panic!("case {index} mismatch returned {other:?}"),
            Err(_) => panic!("case {index} mismatch panicked"),
        }
        mismatches += 1;
        mismatch_digest.u64(index as u64);
        mismatch_digest.byte(root_family as u8);
        mismatch_digest.u32(CodecError::TypeMismatch.code().into());
    }

    assert_eq!(coverage, ALL_FAMILIES);
    assert_eq!(mismatches, VALID_CASES as u64);
    assert_eq!(type_nodes, EXPECTED_TYPE_NODES);
    assert_eq!(value_nodes, EXPECTED_VALUE_NODES);
    assert_eq!(dynamic_bytes, EXPECTED_DYNAMIC_BYTES);
    assert_eq!(list_elements, EXPECTED_LIST_ELEMENTS);
    assert_eq!(lower_allocations, EXPECTED_LOWER_ALLOCATIONS);
    assert_eq!(max_type_depth, EXPECTED_MAX_TYPE_DEPTH);
    assert_eq!(max_value_depth, EXPECTED_MAX_VALUE_DEPTH);
    assert_eq!(
        digest.finish(),
        EXPECTED_CORPUS_DIGEST,
        "corpus digest was {:#018x}",
        digest.finish()
    );
    assert_eq!(
        mismatch_digest.finish(),
        EXPECTED_MISMATCH_DIGEST,
        "mismatch digest was {:#018x}",
        mismatch_digest.finish()
    );
}

fn record_rejection<F>(
    digest: &mut Fnv64,
    count: &mut u64,
    label: &'static str,
    expected: CodecError,
    operation: F,
) where
    F: FnOnce() -> Result<(), CodecError>,
{
    let result = catch_unwind(AssertUnwindSafe(operation));
    match result {
        Ok(Err(error)) => assert_eq!(error, expected, "wrong rejection for {label}"),
        Ok(Ok(())) => panic!("invalid case {label} was accepted"),
        Err(_) => panic!("invalid case {label} panicked"),
    }
    digest.bytes(label.as_bytes());
    digest.u32(expected.code().into());
    *count += 1;
}

fn reject_value(
    digest: &mut Fnv64,
    count: &mut u64,
    label: &'static str,
    ty: ValueType,
    value: CanonicalValue,
    expected: CodecError,
) {
    digest.byte(0x54);
    hash_type(digest, &ty);
    digest.byte(0x56);
    hash_value(digest, &value);
    record_rejection(digest, count, label, expected, || {
        let (mut memory, mut allocator) = memory_and_allocator();
        lower_value(
            &mut memory,
            &mut allocator,
            &ty,
            &value,
            ROOT_POINTER,
            ValuePosition::Parameter,
        )
        .map(|_| ())
    });
}

#[allow(clippy::too_many_arguments)]
fn reject_memory<F>(
    digest: &mut Fnv64,
    count: &mut u64,
    label: &'static str,
    ty: ValueType,
    value: CanonicalValue,
    pointer: u32,
    mutate: F,
    expected: CodecError,
) where
    F: FnOnce(&mut VecMemory),
{
    let (mut memory, mut allocator) = memory_and_allocator();
    lower_value(
        &mut memory,
        &mut allocator,
        &ty,
        &value,
        ROOT_POINTER,
        ValuePosition::Parameter,
    )
    .unwrap();
    mutate(&mut memory);
    digest.byte(0x4d);
    hash_type(digest, &ty);
    hash_value(digest, &value);
    digest.u32(pointer);
    let mut encoded = vec![0; memory.len() as usize];
    memory.read_exact(0, &mut encoded).unwrap();
    digest.bytes(&encoded);
    record_rejection(digest, count, label, expected, || {
        lift_value(
            &memory,
            &RejectResources,
            &ty,
            pointer,
            ValuePosition::Parameter,
        )
        .map(|_| ())
    });
}

#[test]
fn deterministic_invalid_shapes_and_memory_have_stable_rejections() {
    let mut digest = Fnv64::new(b"vibeos.c2.7.canonical-rejections.v1\0");
    let mut count = 0_u64;

    reject_value(
        &mut digest,
        &mut count,
        "value/bool-as-u8",
        ValueType::Bool,
        CanonicalValue::U8(1),
        CodecError::TypeMismatch,
    );
    reject_value(
        &mut digest,
        &mut count,
        "value/list-element",
        ValueType::List(Box::new(ValueType::U16)),
        CanonicalValue::List(vec![CanonicalValue::Bool(true)]),
        CodecError::TypeMismatch,
    );
    reject_value(
        &mut digest,
        &mut count,
        "value/flags-high-bit",
        ValueType::Flags(5),
        CanonicalValue::Flags(vec![0b10_0000]),
        CodecError::InvalidFlags,
    );
    reject_value(
        &mut digest,
        &mut count,
        "value/flags-word-count",
        ValueType::Flags(33),
        CanonicalValue::Flags(vec![0]),
        CodecError::InvalidFlags,
    );
    reject_value(
        &mut digest,
        &mut count,
        "value/enum-discriminant",
        ValueType::Enum(3),
        CanonicalValue::Enum(3),
        CodecError::InvalidDiscriminant,
    );
    reject_value(
        &mut digest,
        &mut count,
        "value/tuple-arity",
        ValueType::Tuple(vec![ValueType::U8]),
        CanonicalValue::Tuple(vec![]),
        CodecError::TypeMismatch,
    );
    reject_value(
        &mut digest,
        &mut count,
        "value/record-arity",
        ValueType::Record(vec![]),
        CanonicalValue::Record(vec![CanonicalValue::U8(0)]),
        CodecError::TypeMismatch,
    );
    reject_value(
        &mut digest,
        &mut count,
        "value/option-payload",
        ValueType::Option(Box::new(ValueType::U8)),
        CanonicalValue::Option(Some(Box::new(CanonicalValue::Bool(false)))),
        CodecError::TypeMismatch,
    );
    reject_value(
        &mut digest,
        &mut count,
        "value/result-missing-payload",
        ValueType::Result {
            ok: Some(Box::new(ValueType::U8)),
            error: None,
        },
        CanonicalValue::Result(Ok(None)),
        CodecError::TypeMismatch,
    );
    reject_value(
        &mut digest,
        &mut count,
        "value/result-unexpected-payload",
        ValueType::Result {
            ok: None,
            error: Some(Box::new(ValueType::U8)),
        },
        CanonicalValue::Result(Ok(Some(Box::new(CanonicalValue::U8(1))))),
        CodecError::TypeMismatch,
    );
    reject_value(
        &mut digest,
        &mut count,
        "value/variant-unit-payload",
        ValueType::Variant(vec![None, Some(ValueType::U16)]),
        CanonicalValue::Variant {
            case: 0,
            payload: Some(Box::new(CanonicalValue::U16(1))),
        },
        CodecError::TypeMismatch,
    );
    reject_value(
        &mut digest,
        &mut count,
        "value/variant-missing-payload",
        ValueType::Variant(vec![None, Some(ValueType::U16)]),
        CanonicalValue::Variant {
            case: 1,
            payload: None,
        },
        CodecError::TypeMismatch,
    );
    reject_value(
        &mut digest,
        &mut count,
        "value/variant-discriminant",
        ValueType::Variant(vec![None]),
        CanonicalValue::Variant {
            case: 1,
            payload: None,
        },
        CodecError::InvalidDiscriminant,
    );
    reject_value(
        &mut digest,
        &mut count,
        "type/zero-flags",
        ValueType::Flags(0),
        CanonicalValue::Flags(vec![]),
        CodecError::InvalidFlags,
    );
    reject_value(
        &mut digest,
        &mut count,
        "type/zero-enum",
        ValueType::Enum(0),
        CanonicalValue::Enum(0),
        CodecError::InvalidDiscriminant,
    );
    reject_value(
        &mut digest,
        &mut count,
        "type/empty-variant",
        ValueType::Variant(vec![]),
        CanonicalValue::Variant {
            case: 0,
            payload: None,
        },
        CodecError::InvalidDiscriminant,
    );
    let mut too_deep = ValueType::U8;
    for _ in 0..32 {
        too_deep = ValueType::Option(Box::new(too_deep));
    }
    reject_value(
        &mut digest,
        &mut count,
        "type/nesting-limit",
        too_deep,
        CanonicalValue::Option(None),
        CodecError::NestingLimit,
    );

    reject_memory(
        &mut digest,
        &mut count,
        "memory/bool",
        ValueType::Bool,
        CanonicalValue::Bool(true),
        ROOT_POINTER,
        |memory| memory.write_exact(ROOT_POINTER, &[2]).unwrap(),
        CodecError::InvalidBool,
    );
    reject_memory(
        &mut digest,
        &mut count,
        "memory/char-surrogate",
        ValueType::Char,
        CanonicalValue::Char('a'),
        ROOT_POINTER,
        |memory| {
            memory
                .write_exact(ROOT_POINTER, &0xd800_u32.to_le_bytes())
                .unwrap()
        },
        CodecError::InvalidChar,
    );
    reject_memory(
        &mut digest,
        &mut count,
        "memory/char-too-large",
        ValueType::Char,
        CanonicalValue::Char('a'),
        ROOT_POINTER,
        |memory| {
            memory
                .write_exact(ROOT_POINTER, &0x11_0000_u32.to_le_bytes())
                .unwrap()
        },
        CodecError::InvalidChar,
    );
    reject_memory(
        &mut digest,
        &mut count,
        "memory/string-utf8",
        ValueType::String,
        CanonicalValue::String(String::from("ok")),
        ROOT_POINTER,
        |memory| memory.write_exact(PAYLOAD_BASE, &[0xff, 0xff]).unwrap(),
        CodecError::InvalidUtf8,
    );
    reject_memory(
        &mut digest,
        &mut count,
        "memory/string-pointer",
        ValueType::String,
        CanonicalValue::String(String::from("x")),
        ROOT_POINTER,
        |memory| {
            memory
                .write_exact(ROOT_POINTER, &u32::MAX.to_le_bytes())
                .unwrap()
        },
        CodecError::OutOfBounds,
    );
    reject_memory(
        &mut digest,
        &mut count,
        "memory/string-length",
        ValueType::String,
        CanonicalValue::String(String::from("x")),
        ROOT_POINTER,
        |memory| {
            memory
                .write_exact(ROOT_POINTER + 4, &65_537_u32.to_le_bytes())
                .unwrap()
        },
        CodecError::ByteLimit,
    );
    reject_memory(
        &mut digest,
        &mut count,
        "memory/list-alignment",
        ValueType::List(Box::new(ValueType::U64)),
        CanonicalValue::List(vec![CanonicalValue::U64(1)]),
        ROOT_POINTER,
        |memory| {
            memory
                .write_exact(ROOT_POINTER, &3_u32.to_le_bytes())
                .unwrap()
        },
        CodecError::Misaligned,
    );
    reject_memory(
        &mut digest,
        &mut count,
        "memory/list-pointer",
        ValueType::List(Box::new(ValueType::U8)),
        CanonicalValue::List(vec![CanonicalValue::U8(1)]),
        ROOT_POINTER,
        |memory| {
            memory
                .write_exact(ROOT_POINTER, &u32::MAX.to_le_bytes())
                .unwrap()
        },
        CodecError::OutOfBounds,
    );
    reject_memory(
        &mut digest,
        &mut count,
        "memory/list-elements",
        ValueType::List(Box::new(ValueType::U8)),
        CanonicalValue::List(vec![CanonicalValue::U8(1)]),
        ROOT_POINTER,
        |memory| {
            memory
                .write_exact(ROOT_POINTER + 4, &4_097_u32.to_le_bytes())
                .unwrap()
        },
        CodecError::ElementLimit,
    );
    reject_memory(
        &mut digest,
        &mut count,
        "memory/flags",
        ValueType::Flags(5),
        CanonicalValue::Flags(vec![0]),
        ROOT_POINTER,
        |memory| memory.write_exact(ROOT_POINTER, &[0b10_0000]).unwrap(),
        CodecError::InvalidFlags,
    );
    reject_memory(
        &mut digest,
        &mut count,
        "memory/enum",
        ValueType::Enum(3),
        CanonicalValue::Enum(0),
        ROOT_POINTER,
        |memory| memory.write_exact(ROOT_POINTER, &[3]).unwrap(),
        CodecError::InvalidDiscriminant,
    );
    reject_memory(
        &mut digest,
        &mut count,
        "memory/option",
        ValueType::Option(Box::new(ValueType::U64)),
        CanonicalValue::Option(None),
        ROOT_POINTER,
        |memory| memory.write_exact(ROOT_POINTER, &[2]).unwrap(),
        CodecError::InvalidDiscriminant,
    );
    reject_memory(
        &mut digest,
        &mut count,
        "memory/result",
        ValueType::Result {
            ok: Some(Box::new(ValueType::U8)),
            error: None,
        },
        CanonicalValue::Result(Ok(Some(Box::new(CanonicalValue::U8(1))))),
        ROOT_POINTER,
        |memory| memory.write_exact(ROOT_POINTER, &[2]).unwrap(),
        CodecError::InvalidDiscriminant,
    );
    reject_memory(
        &mut digest,
        &mut count,
        "memory/variant",
        ValueType::Variant(vec![None, Some(ValueType::U16)]),
        CanonicalValue::Variant {
            case: 0,
            payload: None,
        },
        ROOT_POINTER,
        |memory| memory.write_exact(ROOT_POINTER, &[2]).unwrap(),
        CodecError::InvalidDiscriminant,
    );
    reject_memory(
        &mut digest,
        &mut count,
        "memory/root-alignment",
        ValueType::U64,
        CanonicalValue::U64(1),
        ROOT_POINTER + 1,
        |_| {},
        CodecError::Misaligned,
    );

    assert_eq!(count, EXPECTED_TARGETED_REJECTIONS);
    assert_eq!(
        digest.finish(),
        EXPECTED_REJECTION_DIGEST,
        "rejection digest was {:#018x}",
        digest.finish()
    );
}
