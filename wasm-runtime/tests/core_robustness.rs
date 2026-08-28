use std::panic::{catch_unwind, AssertUnwindSafe};

use vibeos_component_format::{LimitKind, TrapCode, PROFILE_1_LIMITS};
use vibeos_wasm_runtime::{
    AdmissionDetail, AdmissionError, CoreSummary, CoreValue, OwnerAllocationReservation,
    PollResult, ValidatedCore,
};

const SEED: u64 = 0x6a09_e667_f3bc_c909;
const RAW_MAX_LEN: usize = 192;
const STRUCTURED_CASES: usize = 96;
const TOTAL_FUEL: u64 = 50_000;
const EXPECTED_INPUTS: usize = (RAW_MAX_LEN + 1) * 2 + STRUCTURED_CASES * 3 + 5;
const EXPECTED_TOTAL_INPUT_BYTES: usize = 575_262;
const EXPECTED_CORPUS_FNV64: u64 = 0x7fc9_8ac3_2e54_fb64;
const EXPECTED_OUTCOME_FNV64: u64 = 0x2e7b_93e3_73f2_c522;

struct Generator(u64);

impl Generator {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.0 = value;
        value.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    fn index(&mut self, upper: usize) -> usize {
        assert!(upper != 0);
        (self.next_u64() % upper as u64) as usize
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            *byte = (self.next_u64() >> 56) as u8;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expected {
    Ready(i32),
    Trapped(TrapCode),
}

#[derive(Debug)]
struct StructuredCase {
    bytes: Vec<u8>,
    input: i32,
    expected: Expected,
}

fn structured_case(index: usize, generator: &mut Generator) -> StructuredCase {
    let mut input = generator.next_u32() as i32;
    let first = generator.next_u32() as i32;
    let second = generator.next_u32() as i32;
    let variant = index % 12;
    let (source, expected) = match variant {
        0 => (
            format!(
                "(module (func (export \"run\") (param i32) (result i32) \
                 local.get 0 i32.const {first} i32.add))"
            ),
            Expected::Ready(input.wrapping_add(first)),
        ),
        1 => (
            format!(
                "(module (func (export \"run\") (param i32) (result i32) \
                 local.get 0 i32.const {first} i32.sub))"
            ),
            Expected::Ready(input.wrapping_sub(first)),
        ),
        2 => (
            format!(
                "(module (func (export \"run\") (param i32) (result i32) \
                 local.get 0 i32.const {first} i32.xor))"
            ),
            Expected::Ready(input ^ first),
        ),
        3 => (
            format!(
                "(module (func (export \"run\") (param i32) (result i32) \
                 local.get 0 i32.const {first} i32.mul))"
            ),
            Expected::Ready(input.wrapping_mul(first)),
        ),
        4 => {
            let shift = first as u32;
            (
                format!(
                    "(module (func (export \"run\") (param i32) (result i32) \
                     local.get 0 i32.const {first} i32.rotl))"
                ),
                Expected::Ready(input.rotate_left(shift)),
            )
        }
        5 => {
            if (index / 12).is_multiple_of(2) {
                input = 0;
            }
            (
                format!(
                    "(module (func (export \"run\") (param i32) (result i32) \
                     local.get 0 i32.eqz if (result i32) i32.const {first} \
                     else local.get 0 i32.const {second} i32.add end))"
                ),
                Expected::Ready(if input == 0 {
                    first
                } else {
                    input.wrapping_add(second)
                }),
            )
        }
        6 => (
            format!(
                "(module \
                   (func $mix (param i32 i32) (result i32) \
                     local.get 0 local.get 1 i32.xor) \
                   (func (export \"run\") (param i32) (result i32) \
                     local.get 0 i32.const {first} call $mix))"
            ),
            Expected::Ready(input ^ first),
        ),
        7 => {
            let offset = (generator.next_u32() % 1_024) * 4;
            (
                format!(
                    "(module (memory 1 1) \
                       (func (export \"run\") (param i32) (result i32) \
                         i32.const {offset} local.get 0 i32.store \
                         i32.const {offset} i32.load))"
                ),
                Expected::Ready(input),
            )
        }
        8 => {
            input = (generator.next_u32() % 32) as i32;
            (
                String::from(
                    "(module \
                       (func (export \"run\") (param i32) (result i32) (local i32) \
                         local.get 0 local.set 1 \
                         block $done loop $again \
                           local.get 1 i32.eqz br_if $done \
                           local.get 1 i32.const 1 i32.sub local.set 1 \
                           br $again \
                         end end \
                         local.get 1))",
                ),
                Expected::Ready(0),
            )
        }
        9 => (
            String::from("(module (func (export \"run\") (param i32) (result i32) unreachable))"),
            Expected::Trapped(TrapCode::Unreachable),
        ),
        10 => {
            let divisor = (generator.next_u32() % 127 + 1) as i32;
            (
                format!(
                    "(module (func (export \"run\") (param i32) (result i32) \
                     local.get 0 i32.const {divisor} i32.div_s))"
                ),
                Expected::Ready(input / divisor),
            )
        }
        11 => {
            let shift = generator.next_u32() % 32;
            (
                format!(
                    "(module (func (export \"run\") (param i32) (result i32) \
                     local.get 0 i32.const {shift} i32.shr_s))"
                ),
                Expected::Ready(input >> shift),
            )
        }
        _ => unreachable!(),
    };
    let bytes = wat::parse_str(source).expect("generated Profile-1 WAT must encode");
    StructuredCase {
        bytes,
        input,
        expected,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PipelineOutcome {
    AdmissionRejected(AdmissionError),
    InstantiationRejected(AdmissionError),
    StartRejected(TrapCode),
    Ready(Vec<CoreValue>),
    Trapped(TrapCode),
}

fn assert_summary_within_profile(summary: CoreSummary, byte_len: usize) {
    assert_eq!(summary.bytes as usize, byte_len);
    assert!(summary.types <= PROFILE_1_LIMITS.max_types);
    assert!(summary.functions <= PROFILE_1_LIMITS.max_functions);
    assert!(summary.max_params <= PROFILE_1_LIMITS.max_params_per_function);
    assert!(summary.max_results <= PROFILE_1_LIMITS.max_results_per_function);
    assert!(summary.imports <= PROFILE_1_LIMITS.max_imports);
    assert!(summary.exports <= PROFILE_1_LIMITS.max_exports);
    assert!(summary.globals <= PROFILE_1_LIMITS.max_globals);
    assert!(
        summary.locals
            <= PROFILE_1_LIMITS
                .max_locals_per_function
                .saturating_mul(summary.functions)
    );
    assert!(summary.max_locals <= PROFILE_1_LIMITS.max_locals_per_function);
    assert!(summary.max_locals <= summary.locals);
    assert!(summary.memories <= PROFILE_1_LIMITS.max_memories);
    assert!(summary.tables <= PROFILE_1_LIMITS.max_tables);
    assert!(summary.data_segments <= PROFILE_1_LIMITS.max_data_segments);
    assert!(summary.element_segments <= PROFILE_1_LIMITS.max_element_segments);
    assert!(summary.element_items <= PROFILE_1_LIMITS.max_table_elements);
    assert!(summary.custom_sections <= PROFILE_1_LIMITS.max_custom_sections);
    assert!(summary.custom_section_bytes as usize <= PROFILE_1_LIMITS.max_custom_section_bytes);
    assert!(summary.max_control_depth <= PROFILE_1_LIMITS.max_core_nesting);
}

fn exercise(bytes: &[u8], input: i32) -> PipelineOutcome {
    let quantum = PROFILE_1_LIMITS.poll_quantum;
    assert!(quantum != 0);
    let reservation = OwnerAllocationReservation::profile_default();
    let module = match ValidatedCore::new(bytes, reservation) {
        Ok(module) => module,
        Err(error) => return PipelineOutcome::AdmissionRejected(error),
    };
    assert_summary_within_profile(module.summary(), bytes.len());
    assert!(module.reserved_compile_bytes() <= reservation.bytes());

    let mut instance = match module.instantiate() {
        Ok(instance) => instance,
        Err(error) => return PipelineOutcome::InstantiationRejected(error),
    };
    if let Err(trap) = instance.start_call("run", &[CoreValue::I32(input)], TOTAL_FUEL, quantum) {
        assert!(!instance.has_active_call());
        return PipelineOutcome::StartRejected(trap);
    }

    let max_polls = TOTAL_FUEL.div_ceil(quantum).saturating_add(1);
    let mut previous_consumed = 0;
    for _ in 0..max_polls {
        let result = instance.poll_call();
        let metrics = instance
            .call_metrics()
            .expect("a started or terminal call retains its fuel metrics");
        assert_eq!(
            metrics.consumed_fuel.saturating_add(metrics.remaining_fuel),
            TOTAL_FUEL
        );
        assert!(metrics.consumed_fuel >= previous_consumed);
        assert!(metrics.consumed_fuel - previous_consumed <= quantum);
        previous_consumed = metrics.consumed_fuel;

        match result {
            PollResult::Pending {
                consumed_fuel,
                remaining_fuel,
            } => {
                assert!(instance.has_active_call());
                assert_eq!(consumed_fuel, metrics.consumed_fuel);
                assert_eq!(remaining_fuel, metrics.remaining_fuel);
            }
            PollResult::Ready(values) => {
                assert!(!instance.has_active_call());
                return PipelineOutcome::Ready(values);
            }
            PollResult::Trapped(trap) => {
                assert!(!instance.has_active_call());
                return PipelineOutcome::Trapped(trap);
            }
            PollResult::HostCall(call) => {
                panic!("closed generated module reached a host call: {call:?}")
            }
        }
    }
    panic!("generated execution exceeded its fuel-derived poll bound");
}

fn checked_exercise(label: &str, bytes: &[u8], input: i32) -> PipelineOutcome {
    let first = match catch_unwind(AssertUnwindSafe(|| exercise(bytes, input))) {
        Ok(outcome) => outcome,
        Err(_) => panic!("host panic while exercising deterministic input {label}"),
    };
    let repeated = match catch_unwind(AssertUnwindSafe(|| exercise(bytes, input))) {
        Ok(outcome) => outcome,
        Err(_) => panic!("host panic while repeating deterministic input {label}"),
    };
    assert_eq!(
        repeated, first,
        "pipeline outcome was not repeatable for deterministic input {label}"
    );
    first
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Coverage {
    inputs: usize,
    total_input_bytes: usize,
    max_input_bytes: usize,
    admitted: usize,
    instantiated: usize,
    started: usize,
    malformed: usize,
    unsupported: usize,
    limited: usize,
    other_admission_rejections: usize,
    instantiation_rejections: usize,
    start_rejections: usize,
    ready: usize,
    trapped: usize,
}

const EXPECTED_COVERAGE: Coverage = Coverage {
    inputs: 679,
    total_input_bytes: 575_262,
    max_input_bytes: 524_289,
    admitted: 127,
    instantiated: 126,
    started: 111,
    malformed: 506,
    unsupported: 42,
    limited: 4,
    other_admission_rejections: 0,
    instantiation_rejections: 1,
    start_rejections: 15,
    ready: 101,
    trapped: 10,
};

impl Coverage {
    fn record(&mut self, input_bytes: usize, outcome: &PipelineOutcome) {
        self.inputs += 1;
        self.total_input_bytes = self.total_input_bytes.saturating_add(input_bytes);
        self.max_input_bytes = self.max_input_bytes.max(input_bytes);
        match outcome {
            PipelineOutcome::AdmissionRejected(error) => match error.detail {
                AdmissionDetail::Malformed => self.malformed += 1,
                AdmissionDetail::UnsupportedFeature => self.unsupported += 1,
                AdmissionDetail::Limit(_) => self.limited += 1,
                _ => self.other_admission_rejections += 1,
            },
            PipelineOutcome::InstantiationRejected(_) => {
                self.admitted += 1;
                self.instantiation_rejections += 1;
            }
            PipelineOutcome::StartRejected(_) => {
                self.admitted += 1;
                self.instantiated += 1;
                self.start_rejections += 1;
            }
            PipelineOutcome::Ready(_) => {
                self.admitted += 1;
                self.instantiated += 1;
                self.started += 1;
                self.ready += 1;
            }
            PipelineOutcome::Trapped(_) => {
                self.admitted += 1;
                self.instantiated += 1;
                self.started += 1;
                self.trapped += 1;
            }
        }
    }
}

fn hash_byte(hash: &mut u64, byte: u8) {
    *hash ^= u64::from(byte);
    *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
}

fn hash_input(hash: &mut u64, tag: u8, bytes: &[u8], input: i32) {
    hash_byte(hash, tag);
    for byte in (bytes.len() as u64).to_le_bytes() {
        hash_byte(hash, byte);
    }
    for byte in bytes {
        hash_byte(hash, *byte);
    }
    for byte in input.to_le_bytes() {
        hash_byte(hash, byte);
    }
}

fn hash_u64(hash: &mut u64, value: u64) {
    for byte in value.to_le_bytes() {
        hash_byte(hash, byte);
    }
}

fn core_limit_tag(kind: LimitKind) -> u8 {
    match kind {
        LimitKind::CoreModuleBytes => 0,
        LimitKind::Types => 1,
        LimitKind::Functions => 2,
        LimitKind::Parameters => 3,
        LimitKind::Results => 4,
        LimitKind::Imports => 5,
        LimitKind::Exports => 6,
        LimitKind::Globals => 7,
        LimitKind::Locals => 8,
        LimitKind::Memories => 9,
        LimitKind::InitialMemoryPages => 10,
        LimitKind::MemoryPages => 11,
        LimitKind::Tables => 12,
        LimitKind::TableElements => 13,
        LimitKind::DataSegments => 14,
        LimitKind::ElementSegments => 15,
        LimitKind::CustomSections => 16,
        LimitKind::CustomSectionBytes => 17,
        LimitKind::CoreNesting => 18,
        LimitKind::EngineAllocationBytes => 19,
        other => panic!("Core corpus reached a non-Core limit: {other:?}"),
    }
}

fn hash_admission_detail(hash: &mut u64, detail: AdmissionDetail) {
    let tag = match detail {
        AdmissionDetail::Malformed => 0,
        AdmissionDetail::UnsupportedFeature => 1,
        AdmissionDetail::ComponentInsteadOfCore => 2,
        AdmissionDetail::ImportRequiresLinker => 3,
        AdmissionDetail::MissingMaximum => 4,
        AdmissionDetail::Limit(kind) => {
            hash_byte(hash, 5);
            hash_byte(hash, core_limit_tag(kind));
            return;
        }
        AdmissionDetail::AllocationReservation => 6,
        AdmissionDetail::HostImportMismatch => 7,
    };
    hash_byte(hash, tag);
}

fn hash_admission_error(hash: &mut u64, error: AdmissionError) {
    for byte in error.trap.code().to_le_bytes() {
        hash_byte(hash, byte);
    }
    hash_admission_detail(hash, error.detail);
}

fn hash_outcome(hash: &mut u64, outcome: &PipelineOutcome) {
    match outcome {
        PipelineOutcome::AdmissionRejected(error) => {
            hash_byte(hash, 0);
            hash_admission_error(hash, *error);
        }
        PipelineOutcome::InstantiationRejected(error) => {
            hash_byte(hash, 1);
            hash_admission_error(hash, *error);
        }
        PipelineOutcome::StartRejected(trap) => {
            hash_byte(hash, 2);
            for byte in trap.code().to_le_bytes() {
                hash_byte(hash, byte);
            }
        }
        PipelineOutcome::Ready(values) => {
            hash_byte(hash, 3);
            hash_u64(hash, values.len() as u64);
            for value in values {
                match value {
                    CoreValue::I32(value) => {
                        hash_byte(hash, 0);
                        for byte in value.to_le_bytes() {
                            hash_byte(hash, byte);
                        }
                    }
                    CoreValue::I64(value) => {
                        hash_byte(hash, 1);
                        for byte in value.to_le_bytes() {
                            hash_byte(hash, byte);
                        }
                    }
                }
            }
        }
        PipelineOutcome::Trapped(trap) => {
            hash_byte(hash, 4);
            for byte in trap.code().to_le_bytes() {
                hash_byte(hash, byte);
            }
        }
    }
}

fn record_outcome(
    coverage: &mut Coverage,
    outcome_hash: &mut u64,
    input_bytes: usize,
    outcome: &PipelineOutcome,
) {
    coverage.record(input_bytes, outcome);
    hash_outcome(outcome_hash, outcome);
}

#[test]
fn seeded_bounded_core_pipeline_reaches_every_stage_without_host_panics() {
    let mut generator = Generator::new(SEED);
    let mut coverage = Coverage::default();
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    let mut outcome_digest = 0xcbf2_9ce4_8422_2325_u64;

    for len in 0..=RAW_MAX_LEN {
        let mut bytes = vec![0_u8; len];
        generator.fill(&mut bytes);
        hash_input(&mut digest, 0, &bytes, 0);
        let outcome = checked_exercise(&format!("raw-{len}"), &bytes, 0);
        record_outcome(&mut coverage, &mut outcome_digest, bytes.len(), &outcome);
    }

    for tail_len in 0..=RAW_MAX_LEN {
        let mut bytes = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        bytes.resize(bytes.len() + tail_len, 0);
        generator.fill(&mut bytes[8..]);
        hash_input(&mut digest, 1, &bytes, 0);
        let outcome = checked_exercise(&format!("magic-tail-{tail_len}"), &bytes, 0);
        record_outcome(&mut coverage, &mut outcome_digest, bytes.len(), &outcome);
    }

    let disabled_float =
        wat::parse_str("(module (func (export \"run\") (param i32) (result f32) f32.const 0))")
            .unwrap();
    hash_input(&mut digest, 2, &disabled_float, 0);
    let outcome = checked_exercise("disabled-float", &disabled_float, 0);
    assert_eq!(
        outcome,
        PipelineOutcome::AdmissionRejected(AdmissionError {
            trap: TrapCode::UnsupportedFeature,
            detail: AdmissionDetail::UnsupportedFeature,
        })
    );
    record_outcome(
        &mut coverage,
        &mut outcome_digest,
        disabled_float.len(),
        &outcome,
    );

    let unlinked_import = wat::parse_str(
        "(module (import \"env\" \"host\" (func)) \
         (func (export \"run\") (param i32) (result i32) call 0 local.get 0))",
    )
    .unwrap();
    hash_input(&mut digest, 3, &unlinked_import, 0);
    let outcome = checked_exercise("unlinked-import", &unlinked_import, 0);
    assert_eq!(
        outcome,
        PipelineOutcome::InstantiationRejected(AdmissionError {
            trap: TrapCode::Validation,
            detail: AdmissionDetail::ImportRequiresLinker,
        })
    );
    record_outcome(
        &mut coverage,
        &mut outcome_digest,
        unlinked_import.len(),
        &outcome,
    );

    let spin = wat::parse_str(
        "(module (func (export \"run\") (param i32) (result i32) \
         (loop $spin (br $spin)) unreachable))",
    )
    .unwrap();
    hash_input(&mut digest, 7, &spin, 0);
    let outcome = checked_exercise("fuel-bounded-spin", &spin, 0);
    assert_eq!(outcome, PipelineOutcome::Trapped(TrapCode::FuelExhausted));
    record_outcome(&mut coverage, &mut outcome_digest, spin.len(), &outcome);

    let recursion = wat::parse_str(
        "(module (func $recurse (export \"run\") (param i32) (result i32) \
         local.get 0 call $recurse))",
    )
    .unwrap();
    hash_input(&mut digest, 8, &recursion, 0);
    let outcome = checked_exercise("depth-bounded-recursion", &recursion, 0);
    assert_eq!(
        outcome,
        PipelineOutcome::Trapped(TrapCode::CallDepthExceeded)
    );
    record_outcome(
        &mut coverage,
        &mut outcome_digest,
        recursion.len(),
        &outcome,
    );

    let mut reservation_probe = None;
    let mut structured_ready = 0;
    let mut structured_trapped = 0;
    for index in 0..STRUCTURED_CASES {
        let case = structured_case(index, &mut generator);
        assert!(case.bytes.len() <= 4_096);
        if reservation_probe.is_none() {
            reservation_probe = Some(case.bytes.clone());
        }
        hash_input(&mut digest, 4, &case.bytes, case.input);
        let outcome = checked_exercise(&format!("structured-{index}"), &case.bytes, case.input);
        match case.expected {
            Expected::Ready(value) => {
                assert_eq!(outcome, PipelineOutcome::Ready(vec![CoreValue::I32(value)]));
                structured_ready += 1;
            }
            Expected::Trapped(trap) => {
                assert_eq!(outcome, PipelineOutcome::Trapped(trap));
                structured_trapped += 1;
            }
        }
        record_outcome(
            &mut coverage,
            &mut outcome_digest,
            case.bytes.len(),
            &outcome,
        );

        let truncated_len = generator.index(case.bytes.len());
        let truncated = case.bytes[..truncated_len].to_vec();
        hash_input(&mut digest, 5, &truncated, case.input);
        let outcome = checked_exercise(&format!("truncated-{index}"), &truncated, case.input);
        record_outcome(
            &mut coverage,
            &mut outcome_digest,
            truncated.len(),
            &outcome,
        );

        let mut flipped = case.bytes.clone();
        let byte_index = generator.index(flipped.len());
        let bit = 1_u8 << generator.index(8);
        flipped[byte_index] ^= bit;
        hash_input(&mut digest, 6, &flipped, case.input);
        let outcome = checked_exercise(&format!("flipped-{index}"), &flipped, case.input);
        record_outcome(&mut coverage, &mut outcome_digest, flipped.len(), &outcome);
    }

    let oversized = vec![0_u8; PROFILE_1_LIMITS.max_core_module_bytes + 1];
    hash_input(&mut digest, 9, &oversized, 0);
    let outcome = checked_exercise("oversized", &oversized, 0);
    assert_eq!(
        outcome,
        PipelineOutcome::AdmissionRejected(AdmissionError {
            trap: TrapCode::LimitExceeded,
            detail: AdmissionDetail::Limit(LimitKind::CoreModuleBytes),
        })
    );
    record_outcome(
        &mut coverage,
        &mut outcome_digest,
        oversized.len(),
        &outcome,
    );

    let reservation_probe = reservation_probe.unwrap();
    let reservation_result = catch_unwind(AssertUnwindSafe(|| {
        let accepted = ValidatedCore::new(
            &reservation_probe,
            OwnerAllocationReservation::profile_default(),
        )
        .unwrap();
        let required = accepted.reserved_compile_bytes();
        assert!(required > 0);
        ValidatedCore::new(
            &reservation_probe,
            OwnerAllocationReservation::new(required - 1),
        )
        .unwrap_err()
        .detail
    }));
    assert_eq!(
        reservation_result.expect("host panic while checking the tight allocation reservation"),
        AdmissionDetail::AllocationReservation
    );

    assert_eq!(coverage.inputs, EXPECTED_INPUTS, "{coverage:?}");
    assert_eq!(
        coverage.total_input_bytes, EXPECTED_TOTAL_INPUT_BYTES,
        "{coverage:?}"
    );
    assert_eq!(
        coverage.max_input_bytes,
        PROFILE_1_LIMITS.max_core_module_bytes + 1,
        "{coverage:?}"
    );
    assert_eq!(structured_ready, 88);
    assert_eq!(structured_trapped, 8);
    assert!(coverage.malformed != 0, "{coverage:?}");
    assert!(coverage.unsupported != 0, "{coverage:?}");
    assert!(coverage.limited != 0, "{coverage:?}");
    assert!(coverage.instantiation_rejections != 0, "{coverage:?}");
    assert!(coverage.start_rejections != 0, "{coverage:?}");
    assert!(coverage.admitted >= STRUCTURED_CASES + 2, "{coverage:?}");
    assert!(coverage.instantiated > STRUCTURED_CASES, "{coverage:?}");
    assert!(coverage.started >= STRUCTURED_CASES + 2, "{coverage:?}");
    assert!(coverage.ready >= structured_ready, "{coverage:?}");
    assert!(coverage.trapped >= structured_trapped + 2, "{coverage:?}");
    assert_eq!(digest, EXPECTED_CORPUS_FNV64, "corpus drift: {coverage:?}");
    assert_eq!(
        outcome_digest, EXPECTED_OUTCOME_FNV64,
        "pipeline outcome drift: {coverage:?}"
    );
    assert_eq!(coverage, EXPECTED_COVERAGE);
}
