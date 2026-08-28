//! Isolated fixed-QEMU producer for the C8.8-F5 scalar-float qualification.
//!
//! The portable routine lives in `vibeos-wasm-float-target`; this adapter only
//! binds a formal source/challenge envelope, emits a closed UART grammar, and
//! shuts the emulator down. It exposes no command or production engine route.

use alloc::{format, string::String};
use sha2::{Digest, Sha256};
use vibeos_component_format::TrapCode;
use vibeos_component_runtime::float_candidate::{
    FloatCandidateLifecycleMetrics, FloatCandidateState,
};
use vibeos_wasm_float_target::{
    candidate_identity, qualify, CoreObservation, CoreOutcome, CorePath, FuelOutcome,
    LifecycleSnapshot, QualificationReport, CANDIDATE_COMPONENT_BYTES, CANDIDATE_SHA256,
    CANDIDATE_SHA256_BYTES, CORE_CASES, CORE_MEMORY_BYTES, F3_VECTORS, F4_VECTORS,
    PHYSICAL_PROVENANCE, PLATFORM, PLATFORM_CLASS, POLL_QUANTUM, TOTAL_FUEL, WIT_SHA256_BYTES,
    WORLD,
};

const SUITE_ID: &str = "vibeos.c88.f5.float-target";
const TARGET: &str = "riscv64imac-unknown-none-elf";
const SEMANTIC_DIGEST_DOMAIN: &[u8] = b"vibeos.c88.f5.float-target.semantic.v1\0";
const RUN_ID_DOMAIN: &[u8] = b"vibeos.c88.f5.float-target.run.v1\0";
const EXPECTED_SEMANTIC_SHA256: &str =
    "51896391bb2a3493f1252e2633f54678bb1e69aa46a7e740dc4bc110381504f1";

const SOURCE_COMMIT: &str = match option_env!("VIBEOS_C88_F5_SOURCE_COMMIT") {
    Some(value) => value,
    None => "",
};
const SOURCE_TREE: &str = match option_env!("VIBEOS_C88_F5_SOURCE_TREE") {
    Some(value) => value,
    None => "",
};
const CHALLENGE: &str = match option_env!("VIBEOS_C88_F5_CHALLENGE") {
    Some(value) => value,
    None => "",
};
const RUN_ID: &str = match option_env!("VIBEOS_C88_F5_RUN_ID") {
    Some(value) => value,
    None => "",
};
const MANIFEST_SHA256: &str = match option_env!("VIBEOS_C88_F5_MANIFEST_SHA256") {
    Some(value) => value,
    None => "",
};
const TRANSCRIPT_SCHEMA_SHA256: &str = match option_env!("VIBEOS_C88_F5_TRANSCRIPT_SCHEMA_SHA256") {
    Some(value) => value,
    None => "",
};

const CORE_RECORDS: usize = CORE_CASES;
const F3_RECORDS: usize = F3_VECTORS.len() + 1;
const F4_RECORDS: usize = F4_VECTORS.len();
const FUEL_RECORDS: usize = 1_000;
const LIFECYCLE_RECORDS: usize = 5;
const DATA_RECORDS: usize =
    CORE_RECORDS + F3_RECORDS + F4_RECORDS + FUEL_RECORDS + LIFECYCLE_RECORDS;

fn valid_lower_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        && value.as_bytes().iter().any(|byte| *byte != b'0')
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut output = String::new();
    output.reserve_exact(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn expected_run_id() -> String {
    let mut digest = Sha256::new();
    digest.update(RUN_ID_DOMAIN);
    for (index, field) in [
        SOURCE_COMMIT,
        SOURCE_TREE,
        CHALLENGE,
        MANIFEST_SHA256,
        TRANSCRIPT_SCHEMA_SHA256,
        CANDIDATE_SHA256,
    ]
    .into_iter()
    .enumerate()
    {
        if index != 0 {
            digest.update(b"\0");
        }
        digest.update(field.as_bytes());
    }
    digest_hex(&digest.finalize())
}

fn bindings_are_valid() -> bool {
    valid_lower_hex(SOURCE_COMMIT, 40)
        && valid_lower_hex(SOURCE_TREE, 40)
        && valid_lower_hex(CHALLENGE, 64)
        && valid_lower_hex(RUN_ID, 64)
        && valid_lower_hex(MANIFEST_SHA256, 64)
        && valid_lower_hex(TRANSCRIPT_SCHEMA_SHA256, 64)
        && expected_run_id() == RUN_ID
}

fn report_is_frozen(report: &QualificationReport) -> bool {
    CANDIDATE_COMPONENT_BYTES == 291
        && report.core.wasm_bytes == 4_179
        && report.core.wasm_sha256
            == "6e1cb23543bdfbbb9397c3dd5ad69b2f023d23cf292f652029da838d098121ba"
        && report.core.compile_reservation_bytes == 135_720
        && report.core.observations.len() == CORE_RECORDS
        && report.core.runtime_digest == 0x3fb9_3000_b758_09b0
        && report.core.fold_digest == 0x2972_8126_8f51_6746
        && report.core.spin_trace_digest == 0xaf2d_de39_8571_6198
        && report.core.spin_consumed_fuel == 99_998
        && report.core.spin_remaining_fuel == 2
        && report.core.spin_poll_calls == 1_011
        && report.codec.vectors.len() == F3_VECTORS.len()
        && report.codec.scalar_cases == 24
        && report.codec.flat_cases == 48
        && report.codec.memory_cases == 24
        && report.codec.indirect_cases == 3
        && report.codec.variant_cases == 1
        && report.codec.nested_cases == 1
        && report.codec.hostile_rejections == 3
        && report.codec.allocations == 4
        && report.codec.allocated_bytes == 108
        && report.codec.digest == 0x6a86_6785_1156_a05c
        && report.lifecycle.component_sha256_bytes == CANDIDATE_SHA256_BYTES
        && report.lifecycle.wit_sha256_bytes == WIT_SHA256_BYTES
        && report.lifecycle.vectors.len() == F4_VECTORS.len()
        && report.lifecycle.vector_digest == 0x14ec_9b26_b290_191c
        && report.lifecycle.vector_fuel_total == 84
        && report.lifecycle.exhaustion_trace.len() == FUEL_RECORDS
        && report.lifecycle.exhaustion_pending_polls == 999
        && report.lifecycle.exhaustion_trace_digest == 0x1377_4615_3ac6_133c
        && report.lifecycle.exhaustion_consumed_fuel == 99_999
        && report.lifecycle.exhaustion_remaining_fuel == 1
        && report.lifecycle.recovery_output_bits == 0x3ff0_0000_0000_0000
        && report.lifecycle.recovery_consumed_fuel == 7
        && report.lifecycle.snapshots.len() == LIFECYCLE_RECORDS
        && report.lifecycle.snapshots[0].id == "cancelled"
        && report.lifecycle.snapshots[0].state == FloatCandidateState::Cancelled
        && (
            report.lifecycle.snapshots[0].last_consumed_fuel,
            report.lifecycle.snapshots[0].last_remaining_fuel,
        ) == (99, 99_901)
        && report.lifecycle.snapshots[1].id == "unreachable-fault"
        && report.lifecycle.snapshots[1].state
            == FloatCandidateState::Faulted(TrapCode::Unreachable)
        && (
            report.lifecycle.snapshots[1].last_consumed_fuel,
            report.lifecycle.snapshots[1].last_remaining_fuel,
        ) == (5, 99_995)
        && report.lifecycle.snapshots[2].id == "fuel-fault"
        && report.lifecycle.snapshots[2].state
            == FloatCandidateState::Faulted(TrapCode::FuelExhausted)
        && (
            report.lifecycle.snapshots[2].last_consumed_fuel,
            report.lifecycle.snapshots[2].last_remaining_fuel,
        ) == (99_999, 1)
        && report.lifecycle.snapshots[3].id == "recovered"
        && report.lifecycle.snapshots[3].state == FloatCandidateState::Idle
        && (
            report.lifecycle.snapshots[3].last_consumed_fuel,
            report.lifecycle.snapshots[3].last_remaining_fuel,
        ) == (7, 99_993)
        && report.lifecycle.snapshots[4].id == "revoked"
        && report.lifecycle.snapshots[4].state == FloatCandidateState::Revoked
        && (
            report.lifecycle.snapshots[4].last_consumed_fuel,
            report.lifecycle.snapshots[4].last_remaining_fuel,
        ) == (7, 99_993)
}

struct RecordEmitter {
    digest: Sha256,
    sequence: usize,
}

impl RecordEmitter {
    fn new() -> Self {
        let mut digest = Sha256::new();
        digest.update(SEMANTIC_DIGEST_DOMAIN);
        Self {
            digest,
            sequence: 0,
        }
    }

    fn emit(&mut self, family: &str, prefix: &str, schema: &str, semantic: String) {
        self.digest.update(family.as_bytes());
        self.digest.update(b"\0");
        self.digest.update(semantic.as_bytes());
        self.digest.update(b"\n");
        let fields = &semantic[1..semantic.len() - 1];
        crate::println!(
            "{}{{\"schema\":\"{}\",\"version\":1,\"run_id\":\"{}\",\"sequence\":{},{} }}",
            prefix,
            schema,
            RUN_ID,
            self.sequence,
            fields,
        );
        self.sequence += 1;
    }

    fn finish(self) -> (usize, String) {
        (self.sequence, digest_hex(&self.digest.finalize()))
    }
}

fn outcome_token(outcome: CoreOutcome) -> String {
    match outcome {
        CoreOutcome::Value(bits) => format!("{bits:016x}"),
        CoreOutcome::Trap(trap) => format!("trap:{}", trap.name()),
    }
}

fn core_path(path: CorePath) -> &'static str {
    match path {
        CorePath::Runtime => "runtime",
        CorePath::Fold => "fold",
        CorePath::Spin => "spin",
    }
}

fn core_case_id(observation: CoreObservation) -> String {
    match observation.path {
        CorePath::Runtime => format!("runtime-{}", observation.id),
        CorePath::Fold => format!("fold-{}", observation.id),
        CorePath::Spin => String::from(observation.id),
    }
}

fn emit_core(emitter: &mut RecordEmitter, observation: CoreObservation) {
    let expected = outcome_token(observation.expected);
    let actual = outcome_token(observation.actual);
    let outcome = match observation.actual {
        CoreOutcome::Value(_) => "ready",
        CoreOutcome::Trap(_) => "trapped",
    };
    let semantic = format!(
        "{{\"actual\":\"{}\",\"case_id\":\"{}\",\"consumed_fuel\":{},\"expected\":\"{}\",\"input0\":\"{:016x}\",\"input1\":\"{:016x}\",\"op_index\":{},\"outcome\":\"{}\",\"path\":\"{}\",\"pending_polls\":{},\"poll_calls\":{},\"remaining_fuel\":{},\"trace_digest\":\"{:016x}\"}}",
        actual,
        core_case_id(observation),
        observation.consumed_fuel,
        expected,
        observation.input0,
        observation.input1,
        observation.op_index,
        outcome,
        core_path(observation.path),
        observation.pending_polls,
        observation.poll_calls,
        observation.remaining_fuel,
        observation.trace_digest,
    );
    emitter.emit(
        "CORE_CASE",
        "VIBE_C88_F5_CORE_CASE ",
        "vibeos.c88.f5.float-target.core-case",
        semantic,
    );
}

fn emit_f3(emitter: &mut RecordEmitter, report: &QualificationReport) {
    for (vector, observation) in F3_VECTORS.iter().zip(report.codec.vectors.iter()) {
        let semantic = format!(
            "{{\"actual_f32\":\"{:08x}\",\"actual_f64\":\"{:016x}\",\"case_id\":\"{}\",\"expected_f32\":\"{:08x}\",\"expected_f64\":\"{:016x}\",\"kind\":\"vector\",\"raw_f32\":\"{:08x}\",\"raw_f64\":\"{:016x}\"}}",
            observation.actual_f32,
            observation.actual_f64,
            vector.id,
            vector.expected_f32,
            vector.expected_f64,
            vector.raw_f32,
            vector.raw_f64,
        );
        emitter.emit(
            "F3_CASE",
            "VIBE_C88_F5_F3_CASE ",
            "vibeos.c88.f5.float-target.f3-case",
            semantic,
        );
    }
    let codec = &report.codec;
    let semantic = format!(
        "{{\"allocated_bytes\":{},\"allocations\":{},\"case_id\":\"summary\",\"digest\":\"{:016x}\",\"flat_cases\":{},\"hostile_rejections\":{},\"indirect_cases\":{},\"kind\":\"summary\",\"memory_cases\":{},\"nested_cases\":{},\"scalar_cases\":{},\"variant_cases\":{}}}",
        codec.allocated_bytes,
        codec.allocations,
        codec.digest,
        codec.flat_cases,
        codec.hostile_rejections,
        codec.indirect_cases,
        codec.memory_cases,
        codec.nested_cases,
        codec.scalar_cases,
        codec.variant_cases,
    );
    emitter.emit(
        "F3_CASE",
        "VIBE_C88_F5_F3_CASE ",
        "vibeos.c88.f5.float-target.f3-case",
        semantic,
    );
}

fn emit_f4(emitter: &mut RecordEmitter, report: &QualificationReport) {
    for (vector, observation) in F4_VECTORS.iter().zip(report.lifecycle.vectors.iter()) {
        let semantic = format!(
            "{{\"actual_f64\":\"{:016x}\",\"case_id\":\"{}\",\"consumed_fuel\":{},\"expected_f64\":\"{:016x}\",\"left_f32\":\"{:08x}\",\"pending_polls\":{},\"poll_calls\":{},\"remaining_fuel\":{},\"right_f64\":\"{:016x}\"}}",
            observation.output_bits,
            vector.id,
            observation.consumed_fuel,
            vector.expected_bits,
            vector.left_bits,
            observation.pending_polls,
            observation.poll_calls,
            observation.remaining_fuel,
            vector.right_bits,
        );
        emitter.emit(
            "F4_VECTOR",
            "VIBE_C88_F5_F4_VECTOR ",
            "vibeos.c88.f5.float-target.f4-vector",
            semantic,
        );
    }
}

fn emit_fuel(emitter: &mut RecordEmitter, report: &QualificationReport) {
    for observation in &report.lifecycle.exhaustion_trace {
        let outcome = match observation.outcome {
            FuelOutcome::Pending => "pending",
            FuelOutcome::FuelExhausted => "fuel-exhausted",
        };
        let semantic = if observation.outcome == FuelOutcome::FuelExhausted {
            format!(
                "{{\"case_id\":\"policy-fuel-exhaustion\",\"consumed_fuel\":{},\"delta\":{},\"outcome\":\"{}\",\"poll_index\":{},\"remaining_fuel\":{},\"trace_digest\":\"{:016x}\"}}",
                observation.consumed_fuel,
                observation.delta,
                outcome,
                observation.poll_index,
                observation.remaining_fuel,
                report.lifecycle.exhaustion_trace_digest,
            )
        } else {
            format!(
                "{{\"case_id\":\"policy-fuel-exhaustion\",\"consumed_fuel\":{},\"delta\":{},\"outcome\":\"{}\",\"poll_index\":{},\"remaining_fuel\":{}}}",
                observation.consumed_fuel,
                observation.delta,
                outcome,
                observation.poll_index,
                observation.remaining_fuel,
            )
        };
        emitter.emit(
            "FUEL",
            "VIBE_C88_F5_FUEL ",
            "vibeos.c88.f5.float-target.fuel",
            semantic,
        );
    }
}

fn lifecycle_state(state: FloatCandidateState) -> &'static str {
    match state {
        FloatCandidateState::Idle => "idle",
        FloatCandidateState::Cancelled => "cancelled",
        FloatCandidateState::Faulted(TrapCode::Unreachable) => "faulted-unreachable",
        FloatCandidateState::Faulted(TrapCode::FuelExhausted) => "faulted-fuel-exhausted",
        FloatCandidateState::Faulted(_) => "faulted-other",
        FloatCandidateState::Running => "running",
        FloatCandidateState::Poisoned => "poisoned",
        FloatCandidateState::Revoked => "revoked",
    }
}

fn emit_lifecycle_snapshot(emitter: &mut RecordEmitter, snapshot: LifecycleSnapshot) {
    let FloatCandidateLifecycleMetrics {
        activations,
        calls_started,
        calls_completed,
        cancellations,
        revocations,
        faults,
        reclaimed_instances,
        peak_live_instances,
    } = snapshot.metrics;
    let semantic = format!(
        "{{\"activations\":{},\"calls_completed\":{},\"calls_started\":{},\"cancellations\":{},\"case_id\":\"candidate-lifecycle\",\"faults\":{},\"last_consumed_fuel\":{},\"last_remaining_fuel\":{},\"live_instances\":{},\"peak_live_instances\":{},\"reclaimed_instances\":{},\"revocations\":{},\"state\":\"{}\",\"step\":\"{}\"}}",
        activations,
        calls_completed,
        calls_started,
        cancellations,
        faults,
        snapshot.last_consumed_fuel,
        snapshot.last_remaining_fuel,
        snapshot.live_instances,
        peak_live_instances,
        reclaimed_instances,
        revocations,
        lifecycle_state(snapshot.state),
        snapshot.id,
    );
    emitter.emit(
        "LIFECYCLE",
        "VIBE_C88_F5_LIFECYCLE ",
        "vibeos.c88.f5.float-target.lifecycle",
        semantic,
    );
}

fn emit_metadata(report: &QualificationReport) {
    let candidate = candidate_identity();
    let component_sha256 = digest_hex(&report.lifecycle.component_sha256_bytes);
    let wit_sha256 = digest_hex(&report.lifecycle.wit_sha256_bytes);
    crate::println!(
        concat!(
            "VIBE_C88_F5_META {{",
            "\"schema\":\"vibeos.c88.f5.float-target.meta\",\"version\":1,",
            "\"suite_id\":\"{}\",\"suite_revision\":1,",
            "\"source_commit\":\"{}\",\"source_tree\":\"{}\",",
            "\"challenge\":\"{}\",\"run_id\":\"{}\",",
            "\"manifest_sha256\":\"{}\",\"transcript_schema_sha256\":\"{}\",",
            "\"platform\":\"{}\",\"platform_class\":\"{}\",\"target\":\"{}\",",
            "\"physical_provenance\":\"{}\",",
            "\"artifact_profile_code\":5,\"artifact_abi\":5,\"component_profile\":2,",
            "\"core_profile\":2,\"runtime_abi\":5,\"stage\":\"validation-only\",",
            "\"runtime_ready\":false,\"native_async_runtime_ready\":false,",
            "\"execution_enabled\":false,\"current_validation_engine\":false,",
            "\"current_component_engine\":false,",
            "\"candidate_package\":\"{}\",\"candidate_version\":\"{}\",",
            "\"candidate_upstream_commit\":\"{}\",",
            "\"candidate_manifest_sha256\":\"{}\",\"candidate_patch_sha256\":\"{}\",",
            "\"backend_package\":\"{}\",\"backend_version\":\"{}\",",
            "\"backend_archive_sha256\":\"{}\",\"backend_revision\":\"{}\",",
            "\"backend_llvm_revision\":\"{}\",\"candidate_feature_set\":\"{}\",",
            "\"candidate_acceptance_feature\":\"{}\",\"candidate_production_ready\":false,",
            "\"core_module_sha256\":\"{}\",\"core_module_bytes\":{},",
            "\"core_compile_reservation_bytes\":{},\"core_memory_bytes\":{},",
            "\"core_runtime_digest\":\"{:016x}\",\"core_fold_digest\":\"{:016x}\",",
            "\"core_spin_trace_digest\":\"{:016x}\",",
            "\"component_sha256\":\"{}\",\"component_bytes\":{},",
            "\"wit_sha256\":\"{}\",\"world\":\"{}\",\"export\":\"run\",",
            "\"activation_label\":\"c88-f4-float-candidate\",",
            "\"memory_bytes\":131072,\"total_fuel\":{},\"poll_quantum\":{},\"resources\":0,",
            "\"embedded_modules\":1,\"core_instances\":1,\"component_instances\":0,",
            "\"aliases\":1,\"canonical_functions\":1,\"adapters\":0,\"imports\":0,",
            "\"host_imports\":0,\"exports\":1,\"executable_exports\":0,\"exact_binding\":true,",
            "\"core_cases\":{},\"f3_cases\":{},\"f4_vectors\":{},\"fuel_records\":{},",
            "\"lifecycle_records\":{},\"records\":{}",
            "}}"
        ),
        SUITE_ID,
        SOURCE_COMMIT,
        SOURCE_TREE,
        CHALLENGE,
        RUN_ID,
        MANIFEST_SHA256,
        TRANSCRIPT_SCHEMA_SHA256,
        PLATFORM,
        PLATFORM_CLASS,
        TARGET,
        PHYSICAL_PROVENANCE,
        candidate.package,
        candidate.version,
        candidate.upstream_revision,
        candidate.patched_manifest_sha256,
        candidate.patch_delta_sha256,
        candidate.backend_package,
        candidate.backend_version,
        candidate.backend_archive_sha256,
        candidate.backend_revision,
        candidate.backend_llvm_revision,
        candidate.feature_set,
        candidate.acceptance_feature,
        report.core.wasm_sha256,
        report.core.wasm_bytes,
        report.core.compile_reservation_bytes,
        CORE_MEMORY_BYTES,
        report.core.runtime_digest,
        report.core.fold_digest,
        report.core.spin_trace_digest,
        component_sha256,
        CANDIDATE_COMPONENT_BYTES,
        wit_sha256,
        WORLD,
        TOTAL_FUEL,
        POLL_QUANTUM,
        CORE_RECORDS,
        F3_RECORDS,
        F4_RECORDS,
        FUEL_RECORDS,
        LIFECYCLE_RECORDS,
        DATA_RECORDS,
    );
}

fn emit_terminal(prefix: &str, schema: &str, semantic_sha256: &str) {
    crate::println!(
        "{}{{\"schema\":\"{}\",\"version\":1,\"run_id\":\"{}\",\"challenge\":\"{}\",\"core_cases\":{},\"f3_cases\":{},\"f4_vectors\":{},\"fuel_records\":{},\"lifecycle_records\":{},\"records\":{},\"semantic_sha256\":\"{}\"}}",
        prefix,
        schema,
        RUN_ID,
        CHALLENGE,
        CORE_RECORDS,
        F3_RECORDS,
        F4_RECORDS,
        FUEL_RECORDS,
        LIFECYCLE_RECORDS,
        DATA_RECORDS,
        semantic_sha256,
    );
}

fn fail(code: u16) -> ! {
    crate::println!("VIBE_C88_F5_FAIL {{\"code\":{}}}", code);
    crate::sbi::shutdown(true)
}

pub async fn run() {
    if crate::online_hart_count() != 1 || !bindings_are_valid() {
        fail(0xff01);
    }
    let report = match qualify() {
        Ok(report) if report_is_frozen(&report) => report,
        Ok(_) => fail(0xff02),
        Err(error) => fail(error.code()),
    };

    emit_metadata(&report);
    let mut emitter = RecordEmitter::new();
    for observation in report.core.observations.iter().copied() {
        emit_core(&mut emitter, observation);
    }
    emit_f3(&mut emitter, &report);
    emit_f4(&mut emitter, &report);
    emit_fuel(&mut emitter, &report);
    for snapshot in report.lifecycle.snapshots.iter().copied() {
        emit_lifecycle_snapshot(&mut emitter, snapshot);
    }
    let (records, semantic_sha256) = emitter.finish();
    if records != DATA_RECORDS || semantic_sha256 != EXPECTED_SEMANTIC_SHA256 {
        fail(0xff03);
    }
    emit_terminal(
        "VIBE_C88_F5_END ",
        "vibeos.c88.f5.float-target.end",
        &semantic_sha256,
    );
    emit_terminal(
        "VIBE_C88_F5_PASS ",
        "vibeos.c88.f5.float-target.pass",
        &semantic_sha256,
    );
    crate::sbi::shutdown(false)
}
