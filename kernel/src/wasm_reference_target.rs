//! Isolated C8.12-R3 fixed-QEMU code-9 Reference Types qualification adapter.

use alloc::{format, string::String};
use sha2::{Digest, Sha256};
use vibeos_wasm_reference_target::{qualify, CASE_IDS};

const SOURCE_COMMIT: &str = match option_env!("VIBEOS_C812_R3_SOURCE_COMMIT") {
    Some(value) => value,
    None => "",
};
const SOURCE_TREE: &str = match option_env!("VIBEOS_C812_R3_SOURCE_TREE") {
    Some(value) => value,
    None => "",
};
const CHALLENGE: &str = match option_env!("VIBEOS_C812_R3_CHALLENGE") {
    Some(value) => value,
    None => "",
};
const RUN_ID: &str = match option_env!("VIBEOS_C812_R3_RUN_ID") {
    Some(value) => value,
    None => "",
};
const MANIFEST_SHA256: &str = match option_env!("VIBEOS_C812_R3_MANIFEST_SHA256") {
    Some(value) => value,
    None => "",
};
const TRANSCRIPT_SCHEMA_SHA256: &str = match option_env!("VIBEOS_C812_R3_TRANSCRIPT_SCHEMA_SHA256")
{
    Some(value) => value,
    None => "",
};
const EXPECTED_SEMANTIC_SHA256: &str =
    "bf33470617822af905ab8877797416e79aed3cde5a257689b3bbdda4df156279";
const SEMANTIC_DOMAIN: &[u8] = b"vibeos.c812.r3.reference.fixed-qemu.semantic.v1\0";

fn valid_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        && value.as_bytes().iter().any(|byte| *byte != b'0')
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn emit(hasher: &mut Sha256, prefix: &str, payload: &str) {
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload.as_bytes());
    crate::println!("{}{}", prefix, payload);
}

fn fail(code: u16) -> ! {
    crate::println!("VIBE_C812_R3_FAIL {{\"code\":{}}}", code);
    crate::sbi::shutdown(true)
}

pub async fn run() {
    if crate::online_hart_count() != 1
        || !valid_hex(SOURCE_COMMIT, 20)
        || !valid_hex(SOURCE_TREE, 20)
        || !valid_hex(CHALLENGE, 32)
        || !valid_hex(RUN_ID, 32)
        || !valid_hex(MANIFEST_SHA256, 32)
        || !valid_hex(TRANSCRIPT_SCHEMA_SHA256, 32)
    {
        fail(0xff01);
    }
    let report = qualify();
    if !report.passed() {
        fail(0xff02);
    }
    crate::println!(
        "VIBE_C812_R3_META {{\"artifact_abi\":9,\"artifact_profile_code\":9,\"challenge\":\"{}\",\"code5_inert\":true,\"code7_inert\":true,\"component_profile\":6,\"core_profile\":6,\"durable_authorized\":false,\"engine\":\"vibeos-wasmi-reference-validation@1.1.0-vibeos-ref1.1\",\"execution_authorized\":false,\"manifest_sha256\":\"{}\",\"node\":\"C8.12-R3\",\"release_authorized\":false,\"run_id\":\"{}\",\"runtime_abi\":9,\"source_commit\":\"{}\",\"source_tree\":\"{}\",\"stage\":\"validation-only\",\"successor_review_eligible_before_qualification\":false,\"transcript_schema_sha256\":\"{}\",\"world\":\"vibe:references/validation@1.0.0\"}}",
        CHALLENGE, MANIFEST_SHA256, RUN_ID, SOURCE_COMMIT, SOURCE_TREE, TRANSCRIPT_SCHEMA_SHA256,
    );
    let mut hasher = Sha256::new_with_prefix(SEMANTIC_DOMAIN);
    for (id, passed) in CASE_IDS.iter().zip(report.cases) {
        let payload = format!("{{\"id\":\"{}\",\"passed\":{}}}", id, passed);
        emit(&mut hasher, "VIBE_C812_R3_CASE ", &payload);
    }
    let payload = format!(
        "{{\"accepted_inert\":{},\"passed\":true,\"rejected\":{},\"total\":256}}",
        report.mutation_accepted_inert, report.mutation_rejected,
    );
    emit(&mut hasher, "VIBE_C812_R3_CONTAINMENT ", &payload);
    let semantic = hex(&hasher.finalize());
    if semantic != EXPECTED_SEMANTIC_SHA256 {
        fail(0xff03);
    }
    crate::println!(
        "VIBE_C812_R3_END {{\"challenge\":\"{}\",\"run_id\":\"{}\",\"semantic_sha256\":\"{}\"}}",
        CHALLENGE,
        RUN_ID,
        semantic,
    );
    crate::println!(
        "VIBE_C812_R3_PASS {{\"challenge\":\"{}\",\"run_id\":\"{}\",\"semantic_sha256\":\"{}\"}}",
        CHALLENGE,
        RUN_ID,
        semantic,
    );
    crate::sbi::shutdown(false);
}
