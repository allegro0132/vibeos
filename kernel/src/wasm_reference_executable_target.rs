//! Isolated C8.13-E3 fixed-QEMU code-10 Reference Types qualification adapter.

use alloc::{format, string::String};
use sha2::{Digest, Sha256};
use vibeos_wasm_reference_target::{qualify_executable, EXECUTABLE_CASE_IDS};

const SOURCE_COMMIT: &str = match option_env!("VIBEOS_C813_E3_SOURCE_COMMIT") {
    Some(v) => v,
    None => "",
};
const SOURCE_TREE: &str = match option_env!("VIBEOS_C813_E3_SOURCE_TREE") {
    Some(v) => v,
    None => "",
};
const CHALLENGE: &str = match option_env!("VIBEOS_C813_E3_CHALLENGE") {
    Some(v) => v,
    None => "",
};
const RUN_ID: &str = match option_env!("VIBEOS_C813_E3_RUN_ID") {
    Some(v) => v,
    None => "",
};
const MANIFEST_SHA256: &str = match option_env!("VIBEOS_C813_E3_MANIFEST_SHA256") {
    Some(v) => v,
    None => "",
};
const TRANSCRIPT_SCHEMA_SHA256: &str = match option_env!("VIBEOS_C813_E3_TRANSCRIPT_SCHEMA_SHA256")
{
    Some(v) => v,
    None => "",
};
const EXPECTED_SEMANTIC_SHA256: &str =
    "6a654a8428f4f4479db637ab90d391c989c43b2c67dfc51570bd4ac617cc1a49";
const SEMANTIC_DOMAIN: &[u8] = b"vibeos.c813.e3.reference.fixed-qemu.semantic.v1\0";

fn valid_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        && value.as_bytes().iter().any(|b| *b != b'0')
}
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}
fn emit(hasher: &mut Sha256, prefix: &str, payload: &str) {
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload.as_bytes());
    crate::println!("{}{}", prefix, payload);
}
fn fail(code: u16) -> ! {
    crate::println!("VIBE_C813_E3_FAIL {{\"code\":{}}}", code);
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
    let report = qualify_executable();
    if !report.passed() {
        fail(0xff02);
    }
    crate::println!("VIBE_C813_E3_META {{\"artifact_abi\":10,\"artifact_profile_code\":10,\"challenge\":\"{}\",\"code5_inert\":true,\"code9_inert\":true,\"component_profile\":7,\"core_profile\":7,\"engine\":\"vibeos-wasmi-reference-executable@1.1.0-vibeos-ref2.1\",\"manifest_sha256\":\"{}\",\"node\":\"C8.13-E3\",\"physical_inputs\":0,\"release_authorized_before_qualification\":false,\"run_id\":\"{}\",\"runtime_abi\":10,\"source_commit\":\"{}\",\"source_tree\":\"{}\",\"stage\":\"executable\",\"transcript_schema_sha256\":\"{}\",\"world\":\"vibe:references/runtime@1.0.0\"}}", CHALLENGE, MANIFEST_SHA256, RUN_ID, SOURCE_COMMIT, SOURCE_TREE, TRANSCRIPT_SCHEMA_SHA256);
    let mut hasher = Sha256::new_with_prefix(SEMANTIC_DOMAIN);
    for (id, passed) in EXECUTABLE_CASE_IDS.iter().zip(report.cases) {
        let payload = format!("{{\"id\":\"{}\",\"passed\":{}}}", id, passed);
        emit(&mut hasher, "VIBE_C813_E3_CASE ", &payload);
    }
    let payload = format!("{{\"code5_inert\":{},\"code9_inert\":{},\"durable_authorized\":{},\"migration_authorized\":{},\"passed\":true}}", report.code5_inert, report.code9_inert, report.durable_authorized, report.migration_authorized);
    emit(&mut hasher, "VIBE_C813_E3_CONTAINMENT ", &payload);
    let semantic = hex(&hasher.finalize());
    if semantic != EXPECTED_SEMANTIC_SHA256 {
        fail(0xff03);
    }
    crate::println!(
        "VIBE_C813_E3_END {{\"challenge\":\"{}\",\"run_id\":\"{}\",\"semantic_sha256\":\"{}\"}}",
        CHALLENGE,
        RUN_ID,
        semantic
    );
    crate::println!(
        "VIBE_C813_E3_PASS {{\"challenge\":\"{}\",\"run_id\":\"{}\",\"semantic_sha256\":\"{}\"}}",
        CHALLENGE,
        RUN_ID,
        semantic
    );
    crate::sbi::shutdown(false);
}
