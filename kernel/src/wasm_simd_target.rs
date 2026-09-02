//! Isolated C8.10-S5 fixed-QEMU SIMD qualification adapter.

use alloc::{format, string::String};
use sha2::{Digest, Sha256};
use vibeos_wasm_simd_target::{qualify, CASE_IDS};

const SOURCE_COMMIT: &str = match option_env!("VIBEOS_C810_S5_SOURCE_COMMIT") {
    Some(value) => value,
    None => "",
};
const SOURCE_TREE: &str = match option_env!("VIBEOS_C810_S5_SOURCE_TREE") {
    Some(value) => value,
    None => "",
};
const CHALLENGE: &str = match option_env!("VIBEOS_C810_S5_CHALLENGE") {
    Some(value) => value,
    None => "",
};
const RUN_ID: &str = match option_env!("VIBEOS_C810_S5_RUN_ID") {
    Some(value) => value,
    None => "",
};
const MANIFEST_SHA256: &str = match option_env!("VIBEOS_C810_S5_MANIFEST_SHA256") {
    Some(value) => value,
    None => "",
};
const TRANSCRIPT_SCHEMA_SHA256: &str = match option_env!("VIBEOS_C810_S5_TRANSCRIPT_SCHEMA_SHA256")
{
    Some(value) => value,
    None => "",
};
const EXPECTED_SEMANTIC_SHA256: &str =
    "6b34b541a42fdf838eccd55e43473a4154421eadc0e3b4292a5a89fde54ae1c6";
const SEMANTIC_DOMAIN: &[u8] = b"vibeos.c810.s5.simd.fixed-qemu.semantic.v1\0";

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
    crate::println!("VIBE_C810_S5_FAIL {{\"code\":{}}}", code);
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
        "VIBE_C810_S5_META {{\"artifact_abi\":7,\"artifact_profile_code\":7,\"challenge\":\"{}\",\"code5_inert\":true,\"component_profile\":4,\"core_profile\":4,\"durable_authorized\":false,\"engine\":\"vibeos-wasmi-simd-softfloat@1.1.0-vibeos-simd1.1\",\"manifest_sha256\":\"{}\",\"node\":\"C8.10-S5\",\"release_authorized\":false,\"run_id\":\"{}\",\"runtime_abi\":7,\"source_commit\":\"{}\",\"source_tree\":\"{}\",\"stage\":\"validation-only\",\"transcript_schema_sha256\":\"{}\",\"world\":\"vibe:simd/validation@1.0.0\"}}",
        CHALLENGE,
        MANIFEST_SHA256,
        RUN_ID,
        SOURCE_COMMIT,
        SOURCE_TREE,
        TRANSCRIPT_SCHEMA_SHA256,
    );

    let mut hasher = Sha256::new_with_prefix(SEMANTIC_DOMAIN);
    for (id, passed) in CASE_IDS.iter().zip(report.cases) {
        let payload = format!("{{\"id\":\"{}\",\"passed\":{}}}", id, passed);
        emit(&mut hasher, "VIBE_C810_S5_CASE ", &payload);
    }
    let lifecycle = report.lifecycle;
    let payload = format!(
        "{{\"cancellations\":{},\"faults\":{},\"live_instances\":{},\"passed\":true,\"reclaimed_instances\":{},\"recoveries\":{},\"revocations\":{}}}",
        lifecycle.cancellations,
        lifecycle.faults,
        lifecycle.live_instances,
        lifecycle.reclaimed_instances,
        lifecycle.recoveries,
        lifecycle.revocations,
    );
    emit(&mut hasher, "VIBE_C810_S5_LIFECYCLE ", &payload);
    let semantic = hex(&hasher.finalize());
    if semantic != EXPECTED_SEMANTIC_SHA256 {
        fail(0xff03);
    }
    crate::println!(
        "VIBE_C810_S5_END {{\"challenge\":\"{}\",\"run_id\":\"{}\",\"semantic_sha256\":\"{}\"}}",
        CHALLENGE,
        RUN_ID,
        semantic,
    );
    crate::println!(
        "VIBE_C810_S5_PASS {{\"challenge\":\"{}\",\"run_id\":\"{}\",\"semantic_sha256\":\"{}\"}}",
        CHALLENGE,
        RUN_ID,
        semantic,
    );
    crate::sbi::shutdown(false);
}
