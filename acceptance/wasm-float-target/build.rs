#[cfg(any(
    feature = "c88-f5-acceptance",
    feature = "c88-f5-duo-compile-readiness",
    feature = "c89-s3-qemu-qualification"
))]
use std::{env, fs, path::PathBuf};

#[cfg(any(
    feature = "c88-f5-acceptance",
    feature = "c88-f5-duo-compile-readiness",
    feature = "c89-s3-qemu-qualification"
))]
use sha2::{Digest, Sha256};

const SOURCE: &str = "artifacts/scalar-target.wat";
const DUO_MANIFEST: &str = "artifacts/qualification-duo-v1-manifest.json";
const DUO_TRANSCRIPT_SCHEMA: &str = "artifacts/qualification-duo-v1-transcript-schema.json";

fn main() {
    println!("cargo:rerun-if-changed={SOURCE}");
    println!("cargo:rerun-if-changed={DUO_MANIFEST}");
    println!("cargo:rerun-if-changed={DUO_TRANSCRIPT_SCHEMA}");

    #[cfg(any(
        feature = "c88-f5-acceptance",
        feature = "c88-f5-duo-compile-readiness",
        feature = "c89-s3-qemu-qualification"
    ))]
    build_scalar_target();

    #[cfg(feature = "c88-f5-duo-compile-readiness")]
    build_duo_manifest_identity();
}

#[cfg(any(
    feature = "c88-f5-acceptance",
    feature = "c88-f5-duo-compile-readiness",
    feature = "c89-s3-qemu-qualification"
))]
fn build_scalar_target() {
    let source = fs::read(SOURCE).expect("read C8.8-F5 scalar target WAT");
    let bytes = wat::parse_bytes(&source)
        .expect("compile C8.8-F5 scalar target WAT")
        .into_owned();
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let digest_hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let digest_array = digest
        .iter()
        .map(|byte| format!("0x{byte:02x}"))
        .collect::<Vec<_>>()
        .join(", ");

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    fs::write(out.join("scalar-target.wasm"), &bytes).expect("write C8.8-F5 scalar target Wasm");
    fs::write(
        out.join("scalar_target_identity.rs"),
        format!(
            "pub const SCALAR_TARGET_WASM_BYTES: &[u8] = \
             include_bytes!(concat!(env!(\"OUT_DIR\"), \"/scalar-target.wasm\"));\n\
             pub const SCALAR_TARGET_WASM_SHA256: [u8; 32] = [{digest_array}];\n\
             pub const SCALAR_TARGET_WASM_SHA256_HEX: &str = \"{digest_hex}\";\n\
             pub const SCALAR_TARGET_RUNTIME_OP_COUNT: u32 = 72;\n",
        ),
    )
    .expect("write C8.8-F5 scalar target identity");
}

#[cfg(feature = "c88-f5-duo-compile-readiness")]
fn build_duo_manifest_identity() {
    let manifest = fs::read(DUO_MANIFEST).expect("read C8.8-F5 Duo readiness manifest");
    let manifest_digest: [u8; 32] = Sha256::digest(&manifest).into();
    let manifest_digest_hex = manifest_digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let transcript_schema =
        fs::read(DUO_TRANSCRIPT_SCHEMA).expect("read C8.8-F5 Duo transcript schema");
    let transcript_schema_digest: [u8; 32] = Sha256::digest(&transcript_schema).into();
    let transcript_schema_digest_hex = transcript_schema_digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    fs::write(
        out.join("qualification_duo_v1_manifest_identity.rs"),
        format!(
            "pub const DUO_QUALIFICATION_MANIFEST_SHA256: &str = \
             \"{manifest_digest_hex}\";\n\
             pub const DUO_QUALIFICATION_MANIFEST_BYTES: usize = {};\n\
             pub const DUO_TRANSCRIPT_SCHEMA_SHA256: &str = \
             \"{transcript_schema_digest_hex}\";\n\
             pub const DUO_TRANSCRIPT_SCHEMA_BYTES: usize = {};\n",
            manifest.len(),
            transcript_schema.len(),
        ),
    )
    .expect("write C8.8-F5 Duo contract identities");
}
