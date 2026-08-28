#[cfg(feature = "c88-f5-acceptance")]
use std::{env, fs, path::PathBuf};

#[cfg(feature = "c88-f5-acceptance")]
use sha2::{Digest, Sha256};

const SOURCE: &str = "artifacts/scalar-target.wat";

fn main() {
    println!("cargo:rerun-if-changed={SOURCE}");

    #[cfg(feature = "c88-f5-acceptance")]
    build_scalar_target();
}

#[cfg(feature = "c88-f5-acceptance")]
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
