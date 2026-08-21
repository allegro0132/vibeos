use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

const SOURCE: &str = include_str!("artifacts/c53-stream-filter.component.wat");
const NATIVE_ASYNC_SOURCE: &str = include_str!("artifacts/c53-native-async-filter.component.wat");

// This is deliberately independent of the artifact bytes produced below.
// Updating the WAT source or pinned parser must fail the build until review
// explicitly updates this image identity.
const EXPECTED_SHA256: [u8; 32] = [
    0x18, 0x0e, 0xd4, 0x44, 0xde, 0x8b, 0x6c, 0x9e, 0xcd, 0x82, 0x8b, 0x36, 0x9d, 0x4c, 0x8b, 0x9f,
    0x78, 0x37, 0x58, 0xef, 0x22, 0xc0, 0xb1, 0x71, 0x70, 0x68, 0x2d, 0x71, 0xf2, 0xfd, 0x0e, 0x72,
];

// This is an independent validation-only identity. It must never reuse the
// executable synchronous C5.3/C4.8 pin above.
const NATIVE_ASYNC_EXPECTED_SHA256: [u8; 32] = [
    0x8c, 0xff, 0xb5, 0xbc, 0xce, 0x06, 0x22, 0xc6, 0x4a, 0xff, 0xec, 0xd8, 0xc1, 0xa1, 0xee, 0xcc,
    0x57, 0xf3, 0x06, 0xbe, 0x08, 0xc7, 0x6c, 0xc0, 0x46, 0x21, 0xd8, 0x2d, 0x67, 0x8b, 0x10, 0xf3,
];

fn main() {
    println!("cargo:rerun-if-changed=artifacts/c53-stream-filter.component.wat");
    println!("cargo:rerun-if-changed=artifacts/c53-native-async-filter.component.wat");

    let bytes = wat::parse_str(SOURCE).expect("pinned Component WAT must parse");
    let observed: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(
        observed, EXPECTED_SHA256,
        "pinned C5.3 Component digest changed: {observed:02x?}"
    );

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set"));
    fs::write(output.join("c53-stream-filter.component.wasm"), bytes)
        .expect("write pinned Component artifact");
    fs::write(
        output.join("c53-stream-filter.sha256.rs"),
        format!("{EXPECTED_SHA256:?}"),
    )
    .expect("write checked Component identity constant");

    if env::var_os("CARGO_FEATURE_C53_NATIVE_ASYNC_QEMU_ACCEPTANCE").is_some() {
        let bytes = wat::parse_str(NATIVE_ASYNC_SOURCE)
            .expect("pinned native async Component WAT must parse");
        let observed: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(
            observed, NATIVE_ASYNC_EXPECTED_SHA256,
            "pinned native async C5.3 Component digest changed: {observed:02x?}"
        );
        fs::write(output.join("c53-native-async-filter.component.wasm"), bytes)
            .expect("write pinned native async Component artifact");
        fs::write(
            output.join("c53-native-async-filter.sha256.rs"),
            format!("{NATIVE_ASYNC_EXPECTED_SHA256:?}"),
        )
        .expect("write checked native async Component identity constant");
    }
}
