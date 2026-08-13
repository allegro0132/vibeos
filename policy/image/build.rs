use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

const SOURCE: &str = include_str!("artifacts/c4-byte-filter.component.wat");

// This is deliberately independent of the artifact bytes produced below.
// Updating the WAT source or pinned parser must fail the build until review
// explicitly updates this image identity.
const EXPECTED_SHA256: [u8; 32] = [
    0x0e, 0x8d, 0xee, 0x9c, 0xd6, 0xe5, 0xf5, 0xec, 0xa2, 0x3f, 0x82, 0x4b, 0xac, 0x34, 0x65, 0x7c,
    0xd3, 0x94, 0xb1, 0x2f, 0x60, 0xa1, 0xe2, 0xf0, 0xc6, 0xc6, 0xd9, 0x11, 0xc7, 0x85, 0x9c, 0x6a,
];

fn main() {
    println!("cargo:rerun-if-changed=artifacts/c4-byte-filter.component.wat");

    let bytes = wat::parse_str(SOURCE).expect("pinned Component WAT must parse");
    let observed: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(
        observed, EXPECTED_SHA256,
        "pinned C4 Component digest changed: {observed:02x?}"
    );

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set"));
    fs::write(output.join("c4-byte-filter.component.wasm"), bytes)
        .expect("write pinned Component artifact");
    fs::write(
        output.join("c4-byte-filter.sha256.rs"),
        format!("{EXPECTED_SHA256:?}"),
    )
    .expect("write checked Component identity constant");
}
