#[cfg(any(
    feature = "c812-r3-qemu-qualification",
    feature = "c813-e3-qemu-qualification"
))]
use std::{env, fs, path::PathBuf};

const SOURCES: &[(&str, &str)] = &[
    ("bounded", "artifacts/bounded.wat"),
    ("table", "artifacts/table.wat"),
    ("externref", "artifacts/externref.wat"),
    ("reference_export", "artifacts/reference-export.wat"),
    ("passive", "artifacts/passive.wat"),
    ("multiple_tables", "artifacts/multiple-tables.wat"),
    ("adjacent_float", "artifacts/adjacent-float.wat"),
    ("component", "artifacts/component.wat"),
];

fn main() {
    for (_, source) in SOURCES {
        println!("cargo:rerun-if-changed={source}");
    }
    #[cfg(any(
        feature = "c812-r3-qemu-qualification",
        feature = "c813-e3-qemu-qualification"
    ))]
    build_inputs();
}

#[cfg(any(
    feature = "c812-r3-qemu-qualification",
    feature = "c813-e3-qemu-qualification"
))]
fn build_inputs() {
    use sha2::{Digest, Sha256};

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let mut generated = String::new();
    for (name, source) in SOURCES {
        let raw = fs::read(source).expect("read C8.12-R3 WAT");
        let wasm = wat::parse_bytes(&raw)
            .expect("compile C8.12-R3 WAT")
            .into_owned();
        fs::write(out.join(format!("{name}.wasm")), &wasm).expect("write C8.12-R3 Wasm");
        let upper = name.to_ascii_uppercase();
        let digest = Sha256::digest(&wasm)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        generated.push_str(&format!(
            "pub const {upper}_WASM: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{name}.wasm\"));\n\
             pub const {upper}_SHA256: &str = \"{digest}\";\n"
        ));
    }
    fs::write(out.join("inputs.rs"), generated).expect("write C8.12-R3 input identities");
}
