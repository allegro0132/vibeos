#[cfg(feature = "c810-s5-qemu-qualification")]
use std::{env, fs, path::PathBuf};

const SOURCES: &[(&str, &str)] = &[
    ("integer", "artifacts/integer.wat"),
    ("float", "artifacts/float.wat"),
    ("saturating", "artifacts/saturating.wat"),
    ("memory", "artifacts/memory.wat"),
    ("spin", "artifacts/spin.wat"),
    ("relaxed", "artifacts/relaxed.wat"),
    ("component", "artifacts/candidate-component.wat"),
];

fn main() {
    for (_, source) in SOURCES {
        println!("cargo:rerun-if-changed={source}");
    }
    #[cfg(feature = "c810-s5-qemu-qualification")]
    build_inputs();
}

#[cfg(feature = "c810-s5-qemu-qualification")]
fn build_inputs() {
    use sha2::{Digest, Sha256};

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let mut generated = String::new();
    for (name, source) in SOURCES {
        let raw = fs::read(source).expect("read C8.10-S5 WAT");
        let wasm = wat::parse_bytes(&raw)
            .expect("compile C8.10-S5 WAT")
            .into_owned();
        let output = out.join(format!("{name}.wasm"));
        fs::write(&output, &wasm).expect("write C8.10-S5 Wasm");
        let upper = name.to_ascii_uppercase();
        let digest = Sha256::digest(&wasm);
        let hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        generated.push_str(&format!(
            "pub const {upper}_WASM: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{name}.wasm\"));\n\
             pub const {upper}_SHA256: &str = \"{hex}\";\n"
        ));
    }
    fs::write(out.join("inputs.rs"), generated).expect("write C8.10-S5 input identities");
}
