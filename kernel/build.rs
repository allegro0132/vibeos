fn main() {
    println!("cargo:rerun-if-env-changed=VIBEOS_WASMTIME_COREMARK");
    println!("cargo:rerun-if-env-changed=VIBEOS_COREMARK_ITERATIONS");
    println!("cargo:rerun-if-env-changed=VIBEOS_COREMARK_VALIDATION");
    if std::env::var_os("CARGO_FEATURE_WASMTIME_COREMARK_PROBE").is_none() {
        return;
    }
    let path =
        std::path::PathBuf::from(std::env::var_os("VIBEOS_WASMTIME_COREMARK").expect(
            "CoreMark probe requires VIBEOS_WASMTIME_COREMARK pointing to an ordinary .wasm",
        ))
        .canonicalize()
        .expect("CoreMark input path");
    println!("cargo:rerun-if-changed={}", path.display());
    let bytes = std::fs::read(&path).expect("read CoreMark");
    assert!(bytes.len() <= 512 * 1024 && bytes.starts_with(b"\0asm\x01\0\0\0"));
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("coremark.wasm"), bytes).unwrap();
    let validation = std::env::var("VIBEOS_COREMARK_VALIDATION").unwrap_or_else(|_| "0".into());
    assert!(validation == "0" || validation == "1");
    println!("cargo:rustc-env=VIBEOS_COREMARK_VALIDATION={validation}");
    let iterations = std::env::var("VIBEOS_COREMARK_ITERATIONS").unwrap_or_else(|_| "60000".into());
    assert!((1..=1_000_000).contains(&iterations.parse::<u32>().expect("iterations")));
    println!("cargo:rustc-env=VIBEOS_COREMARK_ITERATIONS={iterations}");
}
