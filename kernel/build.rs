fn main() {
    build_native_cxx_probe();
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


fn build_native_cxx_probe() {
    if std::env::var_os("CARGO_FEATURE_NATIVE_CXX_PROBE").is_none() { return; }
    assert_eq!(std::env::var("TARGET").unwrap(), "riscv64gc-unknown-none-elf",
               "native C++ probe requires the LP64D target");
    let manifest = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest.parent().unwrap();
    let source = root.join("tools/node-runtime/tests/native-cxx-probe.cc");
    let tools = root.join("target/node-runtime/toolchain/xpack-riscv-none-elf-gcc-14.2.0-3/bin");
    let cxx = tools.join("riscv-none-elf-g++");
    let ar = tools.join("riscv-none-elf-ar");
    assert!(cxx.is_file() && ar.is_file(), "prepare the pinned native toolchain first");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed={}", root.join("tools/node-runtime/platform/vibeos-cache.h").display());
    println!("cargo:rerun-if-changed={}", root.join("tools/node-runtime/platform/vibeos-stack.h").display());
    println!("cargo:rerun-if-changed={}", cxx.display());
    println!("cargo:rerun-if-changed={}", ar.display());
    println!("cargo:rerun-if-changed={}", root.join("tools/node-runtime/platform/vibeos-tcb-pages.h").display());
    println!("cargo:rerun-if-changed={}", root.join("tools/node-runtime/platform/vibeos-time.h").display());
    println!("cargo:rerun-if-changed={}", root.join("tools/node-runtime/platform/vibeos-sync.h").display());
    println!("cargo:rerun-if-changed={}", root.join("tools/node-runtime/platform/vibeos-backtrace.h").display());
    println!("cargo:rerun-if-changed={}", root.join("tools/node-runtime/platform/vibeos-memory.h").display());
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let object = out.join("native-cxx-probe.o");
    let archive = out.join("libnative_cxx_probe.a");
    let version = std::process::Command::new(&cxx).arg("--version").output().unwrap();
    assert!(version.status.success());
    std::fs::write(out.join("native-cxx-compiler.txt"), version.stdout).unwrap();
    let status = std::process::Command::new(cxx)
        .args(["-std=gnu++20", "-O2", "-march=rv64gc", "-mabi=lp64d", "-mcmodel=medany",
               "-ffreestanding", "-fno-exceptions", "-fno-rtti", "-fno-stack-protector",
               "-fno-omit-frame-pointer", "-c"])
        .arg(source).arg("-o").arg(&object).status().unwrap();
    assert!(status.success(), "compile native C++ probe");
    assert!(std::process::Command::new(ar).arg("crs").arg(archive).arg(object)
            .status().unwrap().success(), "archive native C++ probe");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=native_cxx_probe");
}
