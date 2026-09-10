use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=linker.ld");
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("riscv64")
        || env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("none")
    {
        return;
    }

    // One linker script; only the RAM length differs per boot contract.
    // Golden/test images boot QEMU virt with -m 128M; the storage benchmark
    // contract boots with -m 512M because its qualification workloads
    // legitimately hold multi-MiB record streams in transit; the Python WASI
    // image boots with -m 1G. OpenSBI occupies the first 2 MiB of each.
    let ram_length = if env::var_os("CARGO_FEATURE_PYTHON_WASI").is_some() {
        "1022M"
    } else if env::var_os("CARGO_FEATURE_STORAGE_BENCH").is_some() {
        "510M"
    } else {
        "126M"
    };
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let template = fs::read_to_string(manifest.join("linker.ld")).expect("QEMU linker script must exist");
    assert!(template.contains("@RAM_LENGTH@"), "linker.ld lost its RAM length placeholder");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("linker.ld");
    fs::write(&out, template.replace("@RAM_LENGTH@", ram_length)).expect("write generated linker script");
    println!("cargo:rustc-link-arg-bin=vibeos-qemu-virt={}", format_args!("-T{}", out.display()));
}
