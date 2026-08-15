use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=linker-storage-bench.ld");
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("riscv64")
        || env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("none")
    {
        return;
    }

    // The storage benchmark contract boots with -m 512M; qualification
    // workloads legitimately hold multi-MiB record streams in transit.
    let script_name = if env::var_os("CARGO_FEATURE_STORAGE_BENCH").is_some() {
        "linker-storage-bench.ld"
    } else {
        "linker.ld"
    };
    let script = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join(script_name)
        .canonicalize()
        .expect("QEMU linker script must exist");
    println!(
        "cargo:rustc-link-arg-bin=vibeos-qemu-virt=-T{}",
        script.display()
    );
}
