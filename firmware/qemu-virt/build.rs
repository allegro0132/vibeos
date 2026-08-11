use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=linker.ld");
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("riscv64")
        || env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("none")
    {
        return;
    }

    let script = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("linker.ld")
        .canonicalize()
        .expect("QEMU linker script must exist");
    println!(
        "cargo:rustc-link-arg-bin=vibeos-qemu-virt=-T{}",
        script.display()
    );
}
