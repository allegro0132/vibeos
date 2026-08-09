#[cfg(all(feature = "qemu-virt", feature = "milkv-duo"))]
compile_error!("features `qemu-virt` and `milkv-duo` are mutually exclusive");

#[cfg(not(any(feature = "qemu-virt", feature = "milkv-duo")))]
compile_error!("exactly one board feature must be enabled: `qemu-virt` or `milkv-duo`");

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=linker-milkv-duo.ld");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo supplies target arch");
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("Cargo supplies target OS");
    if target_arch != "riscv64" || target_os != "none" {
        return;
    }

    let linker_script = if cfg!(feature = "milkv-duo") {
        "linker-milkv-duo.ld"
    } else {
        "linker.ld"
    };

    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo supplies the manifest directory"),
    );
    let linker_script = manifest_dir
        .join(linker_script)
        .canonicalize()
        .expect("board linker script must exist");

    println!(
        "cargo:rustc-link-arg-bin=vibeos-kernel=-T{}",
        linker_script.display()
    );
}
