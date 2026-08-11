#[cfg(all(feature = "qemu-virt", feature = "milkv-duo"))]
compile_error!("features `qemu-virt` and `milkv-duo` are mutually exclusive");

#[cfg(not(any(feature = "qemu-virt", feature = "milkv-duo")))]
compile_error!("exactly one board feature must be enabled: `qemu-virt` or `milkv-duo`");

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn tool_from_env_or_candidates(variable: &str, candidates: &[&str]) -> PathBuf {
    if let Some(tool) = env::var_os(variable) {
        return PathBuf::from(tool);
    }

    for candidate in candidates {
        if Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return PathBuf::from(candidate);
        }
    }

    panic!(
        "Milk-V Jitterentropy probe needs {}; set {} to an executable path",
        candidates.join(" or "),
        variable
    );
}

fn run_tool(tool: &Path, args: &[&str]) {
    let status = Command::new(tool)
        .args(args)
        .status()
        .unwrap_or_else(|error| panic!("failed to run {}: {error}", tool.display()));
    assert!(status.success(), "{} failed with {status}", tool.display());
}

fn build_jitterentropy(manifest_dir: &Path) {
    let repo_root = manifest_dir
        .parent()
        .expect("kernel crate must be inside the repository");
    let vendor = repo_root.join("vendor/jitterentropy");
    let vendor_src = vendor.join("src");
    assert!(
        vendor.join("jitterentropy.h").is_file(),
        "Jitterentropy submodule is missing; run `git submodule update --init --recursive`"
    );
    let adapter = manifest_dir.join("jitterentropy-baremetal");
    let source = adapter.join("vibeos-jitterentropy.c");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    let object = out_dir.join("vibeos-jitterentropy.o");
    let archive = out_dir.join("libvibeos_jitterentropy.a");

    println!("cargo:rerun-if-env-changed=VIBEOS_JENT_CC");
    println!("cargo:rerun-if-env-changed=VIBEOS_JENT_AR");
    println!("cargo:rerun-if-changed={}", source.display());
    println!(
        "cargo:rerun-if-changed={}",
        adapter.join("jitterentropy-base-user.h").display()
    );
    for file in [
        "jitterentropy.h",
        "src/jitterentropy-base.c",
        "src/jitterentropy-base.h",
        "src/jitterentropy-gcd.c",
        "src/jitterentropy-gcd.h",
        "src/jitterentropy-health.c",
        "src/jitterentropy-health.h",
        "src/jitterentropy-internal.h",
        "src/jitterentropy-noise.c",
        "src/jitterentropy-noise.h",
        "src/jitterentropy-sha3.c",
        "src/jitterentropy-sha3.h",
        "src/jitterentropy-timer.c",
        "src/jitterentropy-timer.h",
    ] {
        println!("cargo:rerun-if-changed={}", vendor.join(file).display());
    }

    let clang = tool_from_env_or_candidates(
        "VIBEOS_JENT_CC",
        &["/opt/homebrew/opt/llvm/bin/clang", "clang"],
    );
    let llvm_ar = tool_from_env_or_candidates(
        "VIBEOS_JENT_AR",
        &["/opt/homebrew/opt/llvm/bin/llvm-ar", "llvm-ar"],
    );

    let source = source.to_string_lossy();
    let object = object.to_string_lossy();
    let adapter = adapter.to_string_lossy();
    let vendor = vendor.to_string_lossy();
    let vendor_src = vendor_src.to_string_lossy();
    run_tool(
        &clang,
        &[
            "--target=riscv64-unknown-elf",
            "-march=rv64imac_zicsr_zifencei",
            "-mabi=lp64",
            "-mcmodel=medany",
            "-std=c11",
            "-O0",
            "-fwrapv",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-nostdinc",
            "-Wall",
            "-Wextra",
            "-Wconversion",
            "-I",
            &adapter,
            "-I",
            &vendor,
            "-I",
            &vendor_src,
            "-c",
            &source,
            "-o",
            &object,
        ],
    );

    let archive = archive.to_string_lossy();
    run_tool(&llvm_ar, &["crs", &archive, &object]);
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=vibeos_jitterentropy");
}

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
    if env::var_os("CARGO_FEATURE_MILKV_JITTERENTROPY_PROBE").is_some() {
        build_jitterentropy(&manifest_dir);
    }
    let linker_script = manifest_dir
        .join(linker_script)
        .canonicalize()
        .expect("board linker script must exist");

    println!(
        "cargo:rustc-link-arg-bin=vibeos-kernel=-T{}",
        linker_script.display()
    );
}
