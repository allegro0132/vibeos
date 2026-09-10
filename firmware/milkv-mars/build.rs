use std::{env, fs, path::PathBuf};
fn main() {
    println!("cargo:rerun-if-changed=../qemu-virt/linker.ld");
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("riscv64")
        || env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("none")
    {
        return;
    }
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let template = fs::read_to_string(manifest.join("../qemu-virt/linker.ld")).unwrap();
    assert_eq!(template.matches("0x80200000").count(), 1);
    assert_eq!(template.matches("@RAM_LENGTH@").count(), 1);
    assert_eq!(template.matches("KEEP(*(.text.boot))").count(), 1);
    let script = template
        .replace("0x80200000", "0x40200000")
        .replace("@RAM_LENGTH@", "4094M")
        .replace(
            "KEEP(*(.text.boot))",
            "KEEP(*(.text.boot.entry))\n        KEEP(*(.text.boot))",
        );
    let script = format!(
        "{script}\nASSERT(_start == ORIGIN(RAM), \"Mars entry must match FIT load address\");\n"
    );
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("linker.ld");
    fs::write(&output, script).unwrap();
    println!(
        "cargo:rustc-link-arg-bin=vibeos-milkv-mars=-T{}",
        output.display()
    );
}
