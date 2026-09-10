use std::{env, fs, path::PathBuf};
fn main() {
    println!("cargo:rerun-if-changed=../qemu-virt/linker.ld");
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let template = fs::read_to_string(manifest.join("../qemu-virt/linker.ld")).unwrap();
    assert!(template.contains("@RAM_LENGTH@"));
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("linker.ld");
    fs::write(&output, template.replace("@RAM_LENGTH@", "126M")).unwrap();
    println!("cargo:rustc-link-arg-bin=vibeos-qemu-hal-test=-T{}", output.display());
}
