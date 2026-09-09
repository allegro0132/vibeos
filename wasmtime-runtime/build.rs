fn main() {
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_NATIVE_RISCV");
    if std::env::var_os("CARGO_FEATURE_NATIVE_RISCV").is_some() {
        let target = std::env::var("TARGET").unwrap();
        assert!(
            matches!(target.as_str(), "riscv64gc-unknown-none-elf" | "riscv64gc-unknown-linux-gnu"),
            "native-riscv requires an LP64D target (riscv64gc-unknown-none-elf or riscv64gc-unknown-linux-gnu); adding +f,+d to IMAC does not change its LP64 ABI"
        );
    }
}
