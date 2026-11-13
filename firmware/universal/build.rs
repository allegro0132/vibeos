use std::{env, fs, path::PathBuf};
fn main() {
    println!("cargo:rerun-if-env-changed=VIBEOS_RESOLVED_CONFIG");
    println!("cargo:rerun-if-changed=linker.ld");
    if env::var_os("CARGO_FEATURE_IMAGE").is_none() {
        return;
    }
    let path = PathBuf::from(
        env::var_os("VIBEOS_RESOLVED_CONFIG")
            .expect("build universal firmware with ./build.sh --config FILE"),
    );
    println!("cargo:rerun-if-changed={}", path.display());
    let resolved: vibeos_config::Resolved =
        toml::from_str(&fs::read_to_string(&path).expect("read resolved configuration"))
            .expect("parse resolved configuration");
    resolved.require_valid().expect("valid configuration");
    assert_eq!(resolved.version, vibeos_config::SCHEMA);
    assert_eq!(
        env::var("TARGET").unwrap(),
        resolved.target,
        "configuration target mismatch"
    );
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../..");
    // Embedded device modules retain the legacy firmware's diagnostic gates.
    // Recognize those names without enabling them in a universal image.
    for board in ["qemu-virt", "milkv-duo", "milkv-mars"] {
        let manifest = root.join("firmware").join(board).join("Cargo.toml");
        println!("cargo:rerun-if-changed={}", manifest.display());
        let value: toml::Value = toml::from_str(&fs::read_to_string(manifest).unwrap()).unwrap();
        let names = value["features"]
            .as_table()
            .unwrap()
            .keys()
            .map(|s| format!("{s:?}"))
            .collect::<Vec<_>>()
            .join(",");
        println!("cargo:rustc-check-cfg=cfg(feature, values({names}))");
    }
    println!(
        "cargo:rerun-if-changed={}",
        root.join("configs/catalog.toml").display()
    );
    let catalog = vibeos_config::Catalog::load(&root).expect("valid catalog");
    catalog
        .check_features(&root)
        .expect("catalog matches firmware features");
    assert_eq!(
        vibeos_config::resolve(&catalog, &resolved.selection).expect("recompute selection"),
        resolved,
        "stale or modified resolved configuration"
    );
    for feature in &resolved.features {
        let key = format!(
            "CARGO_FEATURE_{}",
            feature.to_ascii_uppercase().replace('-', "_")
        );
        assert!(
            env::var_os(key).is_some(),
            "missing resolved feature {feature}"
        );
    }
    for feature in catalog
        .nodes
        .iter()
        .map(|n| &n.feature)
        .chain(catalog.boards.iter().map(|b| &b.feature))
    {
        let key = format!(
            "CARGO_FEATURE_{}",
            feature.to_ascii_uppercase().replace('-', "_")
        );
        assert_eq!(
            env::var_os(key).is_some(),
            resolved.features.contains(feature),
            "feature {feature} differs from resolved configuration"
        );
    }
    let mut generated = format!("pub const CONFIG_DIGEST: &str = {:?};\n", resolved.digest);
    generated.push_str("pub fn components(board: vibeos_hal::runtime_platform::BoardId) -> &'static [&'static str] { match board {\n");
    for (id, variant) in [
        ("qemu-virt", "QemuVirt"),
        ("milkv-duo", "MilkvDuo"),
        ("milkv-mars", "MilkvMars"),
    ] {
        let components: Vec<_> = resolved
            .boards
            .get(id)
            .into_iter()
            .flat_map(|p| p.enabled.iter())
            .filter(|id| {
                catalog
                    .node(id)
                    .is_some_and(|n| n.kind == vibeos_config::Kind::Component)
            })
            .collect();
        generated.push_str(&format!(
            "vibeos_hal::runtime_platform::BoardId::{variant} => &{components:?},\n"
        ));
    }
    generated.push_str("} }\n");
    generated.push_str("pub fn enabled(board: vibeos_hal::runtime_platform::BoardId, id: &str) -> bool { let items: &[&str] = match board {\n");
    for (id, variant) in [("qemu-virt", "QemuVirt"), ("milkv-duo", "MilkvDuo"), ("milkv-mars", "MilkvMars")] {
        let items: Vec<_> = resolved.boards.get(id).into_iter().flat_map(|p| p.enabled.iter()).collect();
        generated.push_str(&format!("vibeos_hal::runtime_platform::BoardId::{variant} => &{items:?},\n"));
    }
    generated.push_str("}; items.contains(&id) }\n");
    generated.push_str("pub fn unavailable(board: vibeos_hal::runtime_platform::BoardId) -> &'static [(&'static str, &'static str)] { match board {\n");
    for (id, variant) in [
        ("qemu-virt", "QemuVirt"),
        ("milkv-duo", "MilkvDuo"),
        ("milkv-mars", "MilkvMars"),
    ] {
        let unavailable: Vec<_> = resolved
            .boards
            .get(id)
            .into_iter()
            .flat_map(|p| p.unavailable.iter())
            .collect();
        generated.push_str(&format!(
            "vibeos_hal::runtime_platform::BoardId::{variant} => &{unavailable:?},\n"
        ));
    }
    generated.push_str("} }\n");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::write(out.join("configuration.rs"), generated).unwrap();
    println!(
        "cargo:rustc-link-arg-bin=vibeos-universal=-T{}",
        root.join("firmware/universal/linker.ld")
            .canonicalize()
            .unwrap()
            .display()
    );
    println!("cargo:rustc-link-arg-bin=vibeos-universal=-pie");
    println!("cargo:rustc-link-arg-bin=vibeos-universal=--no-dynamic-linker");
    println!("cargo:rustc-link-arg-bin=vibeos-universal=-Bsymbolic");
    println!("cargo:rustc-link-arg-bin=vibeos-universal=-z");
    println!("cargo:rustc-link-arg-bin=vibeos-universal=norelro");
}
