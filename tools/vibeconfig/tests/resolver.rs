use std::collections::BTreeSet;
use vibeos_config::{resolve, Catalog, Config, Selection};
fn catalog() -> Catalog {
    toml::from_str(include_str!("../../../configs/catalog.toml")).unwrap()
}
#[test]
fn defaults_cover_three_boards_with_distinct_storage() {
    let c = catalog();
    let r = resolve(&c, &c.preset("default").unwrap()).unwrap();
    r.require_valid().unwrap();
    for (b, driver) in [
        ("qemu-virt", "virtio-blk"),
        ("milkv-duo", "sdhci-blk"),
        ("milkv-mars", "dw-mshc"),
    ] {
        assert!(r.boards[b].enabled.contains(driver));
        assert!(r.boards[b].enabled.contains("file-tree"));
        assert!(!r.boards[b].enabled.contains("ssh"));
    }
    assert!(r.features.contains("image"));
}
#[test]
fn minimal_omits_peripheral_drivers() {
    let c = catalog();
    let r = resolve(&c, &c.preset("minimal").unwrap()).unwrap();
    r.require_valid().unwrap();
    assert!(!r.features.contains("driver-virtio-blk"));
    assert!(!r.features.contains("driver-eqos-net"));
}
#[test]
fn ssh_uses_native_or_jitter_entropy_per_board() {
    let c = catalog();
    let mut config = c.preset("default").unwrap();
    config.components.insert("ssh".into());
    let r = resolve(&c, &config).unwrap();
    r.require_valid().unwrap();
    assert!(r.boards["qemu-virt"].enabled.contains("virtio-rng"));
    assert!(r.boards["milkv-duo"].enabled.contains("jitter-entropy"));
    assert!(r.boards["milkv-mars"].enabled.contains("jitter-entropy"));
    assert!(r.boards["milkv-mars"].enabled.contains("ssh"));
    assert!(!r.features.contains("driver-starfive-trng"));
}
#[test]
fn explicitly_disabling_storage_propagates_only_to_affected_board() {
    let c = catalog();
    let mut config = c.preset("default").unwrap();
    config.drivers.insert("virtio-blk".into(), Selection::Off);
    let r = resolve(&c, &config).unwrap();
    r.require_valid().unwrap();
    assert!(r.boards["qemu-virt"].unavailable["file-tree"].contains("explicitly disabled"));
    assert!(!r.features.contains("driver-virtio-blk"));
    assert!(r.features.contains("driver-sdhci-blk"));
}
#[test]
fn unavailable_everywhere_is_an_error() {
    let c = catalog();
    let mut config = c.preset("milkv-mars").unwrap();
    config.components.insert("ssh".into());
    config
        .drivers
        .insert("jitter-entropy".into(), Selection::Off);
    let r = resolve(&c, &config).unwrap();
    assert!(!r.valid());
    assert!(r.errors.iter().any(|e| e.contains("ssh cannot run")));
}
#[test]
fn boot_requirements_cannot_be_disabled() {
    let c = catalog();
    let mut config = c.preset("default").unwrap();
    config.drivers.insert("uart16550".into(), Selection::Off);
    assert!(!resolve(&c, &config).unwrap().valid());
}
#[test]
fn library_conflicts_apply_across_all_boards() {
    let c = catalog();
    let mut config = c.preset("default").unwrap();
    config
        .components
        .extend(["python".into(), "wasmtime".into()]);
    let r = resolve(&c, &config).unwrap();
    assert!(r.errors.iter().any(|e| e.contains("conflicts")));
}
#[test]
fn feature_order_and_serialization_are_deterministic() {
    let c = catalog();
    let config = c.preset("default").unwrap();
    let roundtrip: Config = toml::from_str(&toml::to_string_pretty(&config).unwrap()).unwrap();
    assert_eq!(config, roundtrip);
    let a = resolve(&c, &config).unwrap();
    let b = resolve(&c, &roundtrip).unwrap();
    assert_eq!(a, b);
    let r: vibeos_config::Resolved = toml::from_str(&toml::to_string_pretty(&a).unwrap()).unwrap();
    assert_eq!(a, r);
}
#[test]
fn unknown_fields_ids_and_schema_fail() {
    let c = catalog();
    let mut config = c.preset("minimal").unwrap();
    config.boards = BTreeSet::from(["invented".into()]);
    assert!(resolve(&c, &config).is_err());
    config = c.preset("minimal").unwrap();
    config.version = 999;
    assert!(resolve(&c, &config).is_err());
    assert!(toml::from_str::<Config>("version=1\nboards=[]\ncomponents=[]\ntypo=true").is_err());
}
#[test]
fn cyclic_and_missing_provider_catalogs_fail_even_when_unselected() {
    let mut c = catalog();
    c.nodes
        .iter_mut()
        .find(|n| n.id == "uart16550")
        .unwrap()
        .requires
        .push("plic".into());
    c.nodes
        .iter_mut()
        .find(|n| n.id == "plic")
        .unwrap()
        .requires
        .push("uart16550".into());
    assert!(c.validate().unwrap_err().contains("cycle"));
    let mut c = catalog();
    c.nodes
        .iter_mut()
        .find(|n| n.id == "vsh")
        .unwrap()
        .requires
        .push("cap:imaginary".into());
    assert!(c.validate().is_err());
}
#[test]
fn failed_provider_attempt_does_not_leak_dependencies() {
    let c = catalog();
    let mut config = c.preset("milkv-duo").unwrap();
    config.drivers.insert("dwmac-net".into(), Selection::Off);
    let r = resolve(&c, &config).unwrap();
    r.require_valid().unwrap();
    assert!(r.boards["milkv-duo"].enabled.contains("dwc2-host"));
    assert!(!r.features.contains("driver-dwmac-net"));
}
#[test]
fn all_presets_match_actual_cargo_features() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let c = catalog();
    c.check_features(&root).unwrap();
    for p in ["default", "minimal", "qemu-virt", "milkv-duo", "milkv-mars"] {
        resolve(&c, &c.preset(p).unwrap())
            .unwrap()
            .require_valid()
            .unwrap();
    }
}

#[test]
fn qemu_can_explicitly_disable_hardware_entropy_and_use_jitter() {
    let c = catalog();
    let mut config = c.preset("qemu-virt").unwrap();
    config.components.insert("ssh".into());
    config.drivers.insert("virtio-rng".into(), Selection::Off);
    let r = resolve(&c, &config).unwrap();
    r.require_valid().unwrap();
    assert!(r.boards["qemu-virt"].enabled.contains("jitter-entropy"));
    assert!(!r.features.contains("driver-virtio-rng"));
}
