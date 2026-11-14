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
#[test]
fn a_configuration_has_exactly_one_architecture() {
    let c = catalog();
    let mut config = c.preset("default").unwrap();
    assert!(!config.boards.contains("bpi-r4pro-4e"));
    let r = resolve(&c, &config).unwrap();
    assert_eq!(
        (r.arch.label(), r.target.as_str()),
        ("riscv64", "riscv64imac-unknown-none-elf")
    );
    config.boards.insert("bpi-r4pro-4e".into());
    let error = resolve(&c, &config).unwrap_err();
    assert!(
        error.contains("one kernel image has one architecture"),
        "{error}"
    );
}
#[test]
fn an_external_board_resolves_alone_without_universal_features() {
    let c = catalog();
    let config = c.preset("bpi-r4pro-4e").unwrap();
    assert_eq!(
        config.components,
        BTreeSet::from(["network".into(), "vsh".into()])
    );
    let r = resolve(&c, &config).unwrap();
    r.require_valid().unwrap();
    assert_eq!(r.target, "aarch64-unknown-none-softfloat");
    assert!(r.features.is_empty());
    let plan = &r.boards["bpi-r4pro-4e"];
    for id in [
        "aarch64-runtime",
        "mtk-msdc",
        "mtk-netsys",
        "network",
        "vsh",
    ] {
        assert!(plan.enabled.contains(id), "{id}");
    }
    // RISC-V-only parts never leak into an arm64 plan.
    assert!(!plan.enabled.contains("uart16550") && !plan.enabled.contains("plic"));
    let mut with_files = config.clone();
    with_files.components.insert("file-tree".into());
    assert!(!resolve(&c, &with_files).unwrap().valid());
}
#[test]
fn ssh_and_iperf3_share_one_image() {
    let c = catalog();
    let mut config = c.preset("default").unwrap();
    config.components.extend(["ssh".into(), "iperf3".into()]);
    let r = resolve(&c, &config).unwrap();
    r.require_valid().unwrap();
    assert!(r.features.contains("component-ssh") && r.features.contains("component-iperf3"));
    for plan in r.boards.values() {
        assert!(plan.enabled.contains("ssh") && plan.enabled.contains("iperf3"));
    }
}

/// A product repository's own catalog: features name its firmware's features.
const PRODUCT: &str = r#"
version = 1
[[boards]]
id = "dev"
name = "Dev board"
description = "Product board."
arch = "aarch64"
image = "product"
required = ["nic"]
defaults = []
feature = ""
load_address = 0
memory_bytes = 1
[[boards]]
id = "emu"
name = "Emulator"
description = "Same image, emulated."
arch = "aarch64"
image = "product"
required = []
defaults = []
feature = "emulated"
load_address = 0
memory_bytes = 1
[[nodes]]
id = "nic"
name = "NIC"
description = ""
kind = "driver"
feature = ""
boards = ["dev"]
[[nodes]]
id = "offload"
name = "Offload"
description = ""
kind = "driver"
feature = "hw-offload"
boards = ["dev"]
[[nodes]]
id = "vsh"
name = "Shell"
description = ""
kind = "component"
feature = ""
[[nodes]]
id = "router"
name = "Router"
description = ""
kind = "component"
feature = "router"
boards = ["dev"]
requires = ["offload"]
[[presets]]
id = "dev"
name = "Router"
description = "The product."
boards = ["dev"]
components = ["router"]
"#;

#[test]
fn product_images_take_node_features_and_declared_presets() {
    let c: Catalog = toml::from_str(PRODUCT).unwrap();
    c.validate().unwrap();
    assert_eq!(c.preset_names(), ["dev"]);
    let r = resolve(&c, &c.preset("dev").unwrap()).unwrap();
    r.require_valid().unwrap();
    assert_eq!(
        r.features,
        BTreeSet::from(["hw-offload".to_owned(), "router".to_owned()])
    );
    // A board without a declared preset still gets the built-in one.
    let r = resolve(&c, &c.preset("emu").unwrap()).unwrap();
    assert_eq!(r.features, BTreeSet::from(["emulated".to_owned()]));
    // Each product board has its own image.
    let mut both = c.preset("dev").unwrap();
    both.boards.insert("emu".into());
    assert!(resolve(&c, &both).unwrap_err().contains("own image"));
    // Presets are checked against the catalog.
    let bad: Catalog =
        toml::from_str(&PRODUCT.replace(r#"components = ["router"]"#, r#"components = ["nic"]"#))
            .unwrap();
    assert!(bad.validate().unwrap_err().contains("unknown preset component"));
}
