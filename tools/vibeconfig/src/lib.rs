//! Host-side configuration model shared by the terminal UI and build driver.
//! Resolution is pure: it never invokes Cargo or changes source manifests.
//!
//! A product repository that pins VibeOS can reuse the model and the terminal
//! UI with its own catalog: its boards use `image = "product"`, and their node
//! features then name Cargo features of that product's firmware crate.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

#[cfg(feature = "tui")]
pub mod ui;

pub const SCHEMA: u32 = 1;
pub type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Selection {
    #[default]
    Auto,
    On,
    Off,
}
impl Selection {
    pub fn next(self) -> Self {
        match self {
            Self::Auto => Self::On,
            Self::On => Self::Off,
            Self::Off => Self::Auto,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub boards: BTreeSet<String>,
    pub components: BTreeSet<String>,
    #[serde(default)]
    pub drivers: BTreeMap<String, Selection>,
}

/// A named starting selection declared by a catalog. A catalog without any
/// keeps the built-in `default`, `minimal` and per-board presets.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    pub id: String,
    pub name: String,
    pub description: String,
    pub boards: BTreeSet<String>,
    #[serde(default)]
    pub components: BTreeSet<String>,
    #[serde(default)]
    pub drivers: BTreeMap<String, Selection>,
}

/// Instruction set of a board. One kernel image has exactly one, so a
/// configuration's architecture is derived from its boards, never stored.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    Riscv64,
    Aarch64,
}
impl Arch {
    /// The name people use; the Rust target keeps the formal one.
    pub fn label(self) -> &'static str {
        match self {
            Self::Riscv64 => "riscv64",
            Self::Aarch64 => "arm64",
        }
    }
    fn target(self) -> &'static str {
        match self {
            Self::Riscv64 => "riscv64imac-unknown-none-elf",
            Self::Aarch64 => "aarch64-unknown-none-softfloat",
        }
    }
}

/// Who links the bootable image for a board.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Image {
    /// `firmware/universal` in this workspace; boards can share one image.
    #[default]
    Universal,
    /// A product repository that pins VibeOS. This workspace only provides
    /// the platform libraries, so such a board is always configured alone.
    External,
    /// The image of the product whose catalog this is: node and board
    /// features name that product's firmware features. Configured alone.
    Product,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Board {
    pub id: String,
    pub name: String,
    pub description: String,
    pub arch: Arch,
    #[serde(default)]
    pub image: Image,
    /// For an external image: where and how it is built.
    #[serde(default)]
    pub build_hint: String,
    pub required: Vec<String>,
    pub defaults: Vec<String>,
    pub feature: String,
    pub load_address: u64,
    pub memory_bytes: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Driver,
    Component,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub description: String,
    pub kind: Kind,
    pub feature: String,
    #[serde(default)]
    pub boards: Vec<String>,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub provides: Vec<String>,
    #[serde(default)]
    pub conflicts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub version: u32,
    pub boards: Vec<Board>,
    pub nodes: Vec<Node>,
    /// Skipped when empty so existing configuration digests do not change.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub presets: Vec<Preset>,
}

impl Catalog {
    pub fn load(root: &Path) -> Result<Self> {
        Self::load_file(&root.join("configs/catalog.toml"))
    }
    pub fn load_file(path: &Path) -> Result<Self> {
        let catalog: Self = toml::from_str(
            &fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?,
        )
        .map_err(|e| format!("{}: {e}", path.display()))?;
        catalog.validate()?;
        Ok(catalog)
    }
    pub fn node(&self, id: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.id == id)
    }
    pub fn board(&self, id: &str) -> Option<&Board> {
        self.boards.iter().find(|b| b.id == id)
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != SCHEMA {
            return Err("unsupported catalog version".into());
        }
        let mut ids = BTreeSet::new();
        for id in self
            .boards
            .iter()
            .map(|b| &b.id)
            .chain(self.nodes.iter().map(|n| &n.id))
        {
            if id.is_empty()
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                || !ids.insert(id)
            {
                return Err(format!("invalid or duplicate catalog id: {id}"));
            }
        }
        for b in &self.boards {
            let hint_ok = match b.image {
                Image::Universal => b.build_hint.is_empty(),
                Image::External => !b.build_hint.is_empty(),
                Image::Product => true,
            };
            if !hint_ok {
                return Err(format!(
                    "{}: build_hint is required for an external image and absent for a universal one",
                    b.id
                ));
            }
            if b.image == Image::External && !b.feature.is_empty() {
                return Err(format!(
                    "{}: an external image has no firmware feature",
                    b.id
                ));
            }
            for id in b.required.iter().chain(&b.defaults) {
                if !self
                    .node(id)
                    .is_some_and(|n| n.kind == Kind::Driver && n.supports(&b.id))
                {
                    return Err(format!("{}: invalid board driver {id}", b.id));
                }
            }
        }
        for n in &self.nodes {
            for b in &n.boards {
                if self.board(b).is_none() {
                    return Err(format!("{}: unknown board {b}", n.id));
                }
            }
            for dep in &n.requires {
                if let Some(cap) = dep.strip_prefix("cap:") {
                    if !self
                        .nodes
                        .iter()
                        .any(|n| n.provides.iter().any(|p| p == cap))
                    {
                        return Err(format!("{}: unknown capability {cap}", n.id));
                    }
                } else if self.node(dep).is_none() {
                    return Err(format!("{}: unknown dependency {dep}", n.id));
                }
            }
            for id in &n.conflicts {
                if self.node(id).is_none() {
                    return Err(format!("{}: unknown conflict {id}", n.id));
                }
            }
        }
        // Validate every possible provider edge, not just currently selected roots.
        fn visit(
            c: &Catalog,
            id: &str,
            stack: &mut Vec<String>,
            done: &mut BTreeSet<String>,
        ) -> Result<()> {
            if stack.iter().any(|v| v == id) {
                stack.push(id.into());
                return Err(format!("dependency cycle: {}", stack.join(" -> ")));
            }
            if done.contains(id) {
                return Ok(());
            }
            stack.push(id.into());
            for dep in &c.node(id).unwrap().requires {
                if let Some(cap) = dep.strip_prefix("cap:") {
                    for n in c
                        .nodes
                        .iter()
                        .filter(|n| n.provides.iter().any(|p| p == cap))
                    {
                        visit(c, &n.id, stack, done)?;
                    }
                } else {
                    visit(c, dep, stack, done)?;
                }
            }
            stack.pop();
            done.insert(id.into());
            Ok(())
        }
        let mut done = BTreeSet::new();
        for n in &self.nodes {
            visit(self, &n.id, &mut Vec::new(), &mut done)?;
        }
        let mut presets = BTreeSet::new();
        for p in &self.presets {
            if !presets.insert(&p.id) {
                return Err(format!("duplicate preset {}", p.id));
            }
            if p.boards.is_empty() || p.boards.iter().any(|b| self.board(b).is_none()) {
                return Err(format!("{}: preset needs known boards", p.id));
            }
            for id in &p.components {
                if !self.node(id).is_some_and(|n| n.kind == Kind::Component) {
                    return Err(format!("{}: unknown preset component {id}", p.id));
                }
            }
            for id in p.drivers.keys() {
                if !self.node(id).is_some_and(|n| n.kind == Kind::Driver) {
                    return Err(format!("{}: unknown preset driver {id}", p.id));
                }
            }
        }
        Ok(())
    }
    /// Fail before compiling if the catalog drifts from the actual firmware API.
    pub fn check_features(&self, root: &Path) -> Result<()> {
        self.check_features_in(&root.join("firmware/universal/Cargo.toml"))
    }
    /// The same check against another firmware manifest (a product image).
    pub fn check_features_in(&self, manifest: &Path) -> Result<()> {
        let value: toml::Value = toml::from_str(
            &fs::read_to_string(manifest).map_err(|e| format!("{}: {e}", manifest.display()))?,
        )
        .map_err(|e| e.to_string())?;
        let features = value
            .get("features")
            .and_then(|v| v.as_table())
            .ok_or_else(|| format!("{} has no features", manifest.display()))?;
        for (id, feature) in self
            .boards
            .iter()
            .map(|b| (&b.id, &b.feature))
            .chain(self.nodes.iter().map(|n| (&n.id, &n.feature)))
        {
            if !feature.is_empty() && !features.contains_key(feature) {
                return Err(format!(
                    "catalog {id} references absent firmware feature {feature}"
                ));
            }
        }
        Ok(())
    }
    /// Preset ids in display order: the catalog's own, or the built-in ones.
    pub fn preset_names(&self) -> Vec<String> {
        if self.presets.is_empty() {
            ["default", "minimal"]
                .into_iter()
                .map(str::to_owned)
                .chain(self.boards.iter().map(|b| b.id.clone()))
                .collect()
        } else {
            self.presets.iter().map(|p| p.id.clone()).collect()
        }
    }
    pub fn declared_preset(&self, id: &str) -> Option<&Preset> {
        self.presets.iter().find(|p| p.id == id)
    }
    pub fn preset(&self, name: &str) -> Result<Config> {
        if let Some(p) = self.declared_preset(name) {
            let mut components = p.components.clone();
            components.insert("vsh".into());
            return Ok(Config {
                version: SCHEMA,
                boards: p.boards.clone(),
                components,
                drivers: p.drivers.clone(),
            });
        }
        let boards: BTreeSet<String> = if name == "default" || name == "minimal" {
            // Every board that can share the universal image.
            self.boards
                .iter()
                .filter(|b| b.image == Image::Universal)
                .map(|b| b.id.clone())
                .collect()
        } else if self.board(name).is_some() {
            BTreeSet::from([name.into()])
        } else {
            return Err(format!(
                "unknown preset {name}; choose default, minimal, or a board id"
            ));
        };
        let mut c = Config {
            version: SCHEMA,
            boards,
            components: BTreeSet::from(["vsh".into()]),
            drivers: BTreeMap::new(),
        };
        if name != "minimal" {
            // Only what at least one of the boards can actually run.
            c.components.extend(
                ["file-tree", "network"]
                    .into_iter()
                    .filter(|id| {
                        self.node(id)
                            .is_some_and(|n| c.boards.iter().any(|b| n.supports(b)))
                    })
                    .map(str::to_owned),
            );
            for b in c.boards.iter().filter_map(|id| self.board(id)) {
                for d in &b.defaults {
                    c.drivers.insert(d.clone(), Selection::On);
                }
            }
        }
        Ok(c)
    }
}
impl Node {
    pub fn supports(&self, board: &str) -> bool {
        self.boards.is_empty() || self.boards.iter().any(|b| b == board)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct BoardPlan {
    pub enabled: BTreeSet<String>,
    pub reasons: BTreeMap<String, BTreeSet<String>>,
    pub unavailable: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Resolved {
    pub selection: Config,
    pub version: u32,
    pub digest: String,
    pub arch: Arch,
    pub image: Image,
    pub target: String,
    pub features: BTreeSet<String>,
    pub boards: BTreeMap<String, BoardPlan>,
    pub errors: Vec<String>,
}
impl Resolved {
    pub fn valid(&self) -> bool {
        self.errors.is_empty()
    }
    pub fn require_valid(&self) -> Result<()> {
        if self.valid() {
            Ok(())
        } else {
            Err(self.errors.join("\n"))
        }
    }
    pub fn report(&self) -> String {
        let mut text = format!(
            "Architecture: {}\nTarget: {}\nConfig: {}\nFeatures: {}\n",
            self.arch.label(),
            self.target,
            self.digest,
            self.features.iter().cloned().collect::<Vec<_>>().join(",")
        );
        for (b, p) in &self.boards {
            text.push_str(&format!("\n{b}\n"));
            for id in &p.enabled {
                text.push_str(&format!("  + {id}\n"));
            }
            for (id, reason) in &p.unavailable {
                text.push_str(&format!("  - {id}: {reason}\n"));
            }
        }
        for e in &self.errors {
            text.push_str(&format!("ERROR: {e}\n"));
        }
        text
    }
}

pub fn resolve(c: &Catalog, config: &Config) -> Result<Resolved> {
    c.validate()?;
    if config.version != SCHEMA {
        return Err(format!(
            "unsupported configuration version {}",
            config.version
        ));
    }
    if config.boards.is_empty() {
        return Err("select at least one board".into());
    }
    for b in &config.boards {
        if c.board(b).is_none() {
            return Err(format!("unknown board: {b}"));
        }
    }
    for id in &config.components {
        if !c.node(id).is_some_and(|n| n.kind == Kind::Component) {
            return Err(format!("unknown component: {id}"));
        }
    }
    for id in config.drivers.keys() {
        if !c.node(id).is_some_and(|n| n.kind == Kind::Driver) {
            return Err(format!("unknown driver: {id}"));
        }
    }
    let selected: Vec<&Board> = config.boards.iter().filter_map(|id| c.board(id)).collect();
    let arch = selected[0].arch;
    if let Some(other) = selected.iter().find(|b| b.arch != arch) {
        return Err(format!(
            "{} is {} but {} is {}; one kernel image has one architecture, so configure them separately",
            selected[0].name,
            arch.label(),
            other.name,
            other.arch.label()
        ));
    }
    let image = selected[0].image;
    if let Some(b) = selected.iter().find(|b| b.image != Image::Universal) {
        if selected.len() > 1 {
            return Err(format!(
                "{} has its own image and cannot share a configuration with other boards",
                b.name
            ));
        }
    }
    let digest = hex_digest(&serde_json::to_vec(&(c, config)).map_err(|e| e.to_string())?);
    let mut r = Resolved {
        selection: config.clone(),
        version: SCHEMA,
        digest,
        arch,
        image,
        target: arch.target().into(),
        features: match image {
            Image::Universal => BTreeSet::from(["image".into()]),
            Image::External | Image::Product => BTreeSet::new(),
        },
        boards: BTreeMap::new(),
        errors: Vec::new(),
    };
    let roots = config
        .components
        .iter()
        .chain(std::iter::once(&String::from("vsh")))
        .cloned()
        .collect::<BTreeSet<_>>();
    for board in config.boards.iter().filter_map(|id| c.board(id)) {
        let mut p = BoardPlan::default();
        if !board.feature.is_empty() {
            r.features.insert(board.feature.clone());
        }
        for id in &board.required {
            if let Err(e) = enable(c, config, &board.id, id, "required for boot", &mut p) {
                r.errors.push(format!("{}: {e}", board.id));
            }
        }
        for (id, state) in &config.drivers {
            if *state == Selection::On && c.node(id).unwrap().supports(&board.id) {
                let mut candidate = p.clone();
                match enable(
                    c,
                    config,
                    &board.id,
                    id,
                    "explicitly selected",
                    &mut candidate,
                ) {
                    Ok(()) => p = candidate,
                    Err(e) => r.errors.push(format!("{}: {e}", board.id)),
                }
            }
        }
        for id in &roots {
            let mut candidate = p.clone();
            match enable(
                c,
                config,
                &board.id,
                id,
                "selected component",
                &mut candidate,
            ) {
                Ok(()) => p = candidate,
                Err(e) => {
                    p.unavailable.insert(id.clone(), e);
                }
            }
        }
        for id in &p.enabled {
            let f = &c.node(id).unwrap().feature;
            // Feature names belong to the image's firmware manifest; an
            // external image is linked elsewhere and takes none from here.
            if !f.is_empty() && image != Image::External {
                r.features.insert(f.clone());
            }
        }
        r.boards.insert(board.id.clone(), p);
    }
    // Component conflicts are compilation constraints, including across boards.
    let active: BTreeSet<_> = r
        .boards
        .values()
        .flat_map(|p| p.enabled.iter().cloned())
        .collect();
    for id in &active {
        for other in &c.node(id).unwrap().conflicts {
            if active.contains(other) {
                r.errors.push(format!("{id} conflicts with {other}"));
            }
        }
    }
    for id in roots {
        if !r.boards.values().any(|p| p.enabled.contains(&id)) {
            r.errors
                .push(format!("{id} cannot run on any selected board"));
        }
    }
    for (id, state) in &config.drivers {
        if *state == Selection::On
            && !config
                .boards
                .iter()
                .any(|b| c.node(id).unwrap().supports(b))
        {
            r.errors
                .push(format!("{id} does not support any selected board"));
        }
    }
    let universal = image == Image::Universal;
    if universal
        && active.contains("network")
        && !active.contains("ssh")
        && !active.contains("iperf3")
    {
        r.features.insert("image-net-shell".into());
    }
    if universal && active.contains("ssh") && active.contains("wasi") {
        r.features.insert("image-ssh-command".into());
    }
    if arch == Arch::Riscv64 && active.contains("wasmtime") {
        r.target = "riscv64gc-unknown-none-elf".into();
    }
    r.errors.sort();
    r.errors.dedup();
    Ok(r)
}

fn enable(
    c: &Catalog,
    config: &Config,
    board: &str,
    id: &str,
    reason: &str,
    p: &mut BoardPlan,
) -> Result<()> {
    let node = c.node(id).ok_or_else(|| format!("unknown node {id}"))?;
    if !node.supports(board) {
        return Err(format!("{id} is unavailable on {board}"));
    }
    if node.kind == Kind::Driver && config.drivers.get(id) == Some(&Selection::Off) {
        return Err(format!("{id} was explicitly disabled"));
    }
    p.reasons
        .entry(id.into())
        .or_default()
        .insert(reason.into());
    if p.enabled.contains(id) {
        return Ok(());
    }
    for dep in &node.requires {
        if let Some(cap) = dep.strip_prefix("cap:") {
            // Prefer already admitted providers, then explicit choices, then catalog order.
            let mut providers: Vec<_> = c
                .nodes
                .iter()
                .filter(|n| n.supports(board) && n.provides.iter().any(|v| v == cap))
                .collect();
            providers.sort_by_key(|n| {
                (
                    !p.enabled.contains(&n.id),
                    config.drivers.get(&n.id) != Some(&Selection::On),
                )
            });
            let mut failure = Vec::new();
            let mut chosen = None;
            for n in providers {
                let mut candidate = p.clone();
                match enable(
                    c,
                    config,
                    board,
                    &n.id,
                    &format!("{id} requires {cap}"),
                    &mut candidate,
                ) {
                    Ok(()) => {
                        chosen = Some(candidate);
                        break;
                    }
                    Err(e) => failure.push(e),
                }
            }
            if let Some(candidate) = chosen {
                *p = candidate;
            } else {
                return Err(format!(
                    "{id} -> {cap}: {}",
                    if failure.is_empty() {
                        "no qualified provider".into()
                    } else {
                        failure.join("; ")
                    }
                ));
            }
        } else {
            enable(c, config, board, dep, &format!("required by {id}"), p)
                .map_err(|e| format!("{id} -> {e}"))?;
        }
    }
    p.enabled.insert(id.into());
    Ok(())
}

pub fn read_config(path: &Path) -> Result<Config> {
    toml::from_str(&fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?)
        .map_err(|e| format!("{}: {e}", path.display()))
}
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let tmp = parent.join(format!(
        ".vibeconfig-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let result = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(|e| format!("{}: {e}", path.display()))
}
pub fn save_config(path: &Path, config: &Config) -> Result<()> {
    save_config_with_header(
        path,
        config,
        "VibeOS build configuration. Edit this file or run ./configure.sh.",
    )
}
/// `header` becomes the file's leading comment line.
pub fn save_config_with_header(path: &Path, config: &Config, header: &str) -> Result<()> {
    let text = toml::to_string_pretty(config).map_err(|e| e.to_string())?;
    atomic_write(path, format!("# {header}\n{text}").as_bytes())
}
/// Write the resolved closure under `root/target/config` and the selection.
pub fn save_selection(root: &Path, path: &Path, config: &Config, r: &Resolved) -> Result<()> {
    r.require_valid()?;
    save_resolved(
        &root
            .join("target/config")
            .join(&r.digest)
            .join("resolved.toml"),
        r,
    )?;
    save_config(path, config)
}
pub fn save_resolved(path: &Path, r: &Resolved) -> Result<()> {
    r.require_valid()?;
    atomic_write(
        path,
        toml::to_string_pretty(r)
            .map_err(|e| e.to_string())?
            .as_bytes(),
    )
}

pub fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
