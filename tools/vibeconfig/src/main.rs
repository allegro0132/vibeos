use std::{
    env, fs,
    io::{self, IsTerminal},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};
use vibeos_config::{
    atomic_write, read_config, resolve, save_config, save_resolved, Catalog, Config, Result,
};
#[cfg(feature = "tui")]
mod ui;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vibeconfig: {e}");
            ExitCode::FAILURE
        }
    }
}
fn run() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let mut command = "configure".to_owned();
    let mut config_path = root.join("vibeos.toml");
    let mut preset = None;
    let mut non_interactive = false;
    let mut dry_run = false;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "configure" | "resolve" | "check" | "build" | "run" => command = arg,
            "--config" | "--output" => {
                config_path = PathBuf::from(args.next().ok_or("missing config path")?)
            }
            "--preset" => preset = Some(args.next().ok_or("missing preset name")?),
            "--non-interactive" => non_interactive = true,
            "--dry-run" => dry_run = true,
            "--help" | "-h" => {
                println!("VibeOS configuration\n\n./configure.sh [--config FILE] [--preset NAME]\n./configure.sh --preset default --non-interactive\n./configure.sh resolve|check --config FILE\n./build.sh --config FILE [--dry-run]\n\nPresets: default, minimal, qemu-virt, milkv-duo, milkv-mars\nDriver choices: auto / on / off. Escape closes dialogs; Ctrl-S saves.\n");
                return Ok(());
            }
            _ => return Err(format!("unknown argument {arg}; use --help")),
        }
    }
    let catalog = Catalog::load(&root)?;
    let config = match preset {
        Some(name) => catalog.preset(&name)?,
        None if config_path.exists() => read_config(&config_path)?,
        None if command == "configure" => catalog.preset("default")?,
        None => {
            return Err(format!(
                "{} does not exist; choose --preset or run ./configure.sh",
                config_path.display()
            ))
        }
    };
    if command == "configure" && !non_interactive && !dry_run {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err("interactive configuration needs a terminal; use --non-interactive --preset default".into());
        }
        #[cfg(feature = "tui")]
        return ui::run(&root, &catalog, config, &config_path);
        #[cfg(not(feature = "tui"))]
        return Err("use ./configure.sh to open the terminal UI".into());
    }
    let resolved = resolve(&catalog, &config)?;
    print!("{}", resolved.report());
    resolved.require_valid()?;
    catalog.check_features(&root)?;
    match command.as_str() {
        "configure" if !dry_run => save(&root, &config_path, &config, &resolved),
        "resolve" if !dry_run => save_resolved(
            &root
                .join("target/config")
                .join(&resolved.digest)
                .join("resolved.toml"),
            &resolved,
        ),
        "build" => build(&root, &catalog, &resolved, dry_run),
        "run" => {
            if !resolved.boards.contains_key("qemu-virt") {
                return Err("run requires qemu-virt in the configuration".into());
            }
            build(&root, &catalog, &resolved, dry_run)?;
            if dry_run {
                return Ok(());
            }
            let status = Command::new("python3")
                .arg(root.join("scripts/run-universal.py"))
                .arg("--manifest")
                .arg(
                    root.join("target/universal")
                        .join(&resolved.digest)
                        .join("manifest.json"),
                )
                .status()
                .map_err(|e| e.to_string())?;
            if status.success() {
                Ok(())
            } else {
                Err(format!("QEMU exited: {status}"))
            }
        }
        _ => Ok(()),
    }
}
pub fn save(root: &Path, path: &Path, config: &Config, r: &vibeos_config::Resolved) -> Result<()> {
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

fn build(root: &Path, catalog: &Catalog, r: &vibeos_config::Resolved, dry: bool) -> Result<()> {
    let output = root.join("target/universal").join(&r.digest);
    let resolved_path = output.join("resolved.toml");
    let features = r.features.iter().cloned().collect::<Vec<_>>().join(",");
    let args = [
        "build",
        "--locked",
        "--release",
        "--no-default-features",
        "--target",
        &r.target,
        "--features",
        &features,
    ];
    println!(
        "\nBuild directory: {}\nCargo arguments: {:?}\nOutput: {}",
        root.join("firmware/universal").display(),
        args,
        output.display()
    );
    if dry {
        return Ok(());
    }
    save_resolved(&resolved_path, r)?;
    let status = Command::new("cargo")
        .args(args)
        .current_dir(root.join("firmware/universal"))
        .env("CARGO_TARGET_DIR", output.join("cargo"))
        .env("VIBEOS_RESOLVED_CONFIG", &resolved_path)
        .status()
        .map_err(|e| format!("cargo: {e}"))?;
    if !status.success() {
        return Err(format!("universal build failed: {status}"));
    }
    let elf = output
        .join("cargo")
        .join(&r.target)
        .join("release/vibeos-universal");
    let toolchain = Command::new("rustc")
        .args(["--print", "sysroot"])
        .current_dir(root)
        .output()
        .map_err(|e| e.to_string())?;
    if !toolchain.status.success() {
        return Err("cannot locate toolchain".into());
    }
    let sysroot = PathBuf::from(String::from_utf8_lossy(&toolchain.stdout).trim());
    let host = Command::new("rustc")
        .arg("-vV")
        .current_dir(root)
        .output()
        .map_err(|e| e.to_string())?;
    let host_text = String::from_utf8_lossy(&host.stdout);
    let host_triple = host_text
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .ok_or("cannot locate LLVM tools host")?;
    let llvm = sysroot.join("lib/rustlib").join(host_triple).join("bin");
    let image = output.join("vibeos.bin");
    let status = Command::new(llvm.join("llvm-objcopy"))
        .args(["-O", "binary"])
        .arg(&elf)
        .arg(&image)
        .status()
        .map_err(|e| format!("llvm-tools-preview required: {e}"))?;
    if !status.success() {
        return Err("objcopy failed".into());
    }
    let layout_path = output.join("layout.json");
    let mut verifier = Command::new("python3");
    verifier
        .arg(root.join("scripts/universal-image.py"))
        .arg("--elf")
        .arg(&elf)
        .arg("--image")
        .arg(&image)
        .arg("--output")
        .arg(&layout_path);
    for board in r.boards.keys() {
        verifier.arg("--board").arg(board);
    }
    if !verifier
        .status()
        .map_err(|e| format!("image verifier: {e}"))?
        .success()
    {
        return Err("universal ELF/relocation/memory verification failed".into());
    }
    let layout: serde_json::Value =
        serde_json::from_slice(&fs::read(&layout_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let git_head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());
    let git_diff = Command::new("git")
        .args(["diff", "--binary", "HEAD"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success());
    let bytes = fs::read(&image).map_err(|e| e.to_string())?;
    for id in r.boards.keys() {
        let b = catalog.board(id).unwrap();
        if bytes.len() as u64 >= b.memory_bytes {
            return Err(format!("kernel exceeds {} RAM envelope", b.name));
        }
        if id == "milkv-duo" && bytes.len() > 0x1200000 {
            return Err("kernel overlaps Duo FIT source at 0x81400000".into());
        }
    }
    let manifest = serde_json::json!({"schema": 1, "configuration": r.digest, "target": r.target, "features": r.features,
        "boards": r.boards.keys().collect::<Vec<_>>(), "image": "vibeos.bin", "bytes": bytes.len(),
        "sha256": vibeos_config::hex_digest(&bytes), "physical_acceptance": false,
        "resolved_sha256": vibeos_config::hex_digest(&fs::read(&resolved_path).map_err(|e| e.to_string())?),
        "layout": layout, "git_head": git_head, "tracked_diff_sha256": git_diff.as_ref().map(|o| vibeos_config::hex_digest(&o.stdout)),
        "rustc": host_text});
    atomic_write(
        &output.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?,
    )?;
    println!("Built {}", image.display());
    Ok(())
}
