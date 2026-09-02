#![forbid(unsafe_code)]

use std::{env, ffi::OsString, fs, path::PathBuf, process::ExitCode};
use vibeos_c81_preview1_componentizer::{
    componentize_preview1, derive_output_pins, hex_sha256, OutputDirection, OutputKind,
};

struct Arguments {
    core: PathBuf,
    adapter: PathBuf,
    output: PathBuf,
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut core = None;
    let mut adapter = None;
    let mut output = None;
    let mut arguments = env::args_os().skip(1);
    while let Some(flag) = arguments.next() {
        let target = match flag.to_str() {
            Some("--core") => &mut core,
            Some("--adapter") => &mut adapter,
            Some("--output") => &mut output,
            _ => {
                return Err(format!(
                    "unknown argument {:?}; expected --core PATH --adapter PATH --output PATH",
                    flag
                ));
            }
        };
        if target.is_some() {
            return Err(format!("duplicate argument {:?}", flag));
        }
        let value: OsString = arguments
            .next()
            .ok_or_else(|| format!("missing path after {:?}", flag))?;
        *target = Some(PathBuf::from(value));
    }
    let result = Arguments {
        core: core.ok_or_else(|| String::from("missing --core PATH"))?,
        adapter: adapter.ok_or_else(|| String::from("missing --adapter PATH"))?,
        output: output.ok_or_else(|| String::from("missing --output PATH"))?,
    };
    if result.output == result.core || result.output == result.adapter {
        return Err(String::from(
            "output path must differ from both input paths",
        ));
    }
    Ok(result)
}

fn run() -> Result<(), String> {
    let arguments = parse_arguments()?;
    let core = fs::read(&arguments.core)
        .map_err(|error| format!("failed to read --core {:?}: {error}", arguments.core))?;
    let adapter = fs::read(&arguments.adapter)
        .map_err(|error| format!("failed to read --adapter {:?}: {error}", arguments.adapter))?;
    let transformed = componentize_preview1(&core, &adapter)
        .map_err(|error| format!("C8.1 transformation rejected: {error}"))?;
    let pins = derive_output_pins(transformed.bytes())
        .map_err(|error| format!("C8.1 output pin derivation failed: {error}"))?;
    fs::write(&arguments.output, transformed.bytes())
        .map_err(|error| format!("failed to write --output {:?}: {error}", arguments.output))?;

    let report = transformed.report();
    println!("core_bytes={}", report.core_bytes);
    println!("core_sha256={}", hex_sha256(&report.core_sha256));
    println!("adapter_bytes={}", report.adapter_bytes);
    println!("adapter_sha256={}", hex_sha256(&report.adapter_sha256));
    println!("component_bytes={}", report.component_bytes);
    println!("component_sha256={}", hex_sha256(&report.component_sha256));
    println!("outer_imports={}", report.outer_imports);
    println!("outer_exports={}", report.outer_exports);
    println!("embedded_core_modules={}", report.embedded_core_modules);
    println!("nested_components={}", report.nested_components);
    println!("canonical_lowers={}", report.canonical_lowers);
    println!(
        "canonical_lowering_sha256={}",
        hex_sha256(&pins.canonical_lowering_sha256)
    );
    for module in &pins.embedded_core_modules {
        println!(
            "embedded_core_module ordinal={} raw_bytes={} raw_sha256={}",
            module.ordinal,
            module.raw_bytes,
            hex_sha256(&module.raw_sha256)
        );
    }
    for entry in pins.entries {
        let direction = match entry.direction {
            OutputDirection::Import => "import",
            OutputDirection::Export => "export",
        };
        let kind = match entry.kind {
            OutputKind::Module => "module",
            OutputKind::Function => "function",
            OutputKind::Value => "value",
            OutputKind::Type => "type",
            OutputKind::Component => "component",
            OutputKind::Instance => "instance",
        };
        println!(
            "outer_entry direction={direction} kind={kind} name={} raw_bytes={} raw_sha256={}",
            entry.name,
            entry.raw_bytes,
            hex_sha256(&entry.raw_sha256)
        );
    }
    println!("runtime_ready={}", report.runtime_ready);
    println!("guest_calls={}", report.guest_calls);
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
