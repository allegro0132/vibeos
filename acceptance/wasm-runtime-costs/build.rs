use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const UNBOUND_COMMIT: &str = "0000000000000000000000000000000000000000";
const UNBOUND_CHALLENGE: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const EXPECTED_MANIFEST_SHA256: &str =
    "8b5bec7eacd2fd706b716b005af3a5a085730afdeb20839e905cf9177e70aeb4";
const EXPECTED_SCHEMA_SHA256: &str =
    "4d36975acde2de015ef75e6ed402201da3d70f516d6d9f620adde08f3e11ed8d";

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn digest(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn require_hex(name: &str, value: &str, length: usize) {
    assert_eq!(value.len(), length, "{name} has the wrong length");
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{name} must be canonical lowercase hexadecimal"
    );
}

fn compile_wat(source: &Path, destination: &Path) -> Vec<u8> {
    println!("cargo:rerun-if-changed={}", source.display());
    let bytes = wat::parse_file(source)
        .unwrap_or_else(|error| panic!("cannot compile {}: {error}", source.display()));
    fs::write(destination, &bytes)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", destination.display()));
    bytes
}

fn read_bound_file(path: &Path) -> Vec<u8> {
    println!("cargo:rerun-if-changed={}", path.display());
    fs::read(path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn main() {
    println!("cargo:rerun-if-env-changed=VIBEOS_C83_SOURCE_COMMIT");
    println!("cargo:rerun-if-env-changed=VIBEOS_C83_CHALLENGE");

    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let sync_source = manifest.join("../../component-runtime/tests/fixtures/rich.component.wat");
    let route_source = manifest.join("fixtures/async-route.component.wat");
    let core_source = manifest.join("fixtures/core-host-fuel.wat");
    let workload_manifest = manifest.join("../../benchmarks/wasm-runtime/workloads-v1.json");
    let transcript_schema = manifest.join("../../benchmarks/wasm-runtime/schema-v1.json");

    let sync = compile_wat(&sync_source, &output.join("sync.component.wasm"));
    let route = compile_wat(&route_source, &output.join("async-route.component.wasm"));
    let core = compile_wat(&core_source, &output.join("core-host-fuel.wasm"));
    let workload_manifest = read_bound_file(&workload_manifest);
    let transcript_schema = read_bound_file(&transcript_schema);

    let source_commit =
        env::var("VIBEOS_C83_SOURCE_COMMIT").unwrap_or_else(|_| UNBOUND_COMMIT.into());
    let challenge = env::var("VIBEOS_C83_CHALLENGE").unwrap_or_else(|_| UNBOUND_CHALLENGE.into());
    require_hex("VIBEOS_C83_SOURCE_COMMIT", &source_commit, 40);
    require_hex("VIBEOS_C83_CHALLENGE", &challenge, 64);
    let manifest_sha = digest(&workload_manifest);
    let schema_sha = digest(&transcript_schema);
    assert_eq!(
        manifest_sha, EXPECTED_MANIFEST_SHA256,
        "C8.3 workload manifest changed without a reviewed identity update"
    );
    assert_eq!(
        schema_sha, EXPECTED_SCHEMA_SHA256,
        "C8.3 transcript schema changed without a reviewed identity update"
    );
    let run_id = digest(
        format!(
            "vibeos.c83.runtime-costs.v1\0{source_commit}\0{challenge}\0{}\0{}\0{}\0{manifest_sha}\0{schema_sha}",
            digest(&sync),
            digest(&route),
            digest(&core),
        )
        .as_bytes(),
    );

    let generated = format!(
        "pub const SOURCE_COMMIT: &str = {source_commit:?};\n\
         pub const CHALLENGE: &str = {challenge:?};\n\
         pub const RUN_ID: &str = {run_id:?};\n\
         pub const MANIFEST_SHA256: &str = {manifest_sha:?};\n\
         pub const TRANSCRIPT_SCHEMA_SHA256: &str = {schema_sha:?};\n\
         pub const SYNC_COMPONENT_SHA256: &str = {sync_sha:?};\n\
         pub const SYNC_COMPONENT_BYTES: usize = {sync_len};\n\
         pub const ROUTE_COMPONENT_SHA256: &str = {route_sha:?};\n\
         pub const ROUTE_COMPONENT_BYTES: usize = {route_len};\n\
         pub const CORE_MODULE_SHA256: &str = {core_sha:?};\n\
         pub const CORE_MODULE_BYTES: usize = {core_len};\n",
        sync_sha = digest(&sync),
        sync_len = sync.len(),
        route_sha = digest(&route),
        route_len = route.len(),
        core_sha = digest(&core),
        core_len = core.len(),
        run_id = run_id,
    );
    fs::write(output.join("identity.rs"), generated).expect("write C8.3 workload identity");
}
