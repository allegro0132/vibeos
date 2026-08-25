#![cfg(feature = "preview1-corpus-acceptance")]

use std::sync::Arc;

use sha2::{Digest, Sha256};
use vibeos_c82_preview1_corpus::{
    componentize_corpus_core, OutputDirection as CorpusDirection, OutputKind as CorpusKind,
};
use vibeos_component_admission::{
    admit_preview1_corpus_candidate, AdmissionError, Preview1CorpusAdmissionPolicy,
    Preview1CorpusBuildError, Preview1CorpusInvocationInput, Preview1CorpusPending,
    Preview1CorpusPoll, Preview1CorpusTerminal, Preview1WrappedCoreModulePin,
    Preview1WrappedEntityDirection, Preview1WrappedEntityKind, Preview1WrappedTopLevelEntityPin,
};
use vibeos_component_format::{
    ComponentArtifactAdapterV1, ComponentArtifactCoreModuleV1, ComponentArtifactInstanceLimitsV1,
    ComponentArtifactManifestV1, ComponentArtifactSignerPolicyV1, ComponentArtifactV1,
    ComponentArtifactWitPackageV1, ProfileIdentity, PREVIEW1_WRAPPED_ADAPTER_ASSET_BYTE_LEN,
    PREVIEW1_WRAPPED_ADAPTER_ASSET_SHA256, PREVIEW1_WRAPPED_ADAPTER_REVISION,
};
use vibeos_component_host::{
    ByteStream, ByteStreamReader, StreamCloseReason, StreamError, StreamReceiveCommit,
    StreamReceiveDispatch, StreamSendDispatch, STREAM_BUFFER_CHUNKS,
};
use vibeos_wasm_runtime::{
    CoreHostImport, CoreValueType, OwnerAllocationReservation, PollResult, ValidatedCore,
};
use wasmparser::{Parser, Payload};

const ADAPTER: &[u8] = include_bytes!(
    "../../../policy/image/artifacts/c81-wasmtime-v48.0.0-preview1-command-adapter.wasm"
);
const EXTERNAL_POLICY_DIGEST: [u8; 32] = [0x73; 32];
const RUST_CMP1: &[u8] =
    include_bytes!("../../../policy/image/artifacts/c82-rust-ascii-filter.preview1-wrapped.cmp1");
const C_CMP1: &[u8] =
    include_bytes!("../../../policy/image/artifacts/c82-c-ascii-filter.preview1-wrapped.cmp1");

const TEST_HOST_FD_READ: u32 = 1;
const TEST_HOST_FD_WRITE: u32 = 2;
const TEST_HOST_ARGS_SIZES_GET: u32 = 3;
const TEST_HOST_ARGS_GET: u32 = 4;
const TEST_HOST_PROC_EXIT: u32 = 5;
const TEST_I32_X1: [CoreValueType; 1] = [CoreValueType::I32];
const TEST_I32_X2: [CoreValueType; 2] = [CoreValueType::I32; 2];
const TEST_I32_X4: [CoreValueType; 4] = [CoreValueType::I32; 4];
const TEST_HOST_IMPORTS: [CoreHostImport<'static>; 5] = [
    CoreHostImport {
        id: TEST_HOST_FD_READ,
        module: "wasi_snapshot_preview1",
        name: "fd_read",
        params: &TEST_I32_X4,
        results: &TEST_I32_X1,
    },
    CoreHostImport {
        id: TEST_HOST_FD_WRITE,
        module: "wasi_snapshot_preview1",
        name: "fd_write",
        params: &TEST_I32_X4,
        results: &TEST_I32_X1,
    },
    CoreHostImport {
        id: TEST_HOST_ARGS_SIZES_GET,
        module: "wasi_snapshot_preview1",
        name: "args_sizes_get",
        params: &TEST_I32_X2,
        results: &TEST_I32_X1,
    },
    CoreHostImport {
        id: TEST_HOST_ARGS_GET,
        module: "wasi_snapshot_preview1",
        name: "args_get",
        params: &TEST_I32_X2,
        results: &TEST_I32_X1,
    },
    CoreHostImport {
        id: TEST_HOST_PROC_EXIT,
        module: "wasi_snapshot_preview1",
        name: "proc_exit",
        params: &TEST_I32_X1,
        results: &[],
    },
];

const COMPLETE_RUST_ORDER_CORE: &str = r#"
(module
  (type (func (param i32)))
  (type (func (param i32 i32) (result i32)))
  (type (func (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func (type 2)))
  (import "wasi_snapshot_preview1" "proc_exit" (func (type 0)))
  (import "wasi_snapshot_preview1" "args_sizes_get" (func (type 1)))
  (import "wasi_snapshot_preview1" "args_get" (func (type 1)))
  (import "wasi_snapshot_preview1" "fd_read" (func (type 2)))
  (memory (export "memory") 2 16)
  (global (mut i32) (i32.const 65536))
  (func (export "_start")
      i32.const 0
      i32.const 4
      call 2
      drop
      i32.const 8
      i32.const 128
      call 3
      drop

      i32.const 32
      i32.const 12
      i32.load
      i32.store
      i32.const 36
      i32.const 2
      i32.store
      i32.const 1
      i32.const 32
      i32.const 1
      i32.const 40
      call 0
      drop

      i32.const 32
      i32.const 256
      i32.store
      i32.const 36
      i32.const 32
      i32.store
      i32.const 0
      i32.const 32
      i32.const 1
      i32.const 44
      call 4
      drop

      i32.const 32
      i32.const 256
      i32.store
      i32.const 36
      i32.const 44
      i32.load
      i32.store
      i32.const 1
      i32.const 32
      i32.const 1
      i32.const 48
      call 0
      drop

      i32.const 7
      call 1))
"#;

const COMPLETE_C_ORDER_CORE: &str = r#"
(module
  (type (func (param i32)))
  (type (func (param i32 i32) (result i32)))
  (type (func (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "args_sizes_get" (func (type 1)))
  (import "wasi_snapshot_preview1" "args_get" (func (type 1)))
  (import "wasi_snapshot_preview1" "fd_read" (func (type 2)))
  (import "wasi_snapshot_preview1" "fd_write" (func (type 2)))
  (import "wasi_snapshot_preview1" "proc_exit" (func (type 0)))
  (memory (export "memory") 2 16)
  (global (mut i32) (i32.const 65536))
  (func (export "_start")
    i32.const 0
    call 4))
"#;

const FORBIDDEN_IMPORT_CORE: &str = r#"
(module
  (type (func (param i32)))
  (type (func (param i32 i32) (result i32)))
  (type (func (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "args_sizes_get" (func (type 1)))
  (import "wasi_snapshot_preview1" "args_get" (func (type 1)))
  (import "wasi_snapshot_preview1" "fd_read" (func (type 2)))
  (import "wasi_snapshot_preview1" "fd_write" (func (type 2)))
  (import "wasi_snapshot_preview1" "proc_exit" (func (type 0)))
  (import "wasi_snapshot_preview1" "environ_get" (func (type 1)))
  (memory (export "memory") 2 16)
  (global (mut i32) (i32.const 65536))
  (func (export "_start")
    i32.const 0
    call 4))
"#;

const INFINITE_CORE: &str = r#"
(module
  (type (func (param i32)))
  (type (func (param i32 i32) (result i32)))
  (type (func (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "args_sizes_get" (func (type 1)))
  (import "wasi_snapshot_preview1" "args_get" (func (type 1)))
  (import "wasi_snapshot_preview1" "fd_read" (func (type 2)))
  (import "wasi_snapshot_preview1" "fd_write" (func (type 2)))
  (import "wasi_snapshot_preview1" "proc_exit" (func (type 0)))
  (memory (export "memory") 2 16)
  (global (mut i32) (i32.const 65536))
  (func (export "_start")
    (loop
      br 0)))
"#;

const BAD_FD_CORE: &str = r#"
(module
  (type (func (param i32)))
  (type (func (param i32 i32) (result i32)))
  (type (func (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "args_sizes_get" (func (type 1)))
  (import "wasi_snapshot_preview1" "args_get" (func (type 1)))
  (import "wasi_snapshot_preview1" "fd_read" (func (type 2)))
  (import "wasi_snapshot_preview1" "fd_write" (func (type 2)))
  (import "wasi_snapshot_preview1" "proc_exit" (func (type 0)))
  (memory (export "memory") 2 16)
  (global (mut i32) (i32.const 65536))
  (func (export "_start")
    i32.const 2
    i32.const 0
    i32.const 0
    i32.const 0
    call 3
    i32.const 8
    i32.ne
    if
      i32.const 90
      call 4
    end
    i32.const 1
    i32.const 0
    i32.const 0
    i32.const 0
    call 2
    i32.const 8
    i32.ne
    if
      i32.const 91
      call 4
    end
    i32.const 0
    call 4))
"#;

const IOVEC_LIMIT_CORE: &str = r#"
(module
  (type (func (param i32)))
  (type (func (param i32 i32) (result i32)))
  (type (func (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "args_sizes_get" (func (type 1)))
  (import "wasi_snapshot_preview1" "args_get" (func (type 1)))
  (import "wasi_snapshot_preview1" "fd_read" (func (type 2)))
  (import "wasi_snapshot_preview1" "fd_write" (func (type 2)))
  (import "wasi_snapshot_preview1" "proc_exit" (func (type 0)))
  (memory (export "memory") 2 16)
  (global (mut i32) (i32.const 65536))
  (func (export "_start")
    i32.const 1
    i32.const 0
    i32.const 2
    i32.const 32
    call 3
    drop
    i32.const 99
    call 4))
"#;

const FIRST_FD_READ_CORE: &str = r#"
(module
  (type (func (param i32)))
  (type (func (param i32 i32) (result i32)))
  (type (func (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "args_sizes_get" (func (type 1)))
  (import "wasi_snapshot_preview1" "args_get" (func (type 1)))
  (import "wasi_snapshot_preview1" "fd_read" (func (type 2)))
  (import "wasi_snapshot_preview1" "fd_write" (func (type 2)))
  (import "wasi_snapshot_preview1" "proc_exit" (func (type 0)))
  (memory (export "memory") 2 16)
  (global (mut i32) (i32.const 65536))
  (func (export "_start")
    i32.const 32
    i32.const 256
    i32.store
    i32.const 36
    i32.const 1
    i32.store
    i32.const 0
    i32.const 32
    i32.const 1
    i32.const 40
    call 2
    drop
    i32.const 0
    call 4))
"#;

const FIRST_FD_WRITE_CORE: &str = r#"
(module
  (type (func (param i32)))
  (type (func (param i32 i32) (result i32)))
  (type (func (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "args_sizes_get" (func (type 1)))
  (import "wasi_snapshot_preview1" "args_get" (func (type 1)))
  (import "wasi_snapshot_preview1" "fd_read" (func (type 2)))
  (import "wasi_snapshot_preview1" "fd_write" (func (type 2)))
  (import "wasi_snapshot_preview1" "proc_exit" (func (type 0)))
  (memory (export "memory") 2 16)
  (global (mut i32) (i32.const 65536))
  (func (export "_start")
    i32.const 256
    i32.const 65
    i32.store8
    i32.const 32
    i32.const 256
    i32.store
    i32.const 36
    i32.const 1
    i32.store
    i32.const 1
    i32.const 32
    i32.const 1
    i32.const 40
    call 3
    drop
    i32.const 0
    call 4))
"#;

struct Fixture {
    artifact: Option<ComponentArtifactV1>,
    artifact_commitment: [u8; 32],
    modules: Vec<Preview1WrappedCoreModulePin>,
    entities: Vec<Preview1WrappedTopLevelEntityPin<'static>>,
    guest_len: u32,
    guest_hash: [u8; 32],
    canonical_hash: [u8; 32],
    canonical_count: u32,
    nested_count: u32,
    max_arguments: u16,
    max_argument_bytes: u32,
    max_iovecs: u16,
    max_io_bytes_per_call: u32,
    max_stdin_bytes: u32,
    max_stdout_bytes: u32,
    max_host_calls: u32,
}

impl Fixture {
    fn new(core_wat: &str) -> Self {
        Self::new_with_total_fuel(core_wat, 1_000_000)
    }

    fn new_with_total_fuel(core_wat: &str, total_fuel: u64) -> Self {
        let compiler_core = wat::parse_str(core_wat).unwrap();
        let transformed = componentize_corpus_core(&compiler_core, ADAPTER).unwrap();
        let canonical_hash = transformed.pins().canonical_lowering_sha256;
        let entities = transformed
            .pins()
            .entries
            .iter()
            .map(|entry| Preview1WrappedTopLevelEntityPin {
                direction: match entry.direction {
                    CorpusDirection::Import => Preview1WrappedEntityDirection::Import,
                    CorpusDirection::Export => Preview1WrappedEntityDirection::Export,
                },
                kind: match entry.kind {
                    CorpusKind::Module => Preview1WrappedEntityKind::Module,
                    CorpusKind::Function => Preview1WrappedEntityKind::Function,
                    CorpusKind::Value => Preview1WrappedEntityKind::Value,
                    CorpusKind::Type => Preview1WrappedEntityKind::Type,
                    CorpusKind::Component => Preview1WrappedEntityKind::Component,
                    CorpusKind::Instance => Preview1WrappedEntityKind::Instance,
                },
                name: static_component_name(&entry.name),
                raw_entry_sha256: entry.raw_sha256,
            })
            .collect::<Vec<_>>();
        let component = transformed.component_bytes();
        let module_bytes = embedded_modules(component);
        assert_eq!(module_bytes.len(), 4);
        let modules = module_bytes
            .iter()
            .map(|module| Preview1WrappedCoreModulePin {
                byte_len: module.len() as u32,
                sha256: raw_sha256(module),
            })
            .collect::<Vec<_>>();
        let guest_len = modules[0].byte_len;
        let guest_hash = modules[0].sha256;
        let manifest_modules = module_bytes
            .iter()
            .map(|module| ComponentArtifactCoreModuleV1::from_bytes(module).unwrap())
            .collect();
        let manifest = ComponentArtifactManifestV1::new(
            "fixture:command/root",
            vec![ComponentArtifactWitPackageV1::new(
                "fixture:command",
                "0.0.0+c82",
                "package fixture:command; world root {}",
            )
            .unwrap()],
            vec![],
            manifest_modules,
            vec![
                ComponentArtifactAdapterV1::new(0, PREVIEW1_WRAPPED_ADAPTER_REVISION, ADAPTER)
                    .unwrap(),
            ],
        )
        .unwrap();
        let artifact = ComponentArtifactV1::new(
            component,
            ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED,
            ComponentArtifactInstanceLimitsV1::new(16 * 65_536, total_fuel, total_fuel.min(100), 8)
                .unwrap(),
            ComponentArtifactSignerPolicyV1::development_image_pin(EXTERNAL_POLICY_DIGEST).unwrap(),
            manifest,
        )
        .unwrap();
        let artifact_commitment = *artifact.artifact_commitment().unwrap().as_bytes();
        Self {
            artifact: Some(artifact),
            artifact_commitment,
            modules,
            entities,
            guest_len,
            guest_hash,
            canonical_hash,
            canonical_count: 18,
            nested_count: 1,
            max_arguments: 8,
            max_argument_bytes: 256,
            max_iovecs: 4,
            max_io_bytes_per_call: 1_024,
            max_stdin_bytes: 4_096,
            max_stdout_bytes: 4_096,
            max_host_calls: 32,
        }
    }

    fn policy(&self) -> Preview1CorpusAdmissionPolicy<'_> {
        Preview1CorpusAdmissionPolicy {
            artifact_commitment: self.artifact_commitment,
            external_policy_digest: EXTERNAL_POLICY_DIGEST,
            command_name: "fixture-command",
            adapter_revision: PREVIEW1_WRAPPED_ADAPTER_REVISION,
            adapter_embedded_module_ordinal: 1,
            adapter_asset_byte_len: PREVIEW1_WRAPPED_ADAPTER_ASSET_BYTE_LEN as u32,
            adapter_asset_sha256: PREVIEW1_WRAPPED_ADAPTER_ASSET_SHA256,
            guest_module_ordinal: 0,
            guest_module_byte_len: self.guest_len,
            guest_module_sha256: self.guest_hash,
            embedded_modules: &self.modules,
            top_level_entities: &self.entities,
            canonical_lowering_sha256: self.canonical_hash,
            canonical_lowering_count: self.canonical_count,
            nested_component_count: self.nested_count,
            max_arguments: self.max_arguments,
            max_argument_bytes: self.max_argument_bytes,
            max_iovecs: self.max_iovecs,
            max_io_bytes_per_call: self.max_io_bytes_per_call,
            max_stdin_bytes: self.max_stdin_bytes,
            max_stdout_bytes: self.max_stdout_bytes,
            max_host_calls: self.max_host_calls,
        }
    }

    fn admit(
        &mut self,
    ) -> Result<vibeos_component_admission::AdmittedPreview1CorpusCandidate, AdmissionError> {
        let artifact = self.artifact.take().unwrap();
        admit_preview1_corpus_candidate(artifact, &self.policy())
    }
}

#[test]
fn complete_artifact_executes_only_bounded_cli_values_and_exact_proc_exit() {
    let mut fixture = Fixture::new(COMPLETE_RUST_ORDER_CORE);
    let candidate = fixture.admit().unwrap();
    assert_eq!(
        candidate.profile(),
        ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED
    );
    assert!(!candidate.runtime_ready());
    assert_eq!(candidate.guest_calls(), 0);
    assert_eq!(candidate.diagnostics().guest_import_count(), 5);
    candidate.revalidate().unwrap();

    let stdin_stream = ByteStream::new();
    let stdin_writer = stdin_stream.writer();
    assert_eq!(stdin_writer.start(b"abc"), Ok(StreamSendDispatch::Sent));
    assert_eq!(
        stdin_writer.close(StreamCloseReason::Normal),
        vibeos_component_host::StreamCloseOutcome::Published
    );
    stdin_stream
        .supervisor()
        .finalize(StreamCloseReason::Normal);

    let stdout_stream = ByteStream::new();
    let stdout_reader = stdout_stream.reader();
    let input = Preview1CorpusInvocationInput::new(
        stdin_stream.reader(),
        stdout_stream.writer(),
        vec!["xy".into()],
    );
    let mut invocation = candidate.into_acceptance_invocation(input).unwrap();
    let mut output = Vec::new();
    let terminal = loop {
        let poll = invocation.poll();
        drain_buffered(&stdout_stream, &stdout_reader, &mut output);
        match poll {
            Preview1CorpusPoll::Pending { reason, metrics } => {
                assert!(matches!(
                    reason,
                    Preview1CorpusPending::Fuel | Preview1CorpusPending::HostWork
                ));
                assert_eq!(metrics.consumed_fuel + metrics.remaining_fuel, 1_000_000);
            }
            Preview1CorpusPoll::Ready(terminal) => break terminal,
        }
    };
    assert_eq!(terminal, Preview1CorpusTerminal::Exited(7));
    assert_eq!(invocation.host_calls(), 6);
    assert_eq!(invocation.stdin_bytes(), 3);
    assert_eq!(invocation.stdout_bytes(), 5);
    assert_eq!(output, b"xyabc");
    let metrics = invocation.metrics().unwrap();
    assert!(metrics.consumed_fuel > 0);
    assert_eq!(metrics.consumed_fuel + metrics.remaining_fuel, 1_000_000);
}

#[test]
fn both_compiler_import_orders_are_exact_sets_and_forbidden_imports_remain_closed() {
    let mut c_order = Fixture::new(COMPLETE_C_ORDER_CORE);
    assert!(c_order.admit().is_ok());

    let forbidden = wat::parse_str(FORBIDDEN_IMPORT_CORE).unwrap();
    assert!(componentize_corpus_core(&forbidden, ADAPTER).is_err());
}

#[test]
fn policy_value_and_stream_bounds_fail_closed() {
    let mut bad_hash = Fixture::new(COMPLETE_RUST_ORDER_CORE);
    bad_hash.canonical_hash[0] ^= 1;
    assert!(bad_hash.admit().is_err());

    let mut bad_ordinal = Fixture::new(COMPLETE_RUST_ORDER_CORE);
    bad_ordinal.modules.swap(0, 1);
    assert!(bad_ordinal.admit().is_err());

    let mut missing_module = Fixture::new(COMPLETE_RUST_ORDER_CORE);
    missing_module.modules.pop();
    assert!(missing_module.admit().is_err());

    let mut missing_outer = Fixture::new(COMPLETE_RUST_ORDER_CORE);
    missing_outer.entities.pop();
    assert!(missing_outer.admit().is_err());

    let mut replaced_outer = Fixture::new(COMPLETE_RUST_ORDER_CORE);
    replaced_outer.entities[0].name = "wasi:cli/run@0.2.12";
    assert!(replaced_outer.admit().is_err());

    let mut added_outer = Fixture::new(COMPLETE_RUST_ORDER_CORE);
    added_outer.entities.push(added_outer.entities[0]);
    assert!(added_outer.admit().is_err());

    let mut bad_lowering_count = Fixture::new(COMPLETE_RUST_ORDER_CORE);
    bad_lowering_count.canonical_count = 17;
    assert!(bad_lowering_count.admit().is_err());

    let mut bad_nesting = Fixture::new(COMPLETE_RUST_ORDER_CORE);
    bad_nesting.nested_count = 0;
    assert!(bad_nesting.admit().is_err());

    let mut bounded = Fixture::new(COMPLETE_RUST_ORDER_CORE);
    bounded.max_arguments = 1;
    let candidate = bounded.admit().unwrap();
    let stdin = ByteStream::new();
    let stdout = ByteStream::new();
    assert!(matches!(
        candidate.into_acceptance_invocation(Preview1CorpusInvocationInput::new(
            stdin.reader(),
            stdout.writer(),
            vec!["one-too-many".into()],
        )),
        Err(Preview1CorpusBuildError::InvalidArguments)
    ));

    let mut same_stream_fixture = Fixture::new(COMPLETE_RUST_ORDER_CORE);
    let candidate = same_stream_fixture.admit().unwrap();
    let same = ByteStream::new();
    assert!(matches!(
        candidate.into_acceptance_invocation(Preview1CorpusInvocationInput::new(
            same.reader(),
            same.writer(),
            vec![],
        )),
        Err(Preview1CorpusBuildError::InvalidStreams)
    ));
}

#[test]
fn host_call_limit_terminates_before_the_unbounded_call() {
    let mut fixture = Fixture::new(COMPLETE_RUST_ORDER_CORE);
    fixture.max_host_calls = 5;
    let candidate = fixture.admit().unwrap();
    let stdin = ByteStream::new();
    assert_eq!(stdin.writer().start(b"x"), Ok(StreamSendDispatch::Sent));
    let stdout = ByteStream::new();
    let mut invocation = candidate
        .into_acceptance_invocation(Preview1CorpusInvocationInput::new(
            stdin.reader(),
            stdout.writer(),
            vec!["xy".into()],
        ))
        .unwrap();
    let terminal = loop {
        match invocation.poll() {
            Preview1CorpusPoll::Pending { .. } => {
                drain_buffered(&stdout, &stdout.reader(), &mut Vec::new());
            }
            Preview1CorpusPoll::Ready(terminal) => break terminal,
        }
    };
    assert_eq!(terminal, Preview1CorpusTerminal::LimitExceeded);
    assert_eq!(invocation.host_calls(), 5);
}

#[derive(Clone, Copy)]
enum RealProgram {
    Rust,
    C,
}

#[test]
fn reviewed_rust_and_c_cmp1_corpus_runs_upper_lower_bad_and_oversize() {
    for program in [RealProgram::Rust, RealProgram::C] {
        assert_eq!(
            run_real_case(program, "upper", b"aZ!\n"),
            (Preview1CorpusTerminal::Exited(0), b"AZ!\n".to_vec())
        );
        assert_eq!(
            run_real_case(program, "lower", b"aZ!\n"),
            (Preview1CorpusTerminal::Exited(0), b"az!\n".to_vec())
        );
        assert_eq!(
            run_real_case(program, "bad", b""),
            (Preview1CorpusTerminal::Exited(64), Vec::new())
        );
        assert_eq!(
            run_real_case(program, "upper", &vec![b'a'; 4_097]),
            (Preview1CorpusTerminal::Exited(65), Vec::new())
        );
    }
}

#[test]
fn reviewed_cmp1_consumes_one_upstream_chunk_only_in_guest_bounded_prefixes() {
    let input = (0..1_024)
        .map(|index| b'a' + (index % 26) as u8)
        .collect::<Vec<_>>();
    let expected = input
        .iter()
        .copied()
        .map(|byte| byte.to_ascii_uppercase())
        .collect::<Vec<_>>();
    for program in [RealProgram::Rust, RealProgram::C] {
        for per_call_limit in [1_u32, 257] {
            let candidate = real_candidate_with_limits(program, per_call_limit, 4_096);
            let stdin = ByteStream::new();
            let stdin_writer = stdin.writer();
            assert_eq!(stdin_writer.start(&input), Ok(StreamSendDispatch::Sent));
            stdin_writer.close(StreamCloseReason::Normal);
            stdin.supervisor().finalize(StreamCloseReason::Normal);

            let stdout = ByteStream::new();
            let stdout_reader = stdout.reader();
            let mut invocation = candidate
                .into_acceptance_invocation(Preview1CorpusInvocationInput::new(
                    stdin.reader(),
                    stdout.writer(),
                    vec!["upper".into()],
                ))
                .unwrap();
            let mut output = Vec::new();
            let terminal = loop {
                let before_stdin = invocation.stdin_bytes();
                let before_stdout = invocation.stdout_bytes();
                let poll = invocation.poll();
                assert!(invocation.stdin_bytes() >= before_stdin);
                assert!(invocation.stdout_bytes() >= before_stdout);
                assert!(invocation.stdin_bytes() - before_stdin <= per_call_limit as usize);
                assert!(invocation.stdout_bytes() - before_stdout <= per_call_limit as usize);
                drain_buffered(&stdout, &stdout_reader, &mut output);
                match poll {
                    Preview1CorpusPoll::Pending { metrics, .. } => {
                        assert_eq!(metrics.consumed_fuel + metrics.remaining_fuel, 2_000_000);
                    }
                    Preview1CorpusPoll::Ready(terminal) => break terminal,
                }
            };
            assert_eq!(terminal, Preview1CorpusTerminal::Exited(0));
            assert_eq!(invocation.stdin_bytes(), input.len());
            assert_eq!(invocation.stdout_bytes(), expected.len());
            assert_eq!(output, expected);
            assert!(invocation.host_calls() <= 4_096);
        }
    }
}

#[test]
fn reviewed_cmp1_stdin_wait_cancels_exactly_without_guest_resumption() {
    let candidate = real_candidate(RealProgram::Rust);
    let stdin = ByteStream::new();
    let stdin_reader = stdin.reader();
    let stdin_writer = stdin.writer();
    let stdout = ByteStream::new();
    let mut invocation = candidate
        .into_acceptance_invocation(Preview1CorpusInvocationInput::new(
            stdin_reader.clone(),
            stdout.writer(),
            vec!["upper".into()],
        ))
        .unwrap();
    loop {
        match invocation.poll() {
            Preview1CorpusPoll::Pending {
                reason: Preview1CorpusPending::Stdin,
                ..
            } => break,
            Preview1CorpusPoll::Pending { .. } => {}
            terminal => panic!("expected stdin wait before terminal: {terminal:?}"),
        }
    }
    assert_eq!(
        invocation.cancel(),
        Preview1CorpusPoll::Ready(Preview1CorpusTerminal::Cancelled)
    );
    assert_eq!(
        invocation.poll(),
        Preview1CorpusPoll::Ready(Preview1CorpusTerminal::Cancelled)
    );
    assert_eq!(stdin_reader.start(), Err(StreamError::EndpointClosed));
    assert_eq!(
        stdin_writer.start(b"late"),
        Ok(StreamSendDispatch::Closed(StreamCloseReason::Normal))
    );
    assert!(!stdin.is_fail_stopped());
    assert_eq!(stdout.final_reason(), Some(StreamCloseReason::Cancelled));
}

#[test]
fn terminal_drop_closes_stdin_consumer_and_releases_backpressured_producer() {
    let mut fixture = Fixture::new(COMPLETE_C_ORDER_CORE);
    let candidate = fixture.admit().unwrap();
    let stdin = ByteStream::new();
    let stdin_writer = stdin.writer();
    for byte in 0..STREAM_BUFFER_CHUNKS {
        assert_eq!(
            stdin_writer.start(&[byte as u8]),
            Ok(StreamSendDispatch::Sent)
        );
    }
    let blocked = match stdin_writer.start(b"blocked") {
        Ok(StreamSendDispatch::Waiting(operation)) => operation,
        other => panic!("full stdin must backpressure its producer: {other:?}"),
    };

    let stdout = ByteStream::new();
    let mut invocation = candidate
        .into_acceptance_invocation(Preview1CorpusInvocationInput::new(
            stdin.reader(),
            stdout.writer(),
            vec![],
        ))
        .unwrap();
    assert_eq!(
        poll_to_terminal(&mut invocation),
        Preview1CorpusTerminal::Exited(0)
    );
    drop(invocation);

    assert_eq!(stdin.depth(), 0);
    assert_eq!(
        stdin_writer.resume(blocked, b"blocked"),
        Ok(StreamSendDispatch::Closed(StreamCloseReason::Normal))
    );
    assert!(!stdin.is_fail_stopped());
}

#[test]
fn nonzero_proc_exit_preserves_buffered_stdout_until_normal_eof() {
    let mut fixture = Fixture::new(COMPLETE_RUST_ORDER_CORE);
    let candidate = fixture.admit().unwrap();
    let stdin = ByteStream::new();
    let stdin_writer = stdin.writer();
    assert_eq!(stdin_writer.start(b"abc"), Ok(StreamSendDispatch::Sent));
    assert_eq!(
        stdin_writer.close(StreamCloseReason::Normal),
        vibeos_component_host::StreamCloseOutcome::Published
    );
    stdin.supervisor().finalize(StreamCloseReason::Normal);

    let stdout = ByteStream::new();
    let stdout_reader = stdout.reader();
    let mut invocation = candidate
        .into_acceptance_invocation(Preview1CorpusInvocationInput::new(
            stdin.reader(),
            stdout.writer(),
            vec!["xy".into()],
        ))
        .unwrap();
    assert_eq!(
        poll_to_terminal(&mut invocation),
        Preview1CorpusTerminal::Exited(7)
    );
    assert!(stdout.depth() > 0);
    assert!(stdout.is_normal_provisional());
    assert_eq!(stdout.final_reason(), None);

    let mut output = Vec::new();
    drain_buffered(&stdout, &stdout_reader, &mut output);
    assert_eq!(output, b"xyabc");
    assert_eq!(invocation.stdout_bytes(), output.len());
    let promoted = stdout
        .supervisor()
        .promote_normal_if_drained_observed()
        .expect("drained normal producer close must promote to EOF");
    assert_eq!(promoted.effective_reason(), Some(StreamCloseReason::Normal));
    assert_eq!(stdout.final_reason(), Some(StreamCloseReason::Normal));
    assert_eq!(
        stdout_reader.start(),
        Ok(StreamReceiveDispatch::Closed(StreamCloseReason::Normal))
    );
    assert!(!stdout.is_fail_stopped());
}

#[test]
fn reviewed_cmp1_stdout_backpressure_retries_without_duplication_or_loss() {
    let candidate = real_candidate(RealProgram::Rust);
    let stdin = ByteStream::new();
    let stdin_writer = stdin.writer();
    for chunk in vec![b'a'; 4_096].chunks(1_024) {
        assert_eq!(stdin_writer.start(chunk), Ok(StreamSendDispatch::Sent));
    }
    stdin_writer.close(StreamCloseReason::Normal);
    stdin.supervisor().finalize(StreamCloseReason::Normal);

    let stdout = ByteStream::new();
    let stdout_reader = stdout.reader();
    let mut invocation = candidate
        .into_acceptance_invocation(Preview1CorpusInvocationInput::new(
            stdin.reader(),
            stdout.writer(),
            vec!["upper".into()],
        ))
        .unwrap();
    loop {
        match invocation.poll() {
            Preview1CorpusPoll::Pending {
                reason: Preview1CorpusPending::Stdout,
                ..
            } => break,
            Preview1CorpusPoll::Pending { .. } => {}
            terminal => panic!("stdout must backpressure before terminal: {terminal:?}"),
        }
    }
    assert_eq!(stdout.depth(), 8);

    let mut output = Vec::new();
    drain_buffered(&stdout, &stdout_reader, &mut output);
    let terminal = loop {
        let poll = invocation.poll();
        drain_buffered(&stdout, &stdout_reader, &mut output);
        match poll {
            Preview1CorpusPoll::Pending { .. } => {}
            Preview1CorpusPoll::Ready(terminal) => break terminal,
        }
    };
    assert_eq!(terminal, Preview1CorpusTerminal::Exited(0));
    assert_eq!(output, vec![b'A'; 4_096]);
    assert_eq!(invocation.stdout_bytes(), 4_096);
}

#[test]
fn core_fuel_exhaustion_is_terminal_and_never_resumes_guest_code() {
    let mut fixture = Fixture::new(INFINITE_CORE);
    let candidate = fixture.admit().unwrap();
    let stdin = ByteStream::new();
    let stdout = ByteStream::new();
    let mut invocation = candidate
        .into_acceptance_invocation(Preview1CorpusInvocationInput::new(
            stdin.reader(),
            stdout.writer(),
            vec![],
        ))
        .unwrap();
    let mut pending_polls = 0_usize;
    loop {
        match invocation.poll() {
            Preview1CorpusPoll::Pending {
                reason: Preview1CorpusPending::Fuel,
                ..
            } => pending_polls += 1,
            Preview1CorpusPoll::Ready(Preview1CorpusTerminal::LimitExceeded) => break,
            other => panic!("unexpected infinite-loop result: {other:?}"),
        }
        assert!(pending_polls <= 20_000);
    }
    assert!(pending_polls > 0);
    assert_eq!(invocation.host_calls(), 0);
    assert_eq!(stdout.final_reason(), Some(StreamCloseReason::Exhausted));
    assert_eq!(
        invocation.poll(),
        Preview1CorpusPoll::Ready(Preview1CorpusTerminal::LimitExceeded)
    );
}

#[test]
fn low_fuel_host_work_fails_before_stream_effects_and_proc_exit_pays_dispatch() {
    // Four-argument fd imports pay five dispatch units and retain one unit for
    // the returning Core continuation. Leave exactly that post-dispatch unit:
    // the conservative handler debit must fail before touching either stream.
    let read_guest_fuel = guest_fuel_before_first_host(FIRST_FD_READ_CORE, TEST_HOST_FD_READ);
    let read_total = read_guest_fuel.checked_add(6).unwrap();
    let mut read_fixture = Fixture::new_with_total_fuel(FIRST_FD_READ_CORE, read_total);
    let read_candidate = read_fixture.admit().unwrap();
    let read_stdin = ByteStream::new();
    assert_eq!(
        read_stdin.writer().start(&[0x5a; 1_024]),
        Ok(StreamSendDispatch::Sent)
    );
    let read_stdout = ByteStream::new();
    let mut read_invocation = read_candidate
        .into_acceptance_invocation(Preview1CorpusInvocationInput::new(
            read_stdin.reader(),
            read_stdout.writer(),
            vec![],
        ))
        .unwrap();
    assert_eq!(
        poll_to_terminal(&mut read_invocation),
        Preview1CorpusTerminal::LimitExceeded
    );
    assert_eq!(read_invocation.host_calls(), 1);
    assert_eq!(read_invocation.stdin_bytes(), 0);
    assert_eq!(read_invocation.stdout_bytes(), 0);
    assert_eq!(read_stdout.depth(), 0);
    assert_eq!(
        read_stdout.final_reason(),
        Some(StreamCloseReason::Exhausted)
    );
    let read_metrics = read_invocation.metrics().unwrap();
    assert_eq!(
        read_metrics.consumed_fuel + read_metrics.remaining_fuel,
        read_total
    );
    assert_eq!(read_metrics.remaining_fuel, 1);

    let write_guest_fuel = guest_fuel_before_first_host(FIRST_FD_WRITE_CORE, TEST_HOST_FD_WRITE);
    let write_total = write_guest_fuel.checked_add(6).unwrap();
    let mut write_fixture = Fixture::new_with_total_fuel(FIRST_FD_WRITE_CORE, write_total);
    let write_candidate = write_fixture.admit().unwrap();
    let write_stdin = ByteStream::new();
    let write_stdout = ByteStream::new();
    let mut write_invocation = write_candidate
        .into_acceptance_invocation(Preview1CorpusInvocationInput::new(
            write_stdin.reader(),
            write_stdout.writer(),
            vec![],
        ))
        .unwrap();
    assert_eq!(
        poll_to_terminal(&mut write_invocation),
        Preview1CorpusTerminal::LimitExceeded
    );
    assert_eq!(write_invocation.host_calls(), 1);
    assert_eq!(write_invocation.stdin_bytes(), 0);
    assert_eq!(write_invocation.stdout_bytes(), 0);
    assert_eq!(write_stdout.depth(), 0);
    assert_eq!(
        write_stdout.final_reason(),
        Some(StreamCloseReason::Exhausted)
    );
    let write_metrics = write_invocation.metrics().unwrap();
    assert_eq!(
        write_metrics.consumed_fuel + write_metrics.remaining_fuel,
        write_total
    );
    assert_eq!(write_metrics.remaining_fuel, 1);

    // proc_exit never returns to Core, so it pays its two dispatch units but
    // does not reserve continuation fuel. One unit short fails atomically;
    // the exact budget exits with zero fuel remaining.
    let exit_guest_fuel = guest_fuel_before_first_host(COMPLETE_C_ORDER_CORE, TEST_HOST_PROC_EXIT);
    let insufficient_exit_total = exit_guest_fuel.checked_add(1).unwrap();
    let mut insufficient_fixture =
        Fixture::new_with_total_fuel(COMPLETE_C_ORDER_CORE, insufficient_exit_total);
    let candidate = insufficient_fixture.admit().unwrap();
    let stdin = ByteStream::new();
    let stdout = ByteStream::new();
    let mut invocation = candidate
        .into_acceptance_invocation(Preview1CorpusInvocationInput::new(
            stdin.reader(),
            stdout.writer(),
            vec![],
        ))
        .unwrap();
    assert_eq!(
        poll_to_terminal(&mut invocation),
        Preview1CorpusTerminal::LimitExceeded
    );
    assert_eq!(invocation.host_calls(), 0);
    assert_eq!(invocation.metrics().unwrap().remaining_fuel, 1);

    let exact_exit_total = exit_guest_fuel.checked_add(2).unwrap();
    let mut exact_fixture = Fixture::new_with_total_fuel(COMPLETE_C_ORDER_CORE, exact_exit_total);
    let candidate = exact_fixture.admit().unwrap();
    let stdin = ByteStream::new();
    let stdout = ByteStream::new();
    let mut invocation = candidate
        .into_acceptance_invocation(Preview1CorpusInvocationInput::new(
            stdin.reader(),
            stdout.writer(),
            vec![],
        ))
        .unwrap();
    assert_eq!(
        poll_to_terminal(&mut invocation),
        Preview1CorpusTerminal::Exited(0)
    );
    assert_eq!(invocation.host_calls(), 1);
    let exact_metrics = invocation.metrics().unwrap();
    assert_eq!(
        exact_metrics.consumed_fuel + exact_metrics.remaining_fuel,
        exact_exit_total
    );
    assert_eq!(exact_metrics.remaining_fuel, 0);
}

#[test]
fn only_fd_zero_and_one_exist_and_iovec_limit_is_terminal() {
    let mut bad_fd_fixture = Fixture::new(BAD_FD_CORE);
    let candidate = bad_fd_fixture.admit().unwrap();
    let stdin = ByteStream::new();
    let stdout = ByteStream::new();
    let mut invocation = candidate
        .into_acceptance_invocation(Preview1CorpusInvocationInput::new(
            stdin.reader(),
            stdout.writer(),
            vec![],
        ))
        .unwrap();
    assert_eq!(
        poll_to_terminal(&mut invocation),
        Preview1CorpusTerminal::Exited(0)
    );
    assert_eq!(invocation.host_calls(), 3);
    assert_eq!(invocation.stdin_bytes(), 0);
    assert_eq!(invocation.stdout_bytes(), 0);

    let mut iovec_fixture = Fixture::new(IOVEC_LIMIT_CORE);
    iovec_fixture.max_iovecs = 1;
    let candidate = iovec_fixture.admit().unwrap();
    let stdin = ByteStream::new();
    let stdout = ByteStream::new();
    let mut invocation = candidate
        .into_acceptance_invocation(Preview1CorpusInvocationInput::new(
            stdin.reader(),
            stdout.writer(),
            vec![],
        ))
        .unwrap();
    assert_eq!(
        poll_to_terminal(&mut invocation),
        Preview1CorpusTerminal::LimitExceeded
    );
    assert_eq!(invocation.host_calls(), 1);
}

fn run_real_case(
    program: RealProgram,
    mode: &str,
    input_bytes: &[u8],
) -> (Preview1CorpusTerminal, Vec<u8>) {
    let candidate = real_candidate(program);
    assert!(!candidate.runtime_ready());
    let stdin = ByteStream::new();
    let stdin_writer = stdin.writer();
    for chunk in input_bytes.chunks(1_024) {
        assert_eq!(stdin_writer.start(chunk), Ok(StreamSendDispatch::Sent));
    }
    stdin_writer.close(StreamCloseReason::Normal);
    stdin.supervisor().finalize(StreamCloseReason::Normal);

    let stdout = ByteStream::new();
    let stdout_reader = stdout.reader();
    let mut invocation = candidate
        .into_acceptance_invocation(Preview1CorpusInvocationInput::new(
            stdin.reader(),
            stdout.writer(),
            vec![mode.into()],
        ))
        .unwrap();
    let mut output = Vec::new();
    let terminal = loop {
        let poll = invocation.poll();
        drain_buffered(&stdout, &stdout_reader, &mut output);
        match poll {
            Preview1CorpusPoll::Pending { metrics, .. } => {
                assert_eq!(metrics.consumed_fuel + metrics.remaining_fuel, 2_000_000);
            }
            Preview1CorpusPoll::Ready(terminal) => break terminal,
        }
    };
    assert!(invocation.host_calls() <= 64);
    assert!(invocation.stdin_bytes() <= 4_097);
    assert!(invocation.stdout_bytes() <= 4_096);
    (terminal, output)
}

fn poll_to_terminal(
    invocation: &mut vibeos_component_admission::Preview1CorpusInvocation,
) -> Preview1CorpusTerminal {
    loop {
        match invocation.poll() {
            Preview1CorpusPoll::Pending { .. } => {}
            Preview1CorpusPoll::Ready(terminal) => return terminal,
        }
    }
}

fn guest_fuel_before_first_host(core_wat: &str, expected_host: u32) -> u64 {
    let compiler_core = wat::parse_str(core_wat).unwrap();
    let transformed = componentize_corpus_core(&compiler_core, ADAPTER).unwrap();
    let validated = ValidatedCore::new(
        transformed.sanitized_core().bytes(),
        OwnerAllocationReservation::profile_default(),
    )
    .unwrap();
    let mut instance = validated
        .instantiate_with_imports(&TEST_HOST_IMPORTS)
        .unwrap();
    let total_fuel = 1_000_000;
    instance.start_call("_start", &[], total_fuel, 100).unwrap();
    loop {
        match instance.poll_call() {
            PollResult::Pending { .. } => {}
            PollResult::HostCall(call) => {
                assert_eq!(call.id, expected_host);
                let metrics = instance.call_metrics().unwrap();
                assert_eq!(metrics.consumed_fuel + metrics.remaining_fuel, total_fuel);
                assert!(metrics.consumed_fuel > 0);
                return metrics.consumed_fuel;
            }
            other => panic!("expected first host call {expected_host}, got {other:?}"),
        }
    }
}

fn real_candidate(
    program: RealProgram,
) -> vibeos_component_admission::AdmittedPreview1CorpusCandidate {
    real_candidate_with_limits(program, 257, 64)
}

fn real_candidate_with_limits(
    program: RealProgram,
    max_io_bytes_per_call: u32,
    max_host_calls: u32,
) -> vibeos_component_admission::AdmittedPreview1CorpusCandidate {
    let (cmp1, artifact_commitment, module_specs) = match program {
        RealProgram::Rust => (
            RUST_CMP1,
            "6f94afb3bb90498cca67a3f3559b44e717fbafaaeaf2a78e26b18b593037aef0",
            [
                (
                    949,
                    "631e8a7be7af1e24caddaf3f2b16d6e194efe4111d3afce6c2db16ea16917195",
                ),
                (
                    12_442,
                    "555bbb11ac448f46fa05d5302db203d07ed5ce71f74da580fdc7155d6611fe5e",
                ),
                (
                    478,
                    "6805d8e030d86c1ceaf4261e433c2776e36b17afa98d4b5f35fb469e13cfb98d",
                ),
                (
                    249,
                    "e42434400e3b36f97356cf404910cd1979ac88a09924b4c9550728ab76b8a1c1",
                ),
            ],
        ),
        RealProgram::C => (
            C_CMP1,
            "386790cbef9aca7c8745c99acac8ae2c265da8502393dc949ab49cbd91fb554c",
            [
                (
                    1_176,
                    "cc5c7931e9c29d1fbc86f00fe4bace65ac8f6b46f29d154016137eb189d0ce4d",
                ),
                (
                    12_442,
                    "555bbb11ac448f46fa05d5302db203d07ed5ce71f74da580fdc7155d6611fe5e",
                ),
                (
                    478,
                    "5577039daa5cc20251e33bff1d1b4e660a255b0183d3263b8f18680234218371",
                ),
                (
                    249,
                    "d3e532ac157520c4bc92f6dde4a3e0df4581f62f3815ac691d6c395fd3db1d18",
                ),
            ],
        ),
    };
    let artifact = ComponentArtifactV1::decode(cmp1).unwrap();
    assert_eq!(
        artifact.artifact_commitment().unwrap().as_bytes(),
        &hex32(artifact_commitment)
    );
    let modules = module_specs.map(|(byte_len, digest)| Preview1WrappedCoreModulePin {
        byte_len,
        sha256: hex32(digest),
    });
    let entities = reviewed_real_entities();
    let policy = Preview1CorpusAdmissionPolicy {
        artifact_commitment: hex32(artifact_commitment),
        external_policy_digest: hex32(
            "5e002e1369c92253296e25abaf58f765e19b644196d125d5ea46aab783997158",
        ),
        command_name: "c82-ascii-filter",
        adapter_revision: PREVIEW1_WRAPPED_ADAPTER_REVISION,
        adapter_embedded_module_ordinal: 1,
        adapter_asset_byte_len: 51_828,
        adapter_asset_sha256: hex32(
            "316dfbf171591d69ae414efd13b85933ca13526af8d9e0a735ab88ae08fd85f0",
        ),
        guest_module_ordinal: 0,
        guest_module_byte_len: modules[0].byte_len,
        guest_module_sha256: modules[0].sha256,
        embedded_modules: &modules,
        top_level_entities: &entities,
        canonical_lowering_sha256: hex32(
            "c369a1b3e12d9d1e2c0c2716496a64912ba5786f9066864fc0d468eeb3820710",
        ),
        canonical_lowering_count: 18,
        nested_component_count: 1,
        max_arguments: 2,
        max_argument_bytes: 64,
        max_iovecs: 1,
        max_io_bytes_per_call,
        max_stdin_bytes: 4_097,
        max_stdout_bytes: 4_096,
        max_host_calls,
    };
    admit_preview1_corpus_candidate(artifact, &policy).unwrap()
}

fn reviewed_real_entities() -> Vec<Preview1WrappedTopLevelEntityPin<'static>> {
    use Preview1WrappedEntityDirection::{Export, Import};
    vec![
        real_entity(
            Import,
            "wasi:cli/environment@0.2.12",
            "f50c324187f7f874e62dbd92dd9a4e36da0dab7125535ea9c68ba14129c0bb1a",
        ),
        real_entity(
            Import,
            "wasi:cli/exit@0.2.12",
            "31341d2791b54d10618ae75fbea7c4cd62332d182949aa9f1f34727e480fb3a9",
        ),
        real_entity(
            Import,
            "wasi:cli/stderr@0.2.12",
            "0e79fcc93c0fd2085521539f967723836d6009af3fd6cbbcacd5764445c840dc",
        ),
        real_entity(
            Import,
            "wasi:cli/stdin@0.2.12",
            "e23d2c01fe8d328e7ac1a68f2fae3a29aa4bc0f6ad9b897946f7cf6f1b2ff7c2",
        ),
        real_entity(
            Import,
            "wasi:cli/stdout@0.2.12",
            "a8538002a6ae4a200e4f7d4f5f59e421798f40af522eb3f4b7a61c9b82967252",
        ),
        real_entity(
            Import,
            "wasi:clocks/wall-clock@0.2.12",
            "91c40063026581249faa8b7cd2bff0b678f98797b63d457a5d297719a5601267",
        ),
        real_entity(
            Import,
            "wasi:filesystem/preopens@0.2.12",
            "cf72736292af0d2d9b805ce91fa3cc4e0e977130a87e38414db5b9c02166fd41",
        ),
        real_entity(
            Import,
            "wasi:filesystem/types@0.2.12",
            "2db3e681fb6977d94685e68e6dea5c326101c5c855f8a41252d1cbb4af559590",
        ),
        real_entity(
            Import,
            "wasi:io/error@0.2.12",
            "10869b485aec6a494ac45728b82614a9009e7bbf5fcc95d58b7d86de2f9f6cc5",
        ),
        real_entity(
            Import,
            "wasi:io/streams@0.2.12",
            "f510f599ed7e7115e3dbedd5f06e5fd821a52e467add451ce58bcbc83fbba0a9",
        ),
        real_entity(
            Export,
            "wasi:cli/run@0.2.12",
            "08b0fcdf6c81924f182b7781ded22bdb98e4cab91d2a23a9933cdbb875a0f99a",
        ),
    ]
}

fn real_entity(
    direction: Preview1WrappedEntityDirection,
    name: &'static str,
    digest: &str,
) -> Preview1WrappedTopLevelEntityPin<'static> {
    Preview1WrappedTopLevelEntityPin {
        direction,
        kind: Preview1WrappedEntityKind::Instance,
        name,
        raw_entry_sha256: hex32(digest),
    }
}

fn hex32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut result = [0_u8; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    result
}

fn static_component_name(value: &str) -> &'static str {
    match value {
        "wasi:cli/environment@0.2.12" => "wasi:cli/environment@0.2.12",
        "wasi:cli/exit@0.2.12" => "wasi:cli/exit@0.2.12",
        "wasi:cli/stderr@0.2.12" => "wasi:cli/stderr@0.2.12",
        "wasi:cli/stdin@0.2.12" => "wasi:cli/stdin@0.2.12",
        "wasi:cli/stdout@0.2.12" => "wasi:cli/stdout@0.2.12",
        "wasi:clocks/wall-clock@0.2.12" => "wasi:clocks/wall-clock@0.2.12",
        "wasi:filesystem/preopens@0.2.12" => "wasi:filesystem/preopens@0.2.12",
        "wasi:filesystem/types@0.2.12" => "wasi:filesystem/types@0.2.12",
        "wasi:io/error@0.2.12" => "wasi:io/error@0.2.12",
        "wasi:io/streams@0.2.12" => "wasi:io/streams@0.2.12",
        "wasi:cli/run@0.2.12" => "wasi:cli/run@0.2.12",
        unexpected => panic!("unexpected component surface entry {unexpected}"),
    }
}

fn embedded_modules(component: &[u8]) -> Vec<&[u8]> {
    Parser::new(0)
        .parse_all(component)
        .filter_map(|payload| match payload.unwrap() {
            Payload::ModuleSection {
                unchecked_range, ..
            } => Some(&component[unchecked_range]),
            _ => None,
        })
        .collect()
}

fn raw_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn drain_buffered(stream: &Arc<ByteStream>, reader: &ByteStreamReader, output: &mut Vec<u8>) {
    while stream.depth() > 0 {
        let StreamReceiveDispatch::Prepared(prepared) = reader.start().unwrap() else {
            panic!("non-empty stream must prepare its front chunk")
        };
        let offset = output.len();
        output.resize(offset + prepared.length(), 0);
        assert_eq!(
            reader
                .commit(prepared.operation(), &mut output[offset..])
                .unwrap(),
            StreamReceiveCommit::Received(prepared.length())
        );
    }
}
