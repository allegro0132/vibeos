use dlr_wasm_interpreter::{
    decode_and_validate, ExternVal, InstantiationOutcome, ModuleAddr, RuntimeError as DlrError,
    Store as DlrStore, Value as DlrValue,
};
use sha2::{Digest, Sha256};
use vibeos_component_format::{TrapCode, PROFILE_1_LIMITS};
use vibeos_wasm_runtime::{
    CoreInstance, CoreValue, OwnerAllocationReservation, PollResult, ValidatedCore,
};
use wast::{
    core::{WastArgCore, WastRetCore},
    parser::{self, ParseBuffer},
    Wast, WastArg, WastDirective, WastExecute, WastInvoke, WastRet,
};

const FAC_SOURCE: &str = include_str!("spec/core-wg-1.0/fac.wast");
const SPEC_LICENSE: &[u8] = include_bytes!("spec/core-wg-1.0/LICENSE");

const FAC_SHA256: [u8; 32] = [
    0x7b, 0xf2, 0x7b, 0x09, 0x0f, 0x65, 0x33, 0x86, 0x5a, 0xcc, 0x79, 0xa3, 0x7e, 0x03, 0x31, 0xb2,
    0x7f, 0xa1, 0x1d, 0x7a, 0x3a, 0xb2, 0x7b, 0x02, 0xe3, 0x2e, 0x2e, 0xfd, 0xdf, 0xb4, 0x05, 0xe7,
];
const LICENSE_SHA256: [u8; 32] = [
    0xc6, 0x59, 0x6e, 0xb7, 0xbe, 0x85, 0x81, 0xc1, 0x8b, 0xe7, 0x36, 0xc8, 0x46, 0xfb, 0x91, 0x73,
    0xb6, 0x9e, 0xcc, 0xf6, 0xef, 0x94, 0xc5, 0x13, 0x58, 0x93, 0xec, 0x56, 0xbd, 0x92, 0xba, 0x08,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IntegerValue {
    I32(i32),
    I64(i64),
}

impl IntegerValue {
    const fn into_core(self) -> CoreValue {
        match self {
            Self::I32(value) => CoreValue::I32(value),
            Self::I64(value) => CoreValue::I64(value),
        }
    }

    const fn into_dlr(self) -> DlrValue {
        match self {
            Self::I32(value) => DlrValue::I32(value as u32),
            Self::I64(value) => DlrValue::I64(value as u64),
        }
    }
}

fn assert_sha256(label: &str, bytes: &[u8], expected: [u8; 32]) {
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    assert_eq!(
        actual, expected,
        "{label} bytes drifted from the pinned source"
    );
}

fn normalize_arg(arg: &WastArg<'_>) -> IntegerValue {
    match arg {
        WastArg::Core(WastArgCore::I32(value)) => IntegerValue::I32(*value),
        WastArg::Core(WastArgCore::I64(value)) => IntegerValue::I64(*value),
        other => panic!("unsupported official Core argument: {other:?}"),
    }
}

fn normalize_expected(result: &WastRet<'_>) -> IntegerValue {
    match result {
        WastRet::Core(WastRetCore::I32(value)) => IntegerValue::I32(*value),
        WastRet::Core(WastRetCore::I64(value)) => IntegerValue::I64(*value),
        other => panic!("unsupported official Core result: {other:?}"),
    }
}

fn normalize_core(value: &CoreValue) -> IntegerValue {
    match value {
        CoreValue::I32(value) => IntegerValue::I32(*value),
        CoreValue::I64(value) => IntegerValue::I64(*value),
    }
}

fn normalize_dlr(value: &DlrValue) -> IntegerValue {
    match value {
        DlrValue::I32(value) => IntegerValue::I32(*value as i32),
        DlrValue::I64(value) => IntegerValue::I64(*value as i64),
        other => panic!("reference runtime returned a disabled value: {other:?}"),
    }
}

fn invocation_args(invoke: &WastInvoke<'_>) -> Vec<IntegerValue> {
    assert!(
        invoke.module.is_none(),
        "selected fixture must invoke the current anonymous module"
    );
    invoke.args.iter().map(normalize_arg).collect()
}

fn run_selected(
    instance: &mut CoreInstance,
    export: &str,
    arguments: &[IntegerValue],
) -> Result<Vec<IntegerValue>, TrapCode> {
    let arguments = arguments
        .iter()
        .copied()
        .map(IntegerValue::into_core)
        .collect::<Vec<_>>();
    instance
        .start_call(
            export,
            &arguments,
            PROFILE_1_LIMITS.total_fuel,
            PROFILE_1_LIMITS.poll_quantum,
        )
        .unwrap_or_else(|trap| panic!("failed to start official invocation {export:?}: {trap:?}"));

    let max_polls = PROFILE_1_LIMITS
        .total_fuel
        .div_ceil(PROFILE_1_LIMITS.poll_quantum)
        .saturating_add(1);
    for _ in 0..max_polls {
        match instance.poll_call() {
            PollResult::Pending { .. } => {}
            PollResult::Ready(values) => {
                return Ok(values.iter().map(normalize_core).collect());
            }
            PollResult::Trapped(trap) => return Err(trap),
            PollResult::HostCall(call) => {
                panic!("official closed fixture reached a host call: {call:?}")
            }
        }
    }
    panic!("official invocation {export:?} exceeded its fuel-derived poll bound");
}

fn run_dlr(
    store: &mut DlrStore<()>,
    module: ModuleAddr,
    export_name: &str,
    arguments: &[IntegerValue],
) -> Result<Vec<IntegerValue>, DlrError> {
    // SAFETY: `module` was returned by this exact store and remains live for
    // the duration of every invocation in this script.
    let export: ExternVal =
        unsafe { store.instance_export(module, export_name) }.unwrap_or_else(|error| {
            panic!("reference export {export_name:?} lookup failed: {error:?}")
        });
    let function = export
        .as_func()
        .unwrap_or_else(|| panic!("reference export {export_name:?} is not a function"));
    let arguments = arguments
        .iter()
        .copied()
        .map(IntegerValue::into_dlr)
        .collect::<Vec<_>>();
    // SAFETY: `function` belongs to this exact store. The fixture accepts only
    // integer parameters, so no address-bearing DLR value crosses stores.
    unsafe { store.invoke_simple(function, arguments) }
        .map(|values| values.iter().map(normalize_dlr).collect())
}

#[test]
fn official_core_fixture_and_license_match_the_pinned_bytes() {
    assert_eq!(FAC_SOURCE.len(), 2_602);
    assert_eq!(SPEC_LICENSE.len(), 11_358);
    assert_sha256("official fac.wast", FAC_SOURCE.as_bytes(), FAC_SHA256);
    assert_sha256("official test license", SPEC_LICENSE, LICENSE_SHA256);
}

#[test]
fn official_factorial_script_matches_vibe_and_the_pinned_reference_runtime() {
    let buffer = ParseBuffer::new(FAC_SOURCE).expect("pinned official WAST must lex");
    let script = parser::parse::<Wast<'_>>(&buffer).expect("pinned official WAST must parse");
    let mut directives = script.directives.into_iter();

    let first = directives
        .next()
        .expect("official factorial script must define its module first");
    let WastDirective::Module(mut module) = first else {
        panic!("official factorial script did not start with a module: {first:?}");
    };
    assert!(
        module.name().is_none(),
        "selected official module must remain anonymous"
    );
    let bytes = module
        .encode()
        .expect("official factorial module must encode");

    let selected = ValidatedCore::new(&bytes, OwnerAllocationReservation::profile_default())
        .expect("official factorial module must satisfy Profile 1");
    let summary = selected.summary();
    assert_eq!(summary.functions, 5);
    assert_eq!(summary.exports, 5);
    assert_eq!(summary.imports, 0);
    assert_eq!(summary.memories, 0);
    assert_eq!(summary.tables, 0);
    let mut selected_instance = selected
        .instantiate()
        .expect("official factorial module must instantiate");

    let decoded = decode_and_validate(&bytes, &mut ())
        .expect("reference runtime must validate the accepted official module");
    let mut dlr_store = DlrStore::new(());
    // SAFETY: the pinned fixture has no imports. The decoded module is used
    // only to instantiate into this store, which owns the returned address.
    let InstantiationOutcome {
        module_addr: dlr_module,
        ..
    } = unsafe { dlr_store.module_instantiate(&decoded, Vec::new(), None) }
        .expect("reference runtime must instantiate the accepted official module");

    let mut return_count = 0_u32;
    let mut exhaustion_count = 0_u32;
    for directive in directives {
        match directive {
            WastDirective::AssertReturn { exec, results, .. } => {
                return_count += 1;
                let WastExecute::Invoke(invoke) = exec else {
                    panic!("official return assertion was not an invocation: {exec:?}");
                };
                let arguments = invocation_args(&invoke);
                let expected = results.iter().map(normalize_expected).collect::<Vec<_>>();

                let vibe = run_selected(&mut selected_instance, invoke.name, &arguments)
                    .unwrap_or_else(|trap| {
                        panic!(
                            "Vibe trapped for official return {0:?}: {trap:?}",
                            invoke.name
                        )
                    });
                let dlr = run_dlr(&mut dlr_store, dlr_module, invoke.name, &arguments)
                    .unwrap_or_else(|error| {
                        panic!(
                            "reference runtime trapped for official return {0:?}: {error:?}",
                            invoke.name
                        )
                    });

                assert_eq!(vibe, expected, "Vibe disagreed with the official result");
                assert_eq!(
                    dlr, expected,
                    "reference disagreed with the official result"
                );
                assert_eq!(vibe, dlr, "Vibe and reference runtime diverged");
            }
            WastDirective::AssertExhaustion { call, message, .. } => {
                exhaustion_count += 1;
                assert_eq!(message, "call stack exhausted");
                let arguments = invocation_args(&call);

                assert_eq!(
                    run_selected(&mut selected_instance, call.name, &arguments),
                    Err(TrapCode::CallDepthExceeded),
                    "official exhaustion must reach the stable Profile-1 call-depth trap"
                );
                assert_eq!(
                    run_dlr(&mut dlr_store, dlr_module, call.name, &arguments),
                    Err(DlrError::StackExhaustion),
                    "reference runtime must classify the official action as exhaustion"
                );
            }
            other => panic!("unsupported directive in selected official script: {other:?}"),
        }
    }

    assert_eq!(return_count, 5, "not every official return assertion ran");
    assert_eq!(
        exhaustion_count, 1,
        "not every official exhaustion assertion ran"
    );
}
