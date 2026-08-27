//! Host-only C2.7 interoperability evidence for the C2.3 language fixtures.
//!
//! Vibe remains the admission authority. Pinned Wasmtime is used only as an
//! independent Component Model execution reference for bytes which Vibe has
//! already admitted against the exact world. See `reference/PROVENANCE.md`.

use core::fmt::Write as _;

use vibeos_component_format::{ComponentGraphVersionComponentIdentity, TrapCode};
use vibeos_component_runtime::{
    decode::inspect_component,
    resource::ResourceTable,
    sync::{SynchronousComponent, TypedCall, TypedPoll},
    value::CanonicalValue,
    world::WorldContract,
};
use vibeos_wasm_runtime::{inspect_core, OwnerAllocationReservation, ProfileEngine};
use wasm_encoder::{
    CanonicalOption, ComponentBuilder, ComponentExportKind, ComponentExportSection,
    ComponentInstanceSection, ComponentSection, ComponentValType, ExportKind, ModuleArg,
    PrimitiveValType,
};
use wasmtime::component::{Component as ReferenceComponent, Linker as ReferenceLinker, Val};
use wasmtime::{Config, Engine, Store};

const WIT: &str = include_str!("../../component-format/tests/corpus/wit/canonical-values.wit");
const RUST_CORE: &[u8] = include_bytes!("fixtures/language/canonical-values-rust.core.wasm");
const C_CORE: &[u8] = include_bytes!("fixtures/language/canonical-values-c.core.wasm");

const EXACT_WORLD: &str = "vibe:fixture/canonical-language@1.0.0";
const INTERFACE: &str = "vibe:fixture/canonical-values@1.0.0";
const TRANSFORM: &str = "vibe:fixture/canonical-values@1.0.0#transform";
const TOTAL_WORK: u64 = 1_000_000;
const POLL_QUANTUM: u64 = 10_000;
const MAX_POLLS: usize = 101;
const REFERENCE_FUEL: u64 = 10_000_000;

const FIXTURE_COUNT: usize = 2;
const CASE_COUNT: usize = 4;
const EXPECTED_EXECUTIONS_PER_ENGINE: usize = FIXTURE_COUNT * CASE_COUNT;
const AGGREGATE_DYNAMIC_BYTES: usize = 276;
const CORPUS_FNV1A64: u64 = 0x5a3e_5d03_338a_9be3;

const RUST_CORE_BYTES: usize = 557;
const RUST_CORE_SHA256: &str = "79e1eb3f2043c4ae224da6057279f80f32ec171106ad2112e8f7d2bf62e96f52";
const RUST_COMPONENT_BYTES: usize = 950;
const RUST_COMPONENT_SHA256: &str =
    "1826aef365bbc0c1061bd8f23eaea5883ed052220f711243cd7c29c335975cfe";
const C_CORE_BYTES: usize = 1_030;
const C_CORE_SHA256: &str = "20e26c154f2fc3d0892a2175dd85912ea2df77ff43e22200864eba7e6d3f7e8e";
const C_COMPONENT_BYTES: usize = 1_423;
const C_COMPONENT_SHA256: &str = "2ee8f6154c6069d46d726e922a1d07979982d022dd8c02e035dcd244a9248b78";

#[derive(Clone, Copy)]
enum Outcome {
    Ok(u32),
    Err(u8),
}

struct Case {
    tag: u8,
    truth: bool,
    signed: i32,
    wide: u64,
    symbol: char,
    label: &'static str,
    payload: Vec<u8>,
    attributes: u32,
    maybe: Option<u16>,
    outcome: Outcome,
}

struct Fixture<'a> {
    name: &'static str,
    core: &'a [u8],
    core_bytes: usize,
    core_sha256: &'static str,
    component_bytes: usize,
    component_sha256: &'static str,
    resource_generation: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct NeutralFlags {
    urgent: bool,
    audited: bool,
    traced: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum NeutralOutcome {
    Ok(u32),
    Err(u8),
}

#[derive(Debug, PartialEq, Eq)]
struct NeutralRequest {
    truth: bool,
    signed: i32,
    wide: u64,
    symbol: char,
    label: String,
    payload: Vec<u8>,
    attributes: NeutralFlags,
    maybe: Option<u16>,
    outcome: NeutralOutcome,
}

#[derive(Debug, PartialEq, Eq)]
enum NeutralErrorCode {
    Denied,
    Invalid,
    Exhausted,
}

#[derive(Debug, PartialEq, Eq)]
enum NeutralResponse {
    Accepted(NeutralRequest, NeutralErrorCode),
    Rejected(NeutralErrorCode),
}

fn component_from_core(core: &[u8]) -> Vec<u8> {
    let mut builder = ComponentBuilder::default();
    let module = builder.core_module_raw(Some("language-guest"), core);
    let instance = builder.core_instantiate(
        Some("language-guest-instance"),
        module,
        core::iter::empty::<(&str, ModuleArg)>(),
    );
    let memory = builder.core_alias_export(Some("memory"), instance, "memory", ExportKind::Memory);
    let realloc = builder.core_alias_export(
        Some("cabi_realloc"),
        instance,
        "cabi_realloc",
        ExportKind::Func,
    );
    let transform =
        builder.core_alias_export(Some("transform"), instance, "transform", ExportKind::Func);
    let post_return = builder.core_alias_export(
        Some("cabi_post_transform"),
        instance,
        "cabi_post_transform",
        ExportKind::Func,
    );

    let (attributes, ty) = builder.type_defined(Some("attributes"));
    ty.flags(["urgent", "audited", "traced"]);

    let (error_code, ty) = builder.type_defined(Some("error-code"));
    ty.enum_type(["denied", "invalid", "exhausted"]);

    let (bytes, ty) = builder.type_defined(Some("bytes"));
    ty.list(PrimitiveValType::U8);

    let (maybe, ty) = builder.type_defined(Some("maybe"));
    ty.option(PrimitiveValType::U16);

    let (outcome, ty) = builder.type_defined(Some("outcome"));
    ty.result(
        Some(PrimitiveValType::U32.into()),
        Some(PrimitiveValType::U8.into()),
    );

    let (request, ty) = builder.type_defined(Some("request"));
    ty.record([
        ("truth", ComponentValType::Primitive(PrimitiveValType::Bool)),
        ("signed", ComponentValType::Primitive(PrimitiveValType::S32)),
        ("wide", ComponentValType::Primitive(PrimitiveValType::U64)),
        (
            "symbol",
            ComponentValType::Primitive(PrimitiveValType::Char),
        ),
        (
            "label",
            ComponentValType::Primitive(PrimitiveValType::String),
        ),
        ("payload", ComponentValType::Type(bytes)),
        ("attributes", ComponentValType::Type(attributes)),
        ("maybe", ComponentValType::Type(maybe)),
        ("outcome", ComponentValType::Type(outcome)),
    ]);

    let (accepted, ty) = builder.type_defined(Some("accepted"));
    ty.tuple([
        ComponentValType::Type(request),
        ComponentValType::Type(error_code),
    ]);

    let (response, ty) = builder.type_defined(Some("response"));
    ty.variant([
        ("accepted", Some(ComponentValType::Type(accepted))),
        ("rejected", Some(ComponentValType::Type(error_code))),
    ]);

    let (function_type, mut ty) = builder.type_function(Some("transform-type"));
    ty.params([("value", ComponentValType::Type(request))])
        .result(Some(ComponentValType::Type(response)));

    let lifted = builder.lift_func(
        Some("lifted-transform"),
        transform,
        function_type,
        [
            CanonicalOption::UTF8,
            CanonicalOption::Memory(memory),
            CanonicalOption::Realloc(realloc),
            CanonicalOption::PostReturn(post_return),
        ],
    );

    let mut bytes = builder.finish();
    let mut instances = ComponentInstanceSection::new();
    instances.export_items([
        ("attributes", ComponentExportKind::Type, attributes),
        ("error-code", ComponentExportKind::Type, error_code),
        ("request", ComponentExportKind::Type, request),
        ("response", ComponentExportKind::Type, response),
        ("transform", ComponentExportKind::Func, lifted),
    ]);
    instances.append_to_component(&mut bytes);

    let mut exports = ComponentExportSection::new();
    exports.export(INTERFACE, ComponentExportKind::Instance, 0, None);
    exports.append_to_component(&mut bytes);
    bytes
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            tag: 0,
            truth: true,
            signed: i32::MIN,
            wide: 0,
            symbol: '\0',
            label: "",
            payload: Vec::new(),
            attributes: 0,
            maybe: None,
            outcome: Outcome::Ok(0),
        },
        Case {
            tag: 1,
            truth: true,
            signed: i32::MAX,
            wide: u64::MAX,
            symbol: '\u{10ffff}',
            label: "λ界🙂",
            payload: (0_u16..=255).map(|byte| byte as u8).collect(),
            attributes: 0b111,
            maybe: Some(u16::MAX),
            outcome: Outcome::Err(u8::MAX),
        },
        Case {
            tag: 2,
            truth: false,
            signed: -1,
            wide: 1,
            symbol: 'A',
            label: "",
            payload: Vec::new(),
            attributes: 0b001,
            maybe: Some(0),
            outcome: Outcome::Ok(u32::MAX),
        },
        Case {
            tag: 3,
            truth: false,
            signed: 0,
            wide: 1_u64 << 63,
            symbol: '界',
            label: "résumé",
            payload: vec![0, 0x7f, 0xff],
            attributes: 0b110,
            maybe: None,
            outcome: Outcome::Err(0),
        },
    ]
}

fn neutral_flags_from_bits(bits: u32) -> NeutralFlags {
    assert_eq!(bits & !0b111, 0, "unknown fixture attribute bits");
    NeutralFlags {
        urgent: bits & 0b001 != 0,
        audited: bits & 0b010 != 0,
        traced: bits & 0b100 != 0,
    }
}

fn neutral_expected(case: &Case) -> NeutralResponse {
    if case.truth {
        NeutralResponse::Accepted(
            NeutralRequest {
                truth: case.truth,
                signed: case.signed,
                wide: case.wide,
                symbol: case.symbol,
                label: case.label.to_owned(),
                payload: case.payload.clone(),
                attributes: neutral_flags_from_bits(case.attributes),
                maybe: case.maybe,
                outcome: match case.outcome {
                    Outcome::Ok(value) => NeutralOutcome::Ok(value),
                    Outcome::Err(value) => NeutralOutcome::Err(value),
                },
            },
            NeutralErrorCode::Invalid,
        )
    } else {
        NeutralResponse::Rejected(NeutralErrorCode::Denied)
    }
}

fn vibe_request(case: &Case) -> CanonicalValue {
    CanonicalValue::Record(vec![
        CanonicalValue::Bool(case.truth),
        CanonicalValue::S32(case.signed),
        CanonicalValue::U64(case.wide),
        CanonicalValue::Char(case.symbol),
        CanonicalValue::String(case.label.to_owned()),
        CanonicalValue::List(
            case.payload
                .iter()
                .copied()
                .map(CanonicalValue::U8)
                .collect(),
        ),
        CanonicalValue::Flags(vec![case.attributes]),
        CanonicalValue::Option(case.maybe.map(|value| Box::new(CanonicalValue::U16(value)))),
        CanonicalValue::Result(match case.outcome {
            Outcome::Ok(value) => Ok(Some(Box::new(CanonicalValue::U32(value)))),
            Outcome::Err(value) => Err(Some(Box::new(CanonicalValue::U8(value)))),
        }),
    ])
}

fn reference_flag_names(bits: u32) -> Vec<String> {
    assert_eq!(bits & !0b111, 0, "unknown fixture attribute bits");
    [(0b001, "urgent"), (0b010, "audited"), (0b100, "traced")]
        .into_iter()
        .filter(|(mask, _)| bits & mask != 0)
        .map(|(_, name)| name.to_owned())
        .collect()
}

fn reference_request(case: &Case) -> Val {
    Val::Record(vec![
        ("truth".to_owned(), Val::Bool(case.truth)),
        ("signed".to_owned(), Val::S32(case.signed)),
        ("wide".to_owned(), Val::U64(case.wide)),
        ("symbol".to_owned(), Val::Char(case.symbol)),
        ("label".to_owned(), Val::String(case.label.to_owned())),
        (
            "payload".to_owned(),
            Val::List(case.payload.iter().copied().map(Val::U8).collect()),
        ),
        (
            "attributes".to_owned(),
            Val::Flags(reference_flag_names(case.attributes)),
        ),
        (
            "maybe".to_owned(),
            Val::Option(case.maybe.map(|value| Box::new(Val::U16(value)))),
        ),
        (
            "outcome".to_owned(),
            Val::Result(match case.outcome {
                Outcome::Ok(value) => Ok(Some(Box::new(Val::U32(value)))),
                Outcome::Err(value) => Err(Some(Box::new(Val::U8(value)))),
            }),
        ),
    ])
}

fn vibe_error_code(value: &CanonicalValue) -> NeutralErrorCode {
    match value {
        CanonicalValue::Enum(0) => NeutralErrorCode::Denied,
        CanonicalValue::Enum(1) => NeutralErrorCode::Invalid,
        CanonicalValue::Enum(2) => NeutralErrorCode::Exhausted,
        other => panic!("unexpected Vibe error-code value: {other:?}"),
    }
}

fn vibe_outcome(value: &CanonicalValue) -> NeutralOutcome {
    match value {
        CanonicalValue::Result(Ok(Some(value))) => match value.as_ref() {
            CanonicalValue::U32(value) => NeutralOutcome::Ok(*value),
            other => panic!("unexpected Vibe outcome ok payload: {other:?}"),
        },
        CanonicalValue::Result(Err(Some(value))) => match value.as_ref() {
            CanonicalValue::U8(value) => NeutralOutcome::Err(*value),
            other => panic!("unexpected Vibe outcome err payload: {other:?}"),
        },
        other => panic!("unexpected Vibe outcome value: {other:?}"),
    }
}

fn vibe_request_to_neutral(value: &CanonicalValue) -> NeutralRequest {
    let CanonicalValue::Record(fields) = value else {
        panic!("Vibe request was not a record: {value:?}");
    };
    assert_eq!(fields.len(), 9, "Vibe request field count");

    let truth = match &fields[0] {
        CanonicalValue::Bool(value) => *value,
        other => panic!("Vibe request.truth: {other:?}"),
    };
    let signed = match &fields[1] {
        CanonicalValue::S32(value) => *value,
        other => panic!("Vibe request.signed: {other:?}"),
    };
    let wide = match &fields[2] {
        CanonicalValue::U64(value) => *value,
        other => panic!("Vibe request.wide: {other:?}"),
    };
    let symbol = match &fields[3] {
        CanonicalValue::Char(value) => *value,
        other => panic!("Vibe request.symbol: {other:?}"),
    };
    let label = match &fields[4] {
        CanonicalValue::String(value) => value.clone(),
        other => panic!("Vibe request.label: {other:?}"),
    };
    let payload = match &fields[5] {
        CanonicalValue::List(values) => values
            .iter()
            .map(|value| match value {
                CanonicalValue::U8(value) => *value,
                other => panic!("Vibe request.payload element: {other:?}"),
            })
            .collect(),
        other => panic!("Vibe request.payload: {other:?}"),
    };
    let attributes = match &fields[6] {
        CanonicalValue::Flags(words) => {
            assert_eq!(words.len(), 1, "Vibe attributes word count");
            neutral_flags_from_bits(words[0])
        }
        other => panic!("Vibe request.attributes: {other:?}"),
    };
    let maybe = match &fields[7] {
        CanonicalValue::Option(None) => None,
        CanonicalValue::Option(Some(value)) => match value.as_ref() {
            CanonicalValue::U16(value) => Some(*value),
            other => panic!("Vibe request.maybe payload: {other:?}"),
        },
        other => panic!("Vibe request.maybe: {other:?}"),
    };

    NeutralRequest {
        truth,
        signed,
        wide,
        symbol,
        label,
        payload,
        attributes,
        maybe,
        outcome: vibe_outcome(&fields[8]),
    }
}

fn vibe_response_to_neutral(value: &CanonicalValue) -> NeutralResponse {
    match value {
        CanonicalValue::Variant {
            case: 0,
            payload: Some(payload),
        } => {
            let CanonicalValue::Tuple(fields) = payload.as_ref() else {
                panic!("Vibe accepted payload was not a tuple: {payload:?}");
            };
            assert_eq!(fields.len(), 2, "Vibe accepted tuple field count");
            NeutralResponse::Accepted(
                vibe_request_to_neutral(&fields[0]),
                vibe_error_code(&fields[1]),
            )
        }
        CanonicalValue::Variant {
            case: 1,
            payload: Some(payload),
        } => NeutralResponse::Rejected(vibe_error_code(payload)),
        other => panic!("unexpected Vibe response: {other:?}"),
    }
}

fn reference_error_code(value: &Val) -> NeutralErrorCode {
    match value {
        Val::Enum(name) if name == "denied" => NeutralErrorCode::Denied,
        Val::Enum(name) if name == "invalid" => NeutralErrorCode::Invalid,
        Val::Enum(name) if name == "exhausted" => NeutralErrorCode::Exhausted,
        other => panic!("unexpected Wasmtime error-code value: {other:?}"),
    }
}

fn reference_outcome(value: &Val) -> NeutralOutcome {
    match value {
        Val::Result(Ok(Some(value))) => match value.as_ref() {
            Val::U32(value) => NeutralOutcome::Ok(*value),
            other => panic!("unexpected Wasmtime outcome ok payload: {other:?}"),
        },
        Val::Result(Err(Some(value))) => match value.as_ref() {
            Val::U8(value) => NeutralOutcome::Err(*value),
            other => panic!("unexpected Wasmtime outcome err payload: {other:?}"),
        },
        other => panic!("unexpected Wasmtime outcome value: {other:?}"),
    }
}

fn reference_flags_to_neutral(names: &[String]) -> NeutralFlags {
    let mut flags = NeutralFlags {
        urgent: false,
        audited: false,
        traced: false,
    };
    for name in names {
        let selected = match name.as_str() {
            "urgent" => &mut flags.urgent,
            "audited" => &mut flags.audited,
            "traced" => &mut flags.traced,
            other => panic!("unknown Wasmtime attribute flag: {other}"),
        };
        assert!(!*selected, "duplicate Wasmtime attribute flag: {name}");
        *selected = true;
    }
    flags
}

fn reference_field<'a>(fields: &'a [(String, Val)], index: usize, name: &str) -> &'a Val {
    let (actual_name, value) = &fields[index];
    assert_eq!(actual_name, name, "Wasmtime request field {index}");
    value
}

fn reference_request_to_neutral(value: &Val) -> NeutralRequest {
    let Val::Record(fields) = value else {
        panic!("Wasmtime request was not a record: {value:?}");
    };
    assert_eq!(fields.len(), 9, "Wasmtime request field count");

    let truth = match reference_field(fields, 0, "truth") {
        Val::Bool(value) => *value,
        other => panic!("Wasmtime request.truth: {other:?}"),
    };
    let signed = match reference_field(fields, 1, "signed") {
        Val::S32(value) => *value,
        other => panic!("Wasmtime request.signed: {other:?}"),
    };
    let wide = match reference_field(fields, 2, "wide") {
        Val::U64(value) => *value,
        other => panic!("Wasmtime request.wide: {other:?}"),
    };
    let symbol = match reference_field(fields, 3, "symbol") {
        Val::Char(value) => *value,
        other => panic!("Wasmtime request.symbol: {other:?}"),
    };
    let label = match reference_field(fields, 4, "label") {
        Val::String(value) => value.clone(),
        other => panic!("Wasmtime request.label: {other:?}"),
    };
    let payload = match reference_field(fields, 5, "payload") {
        Val::List(values) => values
            .iter()
            .map(|value| match value {
                Val::U8(value) => *value,
                other => panic!("Wasmtime request.payload element: {other:?}"),
            })
            .collect(),
        other => panic!("Wasmtime request.payload: {other:?}"),
    };
    let attributes = match reference_field(fields, 6, "attributes") {
        Val::Flags(names) => reference_flags_to_neutral(names),
        other => panic!("Wasmtime request.attributes: {other:?}"),
    };
    let maybe = match reference_field(fields, 7, "maybe") {
        Val::Option(None) => None,
        Val::Option(Some(value)) => match value.as_ref() {
            Val::U16(value) => Some(*value),
            other => panic!("Wasmtime request.maybe payload: {other:?}"),
        },
        other => panic!("Wasmtime request.maybe: {other:?}"),
    };

    NeutralRequest {
        truth,
        signed,
        wide,
        symbol,
        label,
        payload,
        attributes,
        maybe,
        outcome: reference_outcome(reference_field(fields, 8, "outcome")),
    }
}

fn reference_response_to_neutral(value: &Val) -> NeutralResponse {
    match value {
        Val::Variant(name, Some(payload)) if name == "accepted" => {
            let Val::Tuple(fields) = payload.as_ref() else {
                panic!("Wasmtime accepted payload was not a tuple: {payload:?}");
            };
            assert_eq!(fields.len(), 2, "Wasmtime accepted tuple field count");
            NeutralResponse::Accepted(
                reference_request_to_neutral(&fields[0]),
                reference_error_code(&fields[1]),
            )
        }
        Val::Variant(name, Some(payload)) if name == "rejected" => {
            NeutralResponse::Rejected(reference_error_code(payload))
        }
        other => panic!("unexpected Wasmtime response: {other:?}"),
    }
}

fn drive_vibe(call: &mut TypedCall<'_, ()>, fixture: &str, case: &Case) -> NeutralResponse {
    let mut previous = call.metrics();
    for poll in 1..=MAX_POLLS {
        match call.poll() {
            TypedPoll::Pending(metrics) => {
                assert!(
                    metrics.consumed_work >= previous.consumed_work,
                    "{fixture} case {} work regressed at poll {poll}",
                    case.tag
                );
                assert!(
                    metrics.remaining_work <= previous.remaining_work,
                    "{fixture} case {} remaining work grew at poll {poll}",
                    case.tag
                );
                assert_eq!(
                    metrics.consumed_work + metrics.remaining_work,
                    TOTAL_WORK,
                    "{fixture} case {} work conservation at poll {poll}",
                    case.tag
                );
                previous = metrics;
            }
            TypedPoll::Ready(value) => {
                let neutral = vibe_response_to_neutral(&value);
                assert_eq!(
                    call.poll(),
                    TypedPoll::Trapped(TrapCode::Cancelled),
                    "{fixture} case {} must be terminal after Ready",
                    case.tag
                );
                return neutral;
            }
            TypedPoll::HostPending(operation) => panic!(
                "{fixture} case {} unexpectedly reached host operation {operation:?}",
                case.tag
            ),
            TypedPoll::HostFailed(error) => {
                panic!("{fixture} case {} host failure: {error:?}", case.tag)
            }
            TypedPoll::Trapped(trap) => {
                panic!("{fixture} case {} trapped: {trap:?}", case.tag)
            }
        }
    }
    panic!(
        "{fixture} case {} exceeded the {MAX_POLLS}-poll bound",
        case.tag
    );
}

fn run_vibe(bytes: &[u8], cases: &[Case], fixture: &Fixture<'_>) -> Vec<NeutralResponse> {
    let plan = inspect_component(bytes)
        .unwrap_or_else(|error| panic!("{} Component violates Profile 1: {error:?}", fixture.name));
    assert_eq!(plan.summary().imports, 0, "{} imports", fixture.name);
    assert!(plan.imports().is_empty(), "{} import shapes", fixture.name);
    let executable_exports: Vec<_> = plan.executable_exports().collect();
    assert_eq!(
        executable_exports.len(),
        1,
        "{} executable exports",
        fixture.name
    );
    assert_eq!(executable_exports[0].name, TRANSFORM);

    let world = WorldContract::parse(WIT, EXACT_WORLD).expect("fixture WIT must remain exact");
    plan.check_world(&world)
        .unwrap_or_else(|error| panic!("{} exact-world mismatch: {error:?}", fixture.name));

    let mut component = SynchronousComponent::instantiate(
        &plan,
        &ProfileEngine::new(),
        OwnerAllocationReservation::profile_default(),
    )
    .unwrap_or_else(|error| panic!("{} Vibe instantiation: {error:?}", fixture.name));
    assert_eq!(component.module_count(), 1);
    assert!(!component.is_poisoned());
    let mut resources = ResourceTable::<()>::new(fixture.resource_generation, 1).unwrap();
    let mut observed = Vec::with_capacity(cases.len());

    for case in cases {
        let mut call = component
            .start_typed_call(
                &mut resources,
                TRANSFORM,
                vec![vibe_request(case)],
                TOTAL_WORK,
                POLL_QUANTUM,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "{} case {} failed to start in Vibe: {error:?}",
                    fixture.name, case.tag
                )
            });
        assert_eq!(
            call.metrics().consumed_work + call.metrics().remaining_work,
            TOTAL_WORK
        );
        observed.push(drive_vibe(&mut call, fixture.name, case));
        drop(call);
        assert!(
            !component.is_poisoned(),
            "{} case {} poisoned the Vibe instance",
            fixture.name,
            case.tag
        );
    }
    observed
}

fn run_reference(
    bytes: &[u8],
    cases: &[Case],
    fixture: &Fixture<'_>,
) -> (Vec<NeutralResponse>, u64) {
    let mut config = Config::new();
    config.wasm_component_model(true).consume_fuel(true);
    let engine = Engine::new(&config).expect("pinned Wasmtime engine");
    let component = ReferenceComponent::new(&engine, bytes)
        .unwrap_or_else(|error| panic!("{} Wasmtime compilation: {error:#}", fixture.name));
    let component_type = component.component_type();
    assert_eq!(
        component_type.imports(&engine).len(),
        0,
        "{} Wasmtime-visible imports",
        fixture.name
    );

    let interface = component
        .get_export_index(None, INTERFACE)
        .unwrap_or_else(|| panic!("{} Wasmtime interface export", fixture.name));
    let transform = component
        .get_export_index(Some(&interface), "transform")
        .unwrap_or_else(|| panic!("{} Wasmtime transform export", fixture.name));

    // An empty linker is intentional: the fixtures must not acquire ambient
    // host authority merely because the independent reference is host-only.
    let linker = ReferenceLinker::<()>::new(&engine);
    let mut store = Store::new(&engine, ());
    store
        .set_fuel(REFERENCE_FUEL)
        .expect("Wasmtime fuel must be enabled");
    assert_eq!(store.get_fuel().unwrap(), REFERENCE_FUEL);
    let instance = linker
        .instantiate(&mut store, &component)
        .unwrap_or_else(|error| panic!("{} Wasmtime instantiation: {error:#}", fixture.name));
    assert!(store.get_fuel().unwrap() <= REFERENCE_FUEL);
    let function = instance
        .get_func(&mut store, transform)
        .unwrap_or_else(|| panic!("{} Wasmtime dynamic transform", fixture.name));

    let mut observed = Vec::with_capacity(cases.len());
    let mut consumed_fuel = 0_u64;
    for case in cases {
        store
            .set_fuel(REFERENCE_FUEL)
            .expect("reset bounded reference fuel");
        assert_eq!(store.get_fuel().unwrap(), REFERENCE_FUEL);
        let params = [reference_request(case)];
        let mut results = [Val::Bool(false)];
        function
            .call(&mut store, &params, &mut results)
            .unwrap_or_else(|error| {
                panic!(
                    "{} case {} Wasmtime dynamic call: {error:#}",
                    fixture.name, case.tag
                )
            });
        let remaining = store.get_fuel().expect("observe reference fuel");
        assert!(
            remaining < REFERENCE_FUEL,
            "{} case {} consumed no Wasmtime fuel",
            fixture.name,
            case.tag
        );
        assert!(
            remaining > 0,
            "{} case {} exhausted Wasmtime fuel",
            fixture.name,
            case.tag
        );
        consumed_fuel = consumed_fuel
            .checked_add(REFERENCE_FUEL - remaining)
            .expect("bounded reference fuel sum");
        observed.push(reference_response_to_neutral(&results[0]));
    }
    (observed, consumed_fuel)
}

fn fnv_byte(hash: &mut u64, byte: u8) {
    *hash ^= u64::from(byte);
    *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
}

fn fnv_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        fnv_byte(hash, *byte);
    }
}

fn corpus_digest(cases: &[Case]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325;
    fnv_bytes(&mut hash, b"vibeos.c2.3.canonical-language-corpus.v1\0");
    fnv_bytes(&mut hash, &(cases.len() as u64).to_le_bytes());
    for case in cases {
        fnv_byte(&mut hash, case.tag);
        fnv_byte(&mut hash, u8::from(case.truth));
        fnv_bytes(&mut hash, &case.signed.to_le_bytes());
        fnv_bytes(&mut hash, &case.wide.to_le_bytes());
        fnv_bytes(&mut hash, &(case.symbol as u32).to_le_bytes());
        fnv_bytes(&mut hash, &(case.label.len() as u64).to_le_bytes());
        fnv_bytes(&mut hash, case.label.as_bytes());
        fnv_bytes(&mut hash, &(case.payload.len() as u64).to_le_bytes());
        fnv_bytes(&mut hash, &case.payload);
        fnv_bytes(&mut hash, &case.attributes.to_le_bytes());
        match case.maybe {
            None => fnv_byte(&mut hash, 0),
            Some(value) => {
                fnv_byte(&mut hash, 1);
                fnv_bytes(&mut hash, &value.to_le_bytes());
            }
        }
        match case.outcome {
            Outcome::Ok(value) => {
                fnv_byte(&mut hash, 0);
                fnv_bytes(&mut hash, &value.to_le_bytes());
            }
            Outcome::Err(value) => {
                fnv_byte(&mut hash, 1);
                fnv_byte(&mut hash, value);
            }
        }
    }
    hash
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ComponentGraphVersionComponentIdentity::from_component_bytes(bytes)
        .expect("SHA-256 of a nonempty fixture cannot be the zero sentinel");
    let mut encoded = String::with_capacity(64);
    for byte in digest.as_bytes() {
        write!(encoded, "{byte:02x}").unwrap();
    }
    encoded
}

fn assert_pin(bytes: &[u8], expected_bytes: usize, expected_sha256: &str, label: &str) {
    assert_eq!(bytes.len(), expected_bytes, "{label} byte length");
    assert_eq!(sha256_hex(bytes), expected_sha256, "{label} SHA-256");
}

#[test]
fn rust_and_c_components_agree_with_the_pinned_reference() {
    let cases = cases();
    assert_eq!(cases.len(), CASE_COUNT);
    assert_eq!(
        cases
            .iter()
            .map(|case| case.label.len() + case.payload.len())
            .sum::<usize>(),
        AGGREGATE_DYNAMIC_BYTES
    );
    assert_eq!(corpus_digest(&cases), CORPUS_FNV1A64);

    let fixtures = [
        Fixture {
            name: "Rust",
            core: RUST_CORE,
            core_bytes: RUST_CORE_BYTES,
            core_sha256: RUST_CORE_SHA256,
            component_bytes: RUST_COMPONENT_BYTES,
            component_sha256: RUST_COMPONENT_SHA256,
            resource_generation: 31,
        },
        Fixture {
            name: "C",
            core: C_CORE,
            core_bytes: C_CORE_BYTES,
            core_sha256: C_CORE_SHA256,
            component_bytes: C_COMPONENT_BYTES,
            component_sha256: C_COMPONENT_SHA256,
            resource_generation: 32,
        },
    ];
    assert_eq!(fixtures.len(), FIXTURE_COUNT);

    let mut vibe_executions = 0_usize;
    let mut reference_executions = 0_usize;
    let mut reference_fuel = 0_u64;
    for fixture in &fixtures {
        assert_pin(
            fixture.core,
            fixture.core_bytes,
            fixture.core_sha256,
            &format!("{} Core", fixture.name),
        );
        inspect_core(fixture.core)
            .unwrap_or_else(|error| panic!("{} Core violates Profile 1: {error:?}", fixture.name));
        let bytes = component_from_core(fixture.core);
        assert_pin(
            &bytes,
            fixture.component_bytes,
            fixture.component_sha256,
            &format!("{} derived Component", fixture.name),
        );

        let vibe = run_vibe(&bytes, &cases, fixture);
        let (reference, consumed_fuel) = run_reference(&bytes, &cases, fixture);
        assert_eq!(vibe.len(), CASE_COUNT);
        assert_eq!(reference.len(), CASE_COUNT);
        reference_fuel = reference_fuel
            .checked_add(consumed_fuel)
            .expect("bounded aggregate reference fuel");

        for ((case, vibe), reference) in cases.iter().zip(&vibe).zip(&reference) {
            let expected = neutral_expected(case);
            assert_eq!(
                vibe, &expected,
                "{} case {} Vibe vs neutral expected",
                fixture.name, case.tag
            );
            assert_eq!(
                reference, &expected,
                "{} case {} Wasmtime vs neutral expected",
                fixture.name, case.tag
            );
            assert_eq!(
                vibe, reference,
                "{} case {} Vibe vs Wasmtime",
                fixture.name, case.tag
            );
            vibe_executions += 1;
            reference_executions += 1;
        }
    }

    assert_eq!(vibe_executions, EXPECTED_EXECUTIONS_PER_ENGINE);
    assert_eq!(reference_executions, EXPECTED_EXECUTIONS_PER_ENGINE);
    assert!(reference_fuel > 0, "reference execution consumed no fuel");
}
