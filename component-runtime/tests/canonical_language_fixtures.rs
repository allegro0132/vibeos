use core::fmt::Write as _;

use vibeos_component_format::ComponentGraphVersionComponentIdentity;
use vibeos_component_runtime::{
    decode::inspect_component,
    resource::ResourceTable,
    sync::{SyncError, SynchronousComponent, TypedCall, TypedPoll},
    value::CanonicalValue,
    world::WorldContract,
};
use vibeos_wasm_runtime::{inspect_core, OwnerAllocationReservation, ProfileEngine};
use wasm_encoder::{
    CanonicalOption, ComponentBuilder, ComponentExportKind, ComponentExportSection,
    ComponentInstanceSection, ComponentSection, ComponentValType, ExportKind, ModuleArg,
    PrimitiveValType,
};

const WIT: &str = include_str!("../../component-format/tests/corpus/wit/canonical-values.wit");
const RUST_CORE: &[u8] = include_bytes!("fixtures/language/canonical-values-rust.core.wasm");
const C_CORE: &[u8] = include_bytes!("fixtures/language/canonical-values-c.core.wasm");

const EXACT_WORLD: &str = "vibe:fixture/canonical-language@1.0.0";
const INTERFACE: &str = "vibe:fixture/canonical-values@1.0.0";
const TRANSFORM: &str = "vibe:fixture/canonical-values@1.0.0#transform";
const TOTAL_WORK: u64 = 1_000_000;
const POLL_QUANTUM: u64 = 10_000;
const MAX_POLLS: usize = 101;
const CASE_COUNT: usize = 4;

// Keeping these assertions beside the executable evidence prevents a
// source-only fixture change from silently selecting new code.
const RUST_CORE_BYTES: usize = 557;
const RUST_CORE_SHA256: &str = "79e1eb3f2043c4ae224da6057279f80f32ec171106ad2112e8f7d2bf62e96f52";
const RUST_COMPONENT_BYTES: usize = 950;
const RUST_COMPONENT_SHA256: &str =
    "1826aef365bbc0c1061bd8f23eaea5883ed052220f711243cd7c29c335975cfe";
const C_CORE_BYTES: usize = 1_030;
const C_CORE_SHA256: &str = "20e26c154f2fc3d0892a2175dd85912ea2df77ff43e22200864eba7e6d3f7e8e";
const C_COMPONENT_BYTES: usize = 1_423;
const C_COMPONENT_SHA256: &str = "2ee8f6154c6069d46d726e922a1d07979982d022dd8c02e035dcd244a9248b78";

const AGGREGATE_DYNAMIC_BYTES: usize = 276;
const CORPUS_FNV1A64: u64 = 0x5a3e_5d03_338a_9be3;

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

fn request(case: &Case) -> CanonicalValue {
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

fn expected(case: &Case) -> CanonicalValue {
    if case.truth {
        CanonicalValue::Variant {
            case: 0,
            payload: Some(Box::new(CanonicalValue::Tuple(vec![
                request(case),
                CanonicalValue::Enum(1),
            ]))),
        }
    } else {
        CanonicalValue::Variant {
            case: 1,
            payload: Some(Box::new(CanonicalValue::Enum(0))),
        }
    }
}

fn drive(call: &mut TypedCall<'_, ()>, fixture: &str, case: &Case) {
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
                assert_eq!(
                    value,
                    expected(case),
                    "{fixture} case {} typed output",
                    case.tag
                );
                assert_eq!(
                    call.poll(),
                    TypedPoll::Trapped(vibeos_component_format::TrapCode::Cancelled),
                    "{fixture} case {} must be terminal after Ready",
                    case.tag
                );
                return;
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
fn rust_and_c_components_round_trip_the_same_bounded_canonical_values() {
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
            resource_generation: 1,
        },
        Fixture {
            name: "C",
            core: C_CORE,
            core_bytes: C_CORE_BYTES,
            core_sha256: C_CORE_SHA256,
            component_bytes: C_COMPONENT_BYTES,
            component_sha256: C_COMPONENT_SHA256,
            resource_generation: 2,
        },
    ];

    for fixture in fixtures {
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

        let plan = inspect_component(&bytes).expect("generated Component must satisfy Profile 1");
        assert_eq!(
            plan.summary().imports,
            0,
            "{} Component imports",
            fixture.name
        );
        assert!(
            plan.imports().is_empty(),
            "{} Component import shapes",
            fixture.name
        );
        let executable_exports: Vec<_> = plan.executable_exports().collect();
        assert_eq!(
            executable_exports.len(),
            1,
            "{} executable exports",
            fixture.name
        );
        assert_eq!(
            executable_exports[0].name, TRANSFORM,
            "{} executable export name",
            fixture.name
        );
        let world = WorldContract::parse(WIT, EXACT_WORLD).expect("fixture WIT must remain exact");
        plan.check_world(&world)
            .expect("generated Component must match the exact WIT world");
        let mut component = SynchronousComponent::instantiate(
            &plan,
            &ProfileEngine::new(),
            OwnerAllocationReservation::profile_default(),
        )
        .expect("generated Component must instantiate without imports");
        assert_eq!(component.module_count(), 1);
        assert!(!component.is_poisoned());
        let mut resources = ResourceTable::<()>::new(fixture.resource_generation, 1).unwrap();

        for case in &cases {
            let mut call = component
                .start_typed_call(
                    &mut resources,
                    TRANSFORM,
                    vec![request(case)],
                    TOTAL_WORK,
                    POLL_QUANTUM,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "{} case {} failed to start: {error:?}",
                        fixture.name, case.tag
                    )
                });
            assert_eq!(
                call.metrics().consumed_work + call.metrics().remaining_work,
                TOTAL_WORK
            );
            drive(&mut call, fixture.name, case);
            drop(call);
            assert!(
                !component.is_poisoned(),
                "{} case {} poisoned the instance",
                fixture.name,
                case.tag
            );
        }

        // `start_typed_call` checks active Core calls before the argument
        // shape. Seeing `Value`, rather than `Busy`, proves the final Ready
        // path released its continuation without executing a fifth case.
        assert!(matches!(
            component.start_typed_call(
                &mut resources,
                TRANSFORM,
                Vec::new(),
                TOTAL_WORK,
                POLL_QUANTUM,
            ),
            Err(SyncError::Value)
        ));
        assert!(!component.is_poisoned());
    }
}
