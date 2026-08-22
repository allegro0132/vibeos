use vibeos_component_format::{
    ProfileIdentity, SELECTED_WASI_COMMAND_WIT, SELECTED_WASI_COMMAND_WORLD,
};
use vibeos_component_runtime::{
    decode::{inspect_component_for_profile, DecodeError},
    world::{
        EntityShape, FunctionEffect, FunctionShape, NamedEntityShape, NamedValueShape, TypeShape,
        ValueShape, WorldContract, WorldError,
    },
};

const SELECTED_WASI_COMPONENT: &str =
    include_str!("../../component-format/tests/corpus/component/wasi-selected-0.3.0.component.wat");

fn selected_world() -> WorldContract {
    WorldContract::parse(SELECTED_WASI_COMMAND_WIT, SELECTED_WASI_COMMAND_WORLD)
        .expect("pinned selected-WASI world")
}

fn interface<'a>(world: &'a WorldContract, name: &str) -> &'a [NamedEntityShape] {
    let entity = world
        .imports
        .iter()
        .chain(&world.exports)
        .find(|entity| entity.name == name)
        .unwrap_or_else(|| panic!("missing interface {name}"));
    let EntityShape::Interface(members) = &entity.entity else {
        panic!("{name} must be an interface")
    };
    members
}

fn member<'a>(members: &'a [NamedEntityShape], name: &str) -> &'a EntityShape {
    &members
        .iter()
        .find(|member| member.name == name)
        .unwrap_or_else(|| panic!("missing member {name}"))
        .entity
}

fn assert_member_names(members: &[NamedEntityShape], expected: &[&str]) {
    assert_eq!(
        members
            .iter()
            .map(|member| member.name.as_str())
            .collect::<Vec<_>>(),
        expected
    );
}

fn assert_function(
    members: &[NamedEntityShape],
    name: &str,
    effect: FunctionEffect,
    parameters: Vec<(&str, ValueShape)>,
    result: Option<ValueShape>,
) {
    let expected = EntityShape::Function(FunctionShape {
        effect,
        parameters: parameters
            .into_iter()
            .map(|(name, value)| NamedValueShape {
                name: String::from(name),
                value,
            })
            .collect(),
        result,
    });
    assert_eq!(member(members, name), &expected, "{name}");
}

fn io_error() -> ValueShape {
    ValueShape::Enum(vec![
        String::from("io"),
        String::from("illegal-byte-sequence"),
        String::from("pipe"),
    ])
}

fn io_completion() -> ValueShape {
    ValueShape::Future(Some(Box::new(ValueShape::Result {
        ok: None,
        error: Some(Box::new(io_error())),
    })))
}

#[test]
fn selected_wasi_world_is_the_exact_six_import_one_export_contract() {
    let world = selected_world();
    assert_eq!(world.identity, SELECTED_WASI_COMMAND_WORLD);
    assert_eq!(
        world
            .imports
            .iter()
            .map(|entity| entity.name.as_str())
            .collect::<Vec<_>>(),
        [
            "wasi:clocks/types@0.3.0",
            "wasi:clocks/monotonic-clock@0.3.0",
            "wasi:random/random@0.3.0",
            "wasi:cli/types@0.3.0",
            "wasi:cli/stdin@0.3.0",
            "wasi:cli/stdout@0.3.0",
        ]
    );
    assert_eq!(
        world
            .exports
            .iter()
            .map(|entity| entity.name.as_str())
            .collect::<Vec<_>>(),
        ["wasi:cli/run@0.3.0"]
    );

    let clock_types = interface(&world, "wasi:clocks/types@0.3.0");
    assert_member_names(clock_types, &["duration"]);
    assert_eq!(
        member(clock_types, "duration"),
        &EntityShape::Type(TypeShape::Value(ValueShape::U64))
    );

    let clock = interface(&world, "wasi:clocks/monotonic-clock@0.3.0");
    assert_member_names(
        clock,
        &[
            "duration",
            "mark",
            "now",
            "get-resolution",
            "wait-until",
            "wait-for",
        ],
    );
    for name in ["duration", "mark"] {
        assert_eq!(
            member(clock, name),
            &EntityShape::Type(TypeShape::Value(ValueShape::U64))
        );
    }
    assert_function(
        clock,
        "now",
        FunctionEffect::Sync,
        vec![],
        Some(ValueShape::U64),
    );
    assert_function(
        clock,
        "get-resolution",
        FunctionEffect::Sync,
        vec![],
        Some(ValueShape::U64),
    );
    assert_function(
        clock,
        "wait-until",
        FunctionEffect::Async,
        vec![("when", ValueShape::U64)],
        None,
    );
    assert_function(
        clock,
        "wait-for",
        FunctionEffect::Async,
        vec![("how-long", ValueShape::U64)],
        None,
    );

    let random = interface(&world, "wasi:random/random@0.3.0");
    assert_member_names(random, &["get-random-bytes", "get-random-u64"]);
    assert_function(
        random,
        "get-random-bytes",
        FunctionEffect::Sync,
        vec![("max-len", ValueShape::U64)],
        Some(ValueShape::List(Box::new(ValueShape::U8))),
    );
    assert_function(
        random,
        "get-random-u64",
        FunctionEffect::Sync,
        vec![],
        Some(ValueShape::U64),
    );

    let cli_types = interface(&world, "wasi:cli/types@0.3.0");
    assert_member_names(cli_types, &["error-code"]);
    assert_eq!(
        member(cli_types, "error-code"),
        &EntityShape::Type(TypeShape::Value(io_error()))
    );

    let stdin = interface(&world, "wasi:cli/stdin@0.3.0");
    assert_member_names(stdin, &["error-code", "read-via-stream"]);
    assert_eq!(
        member(stdin, "error-code"),
        &EntityShape::Type(TypeShape::Value(io_error()))
    );
    assert_function(
        stdin,
        "read-via-stream",
        FunctionEffect::Sync,
        vec![],
        Some(ValueShape::Tuple(vec![
            ValueShape::Stream(Some(Box::new(ValueShape::U8))),
            io_completion(),
        ])),
    );

    let stdout = interface(&world, "wasi:cli/stdout@0.3.0");
    assert_member_names(stdout, &["error-code", "write-via-stream"]);
    assert_eq!(
        member(stdout, "error-code"),
        &EntityShape::Type(TypeShape::Value(io_error()))
    );
    assert_function(
        stdout,
        "write-via-stream",
        FunctionEffect::Sync,
        vec![("data", ValueShape::Stream(Some(Box::new(ValueShape::U8))))],
        Some(io_completion()),
    );

    let run = interface(&world, "wasi:cli/run@0.3.0");
    assert_member_names(run, &["run"]);
    assert_function(
        run,
        "run",
        FunctionEffect::Async,
        vec![],
        Some(ValueShape::Result {
            ok: None,
            error: None,
        }),
    );
}

#[test]
fn selected_wasi_component_matches_the_world_but_remains_inert() {
    let bytes = wat::parse_str(SELECTED_WASI_COMPONENT).expect("selected-WASI Component WAT");
    assert_eq!(
        inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_SYNC).err(),
        Some(DecodeError::Unsupported)
    );

    let plan = inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC)
        .expect("validation-only selected-WASI plan");
    assert_eq!(plan.profile(), ProfileIdentity::PROFILE_1_ASYNC);
    assert_eq!((plan.imports().len(), plan.exports().len()), (6, 1));
    assert!(!plan.runtime_ready());
    assert!(!plan.native_async_runtime_ready());
    assert!(plan.native_async_execution_plan().is_none());
    assert_eq!(plan.executable_exports().count(), 0);
    plan.check_world(&selected_world()).unwrap();
}

fn assert_component_world_mismatch(source: &str) {
    let bytes = wat::parse_str(source).expect("mutated Component WAT remains valid");
    let plan = inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC)
        .expect("mutated Component remains inspectable");
    assert_eq!(
        plan.check_world(&selected_world()),
        Err(WorldError::TypeMismatch)
    );
}

#[test]
fn selected_wasi_member_signatures_are_not_structurally_interchangeable() {
    let mutations = [
        SELECTED_WASI_COMPONENT.replacen(
            "(type $duration-private u64)",
            "(type $duration-private u32)",
            1,
        ),
        SELECTED_WASI_COMPONENT.replace(
            "(type $mark-private u64)",
            "(type $mark-private u32)",
        ),
        SELECTED_WASI_COMPONENT.replace(
            "(type $wait-until (func async (param \"when\" $mark-in)))",
            "(type $wait-until (func (param \"when\" $mark-in)))",
        ),
        SELECTED_WASI_COMPONENT.replace(
            "(func (param \"max-len\" u64) (result (list u8)))",
            "(func (param \"max-len\" u32) (result (list u8)))",
        ),
        SELECTED_WASI_COMPONENT.replacen(
            "(enum \"io\" \"illegal-byte-sequence\" \"pipe\")",
            "(enum \"pipe\" \"illegal-byte-sequence\" \"io\")",
            1,
        ),
        SELECTED_WASI_COMPONENT.replacen(
            "(type $bytes (stream u8))",
            "(type $bytes (stream u16))",
            1,
        ),
        SELECTED_WASI_COMPONENT.replace(
            "(type $write-via-stream\n        (func (param \"data\" $bytes) (result $completed)))",
            "(type $write-via-stream\n        (func async (param \"data\" $bytes) (result $completed)))",
        ),
        SELECTED_WASI_COMPONENT
            .replace(
                "(type $run-type (func async (result $run-result)))",
                "(type $run-type (func (result $run-result)))",
            )
            .replace(
                "(canon lift (core func $run-core) async\n      (callback (core func $callback)))",
                "(canon lift (core func $run-core))",
            ),
    ];

    for mutated in mutations {
        assert_ne!(mutated, SELECTED_WASI_COMPONENT);
        assert_component_world_mismatch(&mutated);
    }
}

#[test]
fn selected_wasi_rejects_adjacent_versions_and_forbidden_interfaces() {
    for (selected, adjacent) in [
        (
            "wasi:clocks/monotonic-clock@0.3.0",
            "wasi:clocks/monotonic-clock@0.3.1",
        ),
        (
            "wasi:random/random@0.3.0",
            "wasi:random/random@0.3.0-rc-2026-03-15",
        ),
        ("wasi:cli/stdin@0.3.0", "wasi:cli/stdin@0.2.6"),
        ("wasi:cli/stdout@0.3.0", "wasi:cli/stderr@0.3.0"),
        ("wasi:cli/run@0.3.0", "wasi:cli/run@0.3.1"),
    ] {
        let mutated = SELECTED_WASI_COMPONENT.replace(selected, adjacent);
        assert_ne!(mutated, SELECTED_WASI_COMPONENT);
        let bytes = wat::parse_str(&mutated).unwrap();
        let plan = inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).unwrap();
        assert!(matches!(
            plan.check_world(&selected_world()),
            Err(WorldError::MissingImport | WorldError::MissingExport)
        ));
    }

    let forbidden = [
        "wasi:clocks/system-clock@0.3.0",
        "wasi:clocks/timezone@0.3.0",
        "wasi:random/insecure@0.3.0",
        "wasi:random/insecure-seed@0.3.0",
        "wasi:cli/environment@0.3.0",
        "wasi:cli/exit@0.3.0",
        "wasi:cli/stderr@0.3.0",
        "wasi:cli/terminal-input@0.3.0",
        "wasi:cli/terminal-output@0.3.0",
        "wasi:cli/terminal-stdin@0.3.0",
        "wasi:cli/terminal-stdout@0.3.0",
        "wasi:cli/terminal-stderr@0.3.0",
        "wasi:filesystem/types@0.3.0",
        "wasi:filesystem/preopens@0.3.0",
        "wasi:sockets/types@0.3.0",
        "wasi:sockets/ip-name-lookup@0.3.0",
        "wasi:cli/command@0.3.0",
    ];
    for identity in forbidden {
        // Identity classification is intentionally tested independently of
        // each forbidden interface's member graph: an unknown standard name
        // must fail before any structural shape could make it acceptable.
        let extra = format!(
            "  (type $forbidden-interface (instance))\n  (import \"{identity}\"\n    (instance $forbidden (type $forbidden-interface)))\n"
        );
        let mutated =
            SELECTED_WASI_COMPONENT.replacen("(component\n", &format!("(component\n{extra}"), 1);
        let bytes = wat::parse_str(&mutated).unwrap();
        let plan = inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).unwrap();
        assert_eq!(
            plan.check_world(&selected_world()),
            Err(WorldError::UnexpectedImport),
            "{identity}"
        );
    }

    // A real wasi:cli/command component exposes its included interfaces at the
    // top level; the command world itself is not an importable interface. Add
    // the reviewed forbidden identity set together to prove that such a
    // superset cannot collapse to the selected world, irrespective of member
    // shapes that are already rejected by the exact-contract tests above.
    let mut full_command_imports = String::new();
    for (index, identity) in forbidden[..forbidden.len() - 1].iter().enumerate() {
        full_command_imports.push_str(&format!(
            "  (type $full-command-interface-{index} (instance))\n  (import \"{identity}\"\n    (instance $full-command-{index} (type $full-command-interface-{index})))\n"
        ));
    }
    let full_command_component = SELECTED_WASI_COMPONENT.replacen(
        "(component\n",
        &format!("(component\n{full_command_imports}"),
        1,
    );
    let bytes = wat::parse_str(&full_command_component).unwrap();
    let plan = inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).unwrap();
    assert_eq!(
        plan.check_world(&selected_world()),
        Err(WorldError::UnexpectedImport)
    );
    assert!(matches!(
        WorldContract::parse(SELECTED_WASI_COMMAND_WIT, "wasi:cli/command@0.3.0"),
        Err(WorldError::VersionMismatch)
    ));
}
