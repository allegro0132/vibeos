use vibeos_component_host::{
    HostResourceKind, VibeHostManifest, STREAM_CLOSE_READER_FUNCTION, STREAM_CLOSE_WRITER_FUNCTION,
    STREAM_INTERFACE, STREAM_READ_FUNCTION, STREAM_WRITE_FUNCTION,
};
use vibeos_component_runtime::decode::inspect_component;
use vibeos_core::cap::Rights;

const STREAM_COMPONENT: &str =
    include_str!("../../../component-runtime/tests/fixtures/host-stream.component.wat");

fn manifest(source: &str) -> Result<VibeHostManifest, vibeos_component_host::HostManifestError> {
    let bytes = wat::parse_str(source).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    VibeHostManifest::from_plan(&plan)
}

#[test]
fn exact_stream_interface_yields_two_distinct_nominal_requirements() {
    let manifest = manifest(STREAM_COMPONENT).unwrap();
    let (reader, writer) = manifest.stream_resource_types().unwrap();
    assert_ne!(reader, writer);
    assert_ne!(reader.0, 0);
    assert_ne!(writer.0, 0);

    let requirements = manifest.requirements().collect::<Vec<_>>();
    assert_eq!(requirements.len(), 2);
    assert_eq!(requirements[0].interface(), STREAM_INTERFACE);
    assert_eq!(requirements[0].resource(), "reader");
    assert_eq!(requirements[0].kind(), HostResourceKind::ByteStreamReader);
    assert_eq!(requirements[0].rights(), Rights::RECV);
    assert_eq!(requirements[1].interface(), STREAM_INTERFACE);
    assert_eq!(requirements[1].resource(), "writer");
    assert_eq!(requirements[1].kind(), HostResourceKind::ByteStreamWriter);
    assert_eq!(requirements[1].rights(), Rights::SEND);

    assert_eq!(STREAM_READ_FUNCTION, "read");
    assert_eq!(STREAM_WRITE_FUNCTION, "write");
    assert_eq!(STREAM_CLOSE_READER_FUNCTION, "close-reader");
    assert_eq!(STREAM_CLOSE_WRITER_FUNCTION, "close-writer");
}

#[test]
fn spelling_enum_parameter_and_member_order_spoofs_are_rejected() {
    assert!(manifest(
        &STREAM_COMPONENT.replace("vibe:stream/streams@1.0.0", "vibe:stream/not-streams@1.0.0")
    )
    .is_err());
    assert!(
        manifest(&STREAM_COMPONENT.replace("\"backend-fault\"", "\"backend-broken\"")).is_err()
    );
    assert!(manifest(
        &STREAM_COMPONENT.replace("(param \"bytes\" (list u8))", "(param \"data\" (list u8))")
    )
    .is_err());
    assert!(manifest(&STREAM_COMPONENT.replace(
        "      (export \"read\" (func (type $read-type)))\n      (export \"write\" (func (type $write-type)))",
        "      (export \"write\" (func (type $write-type)))\n      (export \"read\" (func (type $read-type)))"
    ))
    .is_err());
}

#[test]
fn a_fifth_callable_member_is_rejected_even_when_the_guest_does_not_alias_it() {
    let source = STREAM_COMPONENT.replace(
        "      (export \"close-writer\" (func (type $close-writer-type)))))",
        "      (export \"close-writer\" (func (type $close-writer-type)))\n      (type $extra-type (func))\n      (export \"extra\" (func (type $extra-type)))))",
    );
    assert_ne!(source, STREAM_COMPONENT);
    assert!(manifest(&source).is_err());
}

#[test]
fn replacing_one_required_function_with_a_foreign_name_is_rejected() {
    let source = STREAM_COMPONENT
        .replace(
            "      (export \"read\" (func (type $read-type)))",
            "      (export \"read-missing\" (func (type $read-type)))",
        )
        .replace(
            "  (alias export $streams \"read\" (func $read))",
            "  (alias export $streams \"read-missing\" (func $read))",
        );
    assert_ne!(source, STREAM_COMPONENT);
    assert!(manifest(&source).is_err());
}

#[test]
fn reader_and_writer_must_remain_distinct_nominal_resources() {
    let source = STREAM_COMPONENT.replace(
        "      (export \"writer\" (type $writer-in (sub resource)))",
        "      (export \"writer\" (type $writer-in (eq $reader-in)))",
    );
    assert_ne!(source, STREAM_COMPONENT);
    assert!(manifest(&source).is_err());
}
