#[path = "../src/predecode.rs"]
mod predecode;

use predecode::{predecode_component, PredecodeError};
use vibeos_component_format::PROFILE_1_LIMITS;

const COMPONENT: &str =
    include_str!("../../component-format/tests/corpus/component/typed.component.wat");

#[test]
fn accepts_profile_component_without_allocating() {
    let bytes = wat::parse_str(COMPONENT).unwrap();
    assert_eq!(predecode_component(&bytes), Ok(()));
}

#[test]
fn accepts_bounded_nested_instance_type_shapes() {
    let bytes = wat::parse_str(
        r#"(component
              (type $api
                (instance
                  (export "source" (type (sub resource)))
                  (type $borrow (borrow 0))
                  (type $flags (flags "urgent" "audited"))
                  (export "flags-value" (type (eq $flags)))
                  (type $code (enum "denied" "invalid"))
                  (type $bytes (list u8))
                  (type $request
                    (record
                      (field "label" string)
                      (field "payload" $bytes)
                      (field "attributes" $flags)))
                  (type $response
                    (variant
                      (case "accepted" $bytes)
                      (case "rejected" $code)))
                  (type $transform
                    (func
                      (param "value" $request)
                      (param "source" $borrow)
                      (result $response)))
                  (export "transform" (func (type $transform))))))"#,
    )
    .unwrap();
    assert_eq!(predecode_component(&bytes), Ok(()));
}

#[test]
fn rejects_declared_million_entry_vectors_before_the_truncated_body() {
    let million = leb(1_000_000);

    let mut instance_type = vec![1, 0x42];
    instance_type.extend_from_slice(&million);
    assert_eq!(
        predecode_component(&component_with_section(7, &instance_type)),
        Err(PredecodeError::Limit)
    );

    let mut core_args = vec![1, 0, 0];
    core_args.extend_from_slice(&million);
    assert_eq!(
        predecode_component(&component_with_section(2, &core_args)),
        Err(PredecodeError::Limit)
    );

    let mut component_exports = vec![1, 1];
    component_exports.extend_from_slice(&million);
    assert_eq!(
        predecode_component(&component_with_section(5, &component_exports)),
        Err(PredecodeError::Limit)
    );
}

#[test]
fn caps_all_boxed_component_type_vectors() {
    for opcode in [0x72, 0x71, 0x6f, 0x6e, 0x6d] {
        let mut body = vec![1, opcode];
        body.extend_from_slice(&leb(PROFILE_1_LIMITS.max_canonical_values + 1));
        assert_eq!(
            predecode_component(&component_with_section(7, &body)),
            Err(PredecodeError::Limit),
            "opcode {opcode:#x}"
        );
    }

    let mut function = vec![1, 0x40];
    function.extend_from_slice(&leb(PROFILE_1_LIMITS.max_params_per_function + 1));
    assert_eq!(
        predecode_component(&component_with_section(7, &function)),
        Err(PredecodeError::Limit)
    );
}

#[test]
fn malformed_leb_and_section_framing_fail_closed() {
    let mut truncated_length = b"\0asm\x0d\0\x01\0".to_vec();
    truncated_length.extend_from_slice(&[7, 0x80]);
    assert_eq!(
        predecode_component(&truncated_length),
        Err(PredecodeError::Malformed)
    );

    let mut overflowing_length = b"\0asm\x0d\0\x01\0".to_vec();
    overflowing_length.extend_from_slice(&[7, 0xff, 0xff, 0xff, 0xff, 0x10]);
    assert_eq!(
        predecode_component(&overflowing_length),
        Err(PredecodeError::Malformed)
    );

    let missing_body = b"\0asm\x0d\0\x01\0\x07\x01";
    assert_eq!(
        predecode_component(missing_body),
        Err(PredecodeError::Malformed)
    );

    let trailing_type_bytes = component_with_section(7, &[0, 0]);
    assert_eq!(
        predecode_component(&trailing_type_bytes),
        Err(PredecodeError::Malformed)
    );
}

#[test]
fn nested_components_and_async_types_are_profile_unsupported() {
    assert_eq!(
        predecode_component(&component_with_section(7, &[1, 0x41, 0])),
        Err(PredecodeError::Unsupported)
    );
    assert_eq!(
        predecode_component(&component_with_section(7, &[1, 0x43])),
        Err(PredecodeError::Unsupported)
    );
    assert_eq!(
        predecode_component(&component_with_section(4, &[])),
        Err(PredecodeError::Unsupported)
    );
}

fn component_with_section(id: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = b"\0asm\x0d\0\x01\0".to_vec();
    bytes.push(id);
    bytes.extend_from_slice(&leb(body.len() as u32));
    bytes.extend_from_slice(body);
    bytes
}

fn leb(mut value: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            return bytes;
        }
    }
}
