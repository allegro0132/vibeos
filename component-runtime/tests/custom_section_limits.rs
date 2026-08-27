use vibeos_component_format::PROFILE_1_LIMITS;
use vibeos_component_runtime::decode::{inspect_component, DecodeError};

fn u32_leb(mut value: u32) -> Vec<u8> {
    let mut encoded = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        encoded.push(byte);
        if value == 0 {
            return encoded;
        }
    }
}

fn component_with_custom_payload(payload: &[u8]) -> Vec<u8> {
    let mut component = b"\0asm\x0d\0\x01\0".to_vec();
    component.push(0);
    component.extend(u32_leb(payload.len().try_into().unwrap()));
    component.extend_from_slice(payload);
    component
}

#[test]
fn component_custom_budget_counts_encoded_names_and_data() {
    let mut exact_payload = vec![0_u8; PROFILE_1_LIMITS.max_custom_section_bytes];
    exact_payload[0] = 0;
    let exact = component_with_custom_payload(&exact_payload);
    let summary = inspect_component(&exact).unwrap().summary();
    assert_eq!(summary.custom_sections, 1);
    assert_eq!(
        summary.custom_section_bytes as usize,
        PROFILE_1_LIMITS.max_custom_section_bytes
    );

    let name_bytes = PROFILE_1_LIMITS.max_custom_section_bytes + 1;
    let mut oversized_name = u32_leb(name_bytes.try_into().unwrap());
    oversized_name.resize(oversized_name.len() + name_bytes, b'n');
    assert_eq!(
        inspect_component(&component_with_custom_payload(&oversized_name)).err(),
        Some(DecodeError::Limit)
    );
}
