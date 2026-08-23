use vibeos_component_format::{
    MAX_COMPONENT_ARTIFACT_ENCODED_BYTES, MAX_COMPONENT_ARTIFACT_METADATA_BYTES, PROFILE_1_LIMITS,
};
use vibeos_durable_format::MAX_OBJECT_SIZE;

#[test]
fn canonical_component_artifact_fits_one_durable_v1_object() {
    assert_eq!(
        MAX_COMPONENT_ARTIFACT_ENCODED_BYTES,
        vibeos_component_format::COMPONENT_ARTIFACT_HEADER_LEN
            + MAX_COMPONENT_ARTIFACT_METADATA_BYTES
            + PROFILE_1_LIMITS.max_component_bytes
    );
    assert!(MAX_COMPONENT_ARTIFACT_ENCODED_BYTES <= MAX_OBJECT_SIZE);
    assert_eq!(
        MAX_OBJECT_SIZE - MAX_COMPONENT_ARTIFACT_ENCODED_BYTES,
        32_416
    );
}
