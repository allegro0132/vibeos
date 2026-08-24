use vibeos_component_format::{
    ComponentArtifactAuthenticationEvidenceV1, ComponentGraphVersionAuthenticationAlgorithm,
    ComponentGraphVersionAuthenticationError, ComponentGraphVersionAuthenticationEvidenceV1,
    ComponentGraphVersionEd25519Signature, ComponentGraphVersionOperatorPublicKey,
    COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN,
    COMPONENT_GRAPH_VERSION_AUTHENTICATION_ENCODED_LEN,
    COMPONENT_GRAPH_VERSION_AUTHENTICATION_MAGIC,
    COMPONENT_GRAPH_VERSION_AUTHENTICATION_OBJECT_KIND_RAW,
    COMPONENT_GRAPH_VERSION_AUTHENTICATION_VERSION, COMPONENT_GRAPH_VERSION_ED25519_SIGNATURE_LEN,
    COMPONENT_GRAPH_VERSION_OBJECT_KIND_RAW, COMPONENT_GRAPH_VERSION_OPERATOR_PUBLIC_KEY_LEN,
};

const KEY: [u8; COMPONENT_GRAPH_VERSION_OPERATOR_PUBLIC_KEY_LEN] =
    [0x46; COMPONENT_GRAPH_VERSION_OPERATOR_PUBLIC_KEY_LEN];
const SIGNATURE: [u8; COMPONENT_GRAPH_VERSION_ED25519_SIGNATURE_LEN] =
    [0xb7; COMPONENT_GRAPH_VERSION_ED25519_SIGNATURE_LEN];

fn evidence() -> ComponentGraphVersionAuthenticationEvidenceV1 {
    ComponentGraphVersionAuthenticationEvidenceV1::new(KEY, SIGNATURE).unwrap()
}

#[test]
fn graph_evidence_exact_wire_round_trips_and_is_inert() {
    let evidence = evidence();
    let encoded = evidence.encode();
    assert_eq!(
        encoded.len(),
        COMPONENT_GRAPH_VERSION_AUTHENTICATION_ENCODED_LEN
    );
    assert_eq!(&encoded[..8], &COMPONENT_GRAPH_VERSION_AUTHENTICATION_MAGIC);
    assert_eq!(u16::from_le_bytes(encoded[8..10].try_into().unwrap()), 1);
    assert_eq!(
        u16::from_le_bytes(encoded[10..12].try_into().unwrap()),
        COMPONENT_GRAPH_VERSION_AUTHENTICATION_ENCODED_LEN as u16
    );
    assert_eq!(u16::from_le_bytes(encoded[12..14].try_into().unwrap()), 1);
    assert_eq!(u16::from_le_bytes(encoded[14..16].try_into().unwrap()), 0);
    assert_eq!(&encoded[16..48], &KEY);
    assert_eq!(&encoded[48..], &SIGNATURE);

    let decoded = ComponentGraphVersionAuthenticationEvidenceV1::decode(&encoded).unwrap();
    assert_eq!(decoded, evidence);
    assert_eq!(decoded.encode(), encoded);
    assert_eq!(decoded.encoded_len(), 112);
    assert_eq!(
        decoded.algorithm(),
        ComponentGraphVersionAuthenticationAlgorithm::Ed25519
    );
    assert_eq!(decoded.public_key().to_bytes(), KEY);
    assert_eq!(decoded.signature().to_bytes(), SIGNATURE);
    assert!(!decoded.runtime_ready());
}

#[test]
fn graph_and_artifact_evidence_are_domain_separated() {
    let graph = evidence().encode();
    let artifact = ComponentArtifactAuthenticationEvidenceV1::new(KEY, SIGNATURE)
        .unwrap()
        .encode();
    assert_eq!(graph.len(), COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN);
    assert_ne!(&graph[..8], &artifact[..8]);
    assert!(ComponentArtifactAuthenticationEvidenceV1::decode(&graph).is_err());
    assert!(ComponentGraphVersionAuthenticationEvidenceV1::decode(&artifact).is_err());
    assert_ne!(
        COMPONENT_GRAPH_VERSION_AUTHENTICATION_OBJECT_KIND_RAW,
        COMPONENT_GRAPH_VERSION_OBJECT_KIND_RAW
    );
}

#[test]
fn every_prefix_suffix_and_trailing_byte_is_rejected() {
    let encoded = evidence().encode();
    for length in 0..encoded.len() {
        assert_eq!(
            ComponentGraphVersionAuthenticationEvidenceV1::decode(&encoded[..length]),
            Err(ComponentGraphVersionAuthenticationError::EncodedLength { actual: length })
        );
    }
    for start in 1..encoded.len() {
        let suffix = &encoded[start..];
        assert_eq!(
            ComponentGraphVersionAuthenticationEvidenceV1::decode(suffix),
            Err(ComponentGraphVersionAuthenticationError::EncodedLength {
                actual: suffix.len()
            })
        );
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert_eq!(
        ComponentGraphVersionAuthenticationEvidenceV1::decode(&trailing),
        Err(ComponentGraphVersionAuthenticationError::EncodedLength { actual: 113 })
    );
}

#[test]
fn every_header_field_and_zero_sentinel_is_fail_closed() {
    let encoded = evidence().encode();
    for (offset, replacement, expected) in [
        (0, 0_u16, ComponentGraphVersionAuthenticationError::Magic),
        (
            8,
            2,
            ComponentGraphVersionAuthenticationError::Version { actual: 2 },
        ),
        (
            10,
            111,
            ComponentGraphVersionAuthenticationError::DeclaredLength { actual: 111 },
        ),
        (
            12,
            2,
            ComponentGraphVersionAuthenticationError::Algorithm { actual: 2 },
        ),
        (
            14,
            1,
            ComponentGraphVersionAuthenticationError::Flags { actual: 1 },
        ),
    ] {
        let mut mutated = encoded;
        if offset == 0 {
            mutated[0] ^= 1;
        } else {
            mutated[offset..offset + 2].copy_from_slice(&replacement.to_le_bytes());
        }
        assert_eq!(
            ComponentGraphVersionAuthenticationEvidenceV1::decode(&mutated),
            Err(expected)
        );
    }

    assert_eq!(
        ComponentGraphVersionAuthenticationEvidenceV1::new([0; 32], SIGNATURE),
        Err(ComponentGraphVersionAuthenticationError::ZeroPublicKey)
    );
    assert_eq!(
        ComponentGraphVersionAuthenticationEvidenceV1::new(KEY, [0; 64]),
        Err(ComponentGraphVersionAuthenticationError::ZeroSignature)
    );
    assert_eq!(
        ComponentGraphVersionOperatorPublicKey::from_bytes([0; 32]),
        Err(ComponentGraphVersionAuthenticationError::ZeroPublicKey)
    );
    assert_eq!(
        ComponentGraphVersionEd25519Signature::from_bytes([0; 64]),
        Err(ComponentGraphVersionAuthenticationError::ZeroSignature)
    );

    let mut zero_key = encoded;
    zero_key[16..48].fill(0);
    assert_eq!(
        ComponentGraphVersionAuthenticationEvidenceV1::decode(&zero_key),
        Err(ComponentGraphVersionAuthenticationError::ZeroPublicKey)
    );
    let mut zero_signature = encoded;
    zero_signature[48..].fill(0);
    assert_eq!(
        ComponentGraphVersionAuthenticationEvidenceV1::decode(&zero_signature),
        Err(ComponentGraphVersionAuthenticationError::ZeroSignature)
    );
}

#[test]
fn graph_evidence_debug_redacts_key_and_signature() {
    let evidence = evidence();
    let debug = format!("{evidence:?}");
    assert!(debug.contains("ComponentGraphVersionAuthenticationEvidenceV1"));
    assert!(debug.contains("<redacted>"));
    assert!(debug.contains("runtime_ready: false"));
    assert!(!debug.contains(&format!("{KEY:?}")));
    assert!(!debug.contains(&format!("{SIGNATURE:?}")));
    assert_eq!(
        format!("{:?}", evidence.public_key()),
        "ComponentGraphVersionOperatorPublicKey(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", evidence.signature()),
        "ComponentGraphVersionEd25519Signature(<redacted>)"
    );
}

#[test]
fn graph_evidence_public_constants_freeze_v1() {
    assert_eq!(COMPONENT_GRAPH_VERSION_AUTHENTICATION_MAGIC, *b"VIBEGSG\0");
    assert_eq!(COMPONENT_GRAPH_VERSION_AUTHENTICATION_VERSION, 1);
    assert_eq!(COMPONENT_GRAPH_VERSION_AUTHENTICATION_ENCODED_LEN, 112);
    assert_eq!(
        COMPONENT_GRAPH_VERSION_AUTHENTICATION_OBJECT_KIND_RAW,
        0x4347_4531
    );
    assert_eq!(COMPONENT_GRAPH_VERSION_OPERATOR_PUBLIC_KEY_LEN, 32);
    assert_eq!(COMPONENT_GRAPH_VERSION_ED25519_SIGNATURE_LEN, 64);
}
