use vibeos_component_format::{
    ComponentArtifactAuthenticationAlgorithm, ComponentArtifactAuthenticationError,
    ComponentArtifactAuthenticationEvidenceV1, ComponentArtifactEd25519Signature,
    ComponentArtifactOperatorPublicKey, COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN,
    COMPONENT_ARTIFACT_AUTHENTICATION_MAGIC, COMPONENT_ARTIFACT_AUTHENTICATION_VERSION,
    COMPONENT_ARTIFACT_ED25519_SIGNATURE_LEN, COMPONENT_ARTIFACT_OPERATOR_PUBLIC_KEY_LEN,
};

const KEY: [u8; COMPONENT_ARTIFACT_OPERATOR_PUBLIC_KEY_LEN] =
    [0x31; COMPONENT_ARTIFACT_OPERATOR_PUBLIC_KEY_LEN];
const SIGNATURE: [u8; COMPONENT_ARTIFACT_ED25519_SIGNATURE_LEN] =
    [0xa7; COMPONENT_ARTIFACT_ED25519_SIGNATURE_LEN];

fn evidence() -> ComponentArtifactAuthenticationEvidenceV1 {
    ComponentArtifactAuthenticationEvidenceV1::new(KEY, SIGNATURE).unwrap()
}

#[test]
fn exact_wire_round_trips_without_allocation_or_trailing_data() {
    let evidence = evidence();
    let encoded = evidence.encode();

    assert_eq!(encoded.len(), COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN);
    assert_eq!(&encoded[0..8], &COMPONENT_ARTIFACT_AUTHENTICATION_MAGIC);
    assert_eq!(u16::from_le_bytes(encoded[8..10].try_into().unwrap()), 1);
    assert_eq!(
        u16::from_le_bytes(encoded[10..12].try_into().unwrap()),
        COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN as u16
    );
    assert_eq!(u16::from_le_bytes(encoded[12..14].try_into().unwrap()), 1);
    assert_eq!(u16::from_le_bytes(encoded[14..16].try_into().unwrap()), 0);
    assert_eq!(&encoded[16..48], &KEY);
    assert_eq!(&encoded[48..112], &SIGNATURE);

    let decoded = ComponentArtifactAuthenticationEvidenceV1::decode(&encoded).unwrap();
    assert_eq!(decoded, evidence);
    assert_eq!(decoded.encode(), encoded);
    assert_eq!(decoded.encoded_len(), 112);
    assert_eq!(
        decoded.algorithm(),
        ComponentArtifactAuthenticationAlgorithm::Ed25519
    );
    assert_eq!(decoded.algorithm().as_raw(), 1);
    assert_eq!(decoded.public_key().as_bytes(), &KEY);
    assert_eq!(decoded.public_key().to_bytes(), KEY);
    assert_eq!(decoded.signature().as_bytes(), &SIGNATURE);
    assert_eq!(decoded.signature().to_bytes(), SIGNATURE);
}

#[test]
fn every_prefix_suffix_and_trailing_byte_is_rejected_by_exact_length() {
    let encoded = evidence().encode();
    for length in 0..encoded.len() {
        assert_eq!(
            ComponentArtifactAuthenticationEvidenceV1::decode(&encoded[..length]),
            Err(ComponentArtifactAuthenticationError::EncodedLength { actual: length })
        );
    }
    for start in 1..encoded.len() {
        let suffix = &encoded[start..];
        assert_eq!(
            ComponentArtifactAuthenticationEvidenceV1::decode(suffix),
            Err(ComponentArtifactAuthenticationError::EncodedLength {
                actual: suffix.len()
            })
        );
    }

    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert_eq!(
        ComponentArtifactAuthenticationEvidenceV1::decode(&trailing),
        Err(ComponentArtifactAuthenticationError::EncodedLength { actual: 113 })
    );
}

#[test]
fn header_version_algorithm_flags_and_declared_length_are_exact() {
    let encoded = evidence().encode();

    let mut wrong = encoded;
    wrong[0] ^= 1;
    assert_eq!(
        ComponentArtifactAuthenticationEvidenceV1::decode(&wrong),
        Err(ComponentArtifactAuthenticationError::Magic)
    );

    let mut wrong = encoded;
    wrong[8..10].copy_from_slice(&2_u16.to_le_bytes());
    assert_eq!(
        ComponentArtifactAuthenticationEvidenceV1::decode(&wrong),
        Err(ComponentArtifactAuthenticationError::Version { actual: 2 })
    );

    let mut wrong = encoded;
    wrong[10..12].copy_from_slice(&111_u16.to_le_bytes());
    assert_eq!(
        ComponentArtifactAuthenticationEvidenceV1::decode(&wrong),
        Err(ComponentArtifactAuthenticationError::DeclaredLength { actual: 111 })
    );

    let mut wrong = encoded;
    wrong[12..14].copy_from_slice(&0_u16.to_le_bytes());
    assert_eq!(
        ComponentArtifactAuthenticationEvidenceV1::decode(&wrong),
        Err(ComponentArtifactAuthenticationError::Algorithm { actual: 0 })
    );

    let mut wrong = encoded;
    wrong[12..14].copy_from_slice(&2_u16.to_le_bytes());
    assert_eq!(
        ComponentArtifactAuthenticationEvidenceV1::decode(&wrong),
        Err(ComponentArtifactAuthenticationError::Algorithm { actual: 2 })
    );

    let mut wrong = encoded;
    wrong[14..16].copy_from_slice(&1_u16.to_le_bytes());
    assert_eq!(
        ComponentArtifactAuthenticationEvidenceV1::decode(&wrong),
        Err(ComponentArtifactAuthenticationError::Flags { actual: 1 })
    );
}

#[test]
fn zero_key_and_signature_sentinels_fail_at_construction_and_decode() {
    assert_eq!(
        ComponentArtifactAuthenticationEvidenceV1::new([0; 32], SIGNATURE),
        Err(ComponentArtifactAuthenticationError::ZeroPublicKey)
    );
    assert_eq!(
        ComponentArtifactAuthenticationEvidenceV1::new(KEY, [0; 64]),
        Err(ComponentArtifactAuthenticationError::ZeroSignature)
    );
    assert_eq!(
        ComponentArtifactOperatorPublicKey::from_bytes([0; 32]),
        Err(ComponentArtifactAuthenticationError::ZeroPublicKey)
    );
    assert_eq!(
        ComponentArtifactEd25519Signature::from_bytes([0; 64]),
        Err(ComponentArtifactAuthenticationError::ZeroSignature)
    );

    let mut zero_key = evidence().encode();
    zero_key[16..48].fill(0);
    assert_eq!(
        ComponentArtifactAuthenticationEvidenceV1::decode(&zero_key),
        Err(ComponentArtifactAuthenticationError::ZeroPublicKey)
    );

    let mut zero_signature = evidence().encode();
    zero_signature[48..].fill(0);
    assert_eq!(
        ComponentArtifactAuthenticationEvidenceV1::decode(&zero_signature),
        Err(ComponentArtifactAuthenticationError::ZeroSignature)
    );
}

#[test]
fn debug_is_redacted_and_canonical_evidence_remains_inert() {
    let evidence = evidence();
    let debug = format!("{evidence:?}");
    let key_debug = format!("{:?}", evidence.public_key());
    let signature_debug = format!("{:?}", evidence.signature());

    assert!(debug.contains("ComponentArtifactAuthenticationEvidenceV1"));
    assert!(debug.contains("Ed25519"));
    assert!(debug.contains("<redacted>"));
    assert!(debug.contains("runtime_ready: false"));
    assert!(!debug.contains(&format!("{KEY:?}")));
    assert!(!debug.contains(&format!("{SIGNATURE:?}")));
    assert_eq!(key_debug, "ComponentArtifactOperatorPublicKey(<redacted>)");
    assert_eq!(
        signature_debug,
        "ComponentArtifactEd25519Signature(<redacted>)"
    );
    assert!(!evidence.runtime_ready());
}

#[test]
fn format_acceptance_does_not_claim_curve_or_signature_authenticity() {
    let structurally_only =
        ComponentArtifactAuthenticationEvidenceV1::new([0xff; 32], [0xff; 64]).unwrap();
    let decoded =
        ComponentArtifactAuthenticationEvidenceV1::decode(&structurally_only.encode()).unwrap();

    assert_eq!(decoded, structurally_only);
    assert!(!decoded.runtime_ready());
}

#[test]
fn public_constants_freeze_the_v1_contract() {
    assert_eq!(COMPONENT_ARTIFACT_AUTHENTICATION_MAGIC, *b"VIBESIG\0");
    assert_eq!(COMPONENT_ARTIFACT_AUTHENTICATION_VERSION, 1);
    assert_eq!(COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN, 112);
    assert_eq!(COMPONENT_ARTIFACT_OPERATOR_PUBLIC_KEY_LEN, 32);
    assert_eq!(COMPONENT_ARTIFACT_ED25519_SIGNATURE_LEN, 64);
}
