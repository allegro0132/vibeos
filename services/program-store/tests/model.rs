use vibeos_durable_format::{
    DerivationId, GrantFlags, GrantRecord, ObjectId, RootPolicy, RootRightsConstraint, SlotIdentity,
};
use vibeos_program_store::{
    program_root_constraint, program_root_policy_is_exact, sha256, ProgramArtifact,
    ProgramArtifactError, MAX_PROGRAM_EXECUTABLE_BYTES, PROGRAM_ALIAS, PROGRAM_ARTIFACT_HEADER_LEN,
    PROGRAM_ROOT_GENERATION, PROGRAM_ROOT_RIGHTS, PROGRAM_ROOT_SLOT,
};

fn artifact() -> ProgramArtifact {
    ProgramArtifact::new("fn main() { println!(\"hello\"); }\n", b"VIBEEXE\0fixture").unwrap()
}

#[test]
fn sha256_matches_standard_vectors() {
    assert_eq!(
        sha256(b""),
        hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    assert_eq!(
        sha256(b"abc"),
        hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn artifact_is_deterministic_canonical_and_round_trips() {
    let first = artifact().encode();
    let second = artifact().encode();
    assert_eq!(first, second);
    let decoded = ProgramArtifact::decode(&first).unwrap();
    assert_eq!(decoded, artifact());
    assert_eq!(decoded.encode(), first);
}

#[test]
fn every_strict_prefix_and_trailing_suffix_is_rejected() {
    let encoded = artifact().encode();
    for end in 0..encoded.len() {
        assert!(
            ProgramArtifact::decode(&encoded[..end]).is_err(),
            "accepted prefix {end}"
        );
    }
    for extra in 1..=16 {
        let mut extended = encoded.clone();
        extended.resize(extended.len() + extra, 0);
        assert!(ProgramArtifact::decode(&extended).is_err());
    }
}

#[test]
fn header_authority_reserved_and_hash_mutations_fail_closed() {
    let encoded = artifact().encode();
    for offset in [
        0usize, 8, 10, 12, 16, 20, 24, 28, 32, 64, 96, 100, 104, 108, 112, 116, 120, 122, 124, 128,
        132, 134, 136, 141, 151, 159,
    ] {
        let mut corrupted = encoded.clone();
        corrupted[offset] ^= 1;
        assert!(
            ProgramArtifact::decode(&corrupted).is_err(),
            "accepted mutation at {offset}"
        );
    }
    let body = usize::from(PROGRAM_ARTIFACT_HEADER_LEN);
    for offset in [body, encoded.len() - 1] {
        let mut corrupted = encoded.clone();
        corrupted[offset] ^= 1;
        assert!(ProgramArtifact::decode(&corrupted).is_err());
    }
}

#[test]
fn fixed_program_root_constraint_matches_the_artifact_slot() {
    let constraint = program_root_constraint();
    assert_eq!(constraint.space, vibeos_program_store::program_space_id());
    assert_eq!(constraint.first_slot, PROGRAM_ROOT_SLOT);
    assert_eq!(constraint.last_slot_inclusive, PROGRAM_ROOT_SLOT);
    assert_eq!(
        constraint.rights,
        RootRightsConstraint::exact(PROGRAM_ROOT_RIGHTS)
    );
    assert_eq!(PROGRAM_ALIAS, "hello");

    let exact = RootPolicy {
        grant: GrantRecord {
            derivation_id: DerivationId::new(1).unwrap(),
            parent_id: None,
            object_id: ObjectId::new(2).unwrap(),
            target: SlotIdentity {
                space: constraint.space,
                slot: PROGRAM_ROOT_SLOT,
                generation: PROGRAM_ROOT_GENERATION,
            },
            rights: PROGRAM_ROOT_RIGHTS,
            resource_kind: constraint.resource_kind,
            flags: GrantFlags::ROOT,
        },
    };
    assert!(program_root_policy_is_exact(&exact));
    let mut reused = exact;
    reused.grant.target.generation = 1;
    assert!(!program_root_policy_is_exact(&reused));
}

#[test]
fn invalid_utf8_empty_fields_and_limits_are_rejected() {
    assert_eq!(
        ProgramArtifact::new("", b"x"),
        Err(ProgramArtifactError::EmptySource)
    );
    assert_eq!(
        ProgramArtifact::new("x", b""),
        Err(ProgramArtifactError::EmptyExecutable)
    );
    assert!(ProgramArtifact::new("x", &vec![0; MAX_PROGRAM_EXECUTABLE_BYTES + 1]).is_err());

    let mut encoded = artifact().encode();
    let body = usize::from(PROGRAM_ARTIFACT_HEADER_LEN);
    encoded[body] = 0xff;
    let source_hash = sha256(
        &encoded[body..body + u32::from_le_bytes(encoded[20..24].try_into().unwrap()) as usize],
    );
    encoded[32..64].copy_from_slice(&source_hash);
    assert_eq!(
        ProgramArtifact::decode(&encoded),
        Err(ProgramArtifactError::Utf8)
    );
}

fn hex(value: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    out
}
