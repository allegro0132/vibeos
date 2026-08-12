use std::{
    fmt::Debug,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use vibeos_blob_format::{BlobDescriptor, BlobGeometry, HASH_SIZE, HEADER_SIZE};
use vibeos_segment_format::{
    encode_physical_pointer, payload_sha256, ExtentKind, PhysicalPointer, PointerValue, StoreUuid,
    PAGE_SIZE,
};
use vibeos_segment_store::{
    encode_allocation_v2, encode_blob_key, encode_cas_snapshot, encode_persistent_root_set,
    encode_typed_manifest_refs_v1, AllocationV2, BlobKey, BlobMapping, CasCodecContext,
    CasSnapshot, ObjectMapping, PersistentRootEntry, PersistentRootSet, RetiredSegment,
    SegmentAllocation, TypedManifestRefsV1, TypedObjectReference, CAS_SNAPSHOT_HEADER_LEN,
    OBJECT_MAPPING_LEN, REFERENCE_CODEC_TYPED_V1,
};

const MANIFEST_KIND: u32 = 0x44;

fn fixture_error(error: impl Debug) -> io::Error {
    io::Error::other(format!("{error:?}"))
}

fn fixture_dir() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("vibeos-gc-abi-{}-{unique}", std::process::id()))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn pointer(
    store_uuid: StoreUuid,
    segment_no: u64,
    segment_generation: u64,
    exact_len: usize,
    extent_kind: ExtentKind,
    digest: [u8; 32],
) -> PhysicalPointer {
    pointer_at(
        store_uuid,
        segment_no,
        segment_generation,
        2,
        4,
        1,
        exact_len,
        extent_kind,
        digest,
    )
}

#[allow(clippy::too_many_arguments)]
fn pointer_at(
    store_uuid: StoreUuid,
    segment_no: u64,
    segment_generation: u64,
    descriptor_relative_page: u32,
    payload_relative_page: u32,
    ordinal: u32,
    exact_len: usize,
    extent_kind: ExtentKind,
    digest: [u8; 32],
) -> PhysicalPointer {
    PhysicalPointer::Value(PointerValue {
        store_uuid,
        segment_no,
        segment_generation,
        descriptor_relative_page,
        payload_relative_page,
        payload_pages: u32::try_from(exact_len.div_ceil(PAGE_SIZE)).unwrap(),
        ordinal,
        exact_byte_len: exact_len as u64,
        extent_kind,
        payload_sha256: digest,
    })
}

fn extent_evidence_json(
    blob_key: &[u8; 0x40],
    encoded_blob_len: usize,
    extent_index: u32,
    encoded_offset: usize,
    payload_byte_len: usize,
    pointer: PhysicalPointer,
) -> String {
    format!(
        concat!(
            "{{\"blob_key\":\"{}\",\"encoded_blob_len\":{},",
            "\"extent_index\":{},\"extent_count\":3,\"encoded_offset\":{},",
            "\"payload_byte_len\":{},\"pointer\":\"{}\"}}"
        ),
        hex(blob_key),
        encoded_blob_len,
        extent_index,
        encoded_offset,
        payload_byte_len,
        hex(&pointer_bytes(pointer)),
    )
}

fn pointer_bytes(pointer: PhysicalPointer) -> [u8; 0x60] {
    let mut output = [0; 0x60];
    encode_physical_pointer(pointer, &mut output).unwrap();
    output
}

fn run_verifier(repository: &Path, fixture: &Path) -> std::process::Output {
    Command::new("python3")
        .arg("-B")
        .arg(repository.join("scripts/verify-storage-v2-gc.py"))
        .arg("--abi-fixture")
        .arg(fixture)
        .output()
        .unwrap()
}

fn write_fixture(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir(path)?;
    let store_uuid = StoreUuid::new(*b"gc-python-abi!!!").unwrap();
    let g = AllocationV2::new(
        10,
        20,
        3,
        &[
            SegmentAllocation::Allocated,
            SegmentAllocation::Allocated,
            SegmentAllocation::Free,
            SegmentAllocation::Free,
            SegmentAllocation::Free,
            SegmentAllocation::Free,
        ],
        &[],
    )?;
    let g1 = AllocationV2::new(
        11,
        21,
        3,
        &[
            SegmentAllocation::Retired,
            SegmentAllocation::Allocated,
            SegmentAllocation::Allocated,
            SegmentAllocation::Free,
            SegmentAllocation::Free,
            SegmentAllocation::Free,
        ],
        &[RetiredSegment {
            segment_no: 0,
            retire_generation: 11,
        }],
    )?;
    let g2 = AllocationV2::new(
        12,
        22,
        3,
        &[
            SegmentAllocation::Free,
            SegmentAllocation::Allocated,
            SegmentAllocation::Allocated,
            SegmentAllocation::Allocated,
            SegmentAllocation::Free,
            SegmentAllocation::Free,
        ],
        &[],
    )?;
    fs::write(path.join("allocation.bin"), encode_allocation_v2(&g2)?)?;
    fs::write(path.join("g.bin"), encode_allocation_v2(&g)?)?;
    fs::write(path.join("g1.bin"), encode_allocation_v2(&g1)?)?;
    fs::write(path.join("g2.bin"), encode_allocation_v2(&g2)?)?;
    fs::write(path.join("old-seal.bin"), [0_u8; PAGE_SIZE])?;

    let roots = PersistentRootSet::new(
        12,
        vec![PersistentRootEntry {
            object_id: 1,
            commit_generation: 12,
            object_kind: MANIFEST_KIND,
        }],
    )?;
    let root_bytes = encode_persistent_root_set(&roots)?;
    fs::write(path.join("roots.bin"), &root_bytes)?;
    let authority = pointer(
        store_uuid,
        2,
        21,
        root_bytes.len(),
        ExtentKind::Authority,
        payload_sha256(&root_bytes),
    );

    let typed = TypedManifestRefsV1::new(
        MANIFEST_KIND,
        12,
        vec![TypedObjectReference {
            object_id: 2,
            commit_generation: 9,
            object_kind: 0x51,
        }],
    )?;
    let typed_bytes = encode_typed_manifest_refs_v1(&typed)?;
    fs::write(path.join("typed.bin"), &typed_bytes)?;
    let descriptor =
        BlobDescriptor::from_content(MANIFEST_KIND, &typed_bytes).map_err(fixture_error)?;
    let blob_key = BlobKey::sha256(MANIFEST_KIND, typed_bytes.len() as u64, descriptor.root)
        .map_err(fixture_error)?;
    let blob_key_bytes = encode_blob_key(blob_key).map_err(fixture_error)?;
    let blob_geometry = BlobGeometry::for_len(typed_bytes.len() as u64).map_err(fixture_error)?;
    let tree_len = usize::try_from(descriptor.tree_node_count)
        .map_err(fixture_error)?
        .checked_mul(HASH_SIZE)
        .ok_or_else(|| io::Error::other("fixture tree length overflow"))?;
    let g_header = pointer_at(
        store_uuid,
        0,
        10,
        2,
        4,
        1,
        HEADER_SIZE,
        ExtentKind::Blob,
        [0x10; 32],
    );
    let g_content = pointer_at(
        store_uuid,
        0,
        10,
        5,
        7,
        2,
        typed_bytes.len(),
        ExtentKind::Blob,
        [0x20; 32],
    );
    let stable_tree = pointer_at(
        store_uuid,
        1,
        11,
        2,
        4,
        1,
        tree_len,
        ExtentKind::Blob,
        [0x30; 32],
    );
    let g1_header = pointer_at(
        store_uuid,
        2,
        20,
        2,
        4,
        1,
        HEADER_SIZE,
        ExtentKind::Blob,
        [0x10; 32],
    );
    let g1_content = pointer_at(
        store_uuid,
        2,
        20,
        5,
        7,
        2,
        typed_bytes.len(),
        ExtentKind::Blob,
        [0x20; 32],
    );
    let g_evidence = [
        extent_evidence_json(
            &blob_key_bytes,
            blob_geometry.encoded_len(),
            0,
            0,
            HEADER_SIZE,
            g_header,
        ),
        extent_evidence_json(
            &blob_key_bytes,
            blob_geometry.encoded_len(),
            1,
            HEADER_SIZE,
            typed_bytes.len(),
            g_content,
        ),
        extent_evidence_json(
            &blob_key_bytes,
            blob_geometry.encoded_len(),
            2,
            HEADER_SIZE + typed_bytes.len(),
            tree_len,
            stable_tree,
        ),
    ]
    .join(",");
    let g1_evidence = [
        extent_evidence_json(
            &blob_key_bytes,
            blob_geometry.encoded_len(),
            0,
            0,
            HEADER_SIZE,
            g1_header,
        ),
        extent_evidence_json(
            &blob_key_bytes,
            blob_geometry.encoded_len(),
            1,
            HEADER_SIZE,
            typed_bytes.len(),
            g1_content,
        ),
        extent_evidence_json(
            &blob_key_bytes,
            blob_geometry.encoded_len(),
            2,
            HEADER_SIZE + typed_bytes.len(),
            tree_len,
            stable_tree,
        ),
    ]
    .join(",");
    let manifest_pointer = pointer(store_uuid, 1, 20, 0x200, ExtentKind::Catalog, [0x5a; 32]);
    let snapshot = CasSnapshot {
        checkpoint_generation: 12,
        objects: vec![ObjectMapping {
            object_id: 1,
            blob_key,
            commit_generation: 12,
            reference_codec: REFERENCE_CODEC_TYPED_V1,
        }],
        blobs: vec![BlobMapping {
            blob_key,
            manifest: manifest_pointer,
        }],
    };
    let context = CasCodecContext::new(store_uuid, 6, 22).map_err(fixture_error)?;
    let snapshot_bytes = encode_cas_snapshot(&snapshot, context).map_err(fixture_error)?;
    fs::write(
        path.join("object.bin"),
        &snapshot_bytes[CAS_SNAPSHOT_HEADER_LEN..CAS_SNAPSHOT_HEADER_LEN + OBJECT_MAPPING_LEN],
    )?;

    let context_json = format!(
        concat!(
            "{{\"format\":\"vibeos-storage-v2-gc-abi\",\"version\":1,",
            "\"store_uuid\":\"{}\",\"allocation\":\"allocation.bin\",",
            "\"persistent_roots\":\"roots.bin\",\"authority_root\":\"{}\",",
            "\"typed_reference_kinds\":[68],",
            "\"current_pointers\":[{{\"name\":\"manifest\",\"extent_kind\":2,",
            "\"pointer\":\"{}\"}}],",
            "\"typed_manifests\":[{{\"object_mapping\":\"object.bin\",",
            "\"payload\":\"typed.bin\"}}],",
            "\"barrier\":{{\"g\":\"g.bin\",\"g1\":\"g1.bin\",",
            "\"g2\":\"g2.bin\",\"g1_allocate\":[2],\"g1_retire\":[0],",
            "\"g2_allocate\":[3],\"g2_reclaim\":[0],",
            "\"old_checkpoint_seal\":\"old-seal.bin\",",
            "\"pinned_generations\":[11,12],",
            "\"live_blob_keys\":[\"{}\"],",
            "\"g_blob_extent_pointers\":[{}],",
            "\"g1_blob_extent_pointers\":[{}]}}}}"
        ),
        hex(store_uuid.as_bytes()),
        hex(&pointer_bytes(authority)),
        hex(&pointer_bytes(manifest_pointer)),
        hex(&blob_key_bytes),
        g_evidence,
        g1_evidence,
    );
    fs::write(path.join("context.json"), context_json)?;
    Ok(())
}

#[test]
fn rust_gc_codec_payloads_are_accepted_and_payload_mutation_fails_closed() {
    let path = fixture_dir();
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        write_fixture(&path)?;
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let accepted = run_verifier(repository, &path);
        let accepted_stdout = String::from_utf8(accepted.stdout)?;
        assert!(
            accepted.status.success(),
            "Python GC verifier rejected Rust payloads: {accepted_stdout}"
        );
        assert!(accepted_stdout.contains("\"status\":\"ok\""));
        assert!(accepted_stdout.contains("\"barrier_state\":\"G+2\""));

        let mut corrupt = fs::read(path.join("typed.bin"))?;
        *corrupt.last_mut().unwrap() ^= 1;
        fs::write(path.join("typed.bin"), corrupt)?;
        let rejected = run_verifier(repository, &path);
        let rejected_stdout = String::from_utf8(rejected.stdout)?;
        assert!(!rejected.status.success(), "{rejected_stdout}");
        assert!(rejected_stdout.contains("\"status\":\"corrupt\""));
        Ok(())
    })();
    let _ = fs::remove_dir_all(&path);
    result.unwrap();
}
