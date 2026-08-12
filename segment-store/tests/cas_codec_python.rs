use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use vibeos_segment_format::{ExtentKind, PAGE_SIZE, PhysicalPointer, PointerValue, StoreUuid};
use vibeos_segment_store::{
    BlobKey, BlobManifest, BlobMapping, CANONICAL_CONTENT_EXTENT_LEN, CasCodecContext, CasDelta,
    CasSnapshot, ManifestExtent, ObjectMapping, encode_blob_key, encode_blob_manifest,
    encode_cas_delta, encode_cas_snapshot,
};

fn pointer(
    uuid: StoreUuid,
    segment: u64,
    generation: u64,
    len: u64,
    kind: ExtentKind,
    digest: u8,
) -> PhysicalPointer {
    PhysicalPointer::Value(PointerValue {
        store_uuid: uuid,
        segment_no: segment,
        segment_generation: generation,
        descriptor_relative_page: 2,
        payload_relative_page: 4,
        payload_pages: u32::try_from(len.div_ceil(PAGE_SIZE as u64)).unwrap(),
        ordinal: 1,
        exact_byte_len: len,
        extent_kind: kind,
        payload_sha256: [digest; 32],
    })
}

fn fixture_dir() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("vibeos-cas-abi-{}-{unique}", std::process::id()))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[(byte >> 4) as usize] as char);
        value.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    value
}

fn write_fixture(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir(path)?;
    let uuid = StoreUuid::new(*b"cas-python-abi!!").unwrap();
    let context = CasCodecContext::new(uuid, 128, 200).unwrap();
    let blob_key = BlobKey::sha256(0x424c_4f42, 1_100_000, [0xa5; 32]).unwrap();
    let encoded_len = vibeos_blob_format::BlobGeometry::for_len(blob_key.exact_len())
        .expect("fixture Blob geometry must be canonical")
        .encoded_len() as u64;
    let content_count =
        usize::try_from(blob_key.exact_len())?.div_ceil(CANONICAL_CONTENT_EXTENT_LEN as usize);
    let extent_count = content_count + 2;
    let mut offset = 0_u64;
    let mut extents = Vec::new();
    for index in 0..extent_count {
        let len = if index == 0 {
            vibeos_blob_format::HEADER_SIZE as u64
        } else if index <= content_count {
            blob_key
                .exact_len()
                .saturating_sub((index as u64 - 1) * CANONICAL_CONTENT_EXTENT_LEN)
                .min(CANONICAL_CONTENT_EXTENT_LEN)
        } else {
            encoded_len - offset
        };
        extents.push(ManifestExtent {
            extent_index: index as u32,
            extent_count: extent_count as u32,
            encoded_offset: offset,
            payload_byte_len: len,
            pointer: pointer(
                uuid,
                index as u64 + 1,
                index as u64 + 10,
                len,
                ExtentKind::Blob,
                index as u8 + 1,
            ),
        });
        offset += len;
    }
    let manifest = BlobManifest {
        blob_key,
        encoded_blob_len: encoded_len,
        extents,
    };
    let manifest_bytes =
        encode_blob_manifest(&manifest, context).expect("fixture manifest must encode");
    let manifest_pointer = pointer(
        uuid,
        20,
        40,
        manifest_bytes.len() as u64,
        ExtentKind::Catalog,
        20,
    );
    let mapping = BlobMapping {
        blob_key,
        manifest: manifest_pointer,
    };
    let snapshot_id = 0x00012233445566778899aabbccddeeff_u128;
    let first_id = 0x00112233445566778899aabbccddeeff_u128;
    let second_id = 0x102132435465768798a9bacbdcedfe0f_u128;
    let first = ObjectMapping {
        object_id: snapshot_id,
        blob_key,
        commit_generation: 1,
    };
    let snapshot = CasSnapshot {
        checkpoint_generation: 2,
        objects: vec![first],
        blobs: vec![mapping],
    };
    let first_delta = CasDelta {
        checkpoint_generation: 2,
        chain_count: 1,
        previous_delta: PhysicalPointer::Null,
        object: ObjectMapping {
            object_id: first_id,
            commit_generation: 2,
            ..first
        },
        new_blob: Some(mapping),
    };
    let previous = pointer(
        uuid,
        21,
        41,
        vibeos_segment_store::CAS_DELTA_NEW_BLOB_LEN as u64,
        ExtentKind::CatalogDelta,
        21,
    );
    let reuse_delta = CasDelta {
        checkpoint_generation: 3,
        chain_count: 2,
        previous_delta: previous,
        object: ObjectMapping {
            object_id: second_id,
            blob_key,
            commit_generation: 3,
        },
        new_blob: None,
    };

    fs::write(
        path.join("snapshot.bin"),
        encode_cas_snapshot(&snapshot, context).expect("fixture snapshot must encode"),
    )?;
    fs::write(path.join("manifest.bin"), manifest_bytes)?;
    fs::write(
        path.join("delta-new.bin"),
        encode_cas_delta(first_delta, context).expect("fixture new-Blob delta must encode"),
    )?;
    fs::write(
        path.join("delta-reuse.bin"),
        encode_cas_delta(reuse_delta, context).expect("fixture reuse delta must encode"),
    )?;
    let metadata = format!(
        concat!(
            "{{\"format\":\"vibeos-storage-v2-cas-abi\",\"version\":1,",
            "\"store_uuid\":\"{}\",\"admitted_segments\":128,",
            "\"next_segment_generation\":200,\"blob_key\":\"{}\",",
            "\"object_ids\":[\"{}\",\"{}\"]}}"
        ),
        hex(uuid.as_bytes()),
        hex(&encode_blob_key(blob_key).expect("fixture BlobKey must encode")),
        hex(&first_id.to_le_bytes()),
        hex(&second_id.to_le_bytes()),
    );
    fs::write(path.join("context.json"), metadata)?;
    Ok(())
}

#[test]
fn rust_cas_codec_payloads_are_accepted_by_python_abi_verifier() {
    let path = fixture_dir();
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        write_fixture(&path)?;
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let output = Command::new("python3")
            .arg("-B")
            .arg(repository.join("scripts/verify-storage-v2-cas.py"))
            .arg("--abi-fixture")
            .arg(&path)
            .output()?;
        let stdout = String::from_utf8(output.stdout)?;
        assert!(
            output.status.success(),
            "Python CAS verifier rejected Rust codec payloads: {stdout}"
        );
        assert!(stdout.contains("\"status\":\"ok\""), "{stdout}");
        assert!(stdout.contains("\"extent_count\":4"), "{stdout}");
        Ok(())
    })();
    let _ = fs::remove_dir_all(&path);
    result.unwrap();
}
