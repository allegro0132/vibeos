use std::{
    fs::{self, File},
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    process::Command,
};

use vibeos_segment_format::{
    admitted_pages, encode_checkpoint_body, encode_record_seal, encode_superblock_body, Checkpoint,
    FormatGeometry, Page, PhysicalPointer, RecordBinding, StoreUuid, Superblock, ANCHOR_SEGMENT_NO,
    PAGE_SIZE,
};

fn uuid() -> StoreUuid {
    StoreUuid::new(*b"rust-python-v2!!").unwrap()
}

fn binding(
    generation: u64,
    ordinal: u32,
    self_page: u64,
    target_checkpoint_generation: u64,
) -> RecordBinding {
    RecordBinding {
        store_uuid: uuid(),
        generation,
        segment_no: ANCHOR_SEGMENT_NO,
        ordinal,
        self_page,
        target_checkpoint_generation,
    }
}

fn superblock(copy: u8) -> Superblock {
    let segments = 2;
    let pages = admitted_pages(segments).unwrap();
    Superblock {
        binding: binding(1, u32::from(copy), u64::from(copy) * 2, 0),
        copy,
        geometry: FormatGeometry::STORAGE_V2,
        cleaner_reserve_segments: 1,
        initial_range_pages: pages,
        initial_segments: segments,
        device_id: *b"python-fixture!!",
        range_first_logical_block: 0,
        initial_block_count: pages * 8,
        logical_block_size: 512,
        max_replay_records: 64,
    }
}

fn checkpoint() -> Checkpoint {
    Checkpoint {
        binding: binding(1, 0, 4, 1),
        slot: 0,
        previous_generation: 0,
        admitted_range_pages: admitted_pages(2).unwrap(),
        admitted_segments: 2,
        next_segment_generation: 1,
        replay_count: 0,
        max_replay_records: 64,
        cleaner_reserve_segments: 1,
        catalog_root: PhysicalPointer::Null,
        authority_root: PhysicalPointer::Null,
        allocation_root: PhysicalPointer::Null,
        replay_tail: PhysicalPointer::Null,
    }
}

fn write_pair(file: &mut File, body_page: u64, body: &Page, seal: &Page) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(body_page * PAGE_SIZE as u64))?;
    file.write_all(body)?;
    file.write_all(seal)
}

fn fixture_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "vibeos-storage-v2-rust-python-{}.img",
        std::process::id()
    ))
}

#[test]
fn rust_encoded_anchor_is_accepted_by_independent_python_parser() {
    let path = fixture_path();
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut file = File::create(&path)?;
        file.set_len(admitted_pages(2)? * PAGE_SIZE as u64)?;

        for copy in [0_u8, 1] {
            let mut body = [0; PAGE_SIZE];
            let digest = encode_superblock_body(&superblock(copy), &mut body)?;
            let mut seal = [0; PAGE_SIZE];
            encode_record_seal(digest, &mut seal)?;
            write_pair(&mut file, u64::from(copy) * 2, &body, &seal)?;
        }

        let mut body = [0; PAGE_SIZE];
        let digest = encode_checkpoint_body(&checkpoint(), &mut body)?;
        let mut seal = [0; PAGE_SIZE];
        encode_record_seal(digest, &mut seal)?;
        write_pair(&mut file, 4, &body, &seal)?;
        file.sync_all()?;

        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("scripts")
            .join("storage-v2-image.py");
        let output = Command::new("python3")
            .arg("-B")
            .arg(script)
            .arg(&path)
            .output()?;
        assert!(
            output.status.success(),
            "parser rejected Rust fixture: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let json = String::from_utf8(output.stdout)?;
        assert!(
            json.contains("\"status\":\"ok\""),
            "unexpected parser result: {json}"
        );
        Ok(())
    })();
    let _ = fs::remove_file(&path);
    result.unwrap();
}
