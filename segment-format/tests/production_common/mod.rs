#![allow(dead_code)]

use vibeos_segment_format::{
    admitted_pages, segment_base_page, Checkpoint, ExtentKind, ExtentRecord, FormatGeometry,
    PhysicalPointer, PointerValue, RecordBinding, SegmentHeader, SegmentSeal, SegmentSummary,
    StoreUuid, Superblock, ANCHOR_SEGMENT_NO, DATA_FIRST_PAGE, SEGMENT_SEAL_BODY_PAGE,
    SUMMARY_BODY_PAGE,
};

pub fn uuid() -> StoreUuid {
    StoreUuid::new(*b"storage-v2-tests").unwrap()
}

pub fn binding(
    generation: u64,
    segment_no: u64,
    ordinal: u32,
    self_page: u64,
    target_checkpoint_generation: u64,
) -> RecordBinding {
    RecordBinding {
        store_uuid: uuid(),
        generation,
        segment_no,
        ordinal,
        self_page,
        target_checkpoint_generation,
    }
}

pub fn superblock(copy: u8) -> Superblock {
    let segments = 4;
    Superblock {
        binding: binding(
            1,
            ANCHOR_SEGMENT_NO,
            u32::from(copy),
            u64::from(copy) * 2,
            0,
        ),
        copy,
        geometry: FormatGeometry::STORAGE_V2,
        cleaner_reserve_segments: 1,
        initial_range_pages: admitted_pages(segments).unwrap(),
        initial_segments: segments,
        device_id: *b"device-v2-tests!",
        range_first_logical_block: 8,
        initial_block_count: admitted_pages(segments).unwrap(),
        logical_block_size: 4096,
        max_replay_records: 128,
    }
}

pub fn pointer(
    kind: ExtentKind,
    segment_no: u64,
    segment_generation: u64,
    descriptor_relative_page: u32,
    payload_pages: u32,
    ordinal: u32,
) -> PhysicalPointer {
    PhysicalPointer::Value(PointerValue {
        store_uuid: uuid(),
        segment_no,
        segment_generation,
        descriptor_relative_page,
        payload_relative_page: descriptor_relative_page + 2,
        payload_pages,
        ordinal,
        exact_byte_len: u64::from(payload_pages) * 4096,
        extent_kind: kind,
        payload_sha256: [kind as u8; 32],
    })
}

pub fn checkpoint(generation: u64) -> Checkpoint {
    let slot = ((generation - 1) & 1) as u8;
    let segment_no = 0;
    let segment_generation = generation + 40;
    Checkpoint {
        binding: binding(
            generation,
            ANCHOR_SEGMENT_NO,
            slot as u32,
            4 + u64::from(slot) * 2,
            generation,
        ),
        slot,
        previous_generation: generation - 1,
        admitted_range_pages: admitted_pages(4).unwrap(),
        admitted_segments: 4,
        next_segment_generation: segment_generation + 1,
        replay_count: 1,
        max_replay_records: 128,
        cleaner_reserve_segments: 1,
        catalog_root: pointer(ExtentKind::Catalog, segment_no, segment_generation, 2, 1, 1),
        authority_root: pointer(
            ExtentKind::Authority,
            segment_no,
            segment_generation,
            5,
            1,
            2,
        ),
        allocation_root: pointer(
            ExtentKind::Allocation,
            segment_no,
            segment_generation,
            8,
            1,
            3,
        ),
        replay_tail: pointer(
            ExtentKind::CatalogDelta,
            segment_no,
            segment_generation,
            11,
            1,
            4,
        ),
    }
}

pub fn segment_header(segment_no: u64, segment_generation: u64) -> SegmentHeader {
    let base = segment_base_page(segment_no).unwrap();
    let (previous_segment_no, previous_segment_generation, previous_segment_seal_body_sha256) =
        if segment_no == 0 {
            (u64::MAX, 0, [0; 32])
        } else {
            (segment_no - 1, segment_generation - 1, [0x91; 32])
        };
    SegmentHeader {
        binding: binding(segment_generation, segment_no, 0, base, 9),
        base_page: base,
        previous_segment_no,
        previous_segment_generation,
        previous_segment_seal_body_sha256,
    }
}

pub fn extent(
    segment_no: u64,
    segment_generation: u64,
    ordinal: u32,
    descriptor_relative_page: u32,
    payload_pages: u32,
) -> ExtentRecord {
    let base = segment_base_page(segment_no).unwrap();
    let payload_bytes = u64::from(payload_pages) * 4096;
    ExtentRecord {
        binding: binding(
            segment_generation,
            segment_no,
            ordinal,
            base + u64::from(descriptor_relative_page),
            9,
        ),
        extent_kind: ExtentKind::Blob,
        object_kind: 7,
        extent_index: ordinal - 1,
        extent_count: 2,
        payload_pages,
        content_byte_len: payload_bytes * 2,
        encoded_blob_len: payload_bytes * 2,
        encoded_offset: u64::from(ordinal - 1) * payload_bytes,
        payload_byte_len: payload_bytes,
        payload_first_relative_page: descriptor_relative_page + 2,
        record_span_pages: payload_pages + 2,
        merkle_root: [0xa5; 32],
        payload_sha256: [ordinal as u8; 32],
    }
}

pub fn summary(segment_no: u64, segment_generation: u64) -> SegmentSummary {
    let base = segment_base_page(segment_no).unwrap();
    SegmentSummary {
        binding: binding(
            segment_generation,
            segment_no,
            3,
            base + u64::from(SUMMARY_BODY_PAGE),
            9,
        ),
        record_count: 2,
        next_free_page: 10,
        payload_page_count: 4,
        total_payload_bytes: 4 * 4096,
        first_target_checkpoint_generation: 9,
        last_target_checkpoint_generation: 9,
        header_body_sha256: [0x11; 32],
        descriptor_chain_sha256: [0x22; 32],
        payload_chain_sha256: [0x33; 32],
        kind_counts: [2, 0, 0, 0, 0],
        kind_bytes: [4 * 4096, 0, 0, 0, 0],
    }
}

pub fn segment_seal(segment_no: u64, segment_generation: u64) -> SegmentSeal {
    let base = segment_base_page(segment_no).unwrap();
    SegmentSeal {
        binding: binding(
            segment_generation,
            segment_no,
            4,
            base + u64::from(SEGMENT_SEAL_BODY_PAGE),
            9,
        ),
        header_body_sha256: [0x11; 32],
        summary_body_sha256: [0x44; 32],
        final_descriptor_chain_sha256: [0x22; 32],
        final_payload_chain_sha256: [0x33; 32],
        record_count: 2,
        next_free_page: 10,
        payload_page_count: 4,
        total_payload_bytes: 4 * 4096,
        target_checkpoint_generation: 9,
    }
}

pub const fn descriptor_relative_page(record: &ExtentRecord) -> u32 {
    record.payload_first_relative_page - 2
}

pub fn first_extent() -> ExtentRecord {
    extent(0, 41, 1, DATA_FIRST_PAGE, 2)
}
