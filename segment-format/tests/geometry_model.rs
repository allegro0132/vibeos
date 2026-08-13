mod common;

use common::PAGE_SIZE;

const ANCHOR_PAGES: u64 = 16;
const SEGMENT_PAGES: u64 = 1024;
const DATA_FIRST_PAGE: u32 = 2;
const DATA_END_PAGE: u32 = 1020;
const SUMMARY_BODY_PAGE: u32 = 1020;
const SUMMARY_SEAL_PAGE: u32 = 1021;
const SEGMENT_SEAL_BODY_PAGE: u32 = 1022;
const SEGMENT_SEAL_PAGE: u32 = 1023;
const MAX_EXTENT_PAYLOAD_PAGES: u32 = 256;

fn admitted_pages(segments: u64) -> Option<u64> {
    segments
        .checked_mul(SEGMENT_PAGES)
        .and_then(|pages| ANCHOR_PAGES.checked_add(pages))
}

fn extent_span(exact_byte_len: u64) -> Option<u32> {
    let payload_pages = exact_byte_len
        .checked_add(PAGE_SIZE as u64 - 1)?
        .checked_div(PAGE_SIZE as u64)?;
    let payload_pages = u32::try_from(payload_pages).ok()?;
    (2_u32).checked_add(payload_pages)
}

#[test]
fn frozen_segment_geometry_has_no_aliasing_pages() {
    assert_eq!(DATA_FIRST_PAGE, 2);
    assert_eq!(DATA_END_PAGE, SUMMARY_BODY_PAGE);
    assert_eq!(SUMMARY_SEAL_PAGE, SUMMARY_BODY_PAGE + 1);
    assert_eq!(SEGMENT_SEAL_BODY_PAGE, SUMMARY_SEAL_PAGE + 1);
    assert_eq!(SEGMENT_SEAL_PAGE, SEGMENT_SEAL_BODY_PAGE + 1);
    assert_eq!(SEGMENT_SEAL_PAGE as u64 + 1, SEGMENT_PAGES);
    const {
        assert!(MAX_EXTENT_PAYLOAD_PAGES + 2 < DATA_END_PAGE - DATA_FIRST_PAGE);
    }
}

#[test]
fn admitted_page_arithmetic_is_exact_and_checked() {
    assert_eq!(admitted_pages(0), Some(ANCHOR_PAGES));
    assert_eq!(admitted_pages(1), Some(1040));
    assert_eq!(admitted_pages(17), Some(17_424));
    assert_eq!(admitted_pages(u64::MAX), None);
}

#[test]
fn extent_span_rounds_up_and_includes_descriptor_pair() {
    assert_eq!(extent_span(0), Some(2));
    assert_eq!(extent_span(1), Some(3));
    assert_eq!(extent_span(4096), Some(3));
    assert_eq!(extent_span(4097), Some(4));
    assert_eq!(extent_span(256 * 4096), Some(MAX_EXTENT_PAYLOAD_PAGES + 2));
    assert_eq!(extent_span(257 * 4096), Some(MAX_EXTENT_PAYLOAD_PAGES + 3));
    assert_eq!(extent_span(u64::MAX), None);
}

#[test]
fn contiguous_extent_cursor_never_overlaps_reserved_tail() {
    let exact_lengths = [1_u64, 4096, 4097, 32 * 4096, 256 * 4096];
    let mut cursor = DATA_FIRST_PAGE;
    for exact_len in exact_lengths {
        let span = extent_span(exact_len).unwrap();
        let next = cursor.checked_add(span).unwrap();
        assert!(next > cursor);
        assert!(cursor >= DATA_FIRST_PAGE);
        if next > DATA_END_PAGE {
            break;
        }
        cursor = next;
    }
    assert!(cursor <= DATA_END_PAGE);
}
