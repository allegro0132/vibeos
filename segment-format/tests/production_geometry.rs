mod production_common;

use production_common::{pointer, uuid};
use vibeos_segment_format::{
    admitted_pages, segment_base_page, ExtentKind, FormatError, FormatGeometry, PhysicalPointer,
    StoreUuid, ANCHOR_PAGES, DATA_END_PAGE, DATA_FIRST_PAGE, MAX_EXTENT_PAYLOAD_PAGES, PAGE_SIZE,
    SEGMENT_PAGES, SEGMENT_SEAL_BODY_PAGE, SEGMENT_SEAL_PAGE, SUMMARY_BODY_PAGE, SUMMARY_SEAL_PAGE,
};

#[test]
fn frozen_geometry_constants_are_self_consistent() {
    assert_eq!(PAGE_SIZE, 4096);
    assert_eq!(ANCHOR_PAGES, 16);
    assert_eq!(SEGMENT_PAGES, 1024);
    assert_eq!(DATA_FIRST_PAGE, 2);
    assert_eq!(DATA_END_PAGE, 1020);
    assert_eq!(SUMMARY_BODY_PAGE, DATA_END_PAGE);
    assert_eq!(SUMMARY_SEAL_PAGE, SUMMARY_BODY_PAGE + 1);
    assert_eq!(SEGMENT_SEAL_BODY_PAGE, SUMMARY_SEAL_PAGE + 1);
    assert_eq!(SEGMENT_SEAL_PAGE, SEGMENT_SEAL_BODY_PAGE + 1);
    assert_eq!(u64::from(SEGMENT_SEAL_PAGE) + 1, SEGMENT_PAGES);
    assert_eq!(MAX_EXTENT_PAYLOAD_PAGES, 256);
    assert!(FormatGeometry::STORAGE_V2.is_storage_v2());
}

#[test]
fn production_geometry_uses_checked_arithmetic() {
    assert_eq!(admitted_pages(0), Ok(16));
    assert_eq!(admitted_pages(1), Ok(1040));
    assert_eq!(segment_base_page(0), Ok(16));
    assert_eq!(segment_base_page(3), Ok(3088));
    assert_eq!(
        admitted_pages(u64::MAX),
        Err(FormatError::ArithmeticOverflow)
    );
    assert_eq!(
        segment_base_page(u64::MAX),
        Err(FormatError::ArithmeticOverflow)
    );
}

#[test]
fn store_uuid_and_null_pointer_are_unambiguous() {
    assert_eq!(StoreUuid::new([0; 16]), Err(FormatError::ZeroUuid));
    assert_eq!(uuid().into_bytes(), *b"storage-v2-tests");
    assert_ne!(
        pointer(ExtentKind::Blob, 0, 1, DATA_FIRST_PAGE, 1, 1),
        PhysicalPointer::Null
    );
}
