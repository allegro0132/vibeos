mod common;

const DATA_FIRST: u32 = 2;
const DATA_END: u32 = 1020;
const MAX_PAYLOAD_PAGES: u32 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Pointer {
    store: [u8; 16],
    segment: u64,
    segment_generation: u64,
    descriptor_page: u32,
    payload_page: u32,
    payload_pages: u32,
    ordinal: u32,
    exact_byte_len: u64,
    extent_kind: u16,
    payload_sha: [u8; 32],
}

impl Pointer {
    fn end_page(self) -> Option<u32> {
        self.payload_page.checked_add(self.payload_pages)
    }

    fn validate(self) -> bool {
        let minimum_pages = self
            .exact_byte_len
            .checked_add(4095)
            .and_then(|bytes| bytes.checked_div(4096))
            .and_then(|pages| u32::try_from(pages).ok());
        self.store != [0; 16]
            && self.segment_generation != 0
            && self.ordinal != 0
            && self.payload_page == self.descriptor_page.saturating_add(2)
            && self.payload_pages <= MAX_PAYLOAD_PAGES
            && minimum_pages == Some(self.payload_pages)
            && self.descriptor_page >= DATA_FIRST
            && self.end_page().is_some_and(|end| end <= DATA_END)
    }

    fn overlaps(self, other: Self) -> bool {
        self.store == other.store
            && self.segment == other.segment
            && self.segment_generation == other.segment_generation
            && self.descriptor_page < other.end_page().unwrap_or(u32::MAX)
            && other.descriptor_page < self.end_page().unwrap_or(u32::MAX)
    }
}

fn pointer(ordinal: u32, descriptor_page: u32, payload_pages: u32) -> Pointer {
    Pointer {
        store: [7; 16],
        segment: 4,
        segment_generation: 9,
        descriptor_page,
        payload_page: descriptor_page + 2,
        payload_pages,
        ordinal,
        exact_byte_len: u64::from(payload_pages) * 4096,
        extent_kind: 1,
        payload_sha: [ordinal as u8; 32],
    }
}

#[test]
fn pointer_binds_exact_identity_and_length() {
    let valid = pointer(1, DATA_FIRST, 3);
    assert!(valid.validate());

    for mutation in [
        Pointer {
            store: [0; 16],
            ..valid
        },
        Pointer {
            segment_generation: 0,
            ..valid
        },
        Pointer {
            ordinal: 0,
            ..valid
        },
        Pointer {
            payload_page: valid.payload_page + 1,
            ..valid
        },
        Pointer {
            exact_byte_len: valid.exact_byte_len - 4096,
            ..valid
        },
        Pointer {
            payload_pages: MAX_PAYLOAD_PAGES + 1,
            ..valid
        },
    ] {
        assert!(!mutation.validate(), "accepted mutation {mutation:?}");
    }
}

#[test]
fn pointers_must_be_wholly_inside_append_area() {
    assert!(pointer(1, DATA_FIRST, 1).validate());
    assert!(pointer(1, DATA_END - 3, 1).validate());
    assert!(!pointer(1, DATA_END - 2, 1).validate());
    assert!(!pointer(1, DATA_END - 3, 2).validate());
}

#[test]
fn duplicate_or_overlapping_pointers_are_rejected() {
    let first = pointer(1, 2, 4);
    let duplicate = first;
    let overlapping = pointer(2, 7, 2);
    let adjacent = pointer(2, 8, 2);
    assert!(first.overlaps(duplicate));
    assert!(first.overlaps(overlapping));
    assert!(!first.overlaps(adjacent));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SegmentCursor {
    next_ordinal: u32,
    next_page: u32,
    payload_pages: u32,
    payload_bytes: u64,
}

impl SegmentCursor {
    fn new() -> Self {
        Self {
            next_ordinal: 1,
            next_page: DATA_FIRST,
            payload_pages: 0,
            payload_bytes: 0,
        }
    }

    fn append(&mut self, extent: Pointer) -> bool {
        if !extent.validate()
            || extent.ordinal != self.next_ordinal
            || extent.descriptor_page != self.next_page
        {
            return false;
        }
        let Some(next_page) = extent.end_page() else {
            return false;
        };
        let Some(payload_pages) = self.payload_pages.checked_add(extent.payload_pages) else {
            return false;
        };
        let Some(payload_bytes) = self.payload_bytes.checked_add(extent.exact_byte_len) else {
            return false;
        };
        self.next_ordinal += 1;
        self.next_page = next_page;
        self.payload_pages = payload_pages;
        self.payload_bytes = payload_bytes;
        true
    }
}

#[test]
fn segment_verifier_requires_contiguous_ordinals_and_cursor() {
    let first = pointer(1, 2, 2);
    let second = pointer(2, first.end_page().unwrap(), 3);
    let mut cursor = SegmentCursor::new();
    assert!(cursor.append(first));
    assert!(cursor.append(second));
    assert_eq!(cursor.next_ordinal, 3);
    assert_eq!(cursor.next_page, second.end_page().unwrap());
    assert_eq!(cursor.payload_pages, 5);

    let mut skipped_ordinal = SegmentCursor::new();
    assert!(!skipped_ordinal.append(Pointer {
        ordinal: 2,
        ..first
    }));
    let mut skipped_page = SegmentCursor::new();
    assert!(!skipped_page.append(Pointer {
        descriptor_page: 3,
        payload_page: 5,
        ..first
    }));
}
