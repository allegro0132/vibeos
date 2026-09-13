//! Allocation-free placement of indivisible batch metadata records. The
//! publisher binds relative segment indices before encoding physical pointers.

use vibeos_segment_format::{DATA_END_PAGE, DATA_FIRST_PAGE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Placement {
    pub segment_index: u32,
    pub descriptor_page: u32,
    pub ordinal: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LayoutError {
    InvalidRecord,
    InvalidCursor,
    SegmentBudget,
}

/// Relative segment indices deliberately carry no physical address. Allocation
/// must bind every index before any descriptor or catalog pointer is encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MetadataCursor {
    segment_index: u32,
    next_page: u32,
    next_ordinal: u32,
    segment_budget: u32,
}

impl MetadataCursor {
    /// Segment zero can be an existing open data segment. Its prefix and seal
    /// remain the publisher's responsibility; the budget includes that segment.
    pub fn new(next_page: u32, next_ordinal: u32, segment_budget: u32) -> Result<Self, LayoutError> {
        if !(DATA_FIRST_PAGE..=DATA_END_PAGE).contains(&next_page)
            || next_ordinal == 0
            || next_ordinal > DATA_END_PAGE - DATA_FIRST_PAGE + 1
            || segment_budget == 0
        {
            return Err(LayoutError::InvalidCursor);
        }
        Ok(Self { segment_index: 0, next_page, next_ordinal, segment_budget })
    }

    /// Place one descriptor pair plus a nonempty page-rounded payload. Records
    /// are indivisible. A rejected placement leaves the entire cursor unchanged.
    pub fn place(&mut self, span_pages: u32) -> Result<Placement, LayoutError> {
        if !(3..=DATA_END_PAGE - DATA_FIRST_PAGE).contains(&span_pages) {
            return Err(LayoutError::InvalidRecord);
        }
        let mut next = *self;
        if span_pages > DATA_END_PAGE - next.next_page {
            next.segment_index = next.segment_index.checked_add(1)
                .filter(|index| *index < next.segment_budget)
                .ok_or(LayoutError::SegmentBudget)?;
            next.next_page = DATA_FIRST_PAGE;
            next.next_ordinal = 1;
        }
        let placement = Placement {
            segment_index: next.segment_index,
            descriptor_page: next.next_page,
            ordinal: next.next_ordinal,
        };
        next.next_page += span_pages;
        next.next_ordinal += 1;
        *self = next;
        Ok(placement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tail_and_record_size_stays_inside_segment_data_pages() {
        let capacity = DATA_END_PAGE - DATA_FIRST_PAGE;
        for tail in DATA_FIRST_PAGE..=DATA_END_PAGE {
            for span in 3..=capacity {
                let mut cursor = MetadataCursor::new(tail, 7, 2).unwrap();
                let p = cursor.place(span).unwrap();
                let fits = tail + span <= DATA_END_PAGE;
                assert_eq!(p.segment_index, u32::from(!fits));
                assert_eq!(p.descriptor_page, if fits { tail } else { DATA_FIRST_PAGE });
                assert_eq!(p.ordinal, if fits { 7 } else { 1 });
                assert!(p.descriptor_page + span <= DATA_END_PAGE);
                assert_eq!(cursor.next_page, p.descriptor_page + span);
                assert_eq!(cursor.next_ordinal, p.ordinal + 1);
            }
        }
    }

    #[test]
    fn rejected_records_and_exhausted_budget_do_not_change_cursor() {
        let mut cursor = MetadataCursor::new(DATA_END_PAGE - 3, 8, 1).unwrap();
        for span in [0, 1, 2, DATA_END_PAGE, u32::MAX] {
            let before = cursor;
            assert_eq!(cursor.place(span), Err(LayoutError::InvalidRecord));
            assert_eq!(cursor, before);
        }
        cursor.place(3).unwrap();
        let full = cursor;
        assert_eq!(cursor.place(3), Err(LayoutError::SegmentBudget));
        assert_eq!(cursor, full);
        for args in [(1, 1, 1), (DATA_END_PAGE + 1, 1, 1), (2, 0, 1),
                     (2, u32::MAX, 1), (2, 1, 0)] {
            assert_eq!(MetadataCursor::new(args.0, args.1, args.2), Err(LayoutError::InvalidCursor));
        }
    }

    #[test]
    fn thousand_manifests_and_roots_fit_four_segments_without_splitting_records() {
        let mut cursor = MetadataCursor::new(DATA_FIRST_PAGE, 1, 4).unwrap();
        let mut previous_end = DATA_FIRST_PAGE;
        let mut previous_segment = 0;
        let mut last_ordinal = 0;
        // 1,000 one-page manifests, a 63-page catalog plus descriptor pair,
        // one-page authority and allocation records. This models geometry,
        // not successful publication or memory admission for 1,000 objects.
        for span in core::iter::repeat_n(3, 1000).chain([65, 3, 3]) {
            let p = cursor.place(span).unwrap();
            if p.segment_index == previous_segment {
                assert_eq!(p.descriptor_page, previous_end);
                assert_eq!(p.ordinal, last_ordinal + 1);
            } else {
                assert_eq!(p.segment_index, previous_segment + 1);
                assert_eq!(p.descriptor_page, DATA_FIRST_PAGE);
                assert_eq!(p.ordinal, 1);
            }
            previous_end = p.descriptor_page + span;
            previous_segment = p.segment_index;
            last_ordinal = p.ordinal;
        }
        assert_eq!(previous_segment, 3);
    }
}
