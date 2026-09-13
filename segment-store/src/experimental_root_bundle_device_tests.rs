use super::*;
use alloc::{collections::BTreeMap, vec};
use core::{cell::{Cell, RefCell}, future::Future, task::{Context, Poll, Waker}};
use crate::{PageDevice, PageDeviceInfo};
use vibeos_segment_format::{admitted_pages, encode_record_seal, encode_segment_header_body,
    segment_base_page, Page, RecordBinding, SegmentHeader, ANCHOR_SEGMENT_NO, SEGMENT_SEAL_PAGE};
use vibeos_storage_device::MutationResult;

struct Device {
    pages: RefCell<BTreeMap<u64, Page>>,
    reads: RefCell<Vec<(u64, usize)>>,
    fail_at: Cell<Option<usize>>,
    writes: Cell<usize>,
    flushes: Cell<usize>,
}

impl PageDevice for Device {
    type Error = &'static str;
    fn info(&self) -> PageDeviceInfo {
        let pages = admitted_pages(16).unwrap();
        PageDeviceInfo { device_id: [1; 16], range_first_logical_block: 0,
            logical_block_count: pages, logical_block_size: 4096, page_count: pages }
    }
    async fn read_page(&self, page: u64, out: &mut Page) -> Result<(), Self::Error> {
        self.read_pages(page, core::slice::from_mut(out)).await
    }
    async fn read_pages(&self, first: u64, out: &mut [Page]) -> Result<(), Self::Error> {
        let index = self.reads.borrow().len();
        self.reads.borrow_mut().push((first, out.len()));
        if self.fail_at.get() == Some(index) { return Err("injected read failure"); }
        for (offset, page) in out.iter_mut().enumerate() {
            *page = self.pages.borrow().get(&(first + offset as u64)).copied().unwrap_or([0; PAGE_SIZE]);
        }
        Ok(())
    }
    async fn write_page(&self, page: u64, input: &Page) -> MutationResult<(), Self::Error> {
        self.writes.set(self.writes.get() + 1);
        self.pages.borrow_mut().insert(page, *input);
        Ok(())
    }
    async fn flush(&self) -> MutationResult<(), Self::Error> {
        self.flushes.set(self.flushes.get() + 1);
        Ok(())
    }
}

fn run<F: Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("in-memory fixture must not suspend"),
    }
}

#[test]
fn device_reader_authenticates_segment_and_retains_one_bounded_buffer() {
    let device = Device { pages: RefCell::new(BTreeMap::new()), reads: RefCell::new(Vec::new()),
        fail_at: Cell::new(None), writes: Cell::new(0), flushes: Cell::new(0) };
    let store = StoreUuid::new([1; 16]).unwrap();
    let binding = Binding { store: [1; 16], segment: 7, generation: 3, descriptor: 2 };
    let catalog = vec![2; 896];
    let authority = vec![3; 3776];
    let allocation = vec![4; 137];
    let roots = Roots { catalog: &catalog, authority: &authority, allocation: &allocation };
    let mut bytes = vec![0; roots.encoded_len(MAX_BYTES).unwrap()];
    encode_into(binding, roots, &mut bytes, MAX_BYTES).unwrap();
    let hash = payload_sha256(&bytes);
    let record = crate::cas::build_record(store, 7, 3, 4, 1, 2, ExtentKind::Catalog,
        OBJECT_KIND_ROOT_BUNDLE, 0, 1, bytes.len() as u64, bytes.len() as u64, 0,
        bytes.len() as u64, hash, hash).unwrap();
    let refs = RootReferences([RootReference::Bundle(record.pointer()); 3]);
    let base = segment_base_page(7).unwrap();
    let header = SegmentHeader { binding: RecordBinding { store_uuid: store, generation: 3,
        segment_no: 7, ordinal: 0, self_page: base, target_checkpoint_generation: 4 },
        base_page: base, previous_segment_no: ANCHOR_SEGMENT_NO, previous_segment_generation: 0,
        previous_segment_seal_body_sha256: [0; 32] };
    let mut body = [0; PAGE_SIZE];
    let mut seal = [0; PAGE_SIZE];
    let digest = encode_segment_header_body(&header, &mut body).unwrap();
    encode_record_seal(digest, &mut seal).unwrap();
    run(async {
        crate::cas::write_payload_records_with_header(&device, base, Some((&body, &seal)),
            &[(&record, bytes.as_slice())], false, None).await.unwrap();
        crate::cas::finalize_segment(&device, store, 4, 7, 3, digest,
            core::slice::from_ref(&record), false, None).await.unwrap();
    });
    let context = ReadContext { store, admitted_segments: 16, next_segment_generation: 4,
        checkpoint_generation: 4, budget: 8192 };
    #[cfg(feature = "experimental-root-bundle")]
    let (refs, context) = {
        use vibeos_segment_format::{Checkpoint, DecodeStatus};
        use vibeos_segment_format::experimental_root_checkpoint::{self as cp, BundleCheckpoint};
        let checkpoint = BundleCheckpoint { root_bundle_mask: 7, base: Checkpoint {
            binding: RecordBinding { store_uuid: store, generation: 4, segment_no: ANCHOR_SEGMENT_NO,
                ordinal: 1, self_page: 6, target_checkpoint_generation: 4 },
            slot: 1, previous_generation: 3, admitted_range_pages: admitted_pages(16).unwrap(),
            admitted_segments: 16, next_segment_generation: 4, replay_count: 0, max_replay_records: 128,
            cleaner_reserve_segments: 1, catalog_root: record.pointer(), authority_root: record.pointer(),
            allocation_root: record.pointer(), replay_tail: PhysicalPointer::Null,
        }};
        let mut body = [0; PAGE_SIZE];
        let mut seal = [0; PAGE_SIZE];
        let digest = cp::encode_body(checkpoint, &mut body).unwrap();
        encode_record_seal(digest, &mut seal).unwrap();
        let DecodeStatus::Sealed(verified) = cp::decode_verified(&body, &seal).unwrap() else {
            panic!("checkpoint must be sealed");
        };
        let (decoded, read_context) = RootReferences::from_checkpoint(&verified, context.budget).unwrap();
        assert_eq!(decoded, refs);
        (decoded, read_context)
    };
    let owned = run(refs.read_bundle(&device, Role::Catalog, context)).unwrap();
    let calls = device.reads.borrow().len();
    assert!(calls > 0);
    assert_eq!(owned.get(Role::Catalog).unwrap(), catalog);
    assert_eq!(owned.get(Role::Authority).unwrap(), authority);
    assert_eq!(owned.get(Role::Allocation).unwrap(), allocation);
    assert_eq!(device.reads.borrow().len(), calls, "member access must not read again");
    assert!(owned.retained_payload_capacity() <= context.budget);
    assert!(device.reads.borrow().iter().all(|(_, pages)| *pages <= 32));
    assert_eq!(device.reads.borrow().iter().filter(|(page, _)| *page == base + 4).count(), 1);
    device.reads.borrow_mut().clear();
    assert!(matches!(run(refs.read_bundle(&device, Role::Catalog,
        ReadContext { budget: bytes.len() - 1, ..context })), Err(crate::StoreError::MemoryLimit)));
    assert!(device.reads.borrow().is_empty());
    for index in 0..calls {
        device.reads.borrow_mut().clear();
        device.fail_at.set(Some(index));
        assert!(matches!(run(refs.read_bundle(&device, Role::Catalog, context)),
            Err(crate::StoreError::Device("injected read failure"))));
    }
    device.fail_at.set(None);
    for page in [base + 4, base + u64::from(SEGMENT_SEAL_PAGE)] {
        let original = device.pages.borrow()[&page];
        device.pages.borrow_mut().get_mut(&page).unwrap()[0] ^= 1;
        assert!(run(refs.read_bundle(&device, Role::Catalog, context)).is_err());
        device.pages.borrow_mut().insert(page, original);
    }
    assert!(run(refs.read_bundle(&device, Role::Catalog, context)).is_ok());
}

#[test]
fn prepared_bundle_saves_five_device_pages_with_same_explicit_flush() {
    let store = StoreUuid::new([1; 16]).unwrap();
    let binding = Binding { store: [1; 16], segment: 7, generation: 3, descriptor: 2 };
    let parts = [vec![2; 896], vec![3; 3776], vec![4; 137]];
    let roots = Roots { catalog: &parts[0], authority: &parts[1], allocation: &parts[2] };
    let budget = roots.encoded_len(MAX_BYTES).unwrap() + 2 * PAGE_SIZE;
    assert!(prepare_bundle::<()>(binding, roots, 4, 1, budget - 1).unwrap().is_none());
    assert!(prepare_bundle::<()>(Binding { descriptor: 1017, ..binding }, roots, 4, 1, budget)
        .unwrap().is_none());
    let oversized = vec![0; MAX_BYTES];
    assert!(prepare_bundle::<()>(binding, Roots { catalog: &oversized, ..roots }, 4, 1, usize::MAX)
        .unwrap().is_none());
    let prepared = prepare_bundle::<()>(binding, roots, 4, 1, budget).unwrap().unwrap();
    assert_eq!(prepared.saved_pages, 5);
    assert!(prepared.payload.capacity() + 2 * PAGE_SIZE <= budget);
    let mut measured = Vec::new();
    for bundled in [false, true] {
        let device = Device { pages: RefCell::new(BTreeMap::new()), reads: RefCell::new(Vec::new()),
            fail_at: Cell::new(None), writes: Cell::new(0), flushes: Cell::new(0) };
        let base = segment_base_page(7).unwrap();
        let header = SegmentHeader { binding: RecordBinding { store_uuid: store, generation: 3,
            segment_no: 7, ordinal: 0, self_page: base, target_checkpoint_generation: 4 },
            base_page: base, previous_segment_no: ANCHOR_SEGMENT_NO, previous_segment_generation: 0,
            previous_segment_seal_body_sha256: [0; 32] };
        let mut header_body = [0; PAGE_SIZE];
        let mut header_seal = [0; PAGE_SIZE];
        let digest = encode_segment_header_body(&header, &mut header_body).unwrap();
        encode_record_seal(digest, &mut header_seal).unwrap();
        let mut separate = Vec::new();
        let mut at = 2;
        if !bundled {
            for (index, payload) in parts.iter().enumerate() {
                let kind = [ExtentKind::Catalog, ExtentKind::Authority, ExtentKind::Allocation][index];
                let object_kind = [0xffff_0011, 0xffff_0021, 0xffff_0002][index];
                let hash = payload_sha256(payload);
                let record = crate::cas::build_record(store, 7, 3, 4, index as u32 + 1, at, kind,
                    object_kind, 0, 1, payload.len() as u64, payload.len() as u64, 0,
                    payload.len() as u64, hash, hash).unwrap();
                at += record.value.record_span_pages;
                separate.push(record);
            }
        }
        let records = if bundled { core::slice::from_ref(&prepared.record) } else { separate.as_slice() };
        let payloads: Vec<_> = if bundled { vec![(&prepared.record, prepared.payload.as_slice())] }
            else { separate.iter().zip(parts.iter().map(Vec::as_slice)).collect() };
        run(async {
            crate::cas::write_payload_records_with_header(&device, base,
                Some((&header_body, &header_seal)), &payloads, true, None).await.unwrap();
            crate::cas::finalize_segment(&device, store, 4, 7, 3, digest, records, true, None).await.unwrap();
            device.flush().await.unwrap();
        });
        if bundled {
            let refs = RootReferences([RootReference::Bundle(prepared.record.pointer()); 3]);
            let read = run(refs.read_bundle(&device, Role::Catalog, ReadContext { store,
                admitted_segments: 16, next_segment_generation: 4, checkpoint_generation: 4,
                budget: 8192 })).unwrap();
            for role in [Role::Catalog, Role::Authority, Role::Allocation] {
                assert_eq!(read.get(role).unwrap(), roots.get(role));
            }
        } else {
            for (record, expected) in separate.iter().zip(&parts) {
                let read = run(crate::store::read_pointer_payload(&device, store, 16, 4, 4,
                    record.pointer(), record.value.extent_kind, expected.len(), None)).unwrap();
                assert_eq!(&read.bytes, expected);
            }
        }
        measured.push((device.writes.get(), device.flushes.get()));
    }
    assert_eq!(measured, [(15, 1), (10, 1)]);
}
