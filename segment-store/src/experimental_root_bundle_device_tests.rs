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
    info_override: Cell<Option<PageDeviceInfo>>,
}

impl PageDevice for Device {
    type Error = &'static str;
    fn info(&self) -> PageDeviceInfo {
        let pages = admitted_pages(16).unwrap();
        self.info_override.get().unwrap_or(PageDeviceInfo { device_id: [1; 16], range_first_logical_block: 0,
            logical_block_count: pages, logical_block_size: 4096, page_count: pages })
    }
    async fn read_page(&self, page: u64, out: &mut Page) -> Result<(), Self::Error> {
        self.read_pages(page, core::slice::from_mut(out)).await
    }
    async fn read_pages(&self, first: u64, out: &mut [Page]) -> Result<(), Self::Error> {
        let index = self.reads.borrow().len();
        self.reads.borrow_mut().push((first, out.len()));
        if self.fail_at.get() == Some(index) {
            if let Some(page) = out.first_mut() {
                *page = self.pages.borrow().get(&first).copied().unwrap_or([0; PAGE_SIZE]);
            }
            return Err("injected read failure");
        }
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

#[cfg(feature = "experimental-root-bundle")]
#[test]
fn device_pair_recovers_both_maps_and_rejects_sealed_direct_reuse() {
    use vibeos_segment_format::{Checkpoint, FormatGeometry, Superblock};
    use vibeos_segment_format::experimental_root_checkpoint::{self as cp, BundleCheckpoint};
    let store = StoreUuid::new([1; 16]).unwrap();
    for (old_bundled, new_bundled, bootstrap) in [
        (true, true, false), (true, false, false), (false, true, false), (false, false, false),
        (false, true, true), (false, false, true),
    ] {
    for illegal_reuse in [false, true] {
        let device = Device { pages: RefCell::new(BTreeMap::new()), reads: RefCell::new(Vec::new()),
            fail_at: Cell::new(None), writes: Cell::new(0), flushes: Cell::new(0), info_override: Cell::new(None) };
        for copy in 0..2 {
            let mut body = [0; PAGE_SIZE];
            let mut seal = [0; PAGE_SIZE];
            let value = Superblock { binding: RecordBinding { store_uuid: store, generation: 1,
                segment_no: ANCHOR_SEGMENT_NO, ordinal: copy, self_page: u64::from(copy) * 2,
                target_checkpoint_generation: 0 }, copy: copy as u8, geometry: FormatGeometry::STORAGE_V2,
                cleaner_reserve_segments: 1, initial_range_pages: admitted_pages(16).unwrap(), initial_segments: 16,
                device_id: [1; 16], range_first_logical_block: 0, initial_block_count: admitted_pages(16).unwrap(),
                logical_block_size: 4096, max_replay_records: 128 };
            let digest = cp::encode_superblock(&value, &mut body).unwrap();
            encode_record_seal(digest, &mut seal).unwrap();
            run(device.write_pages(u64::from(copy) * 2, &[body, seal])).unwrap();
        }
        let mut previous = (ANCHOR_SEGMENT_NO, 0, [0; 32]);
        let mut payload_lens = [0; 2];
        for number in 0..2_u64 {
            let generation = number + if bootstrap { 1 } else { 3 };
            if bootstrap && number == 0 {
                let empty = BundleCheckpoint { root_bundle_mask: 0, base: Checkpoint {
                    binding: RecordBinding { store_uuid: store, generation: 1, segment_no: ANCHOR_SEGMENT_NO,
                        ordinal: 0, self_page: 4, target_checkpoint_generation: 1 },
                    slot: 0, previous_generation: 0, admitted_range_pages: admitted_pages(16).unwrap(),
                    admitted_segments: 16, next_segment_generation: 1, replay_count: 0,
                    max_replay_records: 128, cleaner_reserve_segments: 1, catalog_root: PhysicalPointer::Null,
                    authority_root: PhysicalPointer::Null, allocation_root: PhysicalPointer::Null, replay_tail: PhysicalPointer::Null } };
                let mut body = [0; PAGE_SIZE];
                let mut seal = [0; PAGE_SIZE];
                let digest = cp::encode_body(empty, &mut body).unwrap();
                encode_record_seal(digest, &mut seal).unwrap();
                run(device.write_pages(4, &[body, seal])).unwrap();
                run(device.flush()).unwrap();
                continue;
            }
            let segment_generation = number + if bootstrap { 0 } else { 1 };
            let mut states = vec![crate::SegmentAllocation::Free; 16];
            if !bootstrap { states[0] = crate::SegmentAllocation::Allocated; }
            if number == 1 {
                states[1] = crate::SegmentAllocation::Allocated;
                if illegal_reuse {
                    states[0] = if bootstrap { crate::SegmentAllocation::Allocated } else { crate::SegmentAllocation::Free };
                }
            }
            let allocation = crate::encode_allocation_v2(&crate::AllocationV2::new(generation,
                segment_generation + 1, 1, &states, &[]).unwrap()).unwrap();
            let context = crate::CasCodecContext::new(store, 16, segment_generation + 1).unwrap();
            let catalog = crate::encode_cas_snapshot(&crate::CasSnapshot {
                checkpoint_generation: generation, objects: vec![], blobs: vec![],
            }, context).unwrap();
            let stream = vibeos_durable_format::RecordChain::new(vibeos_durable_format::StoreId::new(7).unwrap())
                .append(None, vibeos_durable_format::RecordBody::Format).unwrap().to_vec();
            let authority = crate::encode_persistent_authority_snapshot(&crate::PersistentAuthoritySnapshot::new(
                generation, crate::root_policy_commitment(b"test roots"), stream, vec![], vec![]).unwrap()).unwrap();
            let roots = Roots { catalog: &catalog, authority: &authority, allocation: &allocation };
            let binding = Binding { store: [1; 16], segment: number, generation: segment_generation, descriptor: 2 };
            let prepared = prepare_bundle::<&'static str>(binding, roots, generation, 1, 16 * 1024).unwrap().unwrap();
            let bundled = if number == 0 { old_bundled } else { new_bundled };
            let hash = payload_sha256(&allocation);
            let separate = crate::cas::build_record(store, number, segment_generation, generation, 2,
                2 + prepared.record.value.record_span_pages, ExtentKind::Allocation, 0xffff_0002,
                0, 1, allocation.len() as u64, allocation.len() as u64, 0,
                allocation.len() as u64, hash, hash).unwrap();
            payload_lens[number as usize] = if bundled { prepared.payload.len() } else { allocation.len() };
            let allocation_pointer = if bundled { prepared.record.pointer() } else { separate.pointer() };
            let records = if bundled { vec![prepared.record] } else { vec![prepared.record, separate] };
            let mut payloads = vec![(&records[0], prepared.payload.as_slice())];
            if !bundled { payloads.push((&records[1], allocation.as_slice())); }
            let base = segment_base_page(number).unwrap();
            let header = SegmentHeader { binding: RecordBinding { store_uuid: store, generation: segment_generation,
                segment_no: number, ordinal: 0, self_page: base, target_checkpoint_generation: generation },
                base_page: base, previous_segment_no: previous.0, previous_segment_generation: previous.1,
                previous_segment_seal_body_sha256: previous.2 };
            let mut body = [0; PAGE_SIZE];
            let mut seal = [0; PAGE_SIZE];
            let header_digest = encode_segment_header_body(&header, &mut body).unwrap();
            encode_record_seal(header_digest, &mut seal).unwrap();
            previous = run(async {
                crate::cas::write_payload_records_with_header(&device, base, Some((&body, &seal)),
                    &payloads, true, None).await.unwrap();
                let result = crate::cas::finalize_segment(&device, store, generation, number,
                    segment_generation, header_digest, &records, true, None).await.unwrap();
                device.flush().await.unwrap();
                result
            });
            let slot = ((generation - 1) & 1) as u8;
            let checkpoint = BundleCheckpoint { root_bundle_mask: if bundled { 7 } else { 3 }, base: Checkpoint {
                binding: RecordBinding { store_uuid: store, generation, segment_no: ANCHOR_SEGMENT_NO,
                    ordinal: slot as u32, self_page: 4 + u64::from(slot) * 2, target_checkpoint_generation: generation },
                slot, previous_generation: generation - 1, admitted_range_pages: admitted_pages(16).unwrap(),
                admitted_segments: 16, next_segment_generation: segment_generation + 1, replay_count: 0,
                max_replay_records: 128, cleaner_reserve_segments: 1, catalog_root: records[0].pointer(),
                authority_root: records[0].pointer(), allocation_root: allocation_pointer, replay_tail: PhysicalPointer::Null } };
            let digest = cp::encode_body(checkpoint, &mut body).unwrap();
            encode_record_seal(digest, &mut seal).unwrap();
            run(async {
                device.write_page(4 + u64::from(slot) * 2, &body).await.unwrap();
                device.flush().await.unwrap();
                device.write_page(5 + u64::from(slot) * 2, &seal).await.unwrap();
                device.flush().await.unwrap();
            });
        }
        let selected = run(select_device_checkpoint(&device, 16 * 1024, 128)).unwrap();
        assert_eq!(selected.previous().unwrap().value().base.binding.generation, if bootstrap { 1 } else { 3 });
        let result = run(recover_same_admission_allocations(&device, &selected, 16 * 1024, 0));
        {
            device.reads.borrow_mut().clear();
            let joined = run(recover_bundled_checkpoint_without_replay(&device, &selected, 32 * 1024, 0, 0));
            assert_eq!(joined.is_ok(), !illegal_reuse);
            if !illegal_reuse {
                let PhysicalPointer::Value(current_pointer) = selected.value().base.catalog_root else { panic!("missing root"); };
                let current_page = segment_base_page(current_pointer.segment_no).unwrap() + u64::from(current_pointer.payload_relative_page);
                assert_eq!(device.reads.borrow().iter().filter(|(page, _)| *page == current_page).count(), 1);
                let reads = device.reads.borrow().len();
                for failed in 0..reads {
                    device.reads.borrow_mut().clear();
                    device.fail_at.set(Some(failed));
                    assert!(run(recover_bundled_checkpoint_without_replay(&device, &selected,
                        32 * 1024, 0, 0)).is_err());
                }
                device.fail_at.set(None);
                let mut low = 0;
                let mut high = 32 * 1024;
                while low < high {
                    let budget = low + (high - low) / 2;
                    match run(recover_bundled_checkpoint(&device, &selected, budget, 0, 0)) {
                        Ok(_) => high = budget,
                        Err(crate::StoreError::MemoryLimit) => low = budget + 1,
                        Err(_) => panic!("unexpected mixed-layout memory error"),
                    }
                }
                assert!(run(recover_bundled_checkpoint(&device, &selected, high, 0, 0)).is_ok());
                assert!(matches!(run(recover_bundled_checkpoint(&device, &selected, high - 1, 0, 0)),
                    Err(crate::StoreError::MemoryLimit)));
            }
        }
        if illegal_reuse {
            assert!(matches!(result, Err(crate::StoreError::Corrupt)));
        } else {
            let maps = result.unwrap();
            assert_eq!(maps.previous.as_ref().unwrap().map().segment_state(1), Some(crate::SegmentAllocation::Free));
            assert_eq!(maps.current.map().segment_state(1), Some(crate::SegmentAllocation::Allocated));
            let old_bytes = maps.previous.as_ref().unwrap().map().allocated_bytes().unwrap();
            let (refs, context) = RootReferences::from_checkpoint(selected.current(), 16 * 1024).unwrap();
            let bundle = run(refs.read_bundle(&device, Role::Catalog, context)).unwrap();
            let catalog = bundle.decode_catalog_snapshot::<&'static str>(&maps.current, 16 * 1024, old_bytes, 0).unwrap();
            assert_eq!(catalog.checkpoint_generation, selected.value().base.binding.generation);
            assert!(catalog.objects.is_empty() && catalog.blobs.is_empty());
            let catalog_peak = bundle.retained_payload_capacity() + old_bytes + maps.current.map().allocated_bytes().unwrap();
            assert!(bundle.decode_catalog_snapshot::<&'static str>(&maps.current, catalog_peak, old_bytes, 0).is_ok());
            assert!(matches!(bundle.decode_catalog_snapshot::<&'static str>(&maps.current, catalog_peak - 1, old_bytes, 0),
                Err(crate::StoreError::MemoryLimit)));
            assert!(bundle.decode_catalog_snapshot::<&'static str>(maps.previous.as_ref().unwrap(), 16 * 1024, 0, 0).is_err());
            let (authority, roots) = bundle.decode_authority_snapshot::<&'static str>(&maps.current, &catalog,
                32 * 1024, old_bytes).unwrap();
            assert_eq!(authority.checkpoint_generation(), selected.value().base.binding.generation);
            assert!(roots.entries().is_empty());
            assert!(bundle.decode_authority_snapshot::<&'static str>(&maps.current, &catalog, 0, old_bytes).is_err());
            drop((authority, roots));
            let validated = run(bundle.recover_catalog_without_replay(&device, &maps.current, 16 * 1024, old_bytes, 0)).unwrap();
            assert_eq!(validated, catalog);
            let retained = old_bytes + maps.current.map().allocated_bytes().unwrap();
            let peak = (payload_lens[0] + old_bytes).max(payload_lens[1] + retained);
            assert!(run(recover_same_admission_allocations(&device, &selected, peak, 0)).is_ok());
            assert!(matches!(run(recover_same_admission_allocations(&device, &selected, peak - 1, 0)),
                Err(crate::StoreError::MemoryLimit)));
            if bootstrap {
                let complete_seal = device.pages.borrow()[&7];
                for prefix in [0, 1, 16, 512, 2048, 4080, 4095] {
                    let mut partial = [0; PAGE_SIZE];
                    partial[..prefix].copy_from_slice(&complete_seal[..prefix]);
                    device.pages.borrow_mut().insert(7, partial);
                    let fallback = run(select_device_checkpoint(&device, 16 * 1024, 128)).unwrap();
                    assert_eq!(fallback.value().base.binding.generation, 1);
                    let recovered = run(recover_same_admission_allocations(&device, &fallback, 4, 0)).unwrap();
                    assert!(recovered.previous.is_none());
                    for segment in 0..16 {
                        assert_eq!(recovered.current.map().segment_state(segment), Some(crate::SegmentAllocation::Free));
                    }
                }
                device.pages.borrow_mut().insert(7, complete_seal);
                let complete = run(select_device_checkpoint(&device, 16 * 1024, 128)).unwrap();
                assert_eq!(complete.value().base.binding.generation, 2);
                assert!(run(recover_same_admission_allocations(&device, &complete, peak, 0)).is_ok());
            }
            let corruption_target = if bootstrap { selected.current() } else { selected.previous().unwrap() };
            let PhysicalPointer::Value(old_pointer) = corruption_target.value().base.allocation_root else { panic!("missing allocation"); };
            let old_payload_page = segment_base_page(old_pointer.segment_no).unwrap() + u64::from(old_pointer.payload_relative_page);
            device.pages.borrow_mut().get_mut(&old_payload_page).unwrap()[0] ^= 1;
            assert!(run(recover_same_admission_allocations(&device, &selected, 16 * 1024, 0)).is_err());
        }
    }
    }
}

#[cfg(feature = "experimental-root-bundle")]
#[test]
fn recovered_allocation_pair_preserves_retirement_and_generation_rules() {
    use crate::SegmentAllocation::{Allocated as A, Free as F, Retired as R};
    use vibeos_segment_format::{Checkpoint, PointerValue};
    use vibeos_segment_format::experimental_root_checkpoint::BundleCheckpoint;
    // Semantic transition fixtures; these do not simulate checkpoint I/O.
    fn recovered(generation: u64, next: u64, prefix: &[crate::SegmentAllocation],
        retired: &[crate::RetiredSegment]) -> RecoveredAllocation {
        let mut states = vec![crate::SegmentAllocation::Free; 16];
        states[..prefix.len()].copy_from_slice(prefix);
        let allocation = crate::AllocationV2::new(generation, next, 1, &states, retired).unwrap();
        let store = StoreUuid::new([1; 16]).unwrap();
        let carrier = states.iter().rposition(|state| *state == crate::SegmentAllocation::Allocated).unwrap();
        let pointer = PhysicalPointer::Value(PointerValue { store_uuid: store, segment_no: carrier as u64,
            segment_generation: next - 1, descriptor_relative_page: 2, payload_relative_page: 4,
            payload_pages: 1, ordinal: 1, exact_byte_len: 132, extent_kind: ExtentKind::Catalog,
            payload_sha256: [1; 32] });
        let slot = ((generation - 1) & 1) as u8;
        let base = Checkpoint { binding: RecordBinding { store_uuid: store, generation,
            segment_no: ANCHOR_SEGMENT_NO, ordinal: slot as u32, self_page: 4 + u64::from(slot) * 2,
            target_checkpoint_generation: generation }, slot, previous_generation: generation - 1,
            admitted_range_pages: admitted_pages(16).unwrap(), admitted_segments: 16,
            next_segment_generation: next, replay_count: 0, max_replay_records: 128,
            cleaner_reserve_segments: 1, catalog_root: pointer, authority_root: pointer,
            allocation_root: pointer, replay_tail: PhysicalPointer::Null };
        let checkpoint = BundleCheckpoint { base, root_bundle_mask: 7 };
        checkpoint.validate().unwrap();
        RecoveredAllocation { allocation, checkpoint, version: 2 }
    }
    let old = recovered(4, 2, &[A], &[]);
    let ordinary = recovered(5, 3, &[A, A], &[]);
    assert!(old.validate_same_admission_successor::<()>(&ordinary).is_ok());
    let retired = [crate::RetiredSegment { segment_no: 0, retire_generation: 5 }];
    let relocated = recovered(5, 3, &[R, A], &retired);
    assert!(old.validate_same_admission_successor::<()>(&relocated).is_ok());
    let reclaimed = recovered(6, 4, &[F, A, A], &[]);
    assert!(relocated.validate_same_admission_successor::<()>(&reclaimed).is_ok());
    assert!(old.validate_same_admission_successor::<()>(&recovered(5, 3, &[F, A], &[])).is_err());
    assert!(old.validate_same_admission_successor::<()>(&recovered(5, 4, &[A, A], &[])).is_err());
    assert!(old.validate_same_admission_successor::<()>(&recovered(6, 3, &[A, A], &[])).is_err());
    let pending = recovered(6, 4, &[R, A, A], &retired);
    assert!(relocated.validate_same_admission_successor::<()>(&pending).is_err());
    let two_retired = recovered(5, 4, &[R, R, A], &[
        crate::RetiredSegment { segment_no: 0, retire_generation: 5 },
        crate::RetiredSegment { segment_no: 1, retire_generation: 5 }]);
    let partial = recovered(6, 5, &[F, R, A, A], &[
        crate::RetiredSegment { segment_no: 1, retire_generation: 5 }]);
    assert!(two_retired.validate_same_admission_successor::<()>(&partial).is_err());
    let mut mismatched = recovered(5, 3, &[A, A], &[]);
    mismatched.checkpoint.base.binding.store_uuid = StoreUuid::new([2; 16]).unwrap();
    assert!(old.validate_same_admission_successor::<()>(&mismatched).is_err());
}

#[test]
fn device_reader_authenticates_segment_and_retains_one_bounded_buffer() {
    let device = Device { pages: RefCell::new(BTreeMap::new()), reads: RefCell::new(Vec::new()),
        fail_at: Cell::new(None), writes: Cell::new(0), flushes: Cell::new(0), info_override: Cell::new(None) };
    let store = StoreUuid::new([1; 16]).unwrap();
    let binding = Binding { store: [1; 16], segment: 7, generation: 3, descriptor: 2 };
    let catalog = vec![2; 896];
    let authority = vec![3; 3776];
    #[cfg(not(feature = "experimental-root-bundle"))]
    let allocation = vec![4; 137];
    #[cfg(feature = "experimental-root-bundle")]
    let allocation = {
        let mut states = vec![crate::SegmentAllocation::Free; 16];
        states[7] = crate::SegmentAllocation::Allocated;
        crate::encode_allocation_v2(&crate::AllocationV2::new(4, 4, 1, &states, &[]).unwrap()).unwrap()
    };
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
    let selected_checkpoint;
    #[cfg(feature = "experimental-root-bundle")]
    let (refs, context) = {
        use vibeos_segment_format::{Checkpoint, FormatGeometry, Superblock};
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
        let mut supers = vec![[[0; PAGE_SIZE]; 2]; 2];
        for copy in 0..2 {
            let superblock = Superblock { binding: RecordBinding { store_uuid: store, generation: 1,
                segment_no: ANCHOR_SEGMENT_NO, ordinal: copy as u32, self_page: copy as u64 * 2,
                target_checkpoint_generation: 0 }, copy: copy as u8, geometry: FormatGeometry::STORAGE_V2,
                cleaner_reserve_segments: 1, initial_range_pages: admitted_pages(16).unwrap(), initial_segments: 16,
                device_id: [1; 16], range_first_logical_block: 0, initial_block_count: admitted_pages(16).unwrap(),
                logical_block_size: 4096, max_replay_records: 128 };
            let digest = cp::encode_superblock(&superblock, &mut supers[copy][0]).unwrap();
            encode_record_seal(digest, &mut supers[copy][1]).unwrap();
        }
        run(async {
            for copy in 0..2 {
                device.write_pages(copy as u64 * 2, &supers[copy]).await.unwrap();
            }
            device.write_page(6, &body).await.unwrap();
            device.write_page(7, &seal).await.unwrap();
            device.flush().await.unwrap();
        });
        device.reads.borrow_mut().clear();
        assert!(matches!(run(select_device_checkpoint(&device, 4 * PAGE_SIZE - 1, 128)),
            Err(crate::StoreError::MemoryLimit)));
        assert!(device.reads.borrow().is_empty());
        let selected = run(select_device_checkpoint(&device, 4 * PAGE_SIZE, 128)).unwrap();
        assert_eq!(*device.reads.borrow(), [(0, 4), (4, 4)]);
        for index in 0..2 {
            device.reads.borrow_mut().clear();
            device.fail_at.set(Some(index));
            assert!(matches!(run(select_device_checkpoint(&device, 4 * PAGE_SIZE, 128)),
                Err(crate::StoreError::Device("injected read failure"))));
        }
        device.fail_at.set(None);
        let info = device.info();
        for changed in [PageDeviceInfo { device_id: [2; 16], ..info },
            PageDeviceInfo { range_first_logical_block: 1, ..info },
            PageDeviceInfo { logical_block_size: 0, ..info },
            PageDeviceInfo { logical_block_count: info.logical_block_count - 1, ..info },
            PageDeviceInfo { page_count: info.page_count - 1, ..info }] {
            device.info_override.set(Some(changed));
            assert!(run(select_device_checkpoint(&device, 4 * PAGE_SIZE, 128)).is_err());
        }
        device.info_override.set(None);
        assert!(run(select_device_checkpoint(&device, 4 * PAGE_SIZE, 127)).is_err());
        for (page, offset) in [(0, 0xf4), (6, 0xc0)] {
            let original = device.pages.borrow()[&page];
            device.pages.borrow_mut().get_mut(&page).unwrap()[offset] ^= 1;
            assert!(run(select_device_checkpoint(&device, 4 * PAGE_SIZE, 128)).is_err());
            device.pages.borrow_mut().insert(page, original);
        }
        let anchors: Vec<_> = (0..8).map(|page| (page, device.pages.borrow_mut().remove(&page))).collect();
        assert!(matches!(run(select_device_checkpoint(&device, 4 * PAGE_SIZE, 128)),
            Err(crate::StoreError::Unformatted)));
        for (page, bytes) in anchors {
            if let Some(bytes) = bytes { device.pages.borrow_mut().insert(page, bytes); }
        }
        assert!(run(select_device_checkpoint(&device, 4 * PAGE_SIZE, 128)).is_ok());
        let (decoded, read_context) = RootReferences::from_checkpoint(selected.current(), context.budget).unwrap();
        assert_eq!(decoded, refs);
        selected_checkpoint = selected;
        device.reads.borrow_mut().clear();
        (decoded, read_context)
    };
    let owned = run(refs.read_bundle(&device, Role::Catalog, context)).unwrap();
    let calls = device.reads.borrow().len();
    assert!(calls > 0);
    assert_eq!(owned.get(Role::Catalog).unwrap(), catalog);
    assert_eq!(owned.get(Role::Authority).unwrap(), authority);
    assert_eq!(owned.get(Role::Allocation).unwrap(), allocation);
    #[cfg(feature = "experimental-root-bundle")]
    {
        let decoded = owned.recover_allocation::<()>(selected_checkpoint.current(), 16 * 1024, 0).unwrap();
        assert_eq!(decoded.map().segment_state(7), Some(crate::SegmentAllocation::Allocated));
        assert_eq!(decoded.map().segment_state(6), Some(crate::SegmentAllocation::Free));
        let required = owned.retained_payload_capacity() + decoded.map().allocated_bytes().unwrap();
        assert!(matches!(owned.recover_allocation::<()>(selected_checkpoint.current(), required - 1, 0),
            Err(crate::StoreError::MemoryLimit)));
        assert!(owned.recover_allocation::<()>(selected_checkpoint.current(), required, 0).is_ok());
        assert!(matches!(owned.recover_allocation::<()>(selected_checkpoint.current(), required, 1),
            Err(crate::StoreError::MemoryLimit)));
        // Decoded-member semantic fixtures only: these buffers bypass framing
        // authentication, and the declared manifest is not present on disk.
        let PhysicalPointer::Value(carrier) = owned.source_pointer else { panic!("missing carrier"); };
        let key = crate::BlobKey::sha256(1, 4, [9; 32]).unwrap();
        let codec_context = crate::CasCodecContext::new(store, 16, 4).unwrap();
        for (generation, manifest_segment, accepted) in [(4, 7, true), (3, 7, false), (4, 6, false)] {
            let snapshot = crate::CasSnapshot { checkpoint_generation: generation,
                objects: vec![crate::ObjectMapping { object_id: 1, blob_key: key,
                    commit_generation: generation, reference_codec: 0 }],
                blobs: vec![crate::BlobMapping { blob_key: key,
                    manifest: PhysicalPointer::Value(vibeos_segment_format::PointerValue {
                        segment_no: manifest_segment, exact_byte_len: 256, payload_pages: 1, ..carrier }) }] };
            let encoded = crate::encode_cas_snapshot(&snapshot, codec_context).unwrap();
            let len = encoded.len();
            let changed = OwnedRootBundle { bytes: encoded, ranges: [0..len, 0..0, 0..0],
                selected: [true, false, false], source_pointer: owned.source_pointer,
                target_checkpoint_generation: owned.target_checkpoint_generation };
            let result = changed.decode_catalog_snapshot::<()>(&decoded, 16 * 1024, 0, 1);
            assert_eq!(result.is_ok(), accepted);
            if accepted {
                let recovered = result.unwrap();
                assert_eq!(recovered, snapshot);
                let table_bytes = recovered.objects.capacity() * core::mem::size_of::<crate::ObjectMapping>()
                    + recovered.blobs.capacity() * core::mem::size_of::<crate::BlobMapping>();
                let peak = changed.retained_payload_capacity() + decoded.map().allocated_bytes().unwrap() + table_bytes;
                assert!(changed.decode_catalog_snapshot::<()>(&decoded, peak, 0, 1).is_ok());
                assert!(matches!(changed.decode_catalog_snapshot::<()>(&decoded, peak - 1, 0, 1), Err(crate::StoreError::MemoryLimit)));
                // The entry limit must win before any decoded-table allocation.
                assert!(matches!(changed.decode_catalog_snapshot::<()>(&decoded, 0, 0, 0), Err(crate::StoreError::Corrupt)));
                let before = device.reads.borrow().len();
                assert!(run(changed.recover_catalog_without_replay(&device, &decoded, 16 * 1024, 0, 1)).is_err());
                assert!(device.reads.borrow().len() > before, "reference recovery must consult the device");
                device.reads.borrow_mut().truncate(before);
            }
        }
        // Unit-test the semantic layer after authentication. These deliberately
        // altered private buffers are not claimed to be valid on-disk containers.
        for generation in [3, 4] {
            let mut states = vec![crate::SegmentAllocation::Free; 16];
            if generation == 3 { states[7] = crate::SegmentAllocation::Allocated; }
            let invalid = crate::encode_allocation_v2(&crate::AllocationV2::new(generation, 4, 1, &states, &[]).unwrap()).unwrap();
            let mut bytes = owned.bytes.clone();
            bytes[owned.ranges[2].clone()].copy_from_slice(&invalid);
            let changed = OwnedRootBundle { bytes, ranges: owned.ranges.clone(), selected: owned.selected,
                source_pointer: owned.source_pointer, target_checkpoint_generation: owned.target_checkpoint_generation };
            assert!(changed.recover_allocation::<()>(selected_checkpoint.current(), usize::MAX, 0).is_err());
        }
        let mut retired_states = vec![crate::SegmentAllocation::Free; 16];
        retired_states[7] = crate::SegmentAllocation::Retired;
        let retired = crate::encode_allocation_v2(&crate::AllocationV2::new(4, 4, 1, &retired_states,
            &[crate::RetiredSegment { segment_no: 7, retire_generation: 4 }]).unwrap()).unwrap();
        let legacy = crate::AllocationState { checkpoint_generation: 4, admitted_segments: 16,
            allocated_prefix_segments: 8, next_segment_generation: 4, cleaner_reserve_segments: 1 };
        let valid_legacy = crate::encode_allocation(legacy).unwrap();
        let wrong_prefix = crate::encode_allocation(crate::AllocationState {
            allocated_prefix_segments: 9, ..legacy }).unwrap();
        for (payload, accepted) in [(retired.as_slice(), false), (valid_legacy.as_slice(), true),
                                   (wrong_prefix.as_slice(), false)] {
            let mut bytes = owned.bytes[..owned.ranges[2].start].to_vec();
            bytes.extend_from_slice(payload);
            let mut ranges = owned.ranges.clone();
            ranges[2].end = bytes.len();
            let changed = OwnedRootBundle { bytes, ranges, selected: owned.selected,
                source_pointer: owned.source_pointer, target_checkpoint_generation: owned.target_checkpoint_generation };
            assert_eq!(changed.recover_allocation::<()>(selected_checkpoint.current(), usize::MAX, 0).is_ok(), accepted);
        }
    }
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
            fail_at: Cell::new(None), writes: Cell::new(0), flushes: Cell::new(0), info_override: Cell::new(None) };
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

#[cfg(feature = "experimental-root-bundle")]
#[test]
fn empty_checkpoint_recovers_without_payload_io() {
    use vibeos_segment_format::{Checkpoint, FormatGeometry, Superblock};
    use vibeos_segment_format::experimental_root_checkpoint::{self as cp, BundleCheckpoint};
    let store = StoreUuid::new([1; 16]).unwrap();
        let device = Device { pages: RefCell::new(BTreeMap::new()), reads: RefCell::new(Vec::new()),
            fail_at: Cell::new(None), writes: Cell::new(0), flushes: Cell::new(0), info_override: Cell::new(None) };
        for copy in 0..2 {
            let mut body = [0; PAGE_SIZE];
            let mut seal = [0; PAGE_SIZE];
            let value = Superblock { binding: RecordBinding { store_uuid: store, generation: 1,
                segment_no: ANCHOR_SEGMENT_NO, ordinal: copy, self_page: u64::from(copy) * 2,
                target_checkpoint_generation: 0 }, copy: copy as u8, geometry: FormatGeometry::STORAGE_V2,
                cleaner_reserve_segments: 1, initial_range_pages: admitted_pages(16).unwrap(), initial_segments: 16,
                device_id: [1; 16], range_first_logical_block: 0, initial_block_count: admitted_pages(16).unwrap(),
                logical_block_size: 4096, max_replay_records: 128 };
            let digest = cp::encode_superblock(&value, &mut body).unwrap();
            encode_record_seal(digest, &mut seal).unwrap();
            run(device.write_pages(u64::from(copy) * 2, &[body, seal])).unwrap();
        }

    for (generation, next) in [(1, 1), (1, 2), (3, 1)] {
        let checkpoint = BundleCheckpoint { root_bundle_mask: 0, base: Checkpoint {
            binding: RecordBinding { store_uuid: store, generation, segment_no: ANCHOR_SEGMENT_NO,
                ordinal: 0, self_page: 4, target_checkpoint_generation: generation },
            slot: 0, previous_generation: generation - 1, admitted_range_pages: admitted_pages(16).unwrap(),
            admitted_segments: 16, next_segment_generation: next, replay_count: 0,
            max_replay_records: 128, cleaner_reserve_segments: 1, catalog_root: PhysicalPointer::Null,
            authority_root: PhysicalPointer::Null, allocation_root: PhysicalPointer::Null, replay_tail: PhysicalPointer::Null } };
        let mut body = [0; PAGE_SIZE];
        let mut seal = [0; PAGE_SIZE];
        let digest = cp::encode_body(checkpoint, &mut body).unwrap();
        encode_record_seal(digest, &mut seal).unwrap();
        run(device.write_pages(4, &[body, seal])).unwrap();
        let selected = run(select_device_checkpoint(&device, 16 * 1024, 128)).unwrap();
        device.reads.borrow_mut().clear();
        let recovered = run(recover_same_admission_allocations(&device, &selected, 4, 0));
        if generation == 1 && next == 1 {
            let pair = recovered.unwrap();
            assert!(pair.previous.is_none());
            for segment in 0..16 {
                assert_eq!(pair.current.map().segment_state(segment), Some(crate::SegmentAllocation::Free));
            }
            assert!(matches!(run(recover_same_admission_allocations(&device, &selected, 3, 0)),
                Err(crate::StoreError::MemoryLimit)));
            assert!(matches!(run(recover_same_admission_allocations(&device, &selected, 4, 1)),
                Err(crate::StoreError::MemoryLimit)));
        } else {
            assert!(matches!(recovered, Err(crate::StoreError::Corrupt)));
        }
        assert!(device.reads.borrow().is_empty());
        let recovered = run(recover_device_checkpoint(&device, 16 * 1024, 0, 0, 128));
        if generation == 1 && next == 1 {
            let recovered = recovered.unwrap();
            assert!(recovered.roots.is_none());
            assert_eq!(recovered.selected.value().base.binding.generation, 1);
            assert_eq!(device.reads.borrow().as_slice(), &[(0, 4), (4, 4)]);
            device.reads.borrow_mut().clear();
            assert!(matches!(run(recover_device_checkpoint(&device, 16 * 1024 - 1, 0, 0, 128)),
                Err(crate::StoreError::MemoryLimit)));
            assert!(device.reads.borrow().is_empty());
        } else { assert!(recovered.is_err()); }
    }
}

#[cfg(feature = "experimental-root-bundle")]
#[test]
fn nonempty_catalog_recovers_sealed_manifest_and_blob_descriptors() {
    use vibeos_segment_format::{Checkpoint, FormatGeometry, Superblock};
    use vibeos_segment_format::experimental_root_checkpoint::{self as cp, BundleCheckpoint};
    let store = StoreUuid::new([1; 16]).unwrap();
    for (replay_count, introduce_blob, duplicate_blob, cross_segment, split_deltas) in [
        (0_u32, false, false, false, false), (1, false, false, false, false), (3, false, false, false, false),
        (3, true, false, false, false), (3, true, true, false, false), (3, true, false, true, false),
        (3, true, false, true, true),
    ] {
    for separate_catalog in [false, true] {
    if separate_catalog && replay_count != 0 { continue; }
    for separate_authority in [false, true] {
    if separate_authority && !separate_catalog { continue; }
    for cross_checkpoint in [false, true] {
    if cross_checkpoint && !split_deltas { continue; }
    let checkpoint_generation = if cross_checkpoint { 6 } else { 4 };
    let replay = replay_count != 0;
    let delta_segments = if split_deltas { u64::from(replay_count) } else { u64::from(cross_segment) };
    let next_generation = 4 + delta_segments + u64::from(cross_checkpoint);
        let device = Device { pages: RefCell::new(BTreeMap::new()), reads: RefCell::new(Vec::new()),
            fail_at: Cell::new(None), writes: Cell::new(0), flushes: Cell::new(0), info_override: Cell::new(None) };
        for copy in 0..2 {
            let mut body = [0; PAGE_SIZE];
            let mut seal = [0; PAGE_SIZE];
            let value = Superblock { binding: RecordBinding { store_uuid: store, generation: 1,
                segment_no: ANCHOR_SEGMENT_NO, ordinal: copy, self_page: u64::from(copy) * 2,
                target_checkpoint_generation: 0 }, copy: copy as u8, geometry: FormatGeometry::STORAGE_V2,
                cleaner_reserve_segments: 1, initial_range_pages: admitted_pages(16).unwrap(), initial_segments: 16,
                device_id: [1; 16], range_first_logical_block: 0, initial_block_count: admitted_pages(16).unwrap(),
                logical_block_size: 4096, max_replay_records: 128 };
            let digest = cp::encode_superblock(&value, &mut body).unwrap();
            encode_record_seal(digest, &mut seal).unwrap();
            run(device.write_pages(u64::from(copy) * 2, &[body, seal])).unwrap();
        }

    let content = b"data";
    let encoded = vibeos_blob_format::encode_blob(1, content).unwrap();
    let descriptor = vibeos_blob_format::BlobView::decode(&encoded).unwrap().descriptor();
    let key = crate::BlobKey::sha256(1, 4, descriptor.root).unwrap();
    let hash = payload_sha256(&encoded);
    let blob = crate::cas::build_record(store, 7, 3, 4, 1, 2, ExtentKind::Blob, 1,
        0, 1, 4, encoded.len() as u64, 0, encoded.len() as u64, key.merkle_root(), hash).unwrap();
    let context = crate::CasCodecContext::new(store, 16, next_generation).unwrap();
    let manifest = crate::encode_blob_manifest(&crate::BlobManifest { blob_key: key,
        encoded_blob_len: encoded.len() as u64, extents: vec![crate::ManifestExtent {
            extent_index: 0, extent_count: 1, encoded_offset: 0, payload_byte_len: encoded.len() as u64,
            pointer: blob.pointer() }] }, context).unwrap();
    let hash = payload_sha256(&manifest);
    let manifest_record = crate::cas::build_record(store, 7, 3, 4, 2, 2 + blob.value.record_span_pages,
        ExtentKind::Catalog, 0xffff_0010, 0, 1, manifest.len() as u64, manifest.len() as u64,
        0, manifest.len() as u64, hash, hash).unwrap();
    let mapping = crate::BlobMapping { blob_key: key, manifest: manifest_record.pointer() };
    let snapshot = crate::CasSnapshot { checkpoint_generation: 4,
        objects: if introduce_blob { vec![] } else { vec![crate::ObjectMapping { object_id: 1, blob_key: key,
            commit_generation: 4, reference_codec: 0 }] },
        blobs: if introduce_blob { vec![] } else { vec![mapping] } };
    let catalog = crate::encode_cas_snapshot(&snapshot, context).unwrap();
    let mut states = vec![crate::SegmentAllocation::Free; 16];
    states[7] = crate::SegmentAllocation::Allocated;
    for segment in 8..8 + delta_segments { states[segment as usize] = crate::SegmentAllocation::Allocated; }
    let allocation = crate::encode_allocation_v2(&crate::AllocationV2::new(4, next_generation, 1, &states, &[]).unwrap()).unwrap();
    let binding = Binding { store: [1; 16], segment: 7, generation: 3,
        descriptor: 2 + blob.value.record_span_pages + manifest_record.value.record_span_pages };
    let stream = vibeos_durable_format::RecordChain::new(vibeos_durable_format::StoreId::new(7).unwrap())
        .append(None, vibeos_durable_format::RecordBody::Format).unwrap().to_vec();
    let authority = crate::PersistentAuthoritySnapshot::new(4, crate::root_policy_commitment(b"test external roots"),
        stream, vec![], vec![]).unwrap().with_external_roots(vec![crate::PersistentRootEntry {
            object_id: 1, commit_generation: 4, object_kind: 1 }]).unwrap();
    let authority_bytes = crate::encode_persistent_authority_snapshot(&authority).unwrap();
    let prepared = prepare_bundle::<&'static str>(binding,
        Roots { catalog: &catalog, authority: &authority_bytes, allocation: &allocation }, 4, 3, 16 * 1024).unwrap().unwrap();
    let catalog_hash = payload_sha256(&catalog);
    let catalog_record = crate::cas::build_record(store, 7, 3, 4, 4,
        binding.descriptor + prepared.record.value.record_span_pages, ExtentKind::Catalog, 0xffff_0011,
        0, 1, catalog.len() as u64, catalog.len() as u64, 0, catalog.len() as u64, catalog_hash, catalog_hash).unwrap();
    let catalog_pointer = if separate_catalog { catalog_record.pointer() } else { prepared.record.pointer() };
    let authority_hash = payload_sha256(&authority_bytes);
    let authority_record = crate::cas::build_record(store, 7, 3, 4, 5,
        binding.descriptor + prepared.record.value.record_span_pages + catalog_record.value.record_span_pages,
        ExtentKind::Authority, 0xffff_0021, 0, 1, authority_bytes.len() as u64, authority_bytes.len() as u64,
        0, authority_bytes.len() as u64, authority_hash, authority_hash).unwrap();
    let authority_pointer = if separate_authority { authority_record.pointer() } else { prepared.record.pointer() };
    let mut deltas = Vec::new();
    let mut delta_payloads = Vec::new();
    let mut replay_tail = PhysicalPointer::Null;
    let mut delta_at = if cross_segment { 2 } else { binding.descriptor + prepared.record.value.record_span_pages };
    for depth in 1..=replay_count {
        let target = if cross_checkpoint { 3 + u64::from(depth) } else { 4 };
        let payload = crate::encode_cas_delta(crate::CasDelta { checkpoint_generation: target, chain_count: depth,
            previous_delta: replay_tail, object: crate::ObjectMapping { object_id: u128::from(depth) + u128::from(!introduce_blob), blob_key: key,
                commit_generation: target, reference_codec: 0 },
            new_blob: if introduce_blob && (depth == 1 || duplicate_blob && depth == 2) { Some(mapping) } else { None } }, context).unwrap();
        let hash = payload_sha256(&payload);
        let record = crate::cas::build_record(store,
            if split_deltas { 7 + u64::from(depth) } else if cross_segment { 8 } else { 7 },
            if split_deltas { 3 + u64::from(depth) } else if cross_segment { 4 } else { 3 }, target,
            if split_deltas { 1 } else if cross_segment { depth } else { 3 + depth },
            if split_deltas { 2 } else { delta_at }, ExtentKind::CatalogDelta, 0xffff_0012,
            0, 1, payload.len() as u64, payload.len() as u64, 0, payload.len() as u64, hash, hash).unwrap();
        delta_at += record.value.record_span_pages;
        replay_tail = record.pointer();
        deltas.push(record);
        delta_payloads.push(payload);
    }
    let base = segment_base_page(7).unwrap();
    let header = SegmentHeader { binding: RecordBinding { store_uuid: store, generation: 3,
        segment_no: 7, ordinal: 0, self_page: base, target_checkpoint_generation: 4 }, base_page: base,
        previous_segment_no: ANCHOR_SEGMENT_NO, previous_segment_generation: 0, previous_segment_seal_body_sha256: [0; 32] };
    let mut body = [0; PAGE_SIZE];
    let mut seal = [0; PAGE_SIZE];
    let digest = encode_segment_header_body(&header, &mut body).unwrap();
    encode_record_seal(digest, &mut seal).unwrap();
    let mut payloads = vec![(&blob, encoded.as_slice()), (&manifest_record, manifest.as_slice()),
        (&prepared.record, prepared.payload.as_slice())];
    if separate_catalog { payloads.push((&catalog_record, catalog.as_slice())); }
    if separate_authority { payloads.push((&authority_record, authority_bytes.as_slice())); }
    if !cross_segment { payloads.extend(deltas.iter().zip(delta_payloads.iter().map(Vec::as_slice))); }
    run(crate::cas::write_payload_records_with_header(&device, base, Some((&body, &seal)),
        &payloads, true, None)).unwrap();
    drop(payloads);
    let pointer = prepared.record.pointer();
    let manifest_page = base + u64::from(manifest_record.value.payload_first_relative_page);
    let mut records = vec![blob, manifest_record, prepared.record];
    if separate_catalog { records.push(catalog_record); }
    if separate_authority { records.push(authority_record); }
    if !cross_segment { records.append(&mut deltas); }
    let mut previous = run(crate::cas::finalize_segment(&device, store, 4, 7, 3, digest,
        &records, true, None)).unwrap();
    if cross_segment {
        for part in 0..delta_segments {
            let number = 8 + part;
            let generation = 4 + part;
            let target = if cross_checkpoint { 4 + part } else { 4 };
            let delta_base = segment_base_page(number).unwrap();
            let header = SegmentHeader { binding: RecordBinding { store_uuid: store, generation,
                segment_no: number, ordinal: 0, self_page: delta_base, target_checkpoint_generation: target }, base_page: delta_base,
                previous_segment_no: previous.0, previous_segment_generation: previous.1,
                previous_segment_seal_body_sha256: previous.2 };
            let digest = encode_segment_header_body(&header, &mut body).unwrap();
            encode_record_seal(digest, &mut seal).unwrap();
            let range = if split_deltas { part as usize..part as usize + 1 } else { 0..deltas.len() };
            let payloads: Vec<_> = deltas[range.clone()].iter().zip(delta_payloads[range.clone()].iter().map(Vec::as_slice)).collect();
            run(crate::cas::write_payload_records_with_header(&device, delta_base, Some((&body, &seal)),
                &payloads, true, None)).unwrap();
            previous = run(crate::cas::finalize_segment(&device, store, target, number, generation, digest,
                &deltas[range], true, None)).unwrap();
        }
    }
    let mut allocation_pointer = pointer;
    if cross_checkpoint {
        states[11] = crate::SegmentAllocation::Allocated;
        let allocation = crate::encode_allocation_v2(&crate::AllocationV2::new(6, next_generation, 1, &states, &[]).unwrap()).unwrap();
        let hash = payload_sha256(&allocation);
        let record = crate::cas::build_record(store, 11, 7, 6, 1, 2, ExtentKind::Allocation, 0xffff_0002,
            0, 1, allocation.len() as u64, allocation.len() as u64, 0, allocation.len() as u64, hash, hash).unwrap();
        allocation_pointer = record.pointer();
        let allocation_base = segment_base_page(11).unwrap();
        let header = SegmentHeader { binding: RecordBinding { store_uuid: store, generation: 7,
            segment_no: 11, ordinal: 0, self_page: allocation_base, target_checkpoint_generation: 6 }, base_page: allocation_base,
            previous_segment_no: previous.0, previous_segment_generation: previous.1,
            previous_segment_seal_body_sha256: previous.2 };
        let digest = encode_segment_header_body(&header, &mut body).unwrap();
        encode_record_seal(digest, &mut seal).unwrap();
        run(crate::cas::write_payload_records_with_header(&device, allocation_base, Some((&body, &seal)),
            &[(&record, &allocation)], true, None)).unwrap();
        run(crate::cas::finalize_segment(&device, store, 6, 11, 7, digest, &[record], true, None)).unwrap();
    }
    run(device.flush()).unwrap();
    let checkpoint = BundleCheckpoint { root_bundle_mask: if cross_checkpoint { 3 } else if separate_authority { 4 } else if separate_catalog { 6 } else { 7 }, base: Checkpoint {
        binding: RecordBinding { store_uuid: store, generation: checkpoint_generation, segment_no: ANCHOR_SEGMENT_NO,
            ordinal: 1, self_page: 6, target_checkpoint_generation: checkpoint_generation }, slot: 1, previous_generation: checkpoint_generation - 1,
        admitted_range_pages: admitted_pages(16).unwrap(), admitted_segments: 16, next_segment_generation: next_generation,
        replay_count, max_replay_records: 128, cleaner_reserve_segments: 1,
        catalog_root: catalog_pointer, authority_root: authority_pointer, allocation_root: allocation_pointer, replay_tail } };
    let digest = cp::encode_body(checkpoint, &mut body).unwrap();
    encode_record_seal(digest, &mut seal).unwrap();
    run(device.write_pages(6, &[body, seal])).unwrap();
    let selected = run(select_device_checkpoint(&device, 16 * 1024, 128)).unwrap();
    let maps = run(recover_same_admission_allocations(&device, &selected, 16 * 1024, 0)).unwrap();
    let (refs, context) = RootReferences::from_checkpoint(selected.current(), 16 * 1024).unwrap();
    let complete = run(recover_device_checkpoint(&device, 32 * 1024, 0, replay_count as usize + 1, 128));
    if duplicate_blob { assert!(complete.is_err()); }
    else {
        let complete = complete.unwrap();
        assert_eq!(complete.selected.value().base.binding.generation, checkpoint_generation);
        assert_eq!(complete.roots.unwrap().roots.entries().len(), 1);
    }
    if separate_catalog {
        let (_, dispatched) = run(recover_checkpoint_roots(&device, &selected, 32 * 1024, 0, 1)).unwrap();
        assert_eq!(dispatched.catalog, snapshot);
        assert_eq!(dispatched.roots.entries().len(), 1);
        drop(dispatched);
        let restored = run(recover_separate_catalog(&device, &maps.current, 32 * 1024, 0, 1)).unwrap();
        assert_eq!(restored, snapshot);
        let (_, roots) = if separate_authority {
            let result = run(recover_separate_authority(&device, &maps.current, &restored, 32 * 1024, 0)).unwrap();
            assert!(matches!(run(recover_separate_authority(&device, &maps.current, &restored, 0, 0)),
                Err(crate::StoreError::MemoryLimit)));
            let PhysicalPointer::Value(value) = authority_pointer else { panic!("missing authority"); };
            let page = base + u64::from(value.payload_relative_page);
            device.pages.borrow_mut().get_mut(&page).unwrap()[0] ^= 1;
            assert!(run(recover_separate_authority(&device, &maps.current, &restored, 32 * 1024, 0)).is_err());
            device.pages.borrow_mut().get_mut(&page).unwrap()[0] ^= 1;
            result
        } else {
            let authority_bundle = run(refs.read_bundle(&device, Role::Authority, context)).unwrap();
            authority_bundle.decode_authority_snapshot::<()>(&maps.current, &restored, 32 * 1024, 0).unwrap()
        };
        assert_eq!(roots.entries().len(), 1);
        assert!(matches!(run(recover_separate_catalog(&device, &maps.current, 0, 0, 1)), Err(crate::StoreError::MemoryLimit)));
        let PhysicalPointer::Value(catalog_pointer) = catalog_pointer else { panic!("missing catalog"); };
        let page = base + u64::from(catalog_pointer.payload_relative_page);
        device.pages.borrow_mut().get_mut(&page).unwrap()[0] ^= 1;
        assert!(run(recover_separate_catalog(&device, &maps.current, 32 * 1024, 0, 1)).is_err());
        continue;
    }
    let bundle = run(refs.read_bundle(&device, Role::Catalog, context)).unwrap();
    if replay {
        let limit = replay_count as usize + usize::from(!introduce_blob);
        device.reads.borrow_mut().clear();
        let result = run(bundle.recover_catalog(&device, &maps.current, 32 * 1024, 0, limit));
        if duplicate_blob {
            assert!(matches!(result, Err(crate::StoreError::Corrupt)));
            continue;
        }
        let result = result.unwrap();
        assert_eq!(result.objects.len(), limit);
        assert_eq!(result.checkpoint_generation, checkpoint_generation);
        for (index, object) in result.objects.iter().enumerate() { assert_eq!(object.object_id, index as u128 + 1); }
        assert_eq!(result.blobs, vec![mapping]);
        let reads = device.reads.borrow().len();
        for failed in 0..reads {
            let bundle = run(refs.read_bundle(&device, Role::Catalog, context)).unwrap();
            device.reads.borrow_mut().clear();
            device.fail_at.set(Some(failed));
            assert!(run(bundle.recover_catalog(&device, &maps.current, 32 * 1024, 0, limit)).is_err());
            device.fail_at.set(None);
        }
        device.reads.borrow_mut().clear();
        let (joined_maps, joined) = run(recover_bundled_checkpoint(&device, &selected, 32 * 1024, 0, limit)).unwrap();
        assert_eq!(joined_maps.current.map().segment_state(7), Some(crate::SegmentAllocation::Allocated));
        assert_eq!(joined.catalog, result);
        assert_eq!(joined.roots.entries()[0].object_id, 1);
        let PhysicalPointer::Value(root_pointer) = pointer else { panic!("missing root"); };
        let root_page = base + u64::from(root_pointer.payload_relative_page);
        assert_eq!(device.reads.borrow().iter().filter(|(page, _)| *page == root_page).count(), 1);
        drop(joined);
        let mut low = 0;
        let mut high = 32 * 1024;
        while low < high {
            let budget = low + (high - low) / 2;
            let bundle = run(refs.read_bundle(&device, Role::Catalog, context)).unwrap();
            match run(bundle.recover_catalog(&device, &maps.current, budget, 0, limit)) {
                Ok(_) => high = budget,
                Err(crate::StoreError::MemoryLimit) => low = budget + 1,
                Err(_) => panic!("unexpected replay error at memory boundary"),
            }
        }
        let bundle = run(refs.read_bundle(&device, Role::Catalog, context)).unwrap();
        assert!(run(bundle.recover_catalog(&device, &maps.current, high, 0, limit)).is_ok());
        let bundle = run(refs.read_bundle(&device, Role::Catalog, context)).unwrap();
        assert!(matches!(run(bundle.recover_catalog(&device, &maps.current, high - 1, 0, limit)),
            Err(crate::StoreError::MemoryLimit)));
        let bundle = run(refs.read_bundle(&device, Role::Catalog, context)).unwrap();
        assert!(matches!(run(bundle.recover_catalog(&device, &maps.current, 32 * 1024, 0, 1)),
            Err(crate::StoreError::Corrupt)));
        let bundle = run(refs.read_bundle(&device, Role::Catalog, context)).unwrap();
        let PhysicalPointer::Value(tail) = replay_tail else { panic!("missing replay"); };
        let tail_page = segment_base_page(tail.segment_no).unwrap() + u64::from(tail.payload_relative_page);
        device.pages.borrow_mut().get_mut(&tail_page).unwrap()[0] ^= 1;
        assert!(run(bundle.recover_catalog(&device, &maps.current, 32 * 1024, 0, limit)).is_err());
        device.pages.borrow_mut().get_mut(&tail_page).unwrap()[0] ^= 1;
        for segment in 8..8 + delta_segments {
            let segment_seal = segment_base_page(segment).unwrap() + u64::from(SEGMENT_SEAL_PAGE);
            device.pages.borrow_mut().get_mut(&segment_seal).unwrap()[0] ^= 1;
            assert!(run(recover_bundled_checkpoint(&device, &selected, 32 * 1024, 0, limit)).is_err());
            device.pages.borrow_mut().get_mut(&segment_seal).unwrap()[0] ^= 1;
        }
        if replay_count > 1 {
            let mut wrong = checkpoint;
            wrong.base.replay_count -= 1;
            let digest = cp::encode_body(wrong, &mut body).unwrap();
            encode_record_seal(digest, &mut seal).unwrap();
            run(device.write_pages(6, &[body, seal])).unwrap();
            let wrong_selected = run(select_device_checkpoint(&device, 16 * 1024, 128)).unwrap();
            let wrong_maps = run(recover_same_admission_allocations(&device, &wrong_selected, 16 * 1024, 0)).unwrap();
            let bundle = run(refs.read_bundle(&device, Role::Catalog, context)).unwrap();
            assert!(run(bundle.recover_catalog(&device, &wrong_maps.current, 32 * 1024, 0, limit)).is_err());
        }
        continue;
    }
    let decoded_catalog = bundle.decode_catalog_snapshot::<()>(&maps.current, 32 * 1024, 0, 1).unwrap();
    let (decoded_authority, roots) = bundle.decode_authority_snapshot::<()>(&maps.current, &decoded_catalog,
        32 * 1024, 0).unwrap();
    assert_eq!(decoded_authority.checkpoint_generation(), 4);
    assert_eq!(roots.entries(), &[crate::PersistentRootEntry { object_id: 1, commit_generation: 4, object_kind: 1 }]);
    drop((decoded_authority, roots));
    // Catalog mismatch cases test root resolution after authenticated authority
    // decoding; these caller tables are intentionally not sealed fixtures.
    for mismatch in 0..3 {
        let mut wrong = decoded_catalog.clone();
        match mismatch {
            0 => wrong.objects.clear(),
            1 => wrong.objects[0].commit_generation = 3,
            _ => wrong.objects[0].blob_key = crate::BlobKey::sha256(2, 4, descriptor.root).unwrap(),
        }
        assert!(matches!(bundle.decode_authority_snapshot::<()>(&maps.current, &wrong, 32 * 1024, 0),
            Err(crate::StoreError::Corrupt)));
    }
    let mut low = 0;
    let mut high = 32 * 1024;
    while low < high {
        let mid = low + (high - low) / 2;
        match bundle.decode_authority_snapshot::<()>(&maps.current, &decoded_catalog, mid, 0) {
            Ok(_) => high = mid,
            Err(crate::StoreError::MemoryLimit) => low = mid + 1,
            Err(_) => panic!("unexpected semantic failure during memory boundary search"),
        }
    }
    assert!(bundle.decode_authority_snapshot::<()>(&maps.current, &decoded_catalog, high, 0).is_ok());
    assert!(matches!(bundle.decode_authority_snapshot::<()>(&maps.current, &decoded_catalog, high - 1, 0),
        Err(crate::StoreError::MemoryLimit)));
    assert!(matches!(bundle.decode_authority_snapshot::<()>(&maps.current, &decoded_catalog, high, 1),
        Err(crate::StoreError::MemoryLimit)));
    drop(decoded_catalog);
    assert_eq!(run(bundle.recover_catalog_without_replay(&device, &maps.current, 16 * 1024, 0, 1)).unwrap(), snapshot);
    device.reads.borrow_mut().clear();
    let bundle = run(refs.read_bundle(&device, Role::Catalog, context)).unwrap();
    let PhysicalPointer::Value(bundle_pointer) = pointer else { panic!("missing bundle"); };
    let bundle_page = base + u64::from(bundle_pointer.payload_relative_page);
    let combined = run(bundle.recover_roots_without_replay(&device, &maps.current, 32 * 1024, 0, 1)).unwrap();
    assert_eq!(combined.catalog, snapshot);
    assert_eq!(combined.authority.checkpoint_generation(), 4);
    assert_eq!(combined.roots.entries().len(), 1);
    assert_eq!(device.reads.borrow().iter().filter(|(page, _)| *page == bundle_page).count(), 1,
        "combined recovery must not reload the root container");
    drop(combined);
    device.reads.borrow_mut().clear();
    let (all_maps, all_roots) = run(recover_bundled_checkpoint_without_replay(&device, &selected, 32 * 1024, 0, 1)).unwrap();
    assert_eq!(all_roots.catalog, snapshot);
    assert_eq!(all_maps.current.map().segment_state(7), Some(crate::SegmentAllocation::Allocated));
    assert_eq!(device.reads.borrow().iter().filter(|(page, _)| *page == bundle_page).count(), 1,
        "allocation and root recovery must share the current container");
    drop((all_maps, all_roots));
    let recovery_reads = device.reads.borrow().len();
    // Every injected failure partially fills the caller's output before error.
    // No read failure may turn into a successful combined recovery result.
    for failed_read in 0..recovery_reads {
        device.reads.borrow_mut().clear();
        device.fail_at.set(Some(failed_read));
        assert!(run(recover_bundled_checkpoint_without_replay(&device, &selected,
            32 * 1024, 0, 1)).is_err(), "accepted failed read {failed_read}");
    }
    device.fail_at.set(None);
    device.reads.borrow_mut().clear();
    let mut low = 0;
    let mut high = 32 * 1024;
    while low < high {
        let mid = low + (high - low) / 2;
        match run(recover_bundled_checkpoint_without_replay(&device, &selected, mid, 0, 1)) {
            Ok(_) => high = mid,
            Err(crate::StoreError::MemoryLimit) => low = mid + 1,
            Err(_) => panic!("unexpected combined recovery error at budget {mid}"),
        }
    }
    assert!(run(recover_bundled_checkpoint_without_replay(&device, &selected, high, 0, 1)).is_ok());
    assert!(matches!(run(recover_bundled_checkpoint_without_replay(&device, &selected, high - 1, 0, 1)),
        Err(crate::StoreError::MemoryLimit)));
    assert!(matches!(run(recover_bundled_checkpoint_without_replay(&device, &selected, high, 1, 1)),
        Err(crate::StoreError::MemoryLimit)));
    let bundle = run(refs.read_bundle(&device, Role::Catalog, context)).unwrap();
    device.pages.borrow_mut().get_mut(&manifest_page).unwrap()[0] ^= 1;
    assert!(run(bundle.recover_catalog_without_replay(&device, &maps.current, 16 * 1024, 0, 1)).is_err());
    device.pages.borrow_mut().get_mut(&manifest_page).unwrap()[0] ^= 1;
    let bundle = run(refs.read_bundle(&device, Role::Catalog, context)).unwrap();
    device.pages.borrow_mut().get_mut(&(base + 3)).unwrap()[0] ^= 1;
    assert!(run(bundle.recover_catalog_without_replay(&device, &maps.current, 16 * 1024, 0, 1)).is_err());
    }
    }
    }
    }
}
