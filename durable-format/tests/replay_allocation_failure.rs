//! Separate process: deny each append allocation once, without affecting other tests.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use vibeos_durable_format::*;

struct FaultAllocator;
thread_local! {
    static REMAINING: Cell<usize> = const { Cell::new(0) };
    static DENIED: Cell<bool> = const { Cell::new(false) };
}
fn deny() -> bool {
    REMAINING.try_with(|remaining| {
        let count = remaining.get();
        if count == 0 { return false; }
        remaining.set(count - 1);
        if count == 1 {
            DENIED.with(|denied| denied.set(true));
            true
        } else { false }
    }).unwrap_or(false)
}
unsafe impl GlobalAlloc for FaultAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if deny() { std::ptr::null_mut() } else { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout)
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if deny() { std::ptr::null_mut() } else { System.realloc(pointer, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: FaultAllocator = FaultAllocator;

#[test]
fn every_grant_object_and_tombstone_append_allocation_fails_closed() {
    let store = StoreId::new(90000).unwrap();
    let mut chain = RecordChain::new(store);
    let mut records = vec![chain.append(None, RecordBody::Format).unwrap(),
        chain.append(None, RecordBody::IdHighWater { exclusive_end: 100000 }).unwrap()];
    for i in 0..32 {
        let tx = TransactionId::new(10000 + i).unwrap();
        let derivation = DerivationId::new(20000 + i).unwrap();
        let prepare = chain.append(Some(tx), RecordBody::GrantPrepare(GrantRecord {
            derivation_id: derivation, parent_id: None, object_id: ObjectId::new(1).unwrap(),
            target: SlotIdentity { space: SpaceId::new(2).unwrap(), slot: i as u32, generation: 1 },
            rights: DurableRights::ALL, resource_kind: ResourceKind::new(7).unwrap(), flags: GrantFlags::ROOT,
        })).unwrap();
        let DecodeStatus::Valid(decoded) = LogRecord::decode(&prepare).unwrap() else { unreachable!() };
        records.push(prepare);
        records.push(chain.append(Some(tx), RecordBody::GrantCommit {
            prepare_sequence: decoded.record.sequence, prepare_crc32c: decoded.crc32c,
            derivation_id: derivation,
        }).unwrap());
    }
    records.extend(encode_object_transaction(&mut chain, TransactionId::new(30000).unwrap(),
        ObjectId::new(40000).unwrap(), ObjectKind::new(7).unwrap(), &[]).unwrap().records);
    records.push(chain.append(Some(TransactionId::new(30001).unwrap()), RecordBody::ObjectExternal {
        object_id: ObjectId::new(40001).unwrap(), object_kind: ObjectKind::new(7).unwrap(),
        byte_len: 4096, merkle_root: [1; 32],
    }).unwrap());
    let payload = vec![0x5a; 4096];
    records.extend(encode_object_transaction(&mut chain, TransactionId::new(30002).unwrap(),
        ObjectId::new(40002).unwrap(), ObjectKind::new(7).unwrap(), &payload).unwrap().records);
    for i in (0..32).rev() {
        records.push(chain.append(Some(TransactionId::new(60000 + i).unwrap()),
            RecordBody::RevokeTombstone { derivation_id: DerivationId::new(50000 + i).unwrap() }).unwrap());
    }
    records.push(chain.append(Some(TransactionId::new(61000).unwrap()),
        RecordBody::RevokeTombstone { derivation_id: DerivationId::new(50000).unwrap() }).unwrap());
    DENIED.with(|value| value.set(false));
    REMAINING.with(|value| value.set(1));
    for sector in &records { LogRecord::inspect_sector(sector).unwrap().unwrap(); }
    REMAINING.with(|value| value.set(0));
    assert!(!DENIED.with(Cell::get), "strict inspection must not allocate");
    // Replay the same mixed journal under a range of semantic byte limits.
    let mut reference = PreflightValidator::new(store);
    reference.append(&records).unwrap();
    let append_usage = reference.memory_usage().unwrap();
    let (_, reference_usage) = reference.finish_with_memory_usage().unwrap();
    let mut successful = 0;
    let mut rejected = 0;
    for limit in (0..reference_usage.peak_bytes).step_by(64)
        .chain(core::iter::once(reference_usage.peak_bytes)) {
        let mut bounded = PreflightValidator::with_memory_limit(store, limit);
        match bounded.append(&records) {
            Ok(()) => {
                let usage = bounded.memory_usage().unwrap();
                assert!(usage.retained_bytes <= usage.peak_bytes && usage.peak_bytes <= limit);
                match bounded.finish_with_memory_usage() {
                    Ok((sequence, usage)) => {
                        assert_eq!(sequence, records.len() as u64);
                        assert_eq!(usage.retained_bytes, 0);
                        assert!(usage.peak_bytes <= limit);
                        successful += 1;
                    }
                    Err(error) => { assert_eq!(error, RecoveryError::AllocationFailed); rejected += 1; }
                }
            }
            Err(error) => {
                assert_eq!(error, RecoveryError::AllocationFailed);
                assert_eq!(bounded.memory_usage(), Err(RecoveryError::ReplayPoisoned));
                assert_eq!(bounded.append(&[]), Err(RecoveryError::ReplayPoisoned));
                assert_eq!(bounded.finish(), Err(RecoveryError::ReplayPoisoned));
                rejected += 1;
            }
        }
    }
    assert!(successful > 0 && rejected > 0);
    let mut exact = PreflightValidator::with_memory_limit(store, reference_usage.peak_bytes);
    exact.append(&records).unwrap();
    assert_eq!(exact.finish().unwrap(), records.len() as u64);
    for chunk_size in [1, 3, 17] {
        let mut incremental = PreflightValidator::with_memory_limit(store, reference_usage.peak_bytes);
        for batch in records.chunks(chunk_size) {
            incremental.append(batch).unwrap();
            assert!(incremental.memory_usage().unwrap().peak_bytes <= reference_usage.peak_bytes);
        }
        let (sequence, usage) = incremental.finish_with_memory_usage().unwrap();
        assert_eq!(sequence, records.len() as u64);
        assert!(usage.peak_bytes <= reference_usage.peak_bytes);
    }
    eprintln!("VALIDATION_BUDGET append_retained={} append_peak={} finish_peak={} accepted_limits={successful} rejected_limits={rejected}",
        append_usage.retained_bytes, append_usage.peak_bytes, reference_usage.peak_bytes);
    for validate_only in [false, true] {
        let mut failures = 0;
        for nth in 1..256 {
            let mut replay = PreflightReplay::new(store);
            let mut validator = PreflightValidator::new(store);
            DENIED.with(|value| value.set(false));
            REMAINING.with(|value| value.set(nth));
            let result = if validate_only { validator.append(&records) } else { replay.append(&records) };
            REMAINING.with(|value| value.set(0));
            if DENIED.with(Cell::get) {
                failures += 1;
                assert_eq!(result, Err(RecoveryError::AllocationFailed));
                if validate_only {
                    assert_eq!(validator.append(&[]), Err(RecoveryError::ReplayPoisoned));
                    assert_eq!(validator.finish(), Err(RecoveryError::ReplayPoisoned));
                } else {
                    assert_eq!(replay.append(&[]), Err(RecoveryError::ReplayPoisoned));
                    assert_eq!(replay.finish().map(|v| v.last_sequence()), Err(RecoveryError::ReplayPoisoned));
                }
            } else {
                result.unwrap();
                let last = if validate_only { validator.finish().unwrap() } else { {
                    let recovered = replay.finish().unwrap();
                    assert_eq!(recovered.committed_objects().last().unwrap().bytes, payload);
                    recovered.last_sequence()
                } };
                assert_eq!(last, records.len() as u64);
                assert!(failures >= 32, "must include every prepared grant allocation");
                eprintln!("APPEND_ALLOCATION_FAILURE validate_only={validate_only} rejected_allocations={failures}");
                break;
            }
            assert!(nth < 255, "allocation sweep did not reach a successful append");
        }
        let mut finish_failures = 0;
        for nth in 1..256 {
            let mut replay = PreflightReplay::new(store);
            let mut validator = PreflightValidator::new(store);
            if validate_only { validator.append(&records).unwrap(); }
            else { replay.append(&records).unwrap(); }
            DENIED.with(|value| value.set(false));
            REMAINING.with(|value| value.set(nth));
            let result = if validate_only { validator.finish() }
                else { replay.finish().map(|recovered| recovered.last_sequence()) };
            REMAINING.with(|value| value.set(0));
            if DENIED.with(Cell::get) {
                finish_failures += 1;
                assert_eq!(result, Err(RecoveryError::AllocationFailed));
            } else {
                assert_eq!(result.unwrap(), records.len() as u64);
                assert!(finish_failures >= 3);
                eprintln!("FINISH_ALLOCATION_FAILURE validate_only={validate_only} rejected_allocations={finish_failures}");
                break;
            }
            assert!(nth < 255, "finish allocation sweep did not complete");
        }
    }
}

#[test]
fn zero_budget_accepts_allocation_free_format_validation() {
    let store = StoreId::new(90000).unwrap();
    let mut chain = RecordChain::new(store);
    let format = chain.append(None, RecordBody::Format).unwrap();
    let mut validator = PreflightValidator::with_memory_limit(store, 0);
    validator.append(&[format]).unwrap();
    assert_eq!(validator.memory_usage().unwrap().retained_bytes, 0);
    let (sequence, usage) = validator.finish_with_memory_usage().unwrap();
    assert_eq!(sequence, 1);
    assert_eq!(usage, ValidationMemoryUsage { retained_bytes: 0, peak_bytes: 0 });
}
