//! Isolated allocation measurement: run with --ignored --nocapture --test-threads=1.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use vibeos_durable_format::*;

struct Meter;
static ALLOCATION_CALLS: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
fn added(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
        let pointer = System.alloc(layout);
        if !pointer.is_null() {
            added(layout.size());
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(pointer, layout);
    }
    unsafe fn realloc(&self, pointer: *mut u8, old: Layout, size: usize) -> *mut u8 {
        ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
        let result = System.realloc(pointer, old, size);
        if !result.is_null() {
            if size >= old.size() {
                added(size - old.size());
            } else {
                LIVE.fetch_sub(old.size() - size, Ordering::Relaxed);
            }
        }
        result
    }
}
#[global_allocator]
static ALLOCATOR: Meter = Meter;

#[test]
#[ignore = "allocation measurement; run alone with one test thread"]
fn completed_transaction_replay_allocation() {
    const COUNT: u128 = 2048;
    let store_id = StoreId::new(90000).unwrap();
    let mut chain = RecordChain::new(store_id);
    let mut records = vec![
        chain.append(None, RecordBody::Format).unwrap(),
        chain
            .append(
                None,
                RecordBody::IdHighWater {
                    exclusive_end: 100000,
                },
            )
            .unwrap(),
    ];
    for index in 0..COUNT {
        let transaction = TransactionId::new(10000 + index).unwrap();
        let derivation = DerivationId::new(20000 + index).unwrap();
        let grant = GrantRecord {
            derivation_id: derivation,
            parent_id: None,
            object_id: ObjectId::new(1).unwrap(),
            target: SlotIdentity {
                space: SpaceId::new(2).unwrap(),
                slot: index as u32,
                generation: 1,
            },
            rights: DurableRights::ALL,
            resource_kind: ResourceKind::new(7).unwrap(),
            flags: GrantFlags::ROOT,
        };
        let prepared = chain
            .append(Some(transaction), RecordBody::GrantPrepare(grant))
            .unwrap();
        let DecodeStatus::Valid(decoded) = LogRecord::decode(&prepared).unwrap() else {
            unreachable!()
        };
        records.push(prepared);
        records.push(
            chain
                .append(
                    Some(transaction),
                    RecordBody::GrantCommit {
                        prepare_sequence: decoded.record.sequence,
                        prepare_crc32c: decoded.crc32c,
                        derivation_id: derivation,
                    },
                )
                .unwrap(),
        );
    }
    let mut replay = PreflightReplay::new(store_id);
    // Keep the input alive: measure allocator-requested bytes added by replay,
    // excluding record input storage and the later graph-materialization phase.
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let calls_before = ALLOCATION_CALLS.load(Ordering::Relaxed);
    replay.append(&records).unwrap();
    let allocation_calls = ALLOCATION_CALLS.load(Ordering::Relaxed) - calls_before;
    let retained = LIVE.load(Ordering::Relaxed) - baseline;
    let peak = PEAK.load(Ordering::Relaxed) - baseline;
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
    let recovered = replay.finish().unwrap();
    let finish_peak = PEAK.load(Ordering::Relaxed) - baseline;
    assert_eq!(recovered.last_sequence(), records.len() as u64);
    assert_eq!(recovered.slots().len(), COUNT as usize);
    drop(recovered);
    let mut validator = PreflightValidator::new(store_id);
    let validation_baseline = LIVE.load(Ordering::Relaxed);
    validator.append(&records).unwrap();
    assert_eq!(validator.memory_usage().unwrap().retained_bytes,
        LIVE.load(Ordering::Relaxed) - validation_baseline);
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
    let (sequence, usage) = validator.finish_with_memory_usage().unwrap();
    assert_eq!(sequence, records.len() as u64);
    assert_eq!(usage.retained_bytes, 0);
    let validation_finish_peak = PEAK.load(Ordering::Relaxed) - validation_baseline;
    eprintln!("REPLAY_ALLOCATION transactions={COUNT} allocation_calls={allocation_calls} retained_bytes={retained} peak_bytes={peak} finish_peak_bytes={finish_peak} validation_finish_peak_bytes={validation_finish_peak}");
}

#[test]
#[ignore = "allocation measurement; run alone with one test thread"]
fn external_object_validation_allocation() {
    let store = StoreId::new(90000).unwrap();
    let mut chain = RecordChain::new(store);
    let mut records = vec![chain.append(None, RecordBody::Format).unwrap(),
        chain.append(None, RecordBody::IdHighWater { exclusive_end: 100000 }).unwrap()];
    for i in 0..2048 {
        records.push(chain.append(Some(TransactionId::new(10000 + i).unwrap()),
            RecordBody::ObjectExternal {
                object_id: ObjectId::new(20000 + i).unwrap(),
                object_kind: ObjectKind::new(7).unwrap(), byte_len: 4096,
                merkle_root: [1;32],
            }).unwrap());
    }
    let recovered = preflight_recovery(&records, store).unwrap();
    assert_eq!(recovered.committed_objects().len(), 2048);
    drop(recovered);
    let mut validator = PreflightValidator::new(store);
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    validator.append(&records).unwrap();
    let retained = LIVE.load(Ordering::Relaxed) - baseline;
    assert_eq!(validator.memory_usage().unwrap().retained_bytes, retained);
    assert_eq!(validator.finish().unwrap(), records.len() as u64);
    let peak = PEAK.load(Ordering::Relaxed) - baseline;
    eprintln!("OBJECT_VALIDATION objects=2048 retained_bytes={retained} peak_bytes={peak}");
}

#[test]
#[ignore = "allocation measurement; run alone with one test thread"]
fn tombstone_validation_allocation() {
    let store = StoreId::new(90000).unwrap();
    let mut chain = RecordChain::new(store);
    let mut records = vec![chain.append(None, RecordBody::Format).unwrap(),
        chain.append(None, RecordBody::IdHighWater { exclusive_end: 100000 }).unwrap()];
    for i in 0..2048 {
        records.push(chain.append(Some(TransactionId::new(10000 + i).unwrap()),
            RecordBody::RevokeTombstone { derivation_id: DerivationId::new(20000 + i).unwrap() }).unwrap());
    }
    let mut validator = PreflightValidator::new(store);
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let calls_before = ALLOCATION_CALLS.load(Ordering::Relaxed);
    validator.append(&records).unwrap();
    let calls = ALLOCATION_CALLS.load(Ordering::Relaxed) - calls_before;
    let retained = LIVE.load(Ordering::Relaxed) - baseline;
    assert_eq!(validator.memory_usage().unwrap().retained_bytes, retained);
    assert_eq!(validator.finish().unwrap(), records.len() as u64);
    let peak = PEAK.load(Ordering::Relaxed) - baseline;
    eprintln!("TOMBSTONE_VALIDATION tombstones=2048 calls={calls} retained_bytes={retained} peak_bytes={peak}");
}

#[test]
#[ignore = "allocation measurement; run alone with one test thread"]
fn empty_batch_probe_allocation() {
    let store = StoreId::new(90000).unwrap();
    let mut chain = RecordChain::new(store);
    let format = chain.append(None, RecordBody::Format).unwrap();
    let records = vec![[0; RECORD_SIZE]; 65536];
    let mut validator = PreflightValidator::new(store);
    validator.append(&[format]).unwrap();
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    validator.append(&records).unwrap();
    let peak = PEAK.load(Ordering::Relaxed) - baseline;
    assert_eq!(validator.finish().unwrap(), 1);
    eprintln!("EMPTY_BATCH_PROBE sectors=65536 peak_bytes={peak}");
}

#[test]
#[ignore = "allocation measurement; run alone with one test thread"]
fn pending_grant_validation_allocation() {
    let store = StoreId::new(90000).unwrap();
    let mut chain = RecordChain::new(store);
    let mut records = vec![chain.append(None, RecordBody::Format).unwrap(),
        chain.append(None, RecordBody::IdHighWater { exclusive_end: 100000 }).unwrap()];
    for i in 0..2048 {
        records.push(chain.append(Some(TransactionId::new(10000 + i).unwrap()),
            RecordBody::GrantPrepare(GrantRecord {
                derivation_id: DerivationId::new(20000 + i).unwrap(),
                parent_id: None, object_id: ObjectId::new(1).unwrap(),
                target: SlotIdentity { space: SpaceId::new(2).unwrap(), slot: i as u32, generation: 1 },
                rights: DurableRights::ALL, resource_kind: ResourceKind::new(7).unwrap(),
                flags: GrantFlags::ROOT,
            })).unwrap());
    }
    let mut validator = PreflightValidator::new(store);
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    validator.append(&records).unwrap();
    let retained = LIVE.load(Ordering::Relaxed) - baseline;
    let peak = PEAK.load(Ordering::Relaxed) - baseline;
    assert_eq!(validator.memory_usage().unwrap().retained_bytes, retained);
    assert_eq!(validator.finish().unwrap(), records.len() as u64);
    eprintln!("PENDING_GRANTS transactions=2048 retained_bytes={retained} peak_bytes={peak}");
}

#[test]
#[ignore = "allocation measurement; run alone with one test thread"]
fn inline_object_replay_allocation_calls() {
    let store = StoreId::new(90000).unwrap();
    let mut chain = RecordChain::new(store);
    let mut records = vec![chain.append(None, RecordBody::Format).unwrap(),
        chain.append(None, RecordBody::IdHighWater { exclusive_end: 100000 }).unwrap()];
    let payload = vec![0x59; 32768];
    records.extend(encode_object_transaction(&mut chain, TransactionId::new(7).unwrap(),
        ObjectId::new(8).unwrap(), ObjectKind::new(9).unwrap(), &payload).unwrap().records);
    for validation in [false, true] {
        let mut replay = PreflightReplay::new(store);
        let mut validator = PreflightValidator::new(store);
        let baseline = LIVE.load(Ordering::Relaxed);
        PEAK.store(baseline, Ordering::Relaxed);
        let calls_before = ALLOCATION_CALLS.load(Ordering::Relaxed);
        if validation { validator.append(&records).unwrap(); } else { replay.append(&records).unwrap(); }
        let calls = ALLOCATION_CALLS.load(Ordering::Relaxed) - calls_before;
        let retained = LIVE.load(Ordering::Relaxed) - baseline;
        let peak = PEAK.load(Ordering::Relaxed) - baseline;
        if validation {
            assert_eq!(validator.memory_usage().unwrap().retained_bytes, retained);
            assert_eq!(validator.finish().unwrap(), records.len() as u64);
        }
        else { assert_eq!(replay.finish().unwrap().committed_objects()[0].bytes, payload); }
        eprintln!("INLINE_ALLOCATION bytes=32768 validation={validation} calls={calls} retained_bytes={retained} peak_bytes={peak}");
    }
}
