//! Isolated allocation measurement: run with --ignored --nocapture --test-threads=1.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use vibeos_durable_format::*;

struct Meter;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
fn added(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
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
    replay.append(&records).unwrap();
    let retained = LIVE.load(Ordering::Relaxed) - baseline;
    let peak = PEAK.load(Ordering::Relaxed) - baseline;
    let recovered = replay.finish().unwrap();
    assert_eq!(recovered.last_sequence(), records.len() as u64);
    assert_eq!(recovered.slots().len(), COUNT as usize);
    eprintln!("REPLAY_ALLOCATION transactions={COUNT} retained_bytes={retained} peak_bytes={peak}");
}
