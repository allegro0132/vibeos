//! Cross-hart CE submission using borrowed input and private per-hart output.
use super::*;
use core::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};

const ACTIVE: u8 = 0;
const SUCCESS: u8 = 1;
const FAILED: u8 = 2;
const MAX_FLIGHTS: usize = 3;
// Each slot owns uncached key, nonce, tag and padded AAD until retirement.
const METADATA_STRIDE: usize = 0x8000;
const _: () = assert!(AAD + MAX_AAD <= KEY + METADATA_STRIDE);
const _: () = assert!(AAD + (MAX_FLIGHTS - 1) * METADATA_STRIDE + MAX_AAD <= PAYLOAD);
const _: () = assert!(3 * MAX_FLIGHTS < RING);

static DEPTH: AtomicUsize = AtomicUsize::new(2);
pub fn set_depth(depth: usize) {
    assert!((1..=MAX_FLIGHTS).contains(&depth));
    DEPTH.store(depth, Ordering::Relaxed);
}
fn tx_slots(len: usize, aad: usize, decrypt: bool) -> usize {
    let aad_pieces = aad.next_multiple_of(16).div_ceil(PIECE);
    if decrypt {
        3 + aad_pieces.saturating_sub(1) + len.div_ceil(2 * PIECE)
    } else {
        2 + aad_pieces + len.div_ceil(2 * PIECE)
    }
}
static OVERLAP: AtomicU64 = AtomicU64::new(0);
static BUSY: AtomicU64 = AtomicU64::new(0);
static SUBMITTED: AtomicU64 = AtomicU64::new(0);
static RETIRED: AtomicU64 = AtomicU64::new(0);

pub fn pipeline_stats() -> [u64; 4] {
    [&SUBMITTED, &RETIRED, &OVERLAP, &BUSY].map(|n| n.load(Ordering::Relaxed))
}

static SYNC_STATE: [AtomicU8; 4] = [const { AtomicU8::new(ACTIVE) }; 4];
struct Flight {
    tx_slots: usize,
    record: PostedRecord,
    hart: usize,
}

pub(super) struct Queue {
    flights: [Option<Flight>; MAX_FLIGHTS],
    head: usize,
    count: usize,
    tx_used: usize,
    busy_since: u64,
}

impl Queue {
    pub(super) const fn new() -> Self {
        Self {
            flights: [const { None }; MAX_FLIGHTS],
            head: 0,
            count: 0,
            tx_used: 0,
            busy_since: 0,
        }
    }
    fn reserve(&self, slots: usize) -> Option<usize> {
        // Keep one descriptor free, including when adjacent chains wrap.
        // At most three RX descriptors are consumed per record.
        (self.count < DEPTH.load(Ordering::Relaxed) && self.tx_used + slots < RING)
            .then_some((self.head + self.count) % MAX_FLIGHTS)
    }
    fn push(&mut self, slot: usize, flight: Flight) {
        if self.count == 0 {
            self.busy_since = flight.record.started;
        } else {
            OVERLAP.fetch_add(1, Ordering::Relaxed);
        }
        self.tx_used += flight.tx_slots;
        self.flights[slot] = Some(flight);
        self.count += 1;
    }
}

fn reap(service: &mut Service) {
    let q = &mut service.pending;
    while let Some(flight) = q.flights[q.head].as_ref() {
        let start = crate::ticks();
        let Some(result) = service.cipher.as_mut().unwrap().complete(&flight.record) else {
            return;
        };
        let state = if result.is_ok() {
            service.completed += 1;
            SUCCESS
        } else {
            FAILURES.fetch_add(1, Ordering::Relaxed);
            FAILED
        };
        SYNC_STATE[flight.hart].store(state, Ordering::Release);
        q.tx_used -= flight.tx_slots;
        q.flights[q.head] = None;
        q.head = (q.head + 1) % MAX_FLIGHTS;
        q.count -= 1;
        if q.count == 0 {
            BUSY.fetch_add(crate::ticks() - q.busy_since, Ordering::Relaxed);
        }
        RETIRED.fetch_add(1, Ordering::Relaxed);
        SERVICE_TICKS.fetch_add(crate::ticks() - start, Ordering::Relaxed);
    }
}

// A synchronous crypto API caller can pipeline with other harts without
// giving up ownership of its borrowed input or allocating a TLS operation.
pub(super) fn dispatch(
    handle: usize,
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
    tag: Option<&[u8; 16]>,
) -> Result<Option<[u8; 16]>, Error> {
    if !(9..=MAX_RECORD).contains(&data.len()) || aad.len() > MAX_AAD {
        return Ok(None);
    }
    let hart: usize;
    unsafe { asm!("mv {}, tp", out(reg) hart, options(nomem, nostack)) };
    let state = &SYNC_STATE[hart];
    let output = output_address();
    let slots = tx_slots(data.len(), aad.len(), tag.is_some());
    prepare_dma(data, tag.is_none());
    let queued = crate::ticks();
    let (descriptor, started, record) = loop {
        let mut service = SERVICE.lock();
        reap(&mut service);
        if let Some(slot) = service.pending.reserve(slots) {
            let acquired = crate::ticks();
            let Service { keys, cipher, .. } = &mut *service;
            let key = keys.get(handle).and_then(Option::as_ref).ok_or(Error)?;
            let Some(cipher) = cipher.as_mut().filter(|c| c.enabled) else {
                return Ok(None);
            };
            let record = cipher
                .post_gcm(
                    &key.bytes[..key.len],
                    &key.hash,
                    nonce,
                    aad,
                    super::Payload::single(data),
                    tag,
                    RxTarget { address: output, prefix: 0 },
                    slot * METADATA_STRIDE,
                )
                .map_err(|_| Error)?;
            let done = CompletedRecord {
                address: output,
                dma_len: record.capacity + RX_SLACK,
                seal: !record.decrypt,
            };
            let wait = (record.descriptor, record.started, done);
            state.store(ACTIVE, Ordering::Relaxed);
            service.pending.push(
                slot,
                Flight {
                    tx_slots: slots,
                    record,
                    hart,
                },
            );
            SUBMITTED.fetch_add(1, Ordering::Relaxed);
            SERVICE_TICKS.fetch_add(crate::ticks() - acquired, Ordering::Relaxed);
            WAIT_TICKS.fetch_add(acquired - queued, Ordering::Relaxed);
            break wait;
        }
        drop(service);
        for _ in 0..64 {
            core::hint::spin_loop();
        }
    };
    while state.load(Ordering::Acquire) == ACTIVE {
        if read(descriptor + 12) & OWN == 0 || crate::ticks() - started >= 125_000_000 {
            reap(&mut SERVICE.lock());
        } else {
            for _ in 0..64 {
                core::hint::spin_loop();
            }
        }
    }
    if state.load(Ordering::Acquire) == SUCCESS {
        Ok(Some(record.finish(data)))
    } else {
        Err(Error)
    }
}
