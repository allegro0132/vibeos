//! Polled SF21 crypt-engine AES queue. Buffers live in the RV2 uncached DMA arena.
use core::{arch::asm, ptr};

#[cfg(any(feature = "ce-service-profile", feature = "copy-profile"))]
pub mod profile;
macro_rules! timed {
    ($phase:ident, $work:expr) => {{
        #[cfg(feature = "copy-profile")]
        let _span = profile::Span::start(profile::Phase::$phase);
        $work
    }};
}

const CE: usize = 0x0e000000;
const CH: usize = CE + 0x3180;
const TX: usize = 0x24100000;
const RX: usize = TX + 0x200;
const KEY: usize = TX + 0x400;
const IV: usize = KEY + 64;
const EXTRA: usize = IV + 16;
const TAG: usize = EXTRA + 16;
const AAD: usize = TX + 0x1000;
#[cfg(feature = "extended-dma")]
const PAYLOAD: usize = 0x24300000;
#[cfg(not(feature = "extended-dma"))]
const PAYLOAD: usize = TX;
#[cfg(not(feature = "extended-dma"))]
const INPUT: usize = PAYLOAD + 0x6000;
const OUTPUT: usize = PAYLOAD + 0xc000;
pub const MAX_RECORD: usize = 18432;
const MAX_AAD: usize = 16384;
// Each TX buffer length is 13 bits. Keep intermediate pieces AES-block aligned.
const PIECE: usize = 4096;
const OWN: u32 = 1 << 31;
const RING: usize = 16;
#[cfg(all(feature = "ce-poll-profile", not(feature = "ce-queue")))]
pub mod timing;
#[cfg(all(feature = "extended-dma", not(feature = "ce-queue")))]
pub mod owned;


fn read(a: usize) -> u32 {
    unsafe { ptr::read_volatile(a as *const u32) }
}
fn write(a: usize, v: u32) {
    unsafe { ptr::write_volatile(a as *mut u32, v) }
}
fn fence() {
    unsafe { asm!("fence iorw, iorw") }
}
// PBMT non-cacheable DMA RAM supports aligned native-width accesses. Keep
// volatile semantics, including the wipe after every authenticated operation.
fn put(addr: usize, bytes: &[u8]) {
    debug_assert_eq!(addr % 8, 0);
    let mut words = bytes.chunks_exact(8);
    for (i, word) in words.by_ref().enumerate() {
        unsafe {
            ptr::write_volatile(
                (addr as *mut u64).add(i),
                u64::from_ne_bytes(word.try_into().unwrap()),
            )
        }
    }
    let tail = words.remainder();
    for (i, &v) in tail.iter().enumerate() {
        unsafe { ptr::write_volatile((addr + bytes.len() - tail.len() + i) as *mut u8, v) }
    }
}
fn get(addr: usize, bytes: &mut [u8]) {
    let head = (addr.wrapping_neg() % 8).min(bytes.len());
    let (prefix, rest) = bytes.split_at_mut(head);
    for (i, v) in prefix.iter_mut().enumerate() {
        *v = unsafe { ptr::read_volatile((addr + i) as *const u8) };
    }
    let aligned = addr + head;
    let tail_addr = aligned + (rest.len() & !7);
    let mut words = rest.chunks_exact_mut(8);
    for (i, word) in words.by_ref().enumerate() {
        let value = unsafe { ptr::read_volatile((aligned as *const u64).add(i)) };
        word.copy_from_slice(&value.to_ne_bytes());
    }
    for (i, v) in words.into_remainder().iter_mut().enumerate() {
        *v = unsafe { ptr::read_volatile((tail_addr + i) as *const u8) };
    }
}
fn wipe(addr: usize, len: usize) {
    debug_assert_eq!(addr % 8, 0);
    for i in 0..len / 8 {
        unsafe { ptr::write_volatile((addr as *mut u64).add(i), 0) }
    }
    for i in (len & !7)..len {
        unsafe { ptr::write_volatile((addr + i) as *mut u8, 0) }
    }
}

fn wipe_payload(addr: usize, len: usize) {
    wipe(addr, len);
    #[cfg(feature = "extended-dma")]
    crate::ethernet::flush_dma_lines(addr, len);
}

#[cfg(feature = "extended-dma")]
pub fn physical_hart() -> usize {
    let hart: usize;
    unsafe { asm!("mv {}, tp", out(reg) hart, options(nomem, nostack)) };
    assert!(hart < 4);
    hart
}

// The polled proxy runs a synchronous call on each physical hart. Each
// hart owns one isolated output area until it has copied and scrubbed it.
fn output_address() -> usize {
    #[cfg(feature = "extended-dma")]
    {
        const STRIDE: usize = 0x8000;
        const _: () = assert!(MAX_RECORD + 16 + 7 + 32 <= STRIDE);
        const _: () = assert!(OUTPUT + 4 * STRIDE <= 0x24400000);
        OUTPUT + physical_hart() * STRIDE
    }
    #[cfg(not(feature = "extended-dma"))]
    { OUTPUT }
}

const RX_SLACK: usize = 32;

fn output_capacity(len: usize, seal: bool) -> usize {
    (len + if seal { 16 } else { 0 }).next_multiple_of(8)
}

// The last fragment can carry TLSInnerPlaintext's content type. Both borrows
// stay live until the final RX writeback (or a stopped engine on failure).
#[derive(Clone, Copy)]
struct Payload<'a> {
    body: &'a [u8],
    tail: &'a [u8],
}
impl<'a> Payload<'a> {
    fn single(body: &'a [u8]) -> Self { Self { body, tail: &[] } }
    fn len(self) -> usize { self.body.len() + self.tail.len() }
}

#[cfg(feature = "extended-dma")]
fn prepare_dma(data: &[u8], seal: bool) {
    prepare_target(Payload::single(data), seal, RxTarget::scratch());
}
#[cfg(feature = "extended-dma")]
fn prepare_target(data: Payload<'_>, seal: bool, target: RxTarget) {
    // Each synchronous caller owns its hart's scratch until finish returns.
    // Prepare cache lines while other harts can still submit or retire records.
    if (9..=MAX_RECORD).contains(&data.len()) {
        crate::ethernet::clean_dma_source(data.body);
        if !data.tail.is_empty() { crate::ethernet::clean_dma_source(data.tail); }
        // Multi-flight diagnostics prepare the selected output in post_gcm.
        if !cfg!(feature = "ce-queue") {
            if target.prefix != 0 { crate::ethernet::flush_dma_lines(output_address(), target.prefix); }
            crate::ethernet::flush_dma_lines(
                target.address + target.prefix,
                output_capacity(data.len(), seal) + RX_SLACK - target.prefix,
            );
        }
    }
}

// Avoid uncached OWN reads during the first part of the record transfer.
// The authentication and timeout checks still use the final RX descriptor.
#[cfg(all(feature = "extended-dma", not(feature = "ce-queue")))]
static FIRST_POLL_TICKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(5);
#[cfg(all(feature = "extended-dma", not(feature = "ce-queue")))]
pub fn set_first_poll(ticks_per_byte: u64) {
    FIRST_POLL_TICKS.store(ticks_per_byte, core::sync::atomic::Ordering::Relaxed);
}

#[derive(Clone, Copy)]
struct RxTarget {
    address: usize,
    // Up to one partial cache line is written to private, aligned hart scratch.
    prefix: usize,
}
impl RxTarget {
    fn scratch() -> Self { Self { address: output_address(), prefix: 0 } }
    fn scrub(self, dma_len: usize) {
        if self.prefix != 0 { wipe_payload(output_address(), self.prefix); }
        wipe_payload(self.address + self.prefix, dma_len - self.prefix);
    }
}

struct PostedRecord {
    metadata_offset: usize,
    descriptor: usize,
    started: u64,
    target: RxTarget,
    capacity: usize,
    padded_aad: usize,
    len: usize,
    decrypt: bool,
}

struct CompletedRecord {
    address: usize,
    dma_len: usize,
    seal: bool,
}
impl CompletedRecord {
    fn finish(self, buf: &mut [u8]) -> [u8; 16] {
        #[cfg(feature = "extended-dma")]
        {
            timed!(OutputCopy, {
                crate::ethernet::flush_dma_lines(self.address, self.dma_len);
                unsafe { ptr::copy_nonoverlapping(self.address as *const u8, buf.as_mut_ptr(), buf.len()) };
            });
        }
        #[cfg(not(feature = "extended-dma"))]
        get(self.address, buf);
        let mut tag = [0; 16];
        if self.seal { get(self.address + buf.len(), &mut tag); }
        timed!(Scrub, wipe_payload(self.address, self.dma_len));
        tag
    }
}

struct Cipher {
    tx: usize,
    rx: usize,
    enabled: bool,
}
impl Cipher {
    pub fn start() -> Self {
        let crm = 0x0ce00400;
        let resets = 3 << 28;
        write(crm + 0x8c, read(crm + 0x8c) | (3 << 21));
        write(crm + 0x100, 1);
        write(crm + 0x100, 0);
        write(crm + 0xc0, read(crm + 0xc0) & !resets);
        fence();
        write(crm + 0xc0, read(crm + 0xc0) | resets);
        fence();
        write(CE + 0x1092c, 1);
        write(CE + 0x3004, 0x01010006);
        write(CE + 0x3040, 3 << 30);
        write(CE + 0x3044, 3 << 30);
        wipe(TX, 0x400);
        write(CH + 0x14, TX as u32);
        write(CH + 0x1c, RX as u32);
        write(CH + 0x30, 15);
        write(CH + 0x34, 15);
        write(CH + 0x24, TX as u32);
        write(CH + 0x2c, RX as u32);
        fence();
        write(CH + 4, (4 << 16) | 1);
        write(CH + 8, (8 << 16) | 1);
        Self {
            tx: 0,
            rx: 0,
            enabled: true,
        }
    }
    fn push(&mut self, a: (usize, usize, u32), b: (usize, usize, u32), flags: u32) {
        let d = TX + self.tx * 16;
        write(d, a.0 as u32);
        write(d + 4, b.0 as u32);
        write(
            d + 8,
            (1 << 29) | (b.2 << 26) | ((b.1 as u32) << 13) | a.1 as u32,
        );
        write(d + 12, OWN | (a.2 << 25) | flags);
        self.tx = (self.tx + 1) % RING;
    }
    pub fn gcm(
        &mut self,
        key: &[u8],
        h: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: Option<&[u8; 16]>,
    ) -> Result<[u8; 16], &'static str> {
        #[cfg(feature = "extended-dma")]
        prepare_dma(buf, tag.is_none());
        self.submit_gcm(key, h, nonce, aad, Payload::single(buf), tag, RxTarget::scratch()).map(|record| record.finish(buf))
    }
    fn submit_gcm(
        &mut self,
        key: &[u8],
        h: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        buf: Payload<'_>,
        tag: Option<&[u8; 16]>,
        target: RxTarget,
    ) -> Result<CompletedRecord, &'static str> {
        let record = self.post_gcm(key, h, nonce, aad, buf, tag, target, 0)?;
        #[cfg(all(feature = "ce-poll-profile", not(feature = "ce-queue")))]
        if let Some(result) = timing::wait(self, &record) {
            return result;
        }
        #[cfg(all(feature = "extended-dma", not(feature = "ce-queue")))]
        {
            let delay = FIRST_POLL_TICKS.load(core::sync::atomic::Ordering::Relaxed) * buf.len() as u64;
            if delay != 0 {
                while crate::ticks().wrapping_sub(record.started) < delay {
                    core::hint::spin_loop();
                }
            }
        }
        loop {
            if let Some(result) = self.complete(&record) {
                return result;
            }
            #[cfg(feature = "extended-dma")]
            for _ in 0..64 { core::hint::spin_loop(); }
        }
    }

    // The caller holds the CE reservation and keeps both DMA allocations live
    // until complete() observes writeback or resets the engine.
    fn post_gcm(
        &mut self, key: &[u8], h: &[u8; 16], nonce: &[u8; 12], aad: &[u8],
        buf: Payload<'_>, tag: Option<&[u8; 16]>, target: RxTarget, metadata_offset: usize,
    ) -> Result<PostedRecord, &'static str> {
        if !self.enabled
            || !matches!(key.len(), 16 | 24 | 32)
            || !(9..=MAX_RECORD).contains(&buf.len())
            || aad.len() > MAX_AAD
        {
            return Err("unsupported GCM request");
        }
        let key_addr = KEY + metadata_offset;
        let iv_addr = IV + metadata_offset;
        let extra_addr = EXTRA + metadata_offset;
        let tag_addr = TAG + metadata_offset;
        let aad_addr = AAD + metadata_offset;
        let padded = (aad.len() + 15) & !15;
        let len = buf.len();
        let flags = ((tag.is_some() as u32) << 24) | (9 << 20) | ((len + padded) as u32);
        put(key_addr, key);
        put(key_addr + 32, h);
        wipe(iv_addr, 16);
        put(iv_addr, nonce);
        put(extra_addr, &(aad.len() as u64).to_be_bytes());
        put(extra_addr + 8, &(len as u64).to_be_bytes());
        #[cfg(feature = "extended-dma")]
        let input = {
            // Identity-mapped RAM: the CE TX source has no address alignment
            // requirement. The exclusive slice stays live through completion.
            buf.body.as_ptr() as usize
        };
        #[cfg(not(feature = "extended-dma"))]
        let input = {
            debug_assert!(buf.tail.is_empty());
            put(INPUT, buf.body);
            INPUT
        };
        if padded != 0 {
            wipe(aad_addr + padded - 16, 16);
            put(aad_addr, aad)
        }
        self.push((key_addr, key.len(), 4), (iv_addr, 16, 5), flags | (1 << 30));
        // On decrypt the second slot of the EXTRA descriptor can carry the
        // first padded AAD piece. Larger headers continue in the ring.
        let first_aad = if tag.is_some() { PIECE.min(padded) } else { 0 };
        if let Some(tag) = tag {
            put(tag_addr, &16u64.to_be_bytes());
            put(tag_addr + 8, tag);
            self.push((tag_addr, 24, 1), (key_addr + 32, 16, 3), flags);
            let header = if first_aad == 0 { 0 } else { aad_addr };
            self.push((extra_addr, 16, 0), (header, first_aad, 7), flags);
        } else {
            self.push((key_addr + 32, 16, 3), (extra_addr, 16, 0), flags);
        }
        for offset in (first_aad..padded).step_by(PIECE) {
            self.push(
                (aad_addr + offset, PIECE.min(padded - offset), 7),
                (0, 0, 7),
                flags,
            );
        }
        // CE descriptors carry two independent 13-bit source lengths.
        // Consecutive payload pieces can share one descriptor and writeback.
        for offset in (0..buf.body.len()).step_by(2 * PIECE) {
            let remaining = buf.body.len() - offset;
            let first = PIECE.min(remaining);
            let second = PIECE.min(remaining - first);
            let last = u32::from(first + second == remaining && buf.tail.is_empty()) << 29;
            let next = if second == 0 { 0 } else { input + offset + first };
            self.push((input + offset, first, 6), (next, second, 6), flags | last);
        }
        if !buf.tail.is_empty() {
            self.push((buf.tail.as_ptr() as usize, buf.tail.len(), 6), (0, 0, 6), flags | (1 << 29));
        }
        let output = target.address;
        let capacity = output_capacity(len, tag.is_none());
        #[cfg(feature = "ce-queue")]
        crate::ethernet::flush_dma_lines(output, capacity + RX_SLACK);
        let mut d = 0;
        // The engine can consume padding beyond plaintext on decrypt. Keep
        // slack in the last posted buffer, including at exact DMA boundaries.
        // A separate descriptor solely for slack might never be consumed.
        const RX_PIECE: usize = 4000;
        if target.prefix != 0 {
            let d = RX + self.rx * 16;
            write(d, output_address() as u32);
            write(d + 4, 0);
            write(d + 8, target.prefix as u32);
            write(d + 12, OWN | 16);
            self.rx = (self.rx + 1) % RING;
        }
        for offset in (target.prefix..capacity).step_by(2 * RX_PIECE) {
            d = RX + self.rx * 16;
            let first = RX_PIECE.min(capacity - offset);
            let second = RX_PIECE.min(capacity - offset - first);
            let last = offset + first + second == capacity;
            let slack = if last { RX_SLACK } else { 0 };
            let (size1, size2, addr2) = if second == 0 {
                (first + slack, 0, 0)
            } else {
                (first, second + slack, output + offset + first)
            };
            write(d, (output + offset) as u32);
            write(d + 4, addr2 as u32);
            write(d + 8, (size2 << 16 | size1) as u32);
            write(d + 12, OWN | (u32::from(last) << 30) | 16);
            self.rx = (self.rx + 1) % RING;
        }
        fence();
        write(
            CH + 0x2c,
            (RX + (if self.rx == 0 { RING } else { self.rx }) * 16) as u32,
        );
        fence();
        write(
            CH + 0x24,
            (TX + (if self.tx == 0 { RING } else { self.tx }) * 16) as u32,
        );
        Ok(PostedRecord {
            metadata_offset, descriptor: d, started: crate::ticks(), target, capacity,
            padded_aad: padded, len, decrypt: tag.is_some(),
        })
    }

    fn complete(&mut self, record: &PostedRecord) -> Option<Result<CompletedRecord, &'static str>> {
        let PostedRecord { metadata_offset, descriptor: d, started: start, target, capacity,
            padded_aad: padded, len, decrypt } = *record;
        let key_addr = KEY + metadata_offset;
        let aad_addr = AAD + metadata_offset;
        if !self.enabled || read(d + 12) & OWN != 0 {
            if self.enabled && crate::ticks() - start <= 125_000_000 { return None; }
            self.enabled = false;
            let crm = 0x0ce004c0;
            write(crm, read(crm) & !(3 << 28));
            fence();
            wipe(key_addr, TAG + 24 - KEY);
            #[cfg(not(feature = "extended-dma"))]
            wipe_payload(INPUT, len);
            wipe(aad_addr, padded);
            target.scrub(capacity + RX_SLACK);
            return Some(Err("AES DMA reset"));
        }
        fence();
        #[cfg(feature = "extended-dma")]
        {
            let wait = crate::ticks() - start;
            DMA_WAIT_TICKS.fetch_add(wait, core::sync::atomic::Ordering::Relaxed);
            #[cfg(feature = "ce-service-profile")]
            profile::emit(profile::Phase::Dma, wait);
        }
        let status = read(d + 12);
        #[cfg(feature = "extended-dma")]
        if (status >> 24) & 15 != 9
            || status & (1 << 20) == 0
            || decrypt && status & (1 << 23) == 0
        {
            LAST_BAD.store(
                (len as u64) << 32 | status as u64,
                core::sync::atomic::Ordering::Relaxed,
            );
        }
        // Without a final writeback the hardware can still be waiting for an
        // output buffer. Stop DMA before clearing its buffers. The caller
        // rejects this operation and later records can use software.
        if status & (1 << 20) == 0 {
            self.enabled = false;
            let crm = 0x0ce004c0;
            write(crm, read(crm) & !(3 << 28));
            fence();
        }
        let valid = (status >> 24) & 15 == 9 && status & (1 << 20) != 0
            && (!decrypt || status & (1 << 23) != 0);
        wipe(key_addr, TAG + 24 - KEY);
        #[cfg(not(feature = "extended-dma"))]
        wipe_payload(INPUT, len);
        wipe(aad_addr, padded);
        if !valid {
            target.scrub(capacity + RX_SLACK);
            return Some(Err("GCM authentication or DMA status"));
        }
        Some(Ok(CompletedRecord { address: target.address, dma_len: capacity + RX_SLACK, seal: !decrypt }))
    }
    pub fn verify(&mut self) -> Result<(), &'static str> {
        let h = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let mut data = [0; 16];
        let key = [0; 16];
        let iv = [0; 12];
        let mut tag = self.gcm(&key, &h, &iv, &[], &mut data, None)?;
        let cipher = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78,
        ];
        if data != cipher
            || tag
                != [
                    0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12,
                    0x57, 0xbd, 0xdf,
                ]
        {
            return Err("GCM known answer");
        }
        self.gcm(&key, &h, &iv, &[], &mut data, Some(&tag))?;
        if data != [0; 16] {
            return Err("GCM plaintext");
        }
        tag[0] ^= 1;
        data = cipher;
        if self.gcm(&key, &h, &iv, &[], &mut data, Some(&tag)).is_ok() || data != cipher {
            return Err("GCM corrupt tag accepted");
        }
        Ok(())
    }
}

use aes_gcm::{backend, Error};
use vibeos_core::sync::SpinLock;
struct Key {
    bytes: [u8; 32],
    len: usize,
    hash: [u8; 16],
}
#[cfg(feature = "ce-queue")]
mod pipeline;

struct Service {
    #[cfg(feature = "ce-queue")]
    pending: pipeline::Queue,
    cipher: Option<Cipher>,
    keys: [Option<Key>; 32],
    completed: u64,
}
static SERVICE: SpinLock<Service> = SpinLock::new(Service {
    #[cfg(feature = "ce-queue")]
    pending: pipeline::Queue::new(),
    cipher: None,
    keys: [const { None }; 32],
    completed: 0,
});
fn admit(bytes: &[u8], hash: &[u8; 16]) -> Result<Option<usize>, Error> {
    if !matches!(bytes.len(), 16 | 24 | 32) {
        return Err(Error);
    }
    let mut s = SERVICE.lock();
    let Some(i) = s.keys.iter().position(Option::is_none) else {
        return Ok(None);
    };
    let mut key = Key {
        bytes: [0; 32],
        len: bytes.len(),
        hash: *hash,
    };
    key.bytes[..bytes.len()].copy_from_slice(bytes);
    s.keys[i] = Some(key);
    Ok(Some(i))
}
fn destroy(i: usize) {
    let mut s = SERVICE.lock();
    if let Some(k) = s.keys.get_mut(i).and_then(Option::as_mut) {
        for byte in k.bytes.iter_mut().chain(k.hash.iter_mut()) {
            unsafe { ptr::write_volatile(byte, 0) }
        }
        s.keys[i] = None;
    }
}
#[cfg(feature = "extended-dma")]
static LAST_BAD: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "extended-dma")]
static FAILURES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

#[cfg(feature = "extended-dma")]
static DMA_WAIT_TICKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "extended-dma")]
static WAIT_TICKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "extended-dma")]
static SERVICE_TICKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

#[cfg(not(feature = "ce-queue"))]
fn dispatch(
    i: usize,
    iv: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: Option<&[u8; 16]>,
) -> Result<Option<[u8; 16]>, Error> {
    dispatch_inout(i, iv, aad, buf.into(), tag)
}

#[cfg(not(feature = "ce-queue"))]
fn dispatch_inout(
    i: usize,
    iv: &[u8; 12],
    aad: &[u8],
    mut buf: aes_gcm::aead::inout::InOutBuf<'_, '_, u8>,
    tag: Option<&[u8; 16]>,
) -> Result<Option<[u8; 16]>, Error> {
    let Some((_guard, record)) = service_record(i, iv, aad, Payload::single(buf.get_in()), tag, RxTarget::scratch())? else {
        return Ok(None);
    };
    // NAND shares one output and retains the guard through the copy.
    #[cfg(feature = "extended-dma")]
    drop(_guard);
    Ok(Some(record.finish(buf.get_out())))
}

#[cfg(not(feature = "ce-queue"))]
fn service_record(i: usize, iv: &[u8; 12], aad: &[u8], input: Payload<'_>, tag: Option<&[u8; 16]>, target: RxTarget)
    -> Result<Option<(vibeos_core::sync::SpinGuard<'static, Service>, CompletedRecord)>, Error> {
    #[cfg(feature = "ce-service-profile")]
    let _phase = profile::Span::start(profile::Phase::Service);
    if !(9..=MAX_RECORD).contains(&input.len()) || aad.len() > MAX_AAD { return Ok(None); }
    #[cfg(feature = "extended-dma")]
    timed!(Prepare, prepare_target(input, tag.is_none(), target));
    #[cfg(feature = "extended-dma")]
    let queued = crate::ticks();
    let mut s = SERVICE.lock();
    #[cfg(feature = "extended-dma")]
    let acquired = crate::ticks();
    let Service {
        cipher,
        keys,
        completed, ..
    } = &mut *s;
    let key = keys.get(i).and_then(Option::as_ref).ok_or(Error)?;
    let Some(cipher) = cipher.as_mut().filter(|cipher| cipher.enabled) else {
        return Ok(None);
    };
    let result = cipher
        .submit_gcm(&key.bytes[..key.len], &key.hash, iv, aad, input, tag, target)
        .map_err(|_| {
            #[cfg(feature = "extended-dma")]
            FAILURES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Error
        })?;
    #[cfg(feature = "extended-dma")]
    {
        use core::sync::atomic::Ordering::Relaxed;
        WAIT_TICKS.fetch_add(acquired - queued, Relaxed);
        #[cfg(feature = "ce-service-profile")]
        profile::emit(profile::Phase::Lock, acquired - queued);
        SERVICE_TICKS.fetch_add(crate::ticks() - acquired, Relaxed);
    }
    *completed += 1;
    Ok(Some((s, result)))
}
#[cfg(feature = "ce-queue")]
use pipeline::dispatch;

/// # Safety
/// Initialize once, after mapping the reserved CE DMA arena on the boot hart.
pub unsafe fn install(#[cfg(all(feature = "local-offload", not(feature = "ce-queue")))] defer: &'static backend::DeferSeal) -> Result<(), &'static str> {
    static BACKEND: backend::Backend = backend::Backend {
        create: |k, h| admit(k, h)?.ok_or(Error),
        destroy,
        crypt: dispatch,
    };
    static ADMIT: backend::TryCreateKey = admit;
    let mut cipher = Cipher::start();
    cipher.verify()?;
    SERVICE.lock().cipher = Some(cipher);
    backend::install(&BACKEND).map_err(|_| "backend registration")?;
    backend::install_key_admission(&BACKEND, &ADMIT).map_err(|_| "key admission")?;
    #[cfg(not(feature = "ce-queue"))]
    {
        static INOUT: backend::CryptInOut = dispatch_inout;
        backend::install_crypt_inout(&BACKEND, &INOUT).map_err(|_| "GCM in/out")?;
    }
    #[cfg(all(feature = "extended-dma", not(feature = "ce-queue")))]
    {
        #[cfg(feature = "local-offload")]
        {
            backend::install_deferred_seal(&BACKEND, defer).map_err(|_| "GCM seal worker")?;
            static SEAL: backend::SealOwned = seal::submit;
            backend::install_seal_owned(&BACKEND, &SEAL).map_err(|_| "GCM owned ciphertext")?;
        }
        static OPEN: backend::OpenOwned = owned::open;
        backend::install_open_owned(&BACKEND, &OPEN).map_err(|_| "GCM owned output")?;
    }
    Ok(())
}
#[cfg(feature = "extended-dma")]
pub fn dma_wait_ticks() -> u64 {
    DMA_WAIT_TICKS.load(core::sync::atomic::Ordering::Relaxed)
}
#[cfg(feature = "extended-dma")]
pub fn service_ticks() -> (u64, u64) {
    use core::sync::atomic::Ordering::Relaxed;
    (WAIT_TICKS.load(Relaxed), SERVICE_TICKS.load(Relaxed))
}
#[cfg(feature = "extended-dma")]
pub fn status() -> (u64, u64, bool, u64) {
    let s = SERVICE.lock();
    (
        s.completed,
        FAILURES.load(core::sync::atomic::Ordering::Relaxed),
        s.cipher.as_ref().is_some_and(|c| c.enabled),
        LAST_BAD.load(core::sync::atomic::Ordering::Relaxed),
    )
}
pub fn verify_dispatch(known_answer: fn() -> Result<(), &'static str>) -> Result<u64, &'static str> {
    let before = SERVICE.lock().completed;
    known_answer()?;
    #[cfg(feature = "extended-dma")]
    verify_rx_boundaries()?;
    let count = SERVICE.lock().completed - before;
    if count == 0 {
        return Err("no AES DMA operations");
    }
    Ok(count)
}


#[cfg(feature = "extended-dma")]
fn verify_rx_boundaries() -> Result<(), &'static str> {
    extern crate alloc;
    use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit};
    let key = [0x5a; 16];
    let reference = Aes128Gcm::from(aes_gcm::aes::Aes128::new_from_slice(&key).unwrap());
    let hardware = Aes128Gcm::new_from_slice(&key).unwrap();
    for len in [
        2807usize, 2808, 2809, 3999, 4000, 4001, 4095, 4096, 4097,
        7999, 8000, 8001, 8191, 8192, 8193, 15999, 16000, 16001, 16384,
    ] {
        let mut data = alloc::vec![0x3c; len];
        let mut nonce = [0; 12];
        nonce[8..].copy_from_slice(&(len as u32).to_be_bytes());
        let tag = reference
            .encrypt_inout_detached((&nonce).into(), b"TLS13", data.as_mut_slice().into())
            .unwrap();
        if len == 4097 {
            verify_separate_buffers(&hardware, &nonce, &data, &tag)?;
        }
        if len == 16384 {
            // A corrupted ciphertext crossing either half of a descriptor must
            // fail authentication before any plaintext reaches the caller.
            for offset in [3999, 4000, 7999, 8000, 8192, len - 1] {
                data[offset] ^= 1;
                let mut damaged = data.clone();
                let result = hardware.decrypt_inout_detached(
                    (&nonce).into(), b"TLS13", damaged.as_mut_slice().into(), &tag,
                );
                if result.is_ok() || damaged != data {
                    return Err("RX boundary authentication");
                }
                data[offset] ^= 1;
            }
        }
        hardware
            .decrypt_inout_detached((&nonce).into(), b"TLS13", data.as_mut_slice().into(), &tag)
            .map_err(|_| "RX tail authentication")?;
        if data.iter().any(|byte| *byte != 0x3c) {
            return Err("RX tail plaintext");
        }
    }
    Ok(())
}

/// Use independent, misaligned input and output slices with guards on both sides.
#[cfg(feature = "extended-dma")]
fn verify_separate_buffers(
    hardware: &aes_gcm::Aes128Gcm,
    nonce: &[u8; 12],
    ciphertext: &[u8],
    tag: &aes_gcm::Tag,
) -> Result<(), &'static str> {
    extern crate alloc;
    use aes_gcm::{aead::inout::InOutBuf, AeadInOut};

    let len = ciphertext.len();
    let plain = alloc::vec![0x3c; len + 1];
    let mut sealed = alloc::vec![0xa5; len + 4];
    let mut opened = alloc::vec![0xa5; len + 6];
    let seal = InOutBuf::new(&plain[1..], &mut sealed[3..3 + len]).unwrap();
    let actual = hardware.encrypt_inout_detached(nonce.into(), b"TLS13", seal)
        .map_err(|_| "separate GCM seal")?;
    if &actual != tag || &sealed[3..3 + len] != ciphertext
        || sealed[..3] != [0xa5; 3] || sealed[3 + len] != 0xa5 {
        return Err("separate GCM ciphertext or guards");
    }
    let mut invalid = *tag;
    invalid[0] ^= 1;
    let open = InOutBuf::new(&sealed[3..3 + len], &mut opened[5..5 + len]).unwrap();
    if hardware.decrypt_inout_detached(nonce.into(), b"TLS13", open, &invalid).is_ok()
        || opened.iter().any(|&byte| byte != 0xa5) {
        return Err("separate GCM rejected output");
    }
    let open = InOutBuf::new(&sealed[3..3 + len], &mut opened[5..5 + len]).unwrap();
    hardware.decrypt_inout_detached(nonce.into(), b"TLS13", open, tag)
        .map_err(|_| "separate GCM open")?;
    if opened[5..5 + len] != plain[1..] || opened[..5] != [0xa5; 5]
        || opened[5 + len] != 0xa5 || &sealed[3..3 + len] != ciphertext {
        return Err("separate GCM plaintext or guards");
    }
    Ok(())
}

/// Isolate CE completion time from TCP, record mix and application copies.
/// Run only from the idle RAM benchmark console.
#[cfg(feature = "extended-dma")]
pub fn measure_decrypt_dma() -> Result<[u64; 4], &'static str> {
    extern crate alloc;
    use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit};

    const ROUNDS: u64 = 256;
    let key = [0x79; 16];
    let reference = Aes128Gcm::from(aes_gcm::aes::Aes128::new_from_slice(&key).unwrap());
    let hardware = Aes128Gcm::new_from_slice(&key).map_err(|_| "CE profile key")?;
    let mut ticks_per_kib = [0; 4];
    for (sample, kib) in ticks_per_kib.iter_mut().zip([1usize, 4, 8, 16]) {
        let mut nonce = [0; 12];
        nonce[11] = kib as u8;
        let mut sealed = alloc::vec![0x39; kib * 1024];
        let tag = reference
            .encrypt_inout_detached((&nonce).into(), b"TLS13", sealed.as_mut_slice().into())
            .map_err(|_| "CE profile reference")?;
        let mut record = sealed.clone();
        let completed = status().0;
        let start = dma_wait_ticks();
        for _ in 0..ROUNDS {
            record.copy_from_slice(&sealed);
            hardware
                .decrypt_inout_detached((&nonce).into(), b"TLS13", record.as_mut_slice().into(), &tag)
                .map_err(|_| "CE profile authentication")?;
            if record.iter().any(|&byte| byte != 0x39) {
                return Err("CE profile plaintext");
            }
        }
        if status().0 - completed != ROUNDS {
            return Err("CE profile completion count");
        }
        *sample = (dma_wait_ticks() - start) / (ROUNDS * kib as u64);
    }
    Ok(ticks_per_kib)
}

#[cfg(feature = "ce-queue")]
pub use pipeline::{pipeline_stats, set_depth};

#[cfg(all(feature = "local-offload", not(feature = "ce-queue")))]
pub mod seal;
