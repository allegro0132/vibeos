//! Seal a TLS record into cache-line-aligned private storage with header
//! headroom. A completed ciphertext allocation can serve another record only
//! after its last TLS owner releases it.
extern crate alloc;
use super::{Error, RxTarget, MAX_AAD, MAX_RECORD, RX_SLACK};
use alloc::vec::Vec;
use core::{
    ptr,
    sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
};
use vibeos_core::sync::SpinLock;

static SPARE: [SpinLock<Vec<u8>>; 4] = [const { SpinLock::new(Vec::new()) }; 4];
struct Ciphertext {
    storage: Vec<u8>,
    hart: usize,
}
impl aes_gcm::backend::OutputStorage for Ciphertext {
    fn bytes(&self) -> &[u8] {
        &self.storage
    }
    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.storage
    }
    fn into_vec(mut self: alloc::boxed::Box<Self>) -> Vec<u8> {
        core::mem::take(&mut self.storage)
    }
}
impl Drop for Ciphertext {
    fn drop(&mut self) {
        // Contains only wire bytes. A failed DMA operation never constructs this
        // owner. Keep at most one released allocation per submitting hart.
        let mut spare = SPARE[self.hart].lock();
        if self.storage.capacity() > spare.capacity() {
            self.storage.clear();
            core::mem::swap(&mut *spare, &mut self.storage);
        }
    }
}

static ENABLED: AtomicBool = AtomicBool::new(true);
static SEALED_BYTES: AtomicU64 = AtomicU64::new(0);

pub fn enable(on: bool) {
    ENABLED.store(on, Relaxed);
}
pub fn bytes() -> u64 {
    SEALED_BYTES.load(Relaxed)
}

pub fn enabled() -> bool { ENABLED.load(Relaxed) }

pub(super) fn submit(
    handle: usize,
    nonce: &[u8; 12],
    aad: &[u8],
    input: &[u8],
    suffix: &[u8],
) -> Result<Option<(aes_gcm::backend::Output, [u8; 16])>, Error> {
    if !enabled() { return Ok(None); }
    seal_record(handle, nonce, aad, input, suffix)
}

pub fn seal_record(
    handle: usize,
    nonce: &[u8; 12],
    aad: &[u8],
    input: &[u8],
    suffix: &[u8],
) -> Result<Option<(aes_gcm::backend::Output, [u8; 16])>, Error> {
    if suffix.len() != 1
        || !(128..MAX_RECORD).contains(&input.len())
        || aad.len() > MAX_AAD
    {
        return Ok(None);
    }
    let len = input.len() + 1;
    // Leave a TLS header before the first whole, private DMA cache line.
    // The final flush must also end inside this allocation.
    const HEADER: usize = 5;
    let dma = super::output_capacity(len, true) + RX_SLACK;
    let hart = super::physical_hart();
    let mut storage = core::mem::take(&mut *SPARE[hart].lock());
    storage.reserve(HEADER + 63 + dma.next_multiple_of(64));
    let base = storage.as_mut_ptr() as usize;
    let address = (base + HEADER).next_multiple_of(64);
    let head = address - base;
    let split = input.len() & !15;
    #[repr(align(16))]
    struct Tail([u8; 16]);
    let mut tail = Tail([0; 16]);
    let rest = &input[split..];
    tail.0[..rest.len()].copy_from_slice(rest);
    tail.0[rest.len()] = suffix[0];
    let payload = super::Payload {
        body: &input[..split],
        tail: &tail.0[..rest.len() + 1],
    };
    let result = super::service_record(
        handle,
        nonce,
        aad,
        payload,
        None,
        RxTarget { address, prefix: 0 },
    );
    super::wipe(tail.0.as_mut_ptr() as usize, tail.0.len());
    let Some((guard, record)) = result? else {
        return Ok(None);
    };
    drop(guard);
    crate::ethernet::flush_dma_lines(address, record.dma_len);
    // Successful final writeback initialized both ciphertext and its tag.
    // Initialize only the headroom before exposing the allocation as bytes.
    unsafe {
        ptr::write_bytes(storage.as_mut_ptr(), 0, head);
        storage.set_len(head + len + 16);
    }
    let tag = storage[head + len..].try_into().unwrap();
    let output = aes_gcm::backend::Output::from_storage(
        alloc::boxed::Box::new(Ciphertext { storage, hart }),
        head..head + len,
    )?;
    SEALED_BYTES.fetch_add(input.len() as u64, Relaxed);
    Ok(Some((output, tag)))
}

/// Compare the public synchronous sealing path with software AES-GCM, including
/// split input, descriptor boundaries and TLS's prefix/tag operations.
pub fn verify_seal() -> Result<usize, &'static str> {
    use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit};
    use core::task::{Context, Poll, Waker};
    let key = [0x29; 16];
    let software = Aes128Gcm::from(aes_gcm::aes::Aes128::new_from_slice(&key).unwrap());
    let hardware = Aes128Gcm::new_from_slice(&key).unwrap();
    let lengths = [
        128usize,
        129,
        143,
        144,
        145,
        3999,
        4000,
        4001,
        4095,
        4096,
        4097,
        7999,
        8000,
        8001,
        8191,
        8192,
        8193,
        16383,
        16384,
        MAX_RECORD - 1,
    ];
    let bytes: Vec<_> = (0..MAX_RECORD + 8).map(|i| (i ^ (i >> 8)) as u8).collect();
    for (offset, len) in lengths.into_iter().enumerate() {
        let start = offset % 8;
        let plain = &bytes[start..start + len];
        let mut expected = plain.to_vec();
        expected.push(23);
        let mut nonce = [0; 12];
        nonce[8..].copy_from_slice(&(len as u32).to_be_bytes());
        let aad = b"TLS13";
        let tag = software
            .encrypt_inout_detached((&nonce).into(), aad, expected.as_mut_slice().into())
            .unwrap();
        let mut op = hardware
            .try_encrypt_slices(&nonce, aad, plain, &[23])
            .ok_or("CE seal declined")?;
        let Poll::Ready(Ok((mut data, actual))) =
            op.poll_output(&mut Context::from_waker(Waker::noop()))
        else {
            return Err("CE seal failed");
        };
        if data.as_ref() != expected || actual[..] != tag[..] {
            return Err("CE seal ciphertext or tag");
        }
        data.append(&actual);
        data.prepend(&[23, 3, 3, 0, 0]);
        if data.as_ref()[..5] != [23, 3, 3, 0, 0]
            || data.as_ref()[5..5 + len + 1] != expected
            || data.as_ref()[6 + len..] != tag[..]
            || !plain
                .iter()
                .enumerate()
                .all(|(i, &b)| b == ((i + start) ^ ((i + start) >> 8)) as u8)
        {
            return Err("CE TLS output or input guard");
        }
    }
    Ok(lengths.len())
}
