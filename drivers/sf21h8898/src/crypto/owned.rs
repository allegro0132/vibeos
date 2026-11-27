//! Retire authenticated CE plaintext into TLS-owned storage. Only full private
//! cache lines are exposed to DMA. The unaligned head uses the calling hart's scratch.
extern crate alloc;
use super::{Error, RxTarget, MAX_AAD, MAX_RECORD, RX_SLACK};
#[cfg(feature = "ce-record-profile")]
use alloc::vec;
use alloc::vec::Vec;
#[cfg(feature = "ce-record-profile")]
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use core::{mem::MaybeUninit, ptr};

#[cfg(feature = "ce-record-profile")]
static ENABLED: AtomicBool = AtomicBool::new(true);
#[cfg(feature = "ce-record-profile")]
static COUNTERS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
#[cfg(feature = "ce-record-profile")]
pub fn enable(on: bool) {
    ENABLED.store(on, Relaxed);
}
#[cfg(feature = "ce-record-profile")]
pub fn counters() -> [u64; 3] {
    COUNTERS.each_ref().map(|v| v.load(Relaxed))
}

// A final cache-block operation may extend up to 63 bytes past the DMA range.
fn storage_len(len: usize) -> usize {
    super::output_capacity(len, false) + RX_SLACK + 63
}

pub(super) fn open(
    handle: usize,
    nonce: &[u8; 12],
    aad: &[u8],
    input: &[u8],
    tag: &[u8; 16],
) -> Result<Option<Vec<u8>>, Error> {
    #[cfg(feature = "ce-record-profile")]
    if !ENABLED.load(Relaxed) {
        return Ok(None);
    }
    if !(128..=MAX_RECORD).contains(&input.len()) || aad.len() > MAX_AAD {
        return Ok(None);
    }

    let mut private = Vec::with_capacity(storage_len(input.len()));
    if !open_into(handle, nonce, aad, input, tag, private.spare_capacity_mut())? {
        return Ok(None);
    }
    // The successful final writeback and head copy initialized these bytes.
    unsafe {
        private.set_len(input.len());
    }
    Ok(Some(private))
}

fn open_into(
    handle: usize,
    nonce: &[u8; 12],
    aad: &[u8],
    input: &[u8],
    tag: &[u8; 16],
    private: &mut [MaybeUninit<u8>],
) -> Result<bool, Error> {
    let address = private.as_mut_ptr() as usize;
    let prefix = address.wrapping_neg() & 63;
    if address % 8 != 0 || input.len() <= prefix || private.len() < storage_len(input.len()) {
        return Ok(false);
    }
    let target = RxTarget { address, prefix };
    let Some((guard, record)) =
        super::service_record(handle, nonce, aad, super::Payload::single(input), Some(tag), target)?
    else {
        return Ok(false);
    };
    // The CE has stopped accessing both buffers. The small head belongs to
    // this physical hart throughout this synchronous call.
    drop(guard);
    crate::ethernet::flush_dma_lines(address + prefix, record.dma_len - prefix);
    if prefix != 0 {
        let head = super::output_address();
        crate::ethernet::flush_dma_lines(head, prefix);
        unsafe {
            ptr::copy_nonoverlapping(head as *const u8, private.as_mut_ptr().cast(), prefix);
        }
        super::wipe_payload(head, prefix);
    }
    // Erase DMA overrun/padding while the allocation is still private.
    for byte in &mut private[input.len()..record.dma_len] {
        unsafe {
            ptr::write_volatile(byte.as_mut_ptr(), 0);
        }
    }
    #[cfg(feature = "ce-record-profile")]
    for (counter, n) in COUNTERS.iter().zip([1, prefix as u64, input.len() as u64]) {
        counter.fetch_add(n, Relaxed);
    }
    Ok(true)
}

#[cfg(feature = "ce-record-profile")]
pub fn verify() -> Result<usize, &'static str> {
    let h = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e,
    ];
    let handle = super::admit(&[0; 16], &h)
        .map_err(|_| "owned key")?
        .ok_or("owned key slot")?;
    let result = (|| {
        let mut checks = 0;
        for len in [
            128, 3999, 4000, 4001, 7999, 8000, 8001, 8192, 16384, 18432usize,
        ] {
            let plain: Vec<_> = (0..len).map(|i| (i ^ (i >> 8)) as u8).collect();
            let mut cipher = plain.clone();
            let mut nonce = [0; 12];
            nonce[..8].copy_from_slice(&(len as u64).to_be_bytes());
            let tag = super::dispatch(handle, &nonce, b"guard", &mut cipher, None)
                .map_err(|_| "owned seal")?
                .ok_or("seal declined")?;
            let mut bad = tag;
            bad[0] ^= 1;
            for shift in (0..64).step_by(8) {
                let n = storage_len(len);
                let mut guard = vec![MaybeUninit::new(0xa5); n + 256];
                let start = 64 + ((guard.as_ptr() as usize).wrapping_neg() & 63) + shift;
                if !open_into(
                    handle,
                    &nonce,
                    b"guard",
                    &cipher,
                    &tag,
                    &mut guard[start..start + n],
                )
                .map_err(|_| "owned open")?
                    || !guard[start..start + len]
                        .iter()
                        .zip(&plain)
                        .all(|(v, p)| unsafe { v.assume_init() } == *p)
                {
                    return Err("owned plaintext");
                }
                if open_into(
                    handle,
                    &nonce,
                    b"guard",
                    &cipher,
                    &bad,
                    &mut guard[start..start + n],
                )
                .is_ok()
                {
                    return Err("owned bad tag");
                }
                let head = (guard[start..].as_ptr() as usize).wrapping_neg() & 63;
                let end = super::output_capacity(len, false) + RX_SLACK;
                if guard[start + head..start + end]
                    .iter()
                    .any(|v| unsafe { v.assume_init() } != 0)
                {
                    return Err("owned bad-tag scrub");
                }
                if guard[..start]
                    .iter()
                    .chain(&guard[start + end..])
                    .any(|v| unsafe { v.assume_init() } != 0xa5)
                {
                    return Err("owned DMA guard");
                }
                checks += 2;
            }
        }
        Ok(checks)
    })();
    super::destroy(handle);
    result
}
