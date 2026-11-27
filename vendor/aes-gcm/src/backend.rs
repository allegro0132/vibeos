//! Persistent hardware key contexts for 96-bit nonces and 128-bit tags.
use crate::Error;
use aead::inout::InOutBuf;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use zeroize::Zeroize;
extern crate alloc;
use alloc::sync::Arc;
/// Installed once before application tasks. Successful creation owns a context
/// until the final cloned cipher is dropped. Failed creation fails closed.
pub struct Backend {
    pub create: fn(&[u8], &[u8; 16]) -> Result<usize, Error>,
    pub destroy: fn(usize),
    /// Ok(None) declines admission before DMA owns any input or nonce.
    pub crypt: fn(usize, &[u8; 12], &[u8], &mut [u8], Option<&[u8; 16]>) -> Result<Option<[u8; 16]>, Error>,
}
/// Optional synchronous admission for devices with bounded persistent key slots.
/// None declines this record before the device owns a key handle or a nonce.
pub type TryCreateKey = fn(&[u8], &[u8; 16]) -> Result<Option<usize>, Error>;
/// A synchronous device that stages its own output can borrow the original
/// input. It must finish DMA before returning, publish plaintext only after
/// authentication, and leave caller buffers untouched on both Err and Ok(None).
pub type CryptInOut = fn(
    usize,
    &[u8; 12],
    &[u8],
    InOutBuf<'_, '_, u8>,
    Option<&[u8; 16]>,
) -> Result<Option<[u8; 16]>, Error>;
/// Return one authenticated plaintext byte per ciphertext byte in a private allocation.
/// A decline precedes DMA. An error must discard tentative plaintext and preserve the input.
pub type OpenOwned =
    fn(usize, &[u8; 12], &[u8], &[u8], &[u8; 16]) -> Result<Option<alloc::vec::Vec<u8>>, Error>;
static OWNED_OPEN: AtomicPtr<OpenOwned> = AtomicPtr::new(core::ptr::null_mut());

/// Install the synchronous backend's optional authenticated-output operation.
pub fn install_open_owned(backend: &'static Backend, open: &'static OpenOwned) -> Result<(), Error> {
    if !core::ptr::eq(BACKEND.load(Ordering::Acquire), backend) {
        return Err(Error);
    }
    OWNED_OPEN.compare_exchange(
        core::ptr::null_mut(),
        core::ptr::from_ref(open).cast_mut(),
        Ordering::Release,
        Ordering::Relaxed,
    ).map(|_| ()).map_err(|_| Error)
}
pub(crate) fn open_owned(
    key: Option<&RawKey>, nonce: &[u8; 12], aad: &[u8], input: &[u8], tag: &[u8; 16],
) -> Option<Result<alloc::vec::Vec<u8>, Error>> {
    let open = OWNED_OPEN.load(Ordering::Acquire);
    if open.is_null() || !ENABLED.load(Ordering::Acquire) { return None; }
    let key = key?;
    let result = (|| {
        if !record_fits(input.len(), aad.len(), true) { return Err(Error); }
        let Some(handle) = synchronous_handle(key, input.len())? else { return Ok(None); };
        // install_open_owned publishes a static function for this backend.
        (unsafe { *open })(handle, nonce, aad, input, tag)
    })();
    result.transpose()
}
static INOUT: AtomicPtr<CryptInOut> = AtomicPtr::new(core::ptr::null_mut());

/// Register the installed backend's optional synchronous in/out operation.
pub fn install_crypt_inout(backend: &'static Backend, crypt: &'static CryptInOut) -> Result<(), Error> {
    if !core::ptr::eq(BACKEND.load(Ordering::Acquire), backend) {
        return Err(Error);
    }
    INOUT.compare_exchange(
        core::ptr::null_mut(),
        core::ptr::from_ref(crypt).cast_mut(),
        Ordering::Release,
        Ordering::Relaxed,
    ).map(|_| ()).map_err(|_| Error)
}

static KEY_ADMISSION: AtomicPtr<TryCreateKey> = AtomicPtr::new(core::ptr::null_mut());
pub fn install_key_admission(backend: &'static Backend, create: &'static TryCreateKey) -> Result<(), Error> {
    if !core::ptr::eq(BACKEND.load(Ordering::Acquire), backend) { return Err(Error); }
    KEY_ADMISSION.compare_exchange(core::ptr::null_mut(), core::ptr::from_ref(create).cast_mut(),
        Ordering::Release, Ordering::Relaxed).map(|_| ()).map_err(|_| Error)
}
static ENABLED: AtomicBool = AtomicBool::new(true);
/// Applies to subsequently dispatched records; admitted DMA finishes normally.
pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Release);
}
static BACKEND: AtomicPtr<Backend> = AtomicPtr::new(core::ptr::null_mut());
pub fn install(backend: &'static Backend) -> Result<(), Error> {
    BACKEND
        .compare_exchange(
            core::ptr::null_mut(),
            core::ptr::from_ref(backend).cast_mut(),
            Ordering::Release,
            Ordering::Relaxed,
        )
        .map(|_| ())
        .map_err(|_| Error)
}
pub fn installed() -> bool {
    !BACKEND.load(Ordering::Acquire).is_null()
}
pub fn active() -> bool {
    !BACKEND.load(Ordering::Acquire).is_null() && ENABLED.load(Ordering::Acquire)
}
struct Registered {
    backend: &'static Backend,
    // 0=not created, 1=creating, 2=failed; otherwise opaque handle + 3.
    handle: AtomicUsize,
    key: [u8; 32],
    key_len: usize,
    h: [u8; 16],
}
impl Registered {
    fn handle(&self) -> Result<Option<usize>, Error> {
        loop {
            match self.handle.load(Ordering::Acquire) {
                0 => {
                    if self
                        .handle
                        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        struct InitGuard<'a>(&'a AtomicUsize, usize);
                        impl Drop for InitGuard<'_> {
                            fn drop(&mut self) {
                                self.0.store(self.1, Ordering::Release);
                            }
                        }
                        let mut guard = InitGuard(&self.handle, 2);
                        let admission = KEY_ADMISSION.load(Ordering::Acquire);
                        let result = if admission.is_null() {
                            (self.backend.create)(&self.key[..self.key_len], &self.h).map(Some)
                        } else {
                            (unsafe { *admission })(&self.key[..self.key_len], &self.h)
                        };
                        let state = match result {
                            Ok(None) => {
                                guard.1 = 0;
                                return Ok(None);
                            }
                            Ok(Some(h)) => match h.checked_add(3) {
                                Some(v) => v,
                                None => {
                                    (self.backend.destroy)(h);
                                    2
                                }
                            },
                            Err(_) => 2,
                        };
                        guard.1 = state;
                    }
                }
                1 => core::hint::spin_loop(),
                2 => return Err(Error),
                h => return Ok(Some(h - 3)),
            }
        }
    }
}
impl Drop for Registered {
    fn drop(&mut self) {
        let h = self.handle.load(Ordering::Acquire);
        if h >= 3 {
            (self.backend.destroy)(h - 3);
        }
        self.key.zeroize();
        self.h.zeroize();
    }
}
#[derive(Clone)]
pub(crate) struct RawKey(Arc<Registered>);
impl RawKey {
    pub fn new(key: &[u8], h: &[u8; 16]) -> Option<Self> {
        let ptr = BACKEND.load(Ordering::Acquire);
        if ptr.is_null() {
            return None;
        }
        // Published once; the registration and callback table outlive all keys.
        let backend = unsafe { &*ptr };
        if !matches!(key.len(), 16 | 24 | 32) {
            return None;
        }
        let mut bytes = [0; 32];
        bytes[..key.len()].copy_from_slice(key);
        Some(Self(Arc::new(Registered {
            backend,
            handle: AtomicUsize::new(0),
            key: bytes,
            key_len: key.len(),
            h: *h,
        })))
    }
}
struct Scratch(alloc::vec::Vec<u8>);
fn wipe_record(bytes: &mut [u8]) {
    // Every bit pattern is a valid usize. The exclusive slice is initialized,
    // and align_to_mut keeps unaligned boundary bytes out of the word slice.
    let (head, words, tail) = unsafe { bytes.align_to_mut::<usize>() };
    head.zeroize();
    words.zeroize();
    tail.zeroize();
}

impl Drop for Scratch {
    fn drop(&mut self) {
        wipe_record(&mut self.0);
    }
}
pub(crate) fn record_fits(payload: usize, aad: usize, decrypt: bool) -> bool {
    payload <= 18432 && aad <= 16384 && payload + aad + if decrypt { 16 } else { 0 } <= 20480
}

fn synchronous_handle(key: &RawKey, len: usize) -> Result<Option<usize>, Error> {
    let asynchronous = ASYNC_BACKEND.load(Ordering::Acquire);
    if !asynchronous.is_null() && !(unsafe { &*asynchronous }).admit(len, 0) {
        return Ok(None);
    }
    key.0.handle()
}

pub(crate) fn dispatch(
    key: Option<&RawKey>,
    nonce: &[u8],
    aad: &[u8],
    mut buffer: InOutBuf<'_, '_, u8>,
    tag: Option<&[u8]>,
    tag_len: usize,
) -> Option<Result<[u8; 16], Error>> {
    if !ENABLED.load(Ordering::Acquire) {
        return None;
    }
    let key = key?;
    let result = (|| {
        if tag_len != 16 || !record_fits(buffer.len(), aad.len(), tag.is_some()) {
            return Err(Error);
        }
        let nonce = nonce.try_into().map_err(|_| Error)?;
        let tag = tag
            .map(|t| <&[u8; 16]>::try_from(t).map_err(|_| Error))
            .transpose()?;
        let Some(handle) = synchronous_handle(key, buffer.len())? else { return Ok(None); };
        let inout = INOUT.load(Ordering::Acquire);
        if !inout.is_null() {
            // install_crypt_inout publishes a static function for this backend.
            return (unsafe { *inout })(handle, nonce, aad, buffer, tag);
        }
        // Legacy backends receive a private buffer, including for in-place callers.
        let mut scratch = Scratch(buffer.get_in().to_vec());
        let tag = (key.0.backend.crypt)(handle, nonce, aad, &mut scratch.0, tag)?;
        if tag.is_some() {
            buffer.get_out().copy_from_slice(&scratch.0);
        }
        Ok(tag)
    })();
    result.transpose()
}

/// Storage owned by a completed operation. Device implementations return their
/// lease in Drop; no caller can retain a slice beyond the storage lifetime.
pub trait OutputStorage: Send + Sync {
    fn bytes(&self) -> &[u8];
    fn bytes_mut(&mut self) -> &mut [u8];
    /// Copy a validated subrange, allowing device storage to use its native access width.
    fn copy_to(&self, range: core::ops::Range<usize>, dst: &mut [u8]) {
        dst.copy_from_slice(&self.bytes()[range]);
    }
    /// Resize while preserving existing bytes; false leaves storage unchanged.
    fn resize(&mut self, _len: usize) -> bool {
        false
    }
    fn into_vec(self: alloc::boxed::Box<Self>) -> alloc::vec::Vec<u8> {
        self.bytes().to_vec()
    }
}
struct HeapOutput(alloc::vec::Vec<u8>);
impl Drop for HeapOutput {
    fn drop(&mut self) {
        // Wipe the initialized record at native width. Only the spare tail
        // may be uninitialized or contain bytes from an earlier record.
        wipe_record(&mut self.0);
        self.0.spare_capacity_mut().zeroize();
    }
}
impl OutputStorage for HeapOutput {
    fn bytes(&self) -> &[u8] {
        &self.0
    }
    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
    fn resize(&mut self, len: usize) -> bool {
        self.0.resize(len, 0);
        true
    }
    fn into_vec(mut self: alloc::boxed::Box<Self>) -> alloc::vec::Vec<u8> {
        core::mem::take(&mut self.0)
    }
}
/// A view into owned completed storage, with optional prefix/tag headroom.
pub struct Output {
    storage: alloc::boxed::Box<dyn OutputStorage>,
    range: core::ops::Range<usize>,
}
impl Output {
    pub fn from_vec(data: alloc::vec::Vec<u8>) -> Self {
        let len = data.len();
        Self {
            storage: alloc::boxed::Box::new(HeapOutput(data)),
            range: 0..len,
        }
    }
    pub fn from_storage(
        storage: alloc::boxed::Box<dyn OutputStorage>,
        range: core::ops::Range<usize>,
    ) -> Result<Self, Error> {
        if range.start > range.end || range.end > storage.bytes().len() {
            return Err(Error);
        }
        Ok(Self { storage, range })
    }
    pub fn copy_prefix_to(&self, dst: &mut [u8]) -> Result<(), Error> {
        if dst.len() > self.range.len() { return Err(Error); }
        self.storage.copy_to(self.range.start..self.range.start + dst.len(), dst);
        Ok(())
    }
    pub fn prepend(&mut self, prefix: &[u8]) {
        if self.range.start >= prefix.len() {
            self.range.start -= prefix.len();
            self.storage.bytes_mut()[self.range.start..self.range.start + prefix.len()]
                .copy_from_slice(prefix);
        } else if self.storage.resize(prefix.len() + self.range.len()) {
            self.storage
                .bytes_mut()
                .copy_within(self.range.clone(), prefix.len());
            self.range = 0..prefix.len() + self.range.len();
            self.storage.bytes_mut()[..prefix.len()].copy_from_slice(prefix);
        } else {
            let mut data = alloc::vec::Vec::with_capacity(prefix.len() + self.as_ref().len());
            data.extend_from_slice(prefix);
            data.extend_from_slice(self.as_ref());
            *self = Self::from_vec(data);
        }
    }
    pub fn append(&mut self, suffix: &[u8]) {
        if suffix.len() <= self.storage.bytes().len() - self.range.end
            || self.storage.resize(self.range.end + suffix.len())
        {
            let end = self.range.end + suffix.len();
            self.storage.bytes_mut()[self.range.end..end].copy_from_slice(suffix);
            self.range.end = end;
        } else {
            let mut data = self.as_ref().to_vec();
            data.extend_from_slice(suffix);
            *self = Self::from_vec(data);
        }
    }
    pub fn into_vec(self) -> alloc::vec::Vec<u8> {
        let len = self.range.len();
        let mut data = self.storage.into_vec();
        if self.range.start != 0 {
            data.drain(..self.range.start);
        }
        data.truncate(len);
        data
    }
}
impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        &self.storage.bytes()[self.range.clone()]
    }
}
impl AsMut<[u8]> for Output {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.storage.bytes_mut()[self.range.clone()]
    }
}

/// Owned AEAD work. Drop must cancel delivery without freeing live DMA memory.
/// Pending implementations arrange a wakeup; poll never spins awaiting DMA.
pub trait Operation: Send + Sync {
    fn poll(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(alloc::vec::Vec<u8>, [u8; 16]), Error>>;
    /// Preserve completed device storage instead of copying it into a Vec.
    fn poll_output(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(Output, [u8; 16]), Error>> {
        self.poll(cx)
            .map(|result| result.map(|(data, tag)| (Output::from_vec(data), tag)))
    }
}
/// Nonblocking extension to the installed synchronous context backend.
/// Handles must be compatible with Backend::destroy and its persistent keys.
pub struct AsyncBackend {
    /// Advisory record admission before key creation or device submission.
    pub available: fn() -> bool,
    /// Minimum owned payload worth staging through DMA.
    pub min_payload: usize,
    /// Observe a record selected for CPU crypto before device submission.
    pub cpu_record: fn(usize),
    pub create: fn(
        &[u8],
        &[u8; 16],
        &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<usize, Error>>,
    pub start: fn(
        usize,
        [u8; 12],
        alloc::vec::Vec<u8>,
        alloc::vec::Vec<u8>,
        Option<[u8; 16]>,
    ) -> alloc::boxed::Box<dyn Operation>,
}
static ASYNC_BACKEND: AtomicPtr<AsyncBackend> = AtomicPtr::new(core::ptr::null_mut());
/// An implementation must copy the input into device-owned memory before
/// returning. None means the request was declined before submission.
pub type SubmitDecrypt = fn(usize, &[u8; 12], &[u8], &[u8], &[u8; 16])
    -> Result<Option<alloc::boxed::Box<dyn Operation>>, Error>;
static DECRYPT: AtomicPtr<SubmitDecrypt> = AtomicPtr::new(core::ptr::null_mut());

/// Install an optional direct-submission path for the active async backend.
pub fn install_decrypt(backend: &'static AsyncBackend, submit: &'static SubmitDecrypt) -> Result<(), Error> {
    if !core::ptr::eq(ASYNC_BACKEND.load(Ordering::Acquire), backend) {
        return Err(Error);
    }
    DECRYPT.compare_exchange(core::ptr::null_mut(), core::ptr::from_ref(submit).cast_mut(),
        Ordering::Release, Ordering::Relaxed).map(|_| ()).map_err(|_| Error)
}

/// Submit two borrowed plaintext slices as one GCM message. A successful
/// submission owns its DMA input. Only a pre-submission decline returns None.
pub type SubmitEncrypt = fn(usize, &[u8; 12], &[u8], &[u8], &[u8])
    -> Result<Option<alloc::boxed::Box<dyn Operation>>, Error>;
static ENCRYPT: AtomicPtr<SubmitEncrypt> = AtomicPtr::new(core::ptr::null_mut());

pub fn install_encrypt(backend: &'static AsyncBackend, submit: &'static SubmitEncrypt) -> Result<(), Error> {
    if !core::ptr::eq(ASYNC_BACKEND.load(Ordering::Acquire), backend) { return Err(Error); }
    ENCRYPT.compare_exchange(core::ptr::null_mut(), core::ptr::from_ref(submit).cast_mut(),
        Ordering::Release, Ordering::Relaxed).map(|_| ()).map_err(|_| Error)
}

/// Seal two borrowed slices before returning. Only a decline before submission
/// may fall back to the ordinary encrypter with the same nonce.
pub type SealOwned = fn(usize, &[u8; 12], &[u8], &[u8], &[u8])
    -> Result<Option<(Output, [u8; 16])>, Error>;
static OWNED_SEAL: AtomicPtr<SealOwned> = AtomicPtr::new(core::ptr::null_mut());

pub fn install_seal_owned(backend: &'static Backend, seal: &'static SealOwned) -> Result<(), Error> {
    if !core::ptr::eq(BACKEND.load(Ordering::Acquire), backend) { return Err(Error); }
    OWNED_SEAL.compare_exchange(core::ptr::null_mut(), core::ptr::from_ref(seal).cast_mut(),
        Ordering::Release, Ordering::Relaxed).map(|_| ()).map_err(|_| Error)
}

/// A deferred seal keeps its registered key alive through device completion,
/// including when the TLS connection is dropped before the worker finishes.
pub struct SealKey {
    _registration: RawKey,
    handle: usize,
}
impl SealKey {
    pub fn handle(&self) -> usize { self.handle }
}

/// Returning None declines before consuming the nonce or retaining caller input.
/// An accepted job owns both its source bytes and the supplied key lease.
pub type DeferSeal = fn(SealKey, &[u8; 12], &[u8], &[u8], &[u8])
    -> Option<alloc::boxed::Box<dyn Operation>>;
static DEFER_SEAL: AtomicPtr<DeferSeal> = AtomicPtr::new(core::ptr::null_mut());

pub fn install_deferred_seal(backend: &'static Backend, defer: &'static DeferSeal) -> Result<(), Error> {
    if !core::ptr::eq(BACKEND.load(Ordering::Acquire), backend) { return Err(Error); }
    DEFER_SEAL.compare_exchange(core::ptr::null_mut(), core::ptr::from_ref(defer).cast_mut(),
        Ordering::Release, Ordering::Relaxed).map(|_| ()).map_err(|_| Error)
}

struct SealedRecord(Option<Result<(Output, [u8; 16]), Error>>);
impl Operation for SealedRecord {
    fn poll_output(&mut self, _: &mut core::task::Context<'_>)
        -> core::task::Poll<Result<(Output, [u8; 16]), Error>> {
        core::task::Poll::Ready(self.0.take().unwrap_or(Err(Error)))
    }
    fn poll(&mut self, cx: &mut core::task::Context<'_>)
        -> core::task::Poll<Result<(alloc::vec::Vec<u8>, [u8; 16]), Error>> {
        self.poll_output(cx).map(|result| result.map(|(data, tag)| (data.into_vec(), tag)))
    }
}

pub(crate) fn submit_encrypt(key: Option<&RawKey>, nonce: &[u8; 12], aad: &[u8],
    input: &[u8], suffix: &[u8]) -> Option<alloc::boxed::Box<dyn Operation>> {
    let submit = ENCRYPT.load(Ordering::Acquire);
    let len = input.len().checked_add(suffix.len())?;
    if !submit.is_null() {
        return submit_borrowed(key, nonce, aad, len, None,
            |handle| (unsafe { *submit })(handle, nonce, aad, input, suffix));
    }
    let seal = OWNED_SEAL.load(Ordering::Acquire);
    if seal.is_null() || !ENABLED.load(Ordering::Acquire) { return None; }
    let key = key?;
    let handle = if record_fits(len, aad.len(), false) { synchronous_handle(key, len) } else { Err(Error) };
    let completed = match handle {
        Ok(Some(handle)) => {
            let defer = DEFER_SEAL.load(Ordering::Acquire);
            if !defer.is_null() {
                let lease = SealKey { _registration: key.clone(), handle };
                if let Some(job) = (unsafe { *defer })(lease, nonce, aad, input, suffix) {
                    return Some(job);
                }
            }
            (unsafe { *seal })(handle, nonce, aad, input, suffix).transpose()?
        }
        Ok(None) => return None,
        Err(error) => Err(error),
    };
    Some(alloc::boxed::Box::new(SealedRecord(Some(completed))))
}

pub(crate) fn submit_decrypt(key: Option<&RawKey>, nonce: &[u8; 12], aad: &[u8], input: &[u8],
    tag: &[u8; 16]) -> Option<alloc::boxed::Box<dyn Operation>> {
    let submit = DECRYPT.load(Ordering::Acquire);
    if submit.is_null() { return None; }
    submit_borrowed(key, nonce, aad, input.len(), Some(*tag),
        |handle| (unsafe { *submit })(handle, nonce, aad, input, tag))
}

fn submit_borrowed(key: Option<&RawKey>, nonce: &[u8; 12], aad: &[u8], len: usize,
    tag: Option<[u8; 16]>, submit: impl FnOnce(usize) -> Result<Option<alloc::boxed::Box<dyn Operation>>, Error>)
    -> Option<alloc::boxed::Box<dyn Operation>> {
    let (backend, key) = async_target(key)?;
    let handle = key.0.handle.load(Ordering::Acquire).checked_sub(3)?;
    if len < backend.min_payload || !(backend.available)() || !record_fits(len, aad.len(), tag.is_some()) {
        return None;
    }
    match submit(handle) {
        Ok(Some(operation)) => Some(alloc::boxed::Box::new(HardwareOperation {
            operation: Some(operation), key, backend, nonce: *nonce, aad: alloc::vec::Vec::new(),
            input: None, tag, done: false,
        })),
        Ok(None) => None,
        Err(e) => Some(alloc::boxed::Box::new(ReadyOperation(Some(Err(e))))),
    }
}

/// Whether new owned operations can use the asynchronous hardware backend.
pub fn asynchronous_active() -> bool {
    active() && !ASYNC_BACKEND.load(Ordering::Acquire).is_null()
}
/// Whether a new TLS read can currently benefit from an owned DMA operation.
pub fn asynchronous_available() -> bool {
    let p = ASYNC_BACKEND.load(Ordering::Acquire);
    active() && !p.is_null() && (unsafe { &*p }.available)()
}

impl AsyncBackend {
    pub(crate) fn admit_owned(&self, key: &RawKey, len: usize) -> Result<bool, Error> {
        if !self.admit(len, self.min_payload) { return Ok(false); }
        // Legacy async backends create their key from the operation poll.
        if KEY_ADMISSION.load(Ordering::Acquire).is_null() || key.0.handle()?.is_some() {
            return Ok(true);
        }
        (self.cpu_record)(len);
        Ok(false)
    }
    pub(crate) fn admit(&self, len: usize, minimum: usize) -> bool {
        if len >= minimum && (self.available)() { return true; }
        (self.cpu_record)(len);
        false
    }
}

/// Install before any application tasks, after the compatible Backend.
pub fn install_async(backend: &'static AsyncBackend) -> Result<(), Error> {
    if !installed() {
        return Err(Error);
    }
    ASYNC_BACKEND
        .compare_exchange(
            core::ptr::null_mut(),
            core::ptr::from_ref(backend).cast_mut(),
            Ordering::Release,
            Ordering::Relaxed,
        )
        .map(|_| ())
        .map_err(|_| Error)
}
pub(crate) fn async_target(key: Option<&RawKey>) -> Option<(&'static AsyncBackend, RawKey)> {
    if !active() {
        return None;
    }
    let p = ASYNC_BACKEND.load(Ordering::Acquire);
    if p.is_null() {
        return None;
    }
    // Installed once from a static reference; never removed.
    Some((unsafe { &*p }, key?.clone()))
}
impl Registered {
    fn poll_handle(
        &self,
        backend: &AsyncBackend,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<usize, Error>> {
        use core::task::Poll;
        match self.handle.load(Ordering::Acquire) {
            0 => {
                if self
                    .handle
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                // Restore a retryable state when admission is pending or unwinds.
                struct Guard<'a>(&'a AtomicUsize);
                impl Drop for Guard<'_> {
                    fn drop(&mut self) {
                        let _ = self
                            .0
                            .compare_exchange(1, 0, Ordering::Release, Ordering::Relaxed);
                    }
                }
                let _guard = Guard(&self.handle);
                match (backend.create)(&self.key[..self.key_len], &self.h, cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Ok(h)) => match h.checked_add(3) {
                        Some(v) => {
                            self.handle.store(v, Ordering::Release);
                            Poll::Ready(Ok(h))
                        }
                        None => {
                            (self.backend.destroy)(h);
                            self.handle.store(2, Ordering::Release);
                            Poll::Ready(Err(Error))
                        }
                    },
                    Poll::Ready(Err(e)) => {
                        self.handle.store(2, Ordering::Release);
                        Poll::Ready(Err(e))
                    }
                }
            }
            1 => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            2 => Poll::Ready(Err(Error)),
            h => Poll::Ready(Ok(h - 3)),
        }
    }
}
pub(crate) struct HardwareOperation {
    // Drop the device operation before releasing the final key reference.
    operation: Option<alloc::boxed::Box<dyn Operation>>,
    key: RawKey,
    backend: &'static AsyncBackend,
    nonce: [u8; 12],
    aad: alloc::vec::Vec<u8>,
    input: Option<alloc::vec::Vec<u8>>,
    tag: Option<[u8; 16]>,
    done: bool,
}
impl HardwareOperation {
    pub(crate) fn new(
        key: RawKey,
        backend: &'static AsyncBackend,
        nonce: [u8; 12],
        aad: alloc::vec::Vec<u8>,
        input: alloc::vec::Vec<u8>,
        tag: Option<[u8; 16]>,
    ) -> Self {
        Self {
            operation: None,
            key,
            backend,
            nonce,
            aad,
            input: Some(input),
            tag,
            done: false,
        }
    }
}
impl Drop for HardwareOperation {
    fn drop(&mut self) {
        if let Some(input) = self.input.as_mut() {
            input.as_mut_slice().zeroize();
        }
        self.aad.as_mut_slice().zeroize();
    }
}
impl HardwareOperation {
    fn prepare(&mut self, cx: &mut core::task::Context<'_>) -> core::task::Poll<Result<(), Error>> {
        use core::task::Poll;
        if self.done {
            return Poll::Ready(Err(Error));
        }
        if self.operation.is_none() {
            let h = match self.key.0.poll_handle(self.backend, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(h)) => h,
                Poll::Ready(Err(e)) => {
                    self.done = true;
                    return Poll::Ready(Err(e));
                }
            };
            self.operation = Some((self.backend.start)(
                h,
                self.nonce,
                core::mem::take(&mut self.aad),
                self.input.take().unwrap(),
                self.tag,
            ));
        }
        Poll::Ready(Ok(()))
    }
}
impl Operation for HardwareOperation {
    fn poll(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(alloc::vec::Vec<u8>, [u8; 16]), Error>> {
        core::task::ready!(self.prepare(cx))?;
        let result = self.operation.as_mut().unwrap().poll(cx);
        if result.is_ready() {
            self.done = true;
            self.operation = None;
        }
        result
    }
    fn poll_output(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(Output, [u8; 16]), Error>> {
        core::task::ready!(self.prepare(cx))?;
        let result = self.operation.as_mut().unwrap().poll_output(cx);
        if result.is_ready() {
            self.done = true;
            self.operation = None;
        }
        result
    }
}
pub(crate) struct ReadyOperation(pub Option<Result<(alloc::vec::Vec<u8>, [u8; 16]), Error>>);
impl Drop for ReadyOperation {
    fn drop(&mut self) {
        if let Some(Ok((data, _))) = self.0.as_mut() {
            data.as_mut_slice().zeroize();
        }
    }
}
impl Operation for ReadyOperation {
    fn poll(
        &mut self,
        _: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(alloc::vec::Vec<u8>, [u8; 16]), Error>> {
        core::task::Poll::Ready(self.0.take().unwrap_or(Err(Error)))
    }
}
