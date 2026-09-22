//! Entropy is an explicit invocation grant, never an ambient timer/PRNG source.
use alloc::sync::Arc;
use crate::{cap::{Cap, InvocationLease, Rights}, world::Space, virtio_rng::RandomSource};
#[derive(Clone)]
pub(super) struct EntropyGrant { space: Arc<Space>, cap: Cap }
impl EntropyGrant {
    pub(super) fn new(space: Arc<Space>, cap: Cap) -> Option<Self> {
        let grant = Self { space, cap };
        drop(grant.lease()?);
        Some(grant)
    }
    fn lease(&self) -> Option<InvocationLease<RandomSource>> {
        self.space.0.lock().lookup_lease(self.cap, Rights::READ).ok()
    }
}
/// Caller owns a valid writable range for the duration of this synchronous
/// call, including suspension. Service/DMA code never sees the caller pointer.
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_entropy(output: *mut u8, length: usize) -> i32 {
    let Some(grant) = crate::native_tls::entropy_grant() else { return -1; };
    let Some(lease) = grant.lease() else { return -1; };
    if length == 0 { return 0; }
    if output.is_null() || length > crate::virtio_rng::MAX_RANDOM_BYTES { return -1; }
    let mut result = None;
    if !crate::native_tls::park(async {
        result = Some(crate::virtio_rng::bytes_with(lease, length).await);
    }) { return -1; }
    let Some(Ok(bytes)) = result else { return -1; };
    // Do not deliver bytes if the grant was revoked while the device worked.
    let Some(_delivery_lease) = grant.lease() else { return -1; };
    if bytes.as_slice().len() != length { return -1; }
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_slice().as_ptr(), output, length); }
    0
}
