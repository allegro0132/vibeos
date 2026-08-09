//! Host stand-in, used only when compiling for `cargo test`.
//!
//! Interrupts are a no-op: host tests exercise scheduler *logic*, never
//! interrupt ordering. Ordering bugs are the kind this shim cannot reproduce,
//! which is exactly why the in-kernel self-test exists alongside it.
//!
//! Time is a counter the test drives by hand, so timer tests are deterministic
//! rather than racy.

use core::sync::atomic::{fence, AtomicBool, AtomicIsize, AtomicU64, AtomicUsize, Ordering};

use super::{HartState, IpiError};

const TEST_HARTS: usize = usize::BITS as usize;
const NO_EXTENSION: usize = usize::MAX;

pub const RFENCE_EXTENSION_ID: usize = 0x52464E43;

static NOW: AtomicU64 = AtomicU64::new(0);
static NEXT_TIMER: AtomicU64 = AtomicU64::new(u64::MAX);
static CURRENT_HART: AtomicUsize = AtomicUsize::new(0);
static SOFTWARE_PENDING: AtomicUsize = AtomicUsize::new(0);
static IPI_FAILURE_MASK: AtomicUsize = AtomicUsize::new(0);
static IPI_ATTEMPTS: [AtomicU64; usize::BITS as usize] =
    [const { AtomicU64::new(0) }; usize::BITS as usize];
static HART_STATES: [AtomicUsize; TEST_HARTS] = [const { AtomicUsize::new(1) }; TEST_HARTS];
static HART_START_ERRORS: [AtomicIsize; TEST_HARTS] = [const { AtomicIsize::new(0) }; TEST_HARTS];
static HART_STATUS_ERRORS: [AtomicIsize; TEST_HARTS] = [const { AtomicIsize::new(0) }; TEST_HARTS];
static HART_START_ATTEMPTS: [AtomicU64; TEST_HARTS] = [const { AtomicU64::new(0) }; TEST_HARTS];
static HART_STATUS_ATTEMPTS: [AtomicU64; TEST_HARTS] = [const { AtomicU64::new(0) }; TEST_HARTS];
static HART_START_ADDRS: [AtomicUsize; TEST_HARTS] = [const { AtomicUsize::new(0) }; TEST_HARTS];
static HART_START_OPAQUES: [AtomicUsize; TEST_HARTS] = [const { AtomicUsize::new(0) }; TEST_HARTS];
static RFENCE_SUPPORTED: AtomicBool = AtomicBool::new(true);
static PROBE_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static LAST_PROBED_EXTENSION: AtomicUsize = AtomicUsize::new(NO_EXTENSION);
static REMOTE_FENCE_I_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static REMOTE_FENCE_I_MASK: AtomicUsize = AtomicUsize::new(0);
static REMOTE_FENCE_I_BASE: AtomicUsize = AtomicUsize::new(0);
static REMOTE_FENCE_I_ERROR: AtomicIsize = AtomicIsize::new(0);
static REMOTE_SFENCE_VMA_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static REMOTE_SFENCE_VMA_MASK: AtomicUsize = AtomicUsize::new(0);
static REMOTE_SFENCE_VMA_BASE: AtomicUsize = AtomicUsize::new(0);
static REMOTE_SFENCE_VMA_START: AtomicUsize = AtomicUsize::new(0);
static REMOTE_SFENCE_VMA_SIZE: AtomicUsize = AtomicUsize::new(0);
static REMOTE_SFENCE_VMA_ERROR: AtomicIsize = AtomicIsize::new(0);
static LOCAL_SFENCE_VMA_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static LOCAL_SFENCE_VMA_START: AtomicUsize = AtomicUsize::new(0);
static LOCAL_SFENCE_VMA_SIZE: AtomicUsize = AtomicUsize::new(0);
static LOCAL_FENCE_I_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static MXR_ENABLED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HartStartRequest {
    pub start_addr: usize,
    pub opaque: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteFenceIRequest {
    pub hart_mask: usize,
    pub hart_mask_base: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteSfenceVmaRequest {
    pub hart_mask: usize,
    pub hart_mask_base: usize,
    pub start: usize,
    pub size: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalSfenceVmaRequest {
    pub start: usize,
    pub size: usize,
}

pub fn irq_save() -> bool {
    false
}
pub fn irq_restore(_was_on: bool) {}
pub fn enable_interrupts() {}
pub fn wait_for_interrupt() {}

pub fn current_hart_id() -> usize {
    CURRENT_HART.load(Ordering::Acquire)
}

/// Host tests keep exercising the explicit mapping scan so changing the
/// process-global hart selector cannot leave a stale per-thread cache behind.
#[inline(always)]
pub fn cached_logical_hart_index() -> Option<usize> {
    None
}

#[inline(always)]
pub(crate) unsafe fn cache_logical_hart_index(_index: usize) {}

pub fn clear_software_interrupt() {
    let hart = current_hart_id();
    if hart < usize::BITS as usize {
        SOFTWARE_PENDING.fetch_and(!(1usize << hart), Ordering::AcqRel);
    }
}

pub fn fence_ipi() {
    fence(Ordering::SeqCst);
}

pub fn local_sfence_vma(start: usize, size: usize) {
    LOCAL_SFENCE_VMA_START.store(start, Ordering::Relaxed);
    LOCAL_SFENCE_VMA_SIZE.store(size, Ordering::Relaxed);
    LOCAL_SFENCE_VMA_ATTEMPTS.fetch_add(1, Ordering::Release);
    fence(Ordering::SeqCst);
}

pub fn local_fence_i() {
    LOCAL_FENCE_I_ATTEMPTS.fetch_add(1, Ordering::Release);
    fence(Ordering::SeqCst);
}

pub fn clear_mxr() {
    MXR_ENABLED.store(false, Ordering::SeqCst);
}

pub fn mxr_enabled() -> bool {
    MXR_ENABLED.load(Ordering::SeqCst)
}

pub fn probe_extension(extension_id: usize) -> bool {
    LAST_PROBED_EXTENSION.store(extension_id, Ordering::Relaxed);
    PROBE_ATTEMPTS.fetch_add(1, Ordering::Release);
    extension_id == RFENCE_EXTENSION_ID && RFENCE_SUPPORTED.load(Ordering::Acquire)
}

pub fn remote_fence_i(hart_mask: usize, hart_mask_base: usize) -> Result<(), IpiError> {
    REMOTE_FENCE_I_MASK.store(hart_mask, Ordering::Relaxed);
    REMOTE_FENCE_I_BASE.store(hart_mask_base, Ordering::Relaxed);
    REMOTE_FENCE_I_ATTEMPTS.fetch_add(1, Ordering::Release);
    fence(Ordering::SeqCst);

    if !RFENCE_SUPPORTED.load(Ordering::Acquire) {
        return Err(IpiError::NotSupported);
    }
    let injected = REMOTE_FENCE_I_ERROR.load(Ordering::Acquire);
    if injected == 0 {
        Ok(())
    } else {
        Err(IpiError::from_sbi(injected))
    }
}

pub fn remote_sfence_vma(
    hart_mask: usize,
    hart_mask_base: usize,
    start: usize,
    size: usize,
) -> Result<(), IpiError> {
    REMOTE_SFENCE_VMA_MASK.store(hart_mask, Ordering::Relaxed);
    REMOTE_SFENCE_VMA_BASE.store(hart_mask_base, Ordering::Relaxed);
    REMOTE_SFENCE_VMA_START.store(start, Ordering::Relaxed);
    REMOTE_SFENCE_VMA_SIZE.store(size, Ordering::Relaxed);
    REMOTE_SFENCE_VMA_ATTEMPTS.fetch_add(1, Ordering::Release);
    fence(Ordering::SeqCst);

    if !RFENCE_SUPPORTED.load(Ordering::Acquire) {
        return Err(IpiError::NotSupported);
    }
    let injected = REMOTE_SFENCE_VMA_ERROR.load(Ordering::Acquire);
    if injected == 0 {
        Ok(())
    } else {
        Err(IpiError::from_sbi(injected))
    }
}

pub fn send_ipi(hart: usize) -> Result<(), IpiError> {
    if hart >= usize::BITS as usize {
        return Err(IpiError::InvalidParam);
    }
    IPI_ATTEMPTS[hart].fetch_add(1, Ordering::Relaxed);
    let bit = 1usize << hart;
    if IPI_FAILURE_MASK.load(Ordering::Acquire) & bit != 0 {
        return Err(IpiError::Failed);
    }
    SOFTWARE_PENDING.fetch_or(bit, Ordering::Release);
    Ok(())
}

/// Deterministic host model of asynchronous SBI HSM hart start.
///
/// A successful call transitions `Stopped` to `StartPending`. Tests explicitly
/// advance it to `Started` when simulating firmware entering the secondary;
/// this keeps callers from accidentally treating the SBI return as VibeOS's
/// online acknowledgement.
pub fn hart_start(hart: usize, start_addr: usize, opaque: usize) -> Result<(), IpiError> {
    if hart >= TEST_HARTS {
        return Err(IpiError::InvalidParam);
    }
    HART_START_ATTEMPTS[hart].fetch_add(1, Ordering::Relaxed);
    HART_START_ADDRS[hart].store(start_addr, Ordering::Release);
    HART_START_OPAQUES[hart].store(opaque, Ordering::Release);

    let injected = HART_START_ERRORS[hart].load(Ordering::Acquire);
    if injected != 0 {
        return Err(IpiError::from_sbi(injected));
    }

    let state = &HART_STATES[hart];
    loop {
        let raw = state.load(Ordering::Acquire);
        match HartState::from_sbi(raw) {
            HartState::Stopped => {
                if state
                    .compare_exchange_weak(
                        raw,
                        HartState::StartPending.as_sbi(),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    return Ok(());
                }
            }
            HartState::Started | HartState::StartPending => {
                return Err(IpiError::AlreadyAvailable);
            }
            _ => return Err(IpiError::Failed),
        }
    }
}

pub fn hart_status(hart: usize) -> Result<HartState, IpiError> {
    if hart >= TEST_HARTS {
        return Err(IpiError::InvalidParam);
    }
    HART_STATUS_ATTEMPTS[hart].fetch_add(1, Ordering::Relaxed);
    let injected = HART_STATUS_ERRORS[hart].load(Ordering::Acquire);
    if injected != 0 {
        Err(IpiError::from_sbi(injected))
    } else {
        Ok(HartState::from_sbi(
            HART_STATES[hart].load(Ordering::Acquire),
        ))
    }
}

pub fn time() -> u64 {
    NOW.load(Ordering::SeqCst)
}

pub fn set_timer(stime: u64) {
    NEXT_TIMER.store(stime, Ordering::SeqCst);
}

// --- test controls ---

/// Move the simulated clock forward.
pub fn advance_time(ticks: u64) {
    NOW.fetch_add(ticks, Ordering::SeqCst);
}

/// Reset the clock. Call at the start of any test that inspects time.
pub fn reset_time() {
    NOW.store(0, Ordering::SeqCst);
    NEXT_TIMER.store(u64::MAX, Ordering::SeqCst);
}

/// The deadline most recently handed to `set_timer`.
pub fn armed_timer() -> u64 {
    NEXT_TIMER.load(Ordering::SeqCst)
}

/// Select the hart observed by the host architecture shim.
pub fn set_test_hart_id(hart: usize) {
    CURRENT_HART.store(hart, Ordering::Release);
}

pub fn set_test_rfence_supported(supported: bool) {
    RFENCE_SUPPORTED.store(supported, Ordering::Release);
}

pub fn test_probe_attempts() -> u64 {
    PROBE_ATTEMPTS.load(Ordering::Acquire)
}

pub fn test_last_probed_extension() -> Option<usize> {
    (test_probe_attempts() != 0).then(|| LAST_PROBED_EXTENSION.load(Ordering::Acquire))
}

pub fn set_test_remote_fence_i_error(error: Option<IpiError>) {
    let raw = error.map_or(0, IpiError::as_sbi);
    assert!(
        error.is_none() || raw != 0,
        "an injected SBI error must be nonzero"
    );
    REMOTE_FENCE_I_ERROR.store(raw, Ordering::Release);
}

pub fn test_remote_fence_i_attempts() -> u64 {
    REMOTE_FENCE_I_ATTEMPTS.load(Ordering::Acquire)
}

pub fn test_last_remote_fence_i() -> Option<RemoteFenceIRequest> {
    (test_remote_fence_i_attempts() != 0).then(|| RemoteFenceIRequest {
        hart_mask: REMOTE_FENCE_I_MASK.load(Ordering::Acquire),
        hart_mask_base: REMOTE_FENCE_I_BASE.load(Ordering::Acquire),
    })
}

pub fn set_test_remote_sfence_vma_error(error: Option<IpiError>) {
    let raw = error.map_or(0, IpiError::as_sbi);
    assert!(
        error.is_none() || raw != 0,
        "an injected SBI error must be nonzero"
    );
    REMOTE_SFENCE_VMA_ERROR.store(raw, Ordering::Release);
}

pub fn test_remote_sfence_vma_attempts() -> u64 {
    REMOTE_SFENCE_VMA_ATTEMPTS.load(Ordering::Acquire)
}

pub fn test_last_remote_sfence_vma() -> Option<RemoteSfenceVmaRequest> {
    (test_remote_sfence_vma_attempts() != 0).then(|| RemoteSfenceVmaRequest {
        hart_mask: REMOTE_SFENCE_VMA_MASK.load(Ordering::Acquire),
        hart_mask_base: REMOTE_SFENCE_VMA_BASE.load(Ordering::Acquire),
        start: REMOTE_SFENCE_VMA_START.load(Ordering::Acquire),
        size: REMOTE_SFENCE_VMA_SIZE.load(Ordering::Acquire),
    })
}

pub fn test_local_sfence_vma_attempts() -> u64 {
    LOCAL_SFENCE_VMA_ATTEMPTS.load(Ordering::Acquire)
}

pub fn test_last_local_sfence_vma() -> Option<LocalSfenceVmaRequest> {
    (test_local_sfence_vma_attempts() != 0).then(|| LocalSfenceVmaRequest {
        start: LOCAL_SFENCE_VMA_START.load(Ordering::Acquire),
        size: LOCAL_SFENCE_VMA_SIZE.load(Ordering::Acquire),
    })
}

pub fn test_local_fence_i_attempts() -> u64 {
    LOCAL_FENCE_I_ATTEMPTS.load(Ordering::Acquire)
}

pub fn set_test_mxr_enabled(enabled: bool) {
    MXR_ENABLED.store(enabled, Ordering::Release);
}

/// Inject or remove an SBI send failure for one host-model hart.
pub fn set_test_ipi_failure(hart: usize, fail: bool) {
    assert!(hart < usize::BITS as usize);
    let bit = 1usize << hart;
    if fail {
        IPI_FAILURE_MASK.fetch_or(bit, Ordering::AcqRel);
    } else {
        IPI_FAILURE_MASK.fetch_and(!bit, Ordering::AcqRel);
    }
}

pub fn test_software_interrupt_pending(hart: usize) -> bool {
    assert!(hart < usize::BITS as usize);
    SOFTWARE_PENDING.load(Ordering::Acquire) & (1usize << hart) != 0
}

pub fn test_ipi_attempts(hart: usize) -> u64 {
    IPI_ATTEMPTS
        .get(hart)
        .map_or(0, |attempts| attempts.load(Ordering::Acquire))
}

/// Set the firmware state returned by the host HSM status model.
pub fn set_test_hart_state(hart: usize, state: HartState) {
    assert!(hart < TEST_HARTS);
    HART_STATES[hart].store(state.as_sbi(), Ordering::Release);
}

/// Inject one stable SBI error for HSM start, or clear it with `None`.
pub fn set_test_hart_start_error(hart: usize, error: Option<IpiError>) {
    assert!(hart < TEST_HARTS);
    let raw = error.map_or(0, IpiError::as_sbi);
    assert!(
        error.is_none() || raw != 0,
        "an injected SBI error must be nonzero"
    );
    HART_START_ERRORS[hart].store(raw, Ordering::Release);
}

/// Inject one stable SBI error for HSM status, or clear it with `None`.
pub fn set_test_hart_status_error(hart: usize, error: Option<IpiError>) {
    assert!(hart < TEST_HARTS);
    let raw = error.map_or(0, IpiError::as_sbi);
    assert!(
        error.is_none() || raw != 0,
        "an injected SBI error must be nonzero"
    );
    HART_STATUS_ERRORS[hart].store(raw, Ordering::Release);
}

pub fn test_hart_start_attempts(hart: usize) -> u64 {
    HART_START_ATTEMPTS
        .get(hart)
        .map_or(0, |attempts| attempts.load(Ordering::Acquire))
}

pub fn test_hart_status_attempts(hart: usize) -> u64 {
    HART_STATUS_ATTEMPTS
        .get(hart)
        .map_or(0, |attempts| attempts.load(Ordering::Acquire))
}

pub fn test_hart_start_request(hart: usize) -> Option<HartStartRequest> {
    (test_hart_start_attempts(hart) != 0).then(|| HartStartRequest {
        start_addr: HART_START_ADDRS[hart].load(Ordering::Acquire),
        opaque: HART_START_OPAQUES[hart].load(Ordering::Acquire),
    })
}

pub fn reset_ipi_test_state() {
    CURRENT_HART.store(0, Ordering::Release);
    SOFTWARE_PENDING.store(0, Ordering::Release);
    IPI_FAILURE_MASK.store(0, Ordering::Release);
    RFENCE_SUPPORTED.store(true, Ordering::Release);
    PROBE_ATTEMPTS.store(0, Ordering::Release);
    LAST_PROBED_EXTENSION.store(NO_EXTENSION, Ordering::Release);
    REMOTE_FENCE_I_ATTEMPTS.store(0, Ordering::Release);
    REMOTE_FENCE_I_MASK.store(0, Ordering::Release);
    REMOTE_FENCE_I_BASE.store(0, Ordering::Release);
    REMOTE_FENCE_I_ERROR.store(0, Ordering::Release);
    REMOTE_SFENCE_VMA_ATTEMPTS.store(0, Ordering::Release);
    REMOTE_SFENCE_VMA_MASK.store(0, Ordering::Release);
    REMOTE_SFENCE_VMA_BASE.store(0, Ordering::Release);
    REMOTE_SFENCE_VMA_START.store(0, Ordering::Release);
    REMOTE_SFENCE_VMA_SIZE.store(0, Ordering::Release);
    REMOTE_SFENCE_VMA_ERROR.store(0, Ordering::Release);
    LOCAL_SFENCE_VMA_ATTEMPTS.store(0, Ordering::Release);
    LOCAL_SFENCE_VMA_START.store(0, Ordering::Release);
    LOCAL_SFENCE_VMA_SIZE.store(0, Ordering::Release);
    LOCAL_FENCE_I_ATTEMPTS.store(0, Ordering::Release);
    MXR_ENABLED.store(false, Ordering::Release);
    for attempts in &IPI_ATTEMPTS {
        attempts.store(0, Ordering::Release);
    }
    for hart in 0..TEST_HARTS {
        HART_STATES[hart].store(HartState::Stopped.as_sbi(), Ordering::Release);
        HART_START_ERRORS[hart].store(0, Ordering::Release);
        HART_STATUS_ERRORS[hart].store(0, Ordering::Release);
        HART_START_ATTEMPTS[hart].store(0, Ordering::Release);
        HART_STATUS_ATTEMPTS[hart].store(0, Ordering::Release);
        HART_START_ADDRS[hart].store(0, Ordering::Release);
        HART_START_OPAQUES[hart].store(0, Ordering::Release);
    }
    // The host process models the already-running boot hart after reset.
    HART_STATES[0].store(HartState::Started.as_sbi(), Ordering::Release);
}
