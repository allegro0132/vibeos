//! Capability-scoped Storage V2 quota accounting.
//!
//! A [`StoragePrincipal`] is an opaque boot-local accounting resource. It
//! grants no object read authority. The module exposes no
//! integer principal identifier, lookup-by-name operation, or principal
//! iterator.  Code can ask about one principal only while holding its token;
//! store-wide diagnostics are deliberately anonymous aggregates.
//!
//! Both quota dimensions are authority accounting, not an observation of CAS
//! deduplication:
//!
//! - every new Object is charged its exact logical length;
//! - every new Object is charged the same canonical physical envelope,
//!   including the frozen metadata attribution, whether its Blob is new or is
//!   already shared by another Object;
//! - actual unique bytes and dedup savings are aggregate telemetry only and do
//!   not affect admission or per-principal usage.
//!
//! CAS derives ordinary (non-cleaner-reserve) capacity and the frozen physical
//! envelope internally; neither number is accepted from the public caller.
//! The conservative charge is identical for a unique write and a dedup hit, so
//! admission neither consumes cleaner reserve nor becomes a cross-principal
//! content-presence oracle.
//!
//! Reservations are transactions.  Dropping an uncommitted reservation rolls
//! it back.  Committing returns a non-cloneable [`CommittedQuotaCharge`];
//! dropping that token does *not* release accounting. The CAS runtime-authority
//! lease owns it until its final Object handle or derived runtime pin is gone.
//! M7.6 does not encode principal attribution in media.

extern crate alloc;

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::fmt;
use core::hint::spin_loop;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use vibeos_blob_format::BlobGeometry;
use vibeos_segment_format::PAGE_SIZE;

use crate::authority_snapshot::{PersistentPrincipalPolicy, StablePrincipalId};
use crate::cas_codec::{
    BLOB_MANIFEST_HEADER_LEN, BLOB_MAPPING_LEN, CANONICAL_CONTENT_EXTENT_LEN, MANIFEST_EXTENT_LEN,
    OBJECT_MAPPING_LEN,
};

/// Maximum number of boot-local storage principals in one governed runtime.
pub const DEFAULT_MAX_STORAGE_PRINCIPALS: u32 = 256;

/// Maximum number of live boot-local object charges which may be waiting for
/// an exact stable-object binding. The runtime root table has the same hard
/// bound, so reserving this storage up front keeps the quota lock allocation
/// free without introducing a second, smaller admission ceiling.
const MAX_PENDING_PERSISTENT_CHARGES: usize = 256;

/// Frozen M7.6 physical-attribution formula version.
pub const QUOTA_PHYSICAL_FORMULA_VERSION: u16 = 1;

/// Physical attribution that remains unique for a deduplicated Object.
pub const QUOTA_DEDUP_UNIQUE_OBJECT_BYTES: u64 = OBJECT_MAPPING_LEN as u64;

/// Compute the canonical attributable physical bytes for one Object.
///
/// Every canonical Blob extent and its manifest are charged at their exact
/// page-padded payload size plus the two-page descriptor/seal pair.  The
/// Object and Blob mappings are then fully attributed to every Object, so a
/// dedup hit never reduces principal admission.
pub fn canonical_attributable_physical_bytes(exact_len: u64) -> Result<u64, QuotaError> {
    let geometry =
        BlobGeometry::for_len(exact_len).map_err(|_| QuotaError::InvalidConfiguration)?;
    let page = PAGE_SIZE as u64;
    let record_overhead = page.checked_mul(2).ok_or(QuotaError::CounterOverflow)?;
    let mut total = 0_u64;
    let mut add_record = |payload_bytes: u64| -> Result<(), QuotaError> {
        let padded = payload_bytes
            .div_ceil(page)
            .checked_mul(page)
            .ok_or(QuotaError::CounterOverflow)?;
        total = total
            .checked_add(padded)
            .and_then(|bytes| bytes.checked_add(record_overhead))
            .ok_or(QuotaError::CounterOverflow)?;
        Ok(())
    };

    add_record(vibeos_blob_format::HEADER_SIZE as u64)?;
    let mut remaining = exact_len;
    while remaining != 0 {
        let length = remaining.min(CANONICAL_CONTENT_EXTENT_LEN);
        add_record(length)?;
        remaining -= length;
    }
    add_record(geometry.tree_len() as u64)?;

    let content_count = exact_len.div_ceil(CANONICAL_CONTENT_EXTENT_LEN);
    let extent_count = content_count
        .checked_add(2)
        .ok_or(QuotaError::CounterOverflow)?;
    let manifest_bytes = u64::try_from(BLOB_MANIFEST_HEADER_LEN)
        .ok()
        .and_then(|header| {
            u64::try_from(MANIFEST_EXTENT_LEN)
                .ok()
                .and_then(|entry| extent_count.checked_mul(entry))
                .and_then(|table| header.checked_add(table))
        })
        .ok_or(QuotaError::CounterOverflow)?;
    add_record(manifest_bytes)?;
    total
        .checked_add(u64::try_from(OBJECT_MAPPING_LEN).map_err(|_| QuotaError::CounterOverflow)?)
        .and_then(|bytes| bytes.checked_add(BLOB_MAPPING_LEN as u64))
        .ok_or(QuotaError::CounterOverflow)
}

/// Per-principal limits.  Physical bytes are canonical attributable bytes,
/// never unique-on-media bytes after deduplication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrincipalQuotaLimits {
    pub logical_bytes: u64,
    pub physical_bytes: u64,
}

/// Usage visible only to a holder of the corresponding principal capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrincipalQuotaUsage {
    pub limits: PrincipalQuotaLimits,
    pub committed_logical_bytes: u64,
    pub committed_physical_bytes: u64,
    pub reserved_logical_bytes: u64,
    pub reserved_physical_bytes: u64,
    pub admission_revoked: bool,
}

/// Anonymous store-wide quota and dedup diagnostics.
///
/// Event counters saturate deliberately and report that fact.  Byte counters
/// never saturate: an operation that would overflow one is rejected before it
/// mutates accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotaDiagnostics {
    pub admitted_principals: u32,
    pub saturated_principals: u32,
    pub committed_logical_bytes: u64,
    pub committed_physical_bytes: u64,
    pub reserved_logical_bytes: u64,
    pub reserved_physical_bytes: u64,
    pub logical_high_water_bytes: u64,
    pub physical_high_water_bytes: u64,
    pub cumulative_unique_physical_bytes: u64,
    pub cumulative_dedup_savings_bytes: u64,
    pub committed_transactions: u64,
    pub rolled_back_transactions: u64,
    pub rejected_transactions: u64,
    pub event_counters_saturated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaError {
    InvalidConfiguration,
    PrincipalCapacity,
    AllocationFailed,
    UnknownPrincipal,
    PrincipalRevoked,
    LogicalQuotaExceeded,
    PhysicalQuotaExceeded,
    OrdinaryCapacityExceeded,
    CounterOverflow,
    InvalidPhysicalOutcome,
    OutstandingReservations,
    ChargeFromDifferentTable,
}

impl fmt::Display for QuotaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid quota configuration",
            Self::PrincipalCapacity => "principal quota table is full",
            Self::AllocationFailed => "quota table allocation failed",
            Self::UnknownPrincipal => "principal capability is unavailable",
            Self::PrincipalRevoked => "principal admission is revoked",
            Self::LogicalQuotaExceeded => "principal logical-byte quota exceeded",
            Self::PhysicalQuotaExceeded => "principal physical-byte quota exceeded",
            Self::OrdinaryCapacityExceeded => {
                "ordinary capacity cannot admit the canonical physical envelope"
            }
            Self::CounterOverflow => "quota accounting counter overflow",
            Self::InvalidPhysicalOutcome => {
                "unique physical outcome exceeds the admitted physical envelope"
            }
            Self::OutstandingReservations => {
                "principal admission has outstanding quota reservations"
            }
            Self::ChargeFromDifferentTable => "quota charge belongs to a different table",
        })
    }
}

impl core::error::Error for QuotaError {}

/// The uninspectable identity behind a principal capability.
struct PrincipalSeal {
    // Give every `Arc` a real allocation and a distinct address even on
    // allocators that special-case zero-sized values.
    _marker: u8,
    stable_id: Option<StablePrincipalId>,
}

/// Opaque accounting resource required for quota-charged storage admission.
///
/// Cloning derives equivalent authority for the same principal and cannot
/// amplify either limit.  There is intentionally no identifier accessor.
#[derive(Clone)]
pub struct StoragePrincipal {
    seal: Arc<PrincipalSeal>,
    ceilings: PrincipalQuotaLimits,
}

impl fmt::Debug for StoragePrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoragePrincipal(<opaque>)")
    }
}

impl StoragePrincipal {
    pub const fn ceilings(&self) -> PrincipalQuotaLimits {
        self.ceilings
    }

    pub(crate) fn stable_id(&self) -> Option<StablePrincipalId> {
        self.seal.stable_id
    }

    /// Derive an equivalent principal token with ceilings no larger than this
    /// token or the installed account limits.
    pub fn attenuate(&self, ceilings: PrincipalQuotaLimits) -> Result<Self, QuotaError> {
        if ceilings.logical_bytes == 0
            || ceilings.physical_bytes == 0
            || ceilings.logical_bytes > self.ceilings.logical_bytes
            || ceilings.physical_bytes > self.ceilings.physical_bytes
        {
            return Err(QuotaError::InvalidConfiguration);
        }
        Ok(Self {
            seal: Arc::clone(&self.seal),
            ceilings,
        })
    }
}

/// Unforgeable trusted-policy handle for admitting boot-local principals.
/// It is bound to exactly one runtime quota table and cannot create a parallel
/// accounting domain.
pub struct StorageQuotaProvisioner {
    table: PrincipalQuotaTable,
}

impl fmt::Debug for StorageQuotaProvisioner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StorageQuotaProvisioner(<opaque>)")
    }
}

impl StorageQuotaProvisioner {
    pub fn admit_principal(
        &self,
        limits: PrincipalQuotaLimits,
    ) -> Result<StoragePrincipal, QuotaError> {
        self.table.admit_principal(limits)
    }

    pub fn revoke_principal_admission(
        &self,
        principal: &StoragePrincipal,
    ) -> Result<(), QuotaError> {
        self.table.revoke_principal_admission(principal)
    }
}

struct PrincipalAccount {
    seal: Arc<PrincipalSeal>,
    limits: PrincipalQuotaLimits,
    persistent_logical_bytes: u64,
    persistent_physical_bytes: u64,
    committed_logical_bytes: u64,
    committed_physical_bytes: u64,
    reserved_logical_bytes: u64,
    reserved_physical_bytes: u64,
    admission_revoked: bool,
}

struct PersistentRestorePlan {
    account_index: Option<usize>,
    seal: Arc<PrincipalSeal>,
    limits: PrincipalQuotaLimits,
    persistent_logical_bytes: u64,
    persistent_physical_bytes: u64,
    projected_logical_bytes: u64,
    projected_physical_bytes: u64,
    admission_revoked: bool,
}

struct CandidateReconcilePlan {
    charge: Arc<CommittedChargeState>,
    account_index: usize,
    transfer_to_persistent: bool,
}

#[derive(Default)]
struct AggregateAccounting {
    committed_logical_bytes: u64,
    committed_physical_bytes: u64,
    reserved_logical_bytes: u64,
    reserved_physical_bytes: u64,
    reserved_outcome_ceiling_bytes: u64,
    logical_high_water_bytes: u64,
    physical_high_water_bytes: u64,
    cumulative_unique_physical_bytes: u64,
    cumulative_dedup_savings_bytes: u64,
    committed_transactions: u64,
    rolled_back_transactions: u64,
    rejected_transactions: u64,
    event_counters_saturated: bool,
}

struct QuotaStateData {
    maximum_principals: u32,
    accounts: Vec<PrincipalAccount>,
    persistent_candidates: Vec<PersistentChargeCandidate>,
    aggregate: AggregateAccounting,
}

struct PersistentChargeCandidate {
    stable_object_id: u128,
    v2_object_id: u128,
    charge: Weak<CommittedChargeState>,
}

/// A tiny no_std lock.  Quota critical sections contain no allocation, media
/// I/O, callback, or await point.  A single lock makes account and aggregate
/// counters one atomic transaction and avoids partially reserved dimensions.
struct QuotaState {
    locked: AtomicBool,
    data: UnsafeCell<QuotaStateData>,
}

// SAFETY: all access to `data` is serialized by `locked`; a guard releases the
// lock with `Release` and acquisition uses `Acquire`.
unsafe impl Send for QuotaState {}
// SAFETY: see the `Send` implementation above.
unsafe impl Sync for QuotaState {}

impl QuotaState {
    fn lock(&self) -> QuotaStateGuard<'_> {
        loop {
            if self
                .locked
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return QuotaStateGuard { state: self };
            }
            while self.locked.load(Ordering::Relaxed) {
                spin_loop();
            }
        }
    }
}

struct QuotaStateGuard<'a> {
    state: &'a QuotaState,
}

impl Deref for QuotaStateGuard<'_> {
    type Target = QuotaStateData;

    fn deref(&self) -> &Self::Target {
        // SAFETY: construction requires ownership of the state lock.
        unsafe { &*self.state.data.get() }
    }
}

impl DerefMut for QuotaStateGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: construction requires exclusive ownership of the state lock.
        unsafe { &mut *self.state.data.get() }
    }
}

impl Drop for QuotaStateGuard<'_> {
    fn drop(&mut self) {
        self.state.locked.store(false, Ordering::Release);
    }
}

/// Bounded quota authority and accounting state.
#[derive(Clone)]
pub(crate) struct PrincipalQuotaTable {
    state: Arc<QuotaState>,
}

impl fmt::Debug for PrincipalQuotaTable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrincipalQuotaTable(<opaque accounts>)")
    }
}

impl PrincipalQuotaTable {
    /// Construct the one table owned by a mounted Store instance.
    ///
    /// Crate-private visibility prevents an application from manufacturing an
    /// ungoverned parallel quota domain.
    pub(crate) fn new(maximum_principals: u32) -> Result<Self, QuotaError> {
        if maximum_principals == 0 {
            return Err(QuotaError::InvalidConfiguration);
        }
        let capacity =
            usize::try_from(maximum_principals).map_err(|_| QuotaError::InvalidConfiguration)?;
        let mut accounts = Vec::new();
        accounts
            .try_reserve_exact(capacity)
            .map_err(|_| QuotaError::AllocationFailed)?;
        let mut persistent_candidates = Vec::new();
        persistent_candidates
            .try_reserve_exact(MAX_PENDING_PERSISTENT_CHARGES)
            .map_err(|_| QuotaError::AllocationFailed)?;
        Ok(Self {
            state: Arc::new(QuotaState {
                locked: AtomicBool::new(false),
                data: UnsafeCell::new(QuotaStateData {
                    maximum_principals,
                    accounts,
                    persistent_candidates,
                    aggregate: AggregateAccounting::default(),
                }),
            }),
        })
    }

    pub(crate) fn provisioner(&self) -> StorageQuotaProvisioner {
        StorageQuotaProvisioner {
            table: self.clone(),
        }
    }

    /// Admit a new opaque principal.  Only the returned capability can name the
    /// account again; no table-wide principal enumeration exists.
    pub(crate) fn admit_principal(
        &self,
        limits: PrincipalQuotaLimits,
    ) -> Result<StoragePrincipal, QuotaError> {
        if limits.logical_bytes == 0 || limits.physical_bytes == 0 {
            return Err(QuotaError::InvalidConfiguration);
        }
        // Allocate outside the no-allocation critical section.  A concurrent
        // admission may fill the final slot before we acquire the lock; in
        // that case this harmless candidate seal is simply dropped.
        let seal = Arc::new(PrincipalSeal {
            _marker: 0xa7,
            stable_id: None,
        });
        let mut state = self.state.lock();
        if state.accounts.len() >= state.maximum_principals as usize {
            record_rejection(&mut state.aggregate);
            return Err(QuotaError::PrincipalCapacity);
        }
        // Capacity was reserved at table construction, so admission performs no
        // fallible Vec growth while holding the lock.
        state.accounts.push(PrincipalAccount {
            seal: Arc::clone(&seal),
            limits,
            persistent_logical_bytes: 0,
            persistent_physical_bytes: 0,
            committed_logical_bytes: 0,
            committed_physical_bytes: 0,
            reserved_logical_bytes: 0,
            reserved_physical_bytes: 0,
            admission_revoked: false,
        });
        Ok(StoragePrincipal {
            seal,
            ceilings: limits,
        })
    }

    /// Atomically replace the persistent portion of every stable account.
    ///
    /// Existing seals and boot-local committed charges survive replacement;
    /// only the usage attributed to the prior authority snapshot is removed.
    /// After the first install, every existing stable principal must appear
    /// exactly once with unchanged limits and admission state.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn restore_persistent(
        &self,
        policies: &[PersistentPrincipalPolicy],
    ) -> Result<Vec<StoragePrincipal>, QuotaError> {
        self.restore_persistent_inner(policies, None, true)
    }

    pub(crate) fn restore_persistent_with_bindings(
        &self,
        policies: &[PersistentPrincipalPolicy],
        bindings: &[(u128, u128)],
    ) -> Result<Vec<StoragePrincipal>, QuotaError> {
        self.restore_persistent_inner(policies, Some(bindings), true)
    }

    /// Validate a complete persistent-accounting replacement without changing
    /// charge state, principal accounts, aggregate counters, or diagnostics.
    ///
    /// Persistent-authority transactions use this before their first read or
    /// media mutation. They repeat the same validation immediately before the
    /// authority checkpoint write, when all final stable/V2 bindings are known.
    pub(crate) fn preflight_persistent_with_bindings(
        &self,
        policies: &[PersistentPrincipalPolicy],
        bindings: &[(u128, u128)],
    ) -> Result<(), QuotaError> {
        self.restore_persistent_inner(policies, Some(bindings), false)
            .map(drop)
    }

    fn restore_persistent_inner(
        &self,
        policies: &[PersistentPrincipalPolicy],
        bindings: Option<&[(u128, u128)]>,
        apply: bool,
    ) -> Result<Vec<StoragePrincipal>, QuotaError> {
        let mut plans = Vec::new();
        plans
            .try_reserve_exact(policies.len())
            .map_err(|_| QuotaError::AllocationFailed)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(policies.len())
            .map_err(|_| QuotaError::AllocationFailed)?;
        let mut reconciliations = Vec::new();
        reconciliations
            .try_reserve_exact(MAX_PENDING_PERSISTENT_CHARGES)
            .map_err(|_| QuotaError::AllocationFailed)?;
        let mut state = self.state.lock();
        if state.accounts.iter().any(|account| {
            account.seal.stable_id.is_none()
                && (account.committed_logical_bytes != 0
                    || account.committed_physical_bytes != 0
                    || account.reserved_logical_bytes != 0
                    || account.reserved_physical_bytes != 0)
        }) {
            return Err(QuotaError::InvalidConfiguration);
        }
        let mut previous_principal = None;
        for policy in policies {
            if policy.logical_limit_bytes == 0
                || policy.physical_limit_bytes == 0
                || policy.committed_logical_bytes > policy.logical_limit_bytes
                || policy.committed_physical_bytes > policy.physical_limit_bytes
                || previous_principal.is_some_and(|principal| principal >= policy.principal)
            {
                return Err(QuotaError::InvalidConfiguration);
            }
            previous_principal = Some(policy.principal);
        }
        if state.accounts.iter().any(|account| {
            account.seal.stable_id.is_some_and(|principal| {
                !policies.iter().any(|policy| policy.principal == principal)
            })
        }) {
            return Err(QuotaError::InvalidConfiguration);
        }
        let new_count = policies
            .iter()
            .filter(|policy| {
                !state
                    .accounts
                    .iter()
                    .any(|account| account.seal.stable_id == Some(policy.principal))
            })
            .count();
        if state.accounts.len().saturating_add(new_count) > state.maximum_principals as usize {
            return Err(QuotaError::PrincipalCapacity);
        }
        if let Some(bindings) = bindings {
            for candidate in &state.persistent_candidates {
                let Some(charge) = candidate.charge.upgrade() else {
                    continue;
                };
                let persistent =
                    bindings.contains(&(candidate.stable_object_id, candidate.v2_object_id));
                let status = charge.status.load(Ordering::Acquire);
                let transfer_to_persistent = persistent && status == CHARGE_ACTIVE;
                let reactivate_runtime = !persistent && status == CHARGE_TRANSFERRED;
                if !transfer_to_persistent && !reactivate_runtime {
                    continue;
                }
                let account_index = find_account(&state.accounts, &charge.seal)
                    .ok_or(QuotaError::UnknownPrincipal)?;
                reconciliations.push(CandidateReconcilePlan {
                    charge,
                    account_index,
                    transfer_to_persistent,
                });
            }
        }
        let (old_persistent_logical_total, old_persistent_physical_total) = state
            .accounts
            .iter()
            .filter(|account| account.seal.stable_id.is_some())
            .try_fold((0_u64, 0_u64), |(logical, physical), account| {
                Some((
                    logical.checked_add(account.persistent_logical_bytes)?,
                    physical.checked_add(account.persistent_physical_bytes)?,
                ))
            })
            .ok_or(QuotaError::CounterOverflow)?;
        let mut new_persistent_logical_total = 0_u64;
        let mut new_persistent_physical_total = 0_u64;
        for policy in policies {
            let limits = PrincipalQuotaLimits {
                logical_bytes: policy.logical_limit_bytes,
                physical_bytes: policy.physical_limit_bytes,
            };
            let account_index = state
                .accounts
                .iter()
                .position(|account| account.seal.stable_id == Some(policy.principal));
            let (seal, projected_logical_bytes, projected_physical_bytes) =
                if let Some(index) = account_index {
                    let account = &state.accounts[index];
                    if account.limits != limits
                        || account.reserved_logical_bytes != 0
                        || account.reserved_physical_bytes != 0
                        || account.admission_revoked != policy.admission_revoked
                    {
                        return Err(QuotaError::InvalidConfiguration);
                    }
                    let (reconciled_logical, reconciled_physical) = reconciliations
                        .iter()
                        .filter(|plan| plan.account_index == index)
                        .try_fold(
                            (
                                account.committed_logical_bytes,
                                account.committed_physical_bytes,
                            ),
                            |(logical, physical), plan| {
                                if plan.transfer_to_persistent {
                                    Some((
                                        logical.checked_sub(plan.charge.logical_bytes)?,
                                        physical.checked_sub(plan.charge.physical_bytes)?,
                                    ))
                                } else {
                                    Some((
                                        logical.checked_add(plan.charge.logical_bytes)?,
                                        physical.checked_add(plan.charge.physical_bytes)?,
                                    ))
                                }
                            },
                        )
                        .ok_or(QuotaError::InvalidConfiguration)?;
                    let runtime_logical = reconciled_logical
                        .checked_sub(account.persistent_logical_bytes)
                        .ok_or(QuotaError::InvalidConfiguration)?;
                    let runtime_physical = reconciled_physical
                        .checked_sub(account.persistent_physical_bytes)
                        .ok_or(QuotaError::InvalidConfiguration)?;
                    let projected_logical = runtime_logical
                        .checked_add(policy.committed_logical_bytes)
                        .ok_or(QuotaError::CounterOverflow)?;
                    let projected_physical = runtime_physical
                        .checked_add(policy.committed_physical_bytes)
                        .ok_or(QuotaError::CounterOverflow)?;
                    if projected_logical > limits.logical_bytes
                        || projected_physical > limits.physical_bytes
                    {
                        return Err(QuotaError::InvalidConfiguration);
                    }
                    (
                        Arc::clone(&account.seal),
                        projected_logical,
                        projected_physical,
                    )
                } else {
                    (
                        Arc::new(PrincipalSeal {
                            _marker: 0xa7,
                            stable_id: Some(policy.principal),
                        }),
                        policy.committed_logical_bytes,
                        policy.committed_physical_bytes,
                    )
                };
            new_persistent_logical_total = new_persistent_logical_total
                .checked_add(policy.committed_logical_bytes)
                .ok_or(QuotaError::CounterOverflow)?;
            new_persistent_physical_total = new_persistent_physical_total
                .checked_add(policy.committed_physical_bytes)
                .ok_or(QuotaError::CounterOverflow)?;
            plans.push(PersistentRestorePlan {
                account_index,
                seal,
                limits,
                persistent_logical_bytes: policy.committed_logical_bytes,
                persistent_physical_bytes: policy.committed_physical_bytes,
                projected_logical_bytes,
                projected_physical_bytes,
                admission_revoked: policy.admission_revoked,
            });
        }
        let (reconciled_aggregate_logical, reconciled_aggregate_physical) = reconciliations
            .iter()
            .try_fold(
                (
                    state.aggregate.committed_logical_bytes,
                    state.aggregate.committed_physical_bytes,
                ),
                |(logical, physical), plan| {
                    if plan.transfer_to_persistent {
                        Some((
                            logical.checked_sub(plan.charge.logical_bytes)?,
                            physical.checked_sub(plan.charge.physical_bytes)?,
                        ))
                    } else {
                        Some((
                            logical.checked_add(plan.charge.logical_bytes)?,
                            physical.checked_add(plan.charge.physical_bytes)?,
                        ))
                    }
                },
            )
            .ok_or(QuotaError::InvalidConfiguration)?;
        let aggregate_logical = reconciled_aggregate_logical
            .checked_sub(old_persistent_logical_total)
            .ok_or(QuotaError::InvalidConfiguration)?
            .checked_add(new_persistent_logical_total)
            .ok_or(QuotaError::CounterOverflow)?;
        let aggregate_physical = reconciled_aggregate_physical
            .checked_sub(old_persistent_physical_total)
            .ok_or(QuotaError::InvalidConfiguration)?
            .checked_add(new_persistent_physical_total)
            .ok_or(QuotaError::CounterOverflow)?;

        // Everything fallible has completed. A preflight deliberately returns
        // before touching even anonymous high-water/event telemetry.
        if !apply {
            return Ok(Vec::new());
        }

        // Apply the validated plan while
        // holding the same lock, so a failed restore never leaves a partial
        // principal table or aggregate counter update behind.
        for reconciliation in &reconciliations {
            reconciliation.charge.status.store(
                if reconciliation.transfer_to_persistent {
                    CHARGE_TRANSFERRED
                } else {
                    CHARGE_ACTIVE
                },
                Ordering::Release,
            );
        }
        if bindings.is_some() {
            state.persistent_candidates.retain(|candidate| {
                candidate
                    .charge
                    .upgrade()
                    .is_some_and(|charge| charge.status.load(Ordering::Acquire) != CHARGE_RELEASED)
            });
        }
        for plan in plans {
            if let Some(index) = plan.account_index {
                let account = &mut state.accounts[index];
                account.persistent_logical_bytes = plan.persistent_logical_bytes;
                account.persistent_physical_bytes = plan.persistent_physical_bytes;
                account.committed_logical_bytes = plan.projected_logical_bytes;
                account.committed_physical_bytes = plan.projected_physical_bytes;
            } else {
                state.accounts.push(PrincipalAccount {
                    seal: Arc::clone(&plan.seal),
                    limits: plan.limits,
                    persistent_logical_bytes: plan.persistent_logical_bytes,
                    persistent_physical_bytes: plan.persistent_physical_bytes,
                    committed_logical_bytes: plan.projected_logical_bytes,
                    committed_physical_bytes: plan.projected_physical_bytes,
                    reserved_logical_bytes: 0,
                    reserved_physical_bytes: 0,
                    admission_revoked: plan.admission_revoked,
                });
            }
            output.push(StoragePrincipal {
                seal: plan.seal,
                ceilings: plan.limits,
            });
        }
        state.aggregate.committed_logical_bytes = aggregate_logical;
        state.aggregate.committed_physical_bytes = aggregate_physical;
        state.aggregate.logical_high_water_bytes = state
            .aggregate
            .logical_high_water_bytes
            .max(aggregate_logical);
        state.aggregate.physical_high_water_bytes = state
            .aggregate
            .physical_high_water_bytes
            .max(aggregate_physical);
        Ok(output)
    }

    /// Atomically reserve both quota dimensions and ordinary capacity.
    ///
    /// `physical_bytes` is the canonical attributable physical envelope for
    /// this Object, even for a known dedup hit.  `ordinary_available_bytes`
    /// must exclude all cleaner-reserve capacity.  Pending transactions are
    /// conservatively deducted from that snapshot.
    pub(crate) fn reserve(
        &self,
        principal: &StoragePrincipal,
        logical_bytes: u64,
        physical_bytes: u64,
        ordinary_available_bytes: u64,
    ) -> Result<QuotaReservation, QuotaError> {
        let mut state = self.state.lock();
        let account_index = match find_account(&state.accounts, &principal.seal) {
            Some(index) => index,
            None => {
                record_rejection(&mut state.aggregate);
                return Err(QuotaError::UnknownPrincipal);
            }
        };

        if state.accounts[account_index].admission_revoked {
            record_rejection(&mut state.aggregate);
            return Err(QuotaError::PrincipalRevoked);
        }

        let account_logical = checked_projected(
            state.accounts[account_index].committed_logical_bytes,
            state.accounts[account_index].reserved_logical_bytes,
            logical_bytes,
        )?;
        let logical_ceiling = state.accounts[account_index]
            .limits
            .logical_bytes
            .min(principal.ceilings.logical_bytes);
        if account_logical > logical_ceiling {
            record_rejection(&mut state.aggregate);
            return Err(QuotaError::LogicalQuotaExceeded);
        }
        let account_physical = checked_projected(
            state.accounts[account_index].committed_physical_bytes,
            state.accounts[account_index].reserved_physical_bytes,
            physical_bytes,
        )?;
        let physical_ceiling = state.accounts[account_index]
            .limits
            .physical_bytes
            .min(principal.ceilings.physical_bytes);
        if account_physical > physical_ceiling {
            record_rejection(&mut state.aggregate);
            return Err(QuotaError::PhysicalQuotaExceeded);
        }

        let pending_capacity = state
            .aggregate
            .reserved_physical_bytes
            .checked_add(physical_bytes)
            .ok_or(QuotaError::CounterOverflow)?;
        if pending_capacity > ordinary_available_bytes {
            record_rejection(&mut state.aggregate);
            return Err(QuotaError::OrdinaryCapacityExceeded);
        }

        let aggregate_logical = checked_projected(
            state.aggregate.committed_logical_bytes,
            state.aggregate.reserved_logical_bytes,
            logical_bytes,
        )?;
        let aggregate_physical = checked_projected(
            state.aggregate.committed_physical_bytes,
            state.aggregate.reserved_physical_bytes,
            physical_bytes,
        )?;
        let reserved_outcome_ceiling = state
            .aggregate
            .reserved_outcome_ceiling_bytes
            .checked_add(physical_bytes)
            .ok_or(QuotaError::CounterOverflow)?;

        // Preflight the maximum possible commit outcome.  Commit therefore
        // cannot fail after the CAS checkpoint has become durable.
        state
            .aggregate
            .cumulative_unique_physical_bytes
            .checked_add(reserved_outcome_ceiling)
            .ok_or(QuotaError::CounterOverflow)?;
        state
            .aggregate
            .cumulative_dedup_savings_bytes
            .checked_add(reserved_outcome_ceiling)
            .ok_or(QuotaError::CounterOverflow)?;

        {
            let account = &mut state.accounts[account_index];
            account.reserved_logical_bytes = account
                .reserved_logical_bytes
                .checked_add(logical_bytes)
                .ok_or(QuotaError::CounterOverflow)?;
            account.reserved_physical_bytes = account
                .reserved_physical_bytes
                .checked_add(physical_bytes)
                .ok_or(QuotaError::CounterOverflow)?;
        }
        state.aggregate.reserved_logical_bytes = state
            .aggregate
            .reserved_logical_bytes
            .checked_add(logical_bytes)
            .ok_or(QuotaError::CounterOverflow)?;
        state.aggregate.reserved_physical_bytes = pending_capacity;
        state.aggregate.reserved_outcome_ceiling_bytes = reserved_outcome_ceiling;
        state.aggregate.logical_high_water_bytes = state
            .aggregate
            .logical_high_water_bytes
            .max(aggregate_logical);
        state.aggregate.physical_high_water_bytes = state
            .aggregate
            .physical_high_water_bytes
            .max(aggregate_physical);

        Ok(QuotaReservation {
            state: Arc::clone(&self.state),
            seal: Arc::clone(&principal.seal),
            logical_bytes,
            physical_bytes,
            active: true,
        })
    }

    /// Query exactly one principal while holding its authority token.
    pub(crate) fn principal_usage(
        &self,
        principal: &StoragePrincipal,
    ) -> Result<PrincipalQuotaUsage, QuotaError> {
        let state = self.state.lock();
        let index =
            find_account(&state.accounts, &principal.seal).ok_or(QuotaError::UnknownPrincipal)?;
        let account = &state.accounts[index];
        Ok(PrincipalQuotaUsage {
            limits: PrincipalQuotaLimits {
                logical_bytes: account
                    .limits
                    .logical_bytes
                    .min(principal.ceilings.logical_bytes),
                physical_bytes: account
                    .limits
                    .physical_bytes
                    .min(principal.ceilings.physical_bytes),
            },
            committed_logical_bytes: account.committed_logical_bytes,
            committed_physical_bytes: account.committed_physical_bytes,
            reserved_logical_bytes: account.reserved_logical_bytes,
            reserved_physical_bytes: account.reserved_physical_bytes,
            admission_revoked: account.admission_revoked,
        })
    }

    /// Return anonymous aggregates only.  No Object, Blob, or principal key is
    /// included, and the API cannot enumerate principal capabilities.
    pub(crate) fn diagnostics(&self) -> QuotaDiagnostics {
        let state = self.state.lock();
        let saturated_principals = state.accounts.iter().fold(0u32, |count, account| {
            let logical = account
                .committed_logical_bytes
                .checked_add(account.reserved_logical_bytes)
                .expect("quota admission preserves account logical bounds");
            let physical = account
                .committed_physical_bytes
                .checked_add(account.reserved_physical_bytes)
                .expect("quota admission preserves account physical bounds");
            if logical == account.limits.logical_bytes || physical == account.limits.physical_bytes
            {
                count.saturating_add(1)
            } else {
                count
            }
        });
        QuotaDiagnostics {
            admitted_principals: state.accounts.len() as u32,
            saturated_principals,
            committed_logical_bytes: state.aggregate.committed_logical_bytes,
            committed_physical_bytes: state.aggregate.committed_physical_bytes,
            reserved_logical_bytes: state.aggregate.reserved_logical_bytes,
            reserved_physical_bytes: state.aggregate.reserved_physical_bytes,
            logical_high_water_bytes: state.aggregate.logical_high_water_bytes,
            physical_high_water_bytes: state.aggregate.physical_high_water_bytes,
            cumulative_unique_physical_bytes: state.aggregate.cumulative_unique_physical_bytes,
            cumulative_dedup_savings_bytes: state.aggregate.cumulative_dedup_savings_bytes,
            committed_transactions: state.aggregate.committed_transactions,
            rolled_back_transactions: state.aggregate.rolled_back_transactions,
            rejected_transactions: state.aggregate.rejected_transactions,
            event_counters_saturated: state.aggregate.event_counters_saturated,
        }
    }

    /// Stop future admission for a principal without touching committed usage
    /// or the readability of existing Objects.
    fn revoke_principal_admission(&self, principal: &StoragePrincipal) -> Result<(), QuotaError> {
        let mut state = self.state.lock();
        let index =
            find_account(&state.accounts, &principal.seal).ok_or(QuotaError::UnknownPrincipal)?;
        state.accounts[index].admission_revoked = true;
        if state.accounts[index].reserved_logical_bytes != 0
            || state.accounts[index].reserved_physical_bytes != 0
        {
            return Err(QuotaError::OutstandingReservations);
        }
        Ok(())
    }

    /// Release a committed per-Object charge only after the authority layer has
    /// durably revoked that Object.  This is crate-private so an application
    /// cannot release its own charge while retaining read authority.
    pub(crate) fn account_authority_revoked(
        &self,
        mut charge: CommittedQuotaCharge,
    ) -> Result<(), QuotaError> {
        if !Arc::ptr_eq(&self.state, &charge.state) {
            return Err(QuotaError::ChargeFromDifferentTable);
        }
        let mut state = self.state.lock();
        match charge.charge.status.compare_exchange(
            CHARGE_ACTIVE,
            CHARGE_RELEASED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(CHARGE_TRANSFERRED) => {
                charge
                    .charge
                    .status
                    .store(CHARGE_RELEASED, Ordering::Release);
                charge.released = true;
                return Ok(());
            }
            Err(CHARGE_RELEASED) => panic!("a committed charge is released at most once"),
            Err(_) => unreachable!("committed charge state is valid"),
        }
        let index = find_account(&state.accounts, &charge.charge.seal)
            .ok_or(QuotaError::UnknownPrincipal)?;
        {
            let account = &mut state.accounts[index];
            account.committed_logical_bytes = account
                .committed_logical_bytes
                .checked_sub(charge.charge.logical_bytes)
                .expect("a committed charge is released at most once");
            account.committed_physical_bytes = account
                .committed_physical_bytes
                .checked_sub(charge.charge.physical_bytes)
                .expect("a committed charge is released at most once");
        }
        state.aggregate.committed_logical_bytes = state
            .aggregate
            .committed_logical_bytes
            .checked_sub(charge.charge.logical_bytes)
            .expect("aggregate includes every committed charge");
        state.aggregate.committed_physical_bytes = state
            .aggregate
            .committed_physical_bytes
            .checked_sub(charge.charge.physical_bytes)
            .expect("aggregate includes every committed charge");
        charge.released = true;
        Ok(())
    }

    /// Associate one live runtime charge with the exact stable logical object
    /// which created it. The table retains only a weak reference: dropping the
    /// final source capability still releases the charge immediately.
    pub(crate) fn bind_persistent_candidate(
        &self,
        stable_object_id: u128,
        v2_object_id: u128,
        charge: &CommittedQuotaCharge,
    ) -> Result<(), QuotaError> {
        if stable_object_id == 0 || v2_object_id == 0 || !Arc::ptr_eq(&self.state, &charge.state) {
            return Err(QuotaError::ChargeFromDifferentTable);
        }
        if charge.charge.seal.stable_id.is_none()
            || charge.charge.status.load(Ordering::Acquire) != CHARGE_ACTIVE
        {
            return Err(QuotaError::InvalidConfiguration);
        }
        let mut state = self.state.lock();
        state.persistent_candidates.retain(|candidate| {
            candidate
                .charge
                .upgrade()
                .is_some_and(|charge| charge.status.load(Ordering::Acquire) != CHARGE_RELEASED)
        });
        if let Some(existing) = state
            .persistent_candidates
            .iter()
            .find(|candidate| candidate.stable_object_id == stable_object_id)
        {
            return if existing.v2_object_id == v2_object_id
                && existing
                    .charge
                    .upgrade()
                    .is_some_and(|existing| Arc::ptr_eq(&existing, &charge.charge))
            {
                Ok(())
            } else {
                Err(QuotaError::InvalidConfiguration)
            };
        }
        if state.persistent_candidates.len() == state.persistent_candidates.capacity() {
            return Err(QuotaError::PrincipalCapacity);
        }
        state.persistent_candidates.push(PersistentChargeCandidate {
            stable_object_id,
            v2_object_id,
            charge: Arc::downgrade(&charge.charge),
        });
        Ok(())
    }

    pub(crate) fn has_active_persistent_candidate(
        &self,
        stable_object_id: u128,
        v2_object_id: u128,
    ) -> bool {
        let state = self.state.lock();
        state.persistent_candidates.iter().any(|candidate| {
            candidate.stable_object_id == stable_object_id
                && candidate.v2_object_id == v2_object_id
                && candidate
                    .charge
                    .upgrade()
                    .is_some_and(|charge| charge.status.load(Ordering::Acquire) == CHARGE_ACTIVE)
        })
    }

    /// Convert an admission reservation into a rollback-owned committed
    /// charge for a multi-object checkpoint transaction. Until `finish()` is
    /// called, dropping the guard performs the same accounting release as an
    /// explicit authority revocation. This is deliberately separate from an
    /// ordinary committed charge, whose `Drop` must never mint quota.
    pub(crate) fn stage_reserved_charge(
        &self,
        reservation: QuotaReservation,
        unique_physical_bytes: u64,
    ) -> Result<StagedQuotaCharge, QuotaError> {
        if !Arc::ptr_eq(&self.state, &reservation.state) {
            return Err(QuotaError::ChargeFromDifferentTable);
        }
        let charge = reservation.commit_with_unique_physical(unique_physical_bytes)?;
        Ok(StagedQuotaCharge {
            table: self.clone(),
            charge: Some(charge),
        })
    }
}

/// Rollback guard spanning quota-candidate installation and final checkpoint
/// publication. It owns the only strong charge reference until publication
/// succeeds, so cancellation cannot leave an ACTIVE anonymous charge behind.
#[must_use = "dropping a staged charge rolls back its transient accounting"]
pub(crate) struct StagedQuotaCharge {
    table: PrincipalQuotaTable,
    charge: Option<CommittedQuotaCharge>,
}

impl StagedQuotaCharge {
    pub(crate) fn bind_persistent_candidate(
        &self,
        stable_object_id: u128,
        v2_object_id: u128,
    ) -> Result<(), QuotaError> {
        self.table.bind_persistent_candidate(
            stable_object_id,
            v2_object_id,
            self.charge
                .as_ref()
                .ok_or(QuotaError::InvalidConfiguration)?,
        )
    }

    pub(crate) fn finish(mut self) -> CommittedQuotaCharge {
        self.charge
            .take()
            .expect("a staged quota charge finishes at most once")
    }
}

impl Drop for StagedQuotaCharge {
    fn drop(&mut self) {
        if let Some(charge) = self.charge.take() {
            let _ = self.table.account_authority_revoked(charge);
        }
    }
}

/// A pending quota transaction.  It is detached from a borrow of the table so
/// CAS may carry it across bounded async media I/O.
#[must_use = "dropping a quota reservation rolls it back"]
pub(crate) struct QuotaReservation {
    state: Arc<QuotaState>,
    seal: Arc<PrincipalSeal>,
    logical_bytes: u64,
    physical_bytes: u64,
    active: bool,
}

impl fmt::Debug for QuotaReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuotaReservation")
            .field("logical_bytes", &self.logical_bytes)
            .field("physical_bytes", &self.physical_bytes)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl QuotaReservation {
    /// Commit a non-deduplicated admission.  Principal quota accounting is the
    /// same as [`Self::commit_with_unique_physical`]; this convenience merely
    /// records the full envelope as newly unique aggregate media.
    pub(crate) fn commit(self) -> CommittedQuotaCharge {
        let unique_physical_bytes = self.physical_bytes;
        self.commit_inner(unique_physical_bytes)
            .expect("the reserved full-envelope outcome was preflighted")
    }

    /// Commit with the actual newly unique byte count for anonymous telemetry.
    ///
    /// CAS uses the newly appended `ObjectMapping` length for a dedup hit. This
    /// value never changes the committed principal charge or any admission
    /// decision.
    pub(crate) fn commit_with_unique_physical(
        self,
        unique_physical_bytes: u64,
    ) -> Result<CommittedQuotaCharge, QuotaError> {
        self.commit_inner(unique_physical_bytes)
    }

    fn commit_inner(
        mut self,
        unique_physical_bytes: u64,
    ) -> Result<CommittedQuotaCharge, QuotaError> {
        if unique_physical_bytes > self.physical_bytes {
            return Err(QuotaError::InvalidPhysicalOutcome);
        }
        let dedup_savings = self.physical_bytes - unique_physical_bytes;
        {
            let mut state = self.state.lock();
            let index = find_account(&state.accounts, &self.seal)
                .expect("principal accounts are never removed");
            {
                let account = &mut state.accounts[index];
                account.reserved_logical_bytes = account
                    .reserved_logical_bytes
                    .checked_sub(self.logical_bytes)
                    .expect("reservation owns its account logical bytes");
                account.reserved_physical_bytes = account
                    .reserved_physical_bytes
                    .checked_sub(self.physical_bytes)
                    .expect("reservation owns its account physical bytes");
                account.committed_logical_bytes = account
                    .committed_logical_bytes
                    .checked_add(self.logical_bytes)
                    .expect("reserve preflighted committed logical bytes");
                account.committed_physical_bytes = account
                    .committed_physical_bytes
                    .checked_add(self.physical_bytes)
                    .expect("reserve preflighted committed physical bytes");
            }
            state.aggregate.reserved_logical_bytes = state
                .aggregate
                .reserved_logical_bytes
                .checked_sub(self.logical_bytes)
                .expect("aggregate contains reservation logical bytes");
            state.aggregate.reserved_physical_bytes = state
                .aggregate
                .reserved_physical_bytes
                .checked_sub(self.physical_bytes)
                .expect("aggregate contains reservation physical bytes");
            state.aggregate.reserved_outcome_ceiling_bytes = state
                .aggregate
                .reserved_outcome_ceiling_bytes
                .checked_sub(self.physical_bytes)
                .expect("aggregate contains reservation outcome ceiling");
            state.aggregate.committed_logical_bytes = state
                .aggregate
                .committed_logical_bytes
                .checked_add(self.logical_bytes)
                .expect("reserve preflighted aggregate logical bytes");
            state.aggregate.committed_physical_bytes = state
                .aggregate
                .committed_physical_bytes
                .checked_add(self.physical_bytes)
                .expect("reserve preflighted aggregate physical bytes");
            state.aggregate.cumulative_unique_physical_bytes = state
                .aggregate
                .cumulative_unique_physical_bytes
                .checked_add(unique_physical_bytes)
                .expect("reserve preflighted cumulative unique bytes");
            state.aggregate.cumulative_dedup_savings_bytes = state
                .aggregate
                .cumulative_dedup_savings_bytes
                .checked_add(dedup_savings)
                .expect("reserve preflighted cumulative dedup savings");
            let aggregate = &mut state.aggregate;
            increment_event_counter(
                &mut aggregate.committed_transactions,
                &mut aggregate.event_counters_saturated,
            );
        }
        self.active = false;
        let charge = Arc::new(CommittedChargeState {
            status: AtomicU8::new(CHARGE_ACTIVE),
            seal: Arc::clone(&self.seal),
            logical_bytes: self.logical_bytes,
            physical_bytes: self.physical_bytes,
        });
        Ok(CommittedQuotaCharge {
            state: Arc::clone(&self.state),
            charge,
            released: false,
        })
    }
}

impl Drop for QuotaReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.state.lock();
        let index = find_account(&state.accounts, &self.seal)
            .expect("principal accounts are never removed");
        {
            let account = &mut state.accounts[index];
            account.reserved_logical_bytes = account
                .reserved_logical_bytes
                .checked_sub(self.logical_bytes)
                .expect("reservation owns its account logical bytes");
            account.reserved_physical_bytes = account
                .reserved_physical_bytes
                .checked_sub(self.physical_bytes)
                .expect("reservation owns its account physical bytes");
        }
        state.aggregate.reserved_logical_bytes = state
            .aggregate
            .reserved_logical_bytes
            .checked_sub(self.logical_bytes)
            .expect("aggregate contains reservation logical bytes");
        state.aggregate.reserved_physical_bytes = state
            .aggregate
            .reserved_physical_bytes
            .checked_sub(self.physical_bytes)
            .expect("aggregate contains reservation physical bytes");
        state.aggregate.reserved_outcome_ceiling_bytes = state
            .aggregate
            .reserved_outcome_ceiling_bytes
            .checked_sub(self.physical_bytes)
            .expect("aggregate contains reservation outcome ceiling");
        let aggregate = &mut state.aggregate;
        increment_event_counter(
            &mut aggregate.rolled_back_transactions,
            &mut aggregate.event_counters_saturated,
        );
        self.active = false;
    }
}

/// Non-cloneable durable charge to be owned by one authorized Object.
///
/// `Drop` intentionally has no accounting effect.  This prevents temporary
/// wrapper lifetimes, publication failures, or application behavior from
/// silently minting quota.  CAS must call
/// [`PrincipalQuotaTable::account_authority_revoked`] after durable revocation.
#[must_use = "a committed quota charge must remain attached to its Object authority"]
pub(crate) struct CommittedQuotaCharge {
    state: Arc<QuotaState>,
    charge: Arc<CommittedChargeState>,
    released: bool,
}

const CHARGE_ACTIVE: u8 = 0;
const CHARGE_TRANSFERRED: u8 = 1;
const CHARGE_RELEASED: u8 = 2;

struct CommittedChargeState {
    status: AtomicU8,
    seal: Arc<PrincipalSeal>,
    logical_bytes: u64,
    physical_bytes: u64,
}

impl fmt::Debug for CommittedQuotaCharge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedQuotaCharge")
            .field("logical_bytes", &self.charge.logical_bytes)
            .field("physical_bytes", &self.charge.physical_bytes)
            .field("released", &self.released)
            .finish_non_exhaustive()
    }
}

impl CommittedQuotaCharge {
    pub(crate) fn is_active(&self) -> bool {
        self.charge.status.load(Ordering::Acquire) == CHARGE_ACTIVE
    }
}

impl Drop for CommittedQuotaCharge {
    fn drop(&mut self) {
        // Deliberately no release. See the type-level contract above.
    }
}

fn find_account(accounts: &[PrincipalAccount], seal: &Arc<PrincipalSeal>) -> Option<usize> {
    accounts
        .iter()
        .position(|account| Arc::ptr_eq(&account.seal, seal))
}

fn checked_projected(committed: u64, reserved: u64, added: u64) -> Result<u64, QuotaError> {
    committed
        .checked_add(reserved)
        .and_then(|used| used.checked_add(added))
        .ok_or(QuotaError::CounterOverflow)
}

fn record_rejection(aggregate: &mut AggregateAccounting) {
    increment_event_counter(
        &mut aggregate.rejected_transactions,
        &mut aggregate.event_counters_saturated,
    );
}

fn increment_event_counter(counter: &mut u64, saturated: &mut bool) {
    match counter.checked_add(1) {
        Some(next) => *counter = next,
        None => *saturated = true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(logical_bytes: u64, physical_bytes: u64) -> PrincipalQuotaLimits {
        PrincipalQuotaLimits {
            logical_bytes,
            physical_bytes,
        }
    }

    #[test]
    fn seal_debug_and_api_do_not_expose_an_ambient_identifier() {
        let table = PrincipalQuotaTable::new(1).unwrap();
        let principal = table.admit_principal(limits(1, 1)).unwrap();
        assert_eq!(
            alloc::format!("{principal:?}"),
            "StoragePrincipal(<opaque>)"
        );
    }

    #[test]
    fn uncommitted_reservation_rolls_back_both_dimensions() {
        let table = PrincipalQuotaTable::new(1).unwrap();
        let principal = table.admit_principal(limits(100, 100)).unwrap();
        {
            let reservation = table.reserve(&principal, 40, 60, 60).unwrap();
            let usage = table.principal_usage(&principal).unwrap();
            assert_eq!(usage.reserved_logical_bytes, 40);
            assert_eq!(usage.reserved_physical_bytes, 60);
            drop(reservation);
        }
        let usage = table.principal_usage(&principal).unwrap();
        assert_eq!(usage.reserved_logical_bytes, 0);
        assert_eq!(usage.reserved_physical_bytes, 0);
        assert_eq!(table.diagnostics().rolled_back_transactions, 1);
    }

    #[test]
    fn committed_charge_drop_does_not_release_quota() {
        let table = PrincipalQuotaTable::new(1).unwrap();
        let principal = table.admit_principal(limits(100, 100)).unwrap();
        let charge = table.reserve(&principal, 40, 60, 60).unwrap().commit();
        drop(charge);
        let usage = table.principal_usage(&principal).unwrap();
        assert_eq!(usage.committed_logical_bytes, 40);
        assert_eq!(usage.committed_physical_bytes, 60);
    }

    #[test]
    fn staged_charge_drop_releases_active_accounting_and_candidate() {
        let table = PrincipalQuotaTable::new(1).unwrap();
        let principal = table.admit_principal(limits(100, 100)).unwrap();
        {
            let staged = table
                .stage_reserved_charge(table.reserve(&principal, 40, 60, 60).unwrap(), 60)
                .unwrap();
            staged.bind_persistent_candidate(7, 11).unwrap();
            assert!(table.has_active_persistent_candidate(7, 11));
            assert_eq!(
                table
                    .principal_usage(&principal)
                    .unwrap()
                    .committed_logical_bytes,
                40
            );
        }
        let usage = table.principal_usage(&principal).unwrap();
        assert_eq!(usage.committed_logical_bytes, 0);
        assert_eq!(usage.committed_physical_bytes, 0);
        assert!(!table.has_active_persistent_candidate(7, 11));
    }

    #[test]
    fn finishing_staged_charge_restores_normal_non_releasing_drop_contract() {
        let table = PrincipalQuotaTable::new(1).unwrap();
        let principal = table.admit_principal(limits(100, 100)).unwrap();
        let staged = table
            .stage_reserved_charge(table.reserve(&principal, 40, 60, 60).unwrap(), 60)
            .unwrap();
        let charge = staged.finish();
        drop(charge);
        let usage = table.principal_usage(&principal).unwrap();
        assert_eq!(usage.committed_logical_bytes, 40);
        assert_eq!(usage.committed_physical_bytes, 60);
    }

    #[test]
    fn explicit_authority_revocation_releases_exactly_one_charge() {
        let table = PrincipalQuotaTable::new(1).unwrap();
        let principal = table.admit_principal(limits(100, 100)).unwrap();
        let charge = table.reserve(&principal, 40, 60, 60).unwrap().commit();
        table.account_authority_revoked(charge).unwrap();
        let usage = table.principal_usage(&principal).unwrap();
        assert_eq!(usage.committed_logical_bytes, 0);
        assert_eq!(usage.committed_physical_bytes, 0);
    }

    #[test]
    fn physical_outcome_cannot_exceed_preflighted_envelope() {
        let table = PrincipalQuotaTable::new(1).unwrap();
        let principal = table.admit_principal(limits(100, 100)).unwrap();
        let error = table
            .reserve(&principal, 10, 20, 20)
            .unwrap()
            .commit_with_unique_physical(21)
            .unwrap_err();
        assert_eq!(error, QuotaError::InvalidPhysicalOutcome);
        assert_eq!(
            table
                .principal_usage(&principal)
                .unwrap()
                .reserved_physical_bytes,
            0
        );
    }

    #[test]
    fn frozen_formula_counts_payload_padding_records_manifest_and_both_mappings() {
        assert_eq!(canonical_attributable_physical_bytes(0).unwrap(), 37_120);
        assert_eq!(canonical_attributable_physical_bytes(1).unwrap(), 49_408);
    }

    #[test]
    fn revocation_closes_admission_even_while_a_reservation_drains() {
        let table = PrincipalQuotaTable::new(1).unwrap();
        let principal = table.admit_principal(limits(100, 100)).unwrap();
        let pending = table.reserve(&principal, 10, 10, 100).unwrap();
        assert_eq!(
            table.revoke_principal_admission(&principal),
            Err(QuotaError::OutstandingReservations)
        );
        assert_eq!(
            table.reserve(&principal, 1, 1, 100).unwrap_err(),
            QuotaError::PrincipalRevoked
        );
        drop(pending);
        assert!(table.principal_usage(&principal).unwrap().admission_revoked);
    }

    #[test]
    fn stable_principal_usage_rebuild_is_idempotent_and_exact() {
        let table = PrincipalQuotaTable::new(2).unwrap();
        let policy = PersistentPrincipalPolicy {
            principal: StablePrincipalId::new([0x51; 16]).unwrap(),
            logical_limit_bytes: 100,
            physical_limit_bytes: 200,
            committed_logical_bytes: 40,
            committed_physical_bytes: 80,
            admission_revoked: false,
        };
        let first = table.restore_persistent(&[policy]).unwrap();
        let second = table.restore_persistent(&[policy]).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(table.diagnostics().admitted_principals, 1);
        assert_eq!(
            table.principal_usage(&second[0]).unwrap(),
            PrincipalQuotaUsage {
                limits: limits(100, 200),
                committed_logical_bytes: 40,
                committed_physical_bytes: 80,
                reserved_logical_bytes: 0,
                reserved_physical_bytes: 0,
                admission_revoked: false,
            }
        );
        let mut reduced = policy;
        reduced.committed_logical_bytes = 30;
        reduced.committed_physical_bytes = 60;
        let reduced_principal = table.restore_persistent(&[reduced]).unwrap();
        assert_eq!(
            table.principal_usage(&reduced_principal[0]).unwrap(),
            PrincipalQuotaUsage {
                limits: limits(100, 200),
                committed_logical_bytes: 30,
                committed_physical_bytes: 60,
                reserved_logical_bytes: 0,
                reserved_physical_bytes: 0,
                admission_revoked: false,
            }
        );
        let diagnostics = table.diagnostics();
        assert_eq!(diagnostics.committed_logical_bytes, 30);
        assert_eq!(diagnostics.committed_physical_bytes, 60);
        assert_eq!(diagnostics.logical_high_water_bytes, 40);
        assert_eq!(diagnostics.physical_high_water_bytes, 80);

        let mut mismatch = reduced;
        mismatch.logical_limit_bytes = 101;
        assert_eq!(
            table.restore_persistent(&[mismatch]).unwrap_err(),
            QuotaError::InvalidConfiguration
        );
    }

    #[test]
    fn persistent_replacement_preserves_runtime_committed_charges() {
        let table = PrincipalQuotaTable::new(1).unwrap();
        let mut policy = PersistentPrincipalPolicy {
            principal: StablePrincipalId::new([0x59; 16]).unwrap(),
            logical_limit_bytes: 100,
            physical_limit_bytes: 200,
            committed_logical_bytes: 40,
            committed_physical_bytes: 80,
            admission_revoked: false,
        };
        let principal = table.restore_persistent(&[policy]).unwrap().remove(0);
        drop(table.reserve(&principal, 10, 20, 200).unwrap().commit());

        policy.committed_logical_bytes = 15;
        policy.committed_physical_bytes = 30;
        let restored = table.restore_persistent(&[policy]).unwrap();
        let usage = table.principal_usage(&restored[0]).unwrap();
        assert_eq!(usage.committed_logical_bytes, 25);
        assert_eq!(usage.committed_physical_bytes, 50);
        let diagnostics = table.diagnostics();
        assert_eq!(diagnostics.committed_logical_bytes, 25);
        assert_eq!(diagnostics.committed_physical_bytes, 50);
        assert_eq!(diagnostics.logical_high_water_bytes, 50);
        assert_eq!(diagnostics.physical_high_water_bytes, 100);
    }

    #[test]
    fn exact_binding_reconcile_transfers_and_reactivates_atomically() {
        let table = PrincipalQuotaTable::new(1).unwrap();
        let policy = PersistentPrincipalPolicy {
            principal: StablePrincipalId::new([0x61; 16]).unwrap(),
            logical_limit_bytes: 100,
            physical_limit_bytes: 200,
            committed_logical_bytes: 0,
            committed_physical_bytes: 0,
            admission_revoked: false,
        };
        let principal = table.restore_persistent(&[policy]).unwrap().remove(0);
        let charge = table.reserve(&principal, 10, 20, 200).unwrap().commit();
        table.bind_persistent_candidate(7, 11, &charge).unwrap();

        let mut rooted = policy;
        rooted.committed_logical_bytes = 10;
        rooted.committed_physical_bytes = 20;
        let before_preflight = table.principal_usage(&principal).unwrap();
        let diagnostics_before_preflight = table.diagnostics();
        table
            .preflight_persistent_with_bindings(&[rooted], &[(7, 11)])
            .unwrap();
        assert_eq!(charge.charge.status.load(Ordering::Acquire), CHARGE_ACTIVE);
        assert_eq!(table.principal_usage(&principal).unwrap(), before_preflight);
        assert_eq!(table.diagnostics(), diagnostics_before_preflight);
        table
            .restore_persistent_with_bindings(&[rooted], &[(7, 11)])
            .unwrap();
        assert_eq!(
            charge.charge.status.load(Ordering::Acquire),
            CHARGE_TRANSFERRED
        );
        assert_eq!(
            table
                .principal_usage(&principal)
                .unwrap()
                .committed_logical_bytes,
            10
        );

        // A stable-ID match to the wrong V2 mapping does not consume this
        // candidate; removing the exact binding reactivates runtime ownership.
        table
            .restore_persistent_with_bindings(&[policy], &[(7, 12)])
            .unwrap();
        assert_eq!(charge.charge.status.load(Ordering::Acquire), CHARGE_ACTIVE);
        assert_eq!(
            table
                .principal_usage(&principal)
                .unwrap()
                .committed_logical_bytes,
            10
        );
        table.account_authority_revoked(charge).unwrap();
        assert_eq!(
            table
                .principal_usage(&principal)
                .unwrap()
                .committed_logical_bytes,
            0
        );
    }

    #[test]
    fn failed_binding_restore_preserves_active_and_transferred_charge_state() {
        let table = PrincipalQuotaTable::new(1).unwrap();
        let policy = PersistentPrincipalPolicy {
            principal: StablePrincipalId::new([0x63; 16]).unwrap(),
            logical_limit_bytes: 100,
            physical_limit_bytes: 200,
            committed_logical_bytes: 0,
            committed_physical_bytes: 0,
            admission_revoked: false,
        };
        let principal = table.restore_persistent(&[policy]).unwrap().remove(0);
        let charge = table.reserve(&principal, 10, 20, 200).unwrap().commit();
        table.bind_persistent_candidate(7, 11, &charge).unwrap();

        // The exact binding would transfer this ACTIVE charge, but the later
        // account-policy mismatch must fail without changing any state.
        let mut invalid_active = policy;
        invalid_active.logical_limit_bytes = 101;
        let active_usage = table.principal_usage(&principal).unwrap();
        let active_diagnostics = table.diagnostics();
        assert_eq!(
            table
                .restore_persistent_with_bindings(&[invalid_active], &[(7, 11)])
                .unwrap_err(),
            QuotaError::InvalidConfiguration
        );
        assert_eq!(charge.charge.status.load(Ordering::Acquire), CHARGE_ACTIVE);
        assert_eq!(table.principal_usage(&principal).unwrap(), active_usage);
        assert_eq!(table.diagnostics(), active_diagnostics);

        let mut rooted = policy;
        rooted.committed_logical_bytes = 10;
        rooted.committed_physical_bytes = 20;
        table
            .restore_persistent_with_bindings(&[rooted], &[(7, 11)])
            .unwrap();
        assert_eq!(
            charge.charge.status.load(Ordering::Acquire),
            CHARGE_TRANSFERRED
        );

        // Omitting the binding would reactivate the TRANSFERRED charge. The
        // same late policy failure must leave it transferred and leave both
        // capability-scoped usage and anonymous diagnostics byte-for-byte
        // unchanged.
        let mut invalid_transferred = policy;
        invalid_transferred.logical_limit_bytes = 101;
        let transferred_usage = table.principal_usage(&principal).unwrap();
        let transferred_diagnostics = table.diagnostics();
        assert_eq!(
            table
                .restore_persistent_with_bindings(&[invalid_transferred], &[])
                .unwrap_err(),
            QuotaError::InvalidConfiguration
        );
        assert_eq!(
            charge.charge.status.load(Ordering::Acquire),
            CHARGE_TRANSFERRED
        );
        assert_eq!(
            table.principal_usage(&principal).unwrap(),
            transferred_usage
        );
        assert_eq!(table.diagnostics(), transferred_diagnostics);
    }

    #[test]
    fn failed_multi_principal_restore_is_atomic_and_replacement_updates_high_water() {
        let table = PrincipalQuotaTable::new(3).unwrap();
        let first = PersistentPrincipalPolicy {
            principal: StablePrincipalId::new([0x61; 16]).unwrap(),
            logical_limit_bytes: 100,
            physical_limit_bytes: 200,
            committed_logical_bytes: 10,
            committed_physical_bytes: 20,
            admission_revoked: false,
        };
        let second = PersistentPrincipalPolicy {
            principal: StablePrincipalId::new([0x62; 16]).unwrap(),
            logical_limit_bytes: 100,
            physical_limit_bytes: 200,
            committed_logical_bytes: 30,
            committed_physical_bytes: 40,
            admission_revoked: false,
        };
        let principals = table.restore_persistent(&[first, second]).unwrap();
        let baseline = table.diagnostics();
        assert_eq!(baseline.committed_logical_bytes, 40);
        assert_eq!(baseline.committed_physical_bytes, 60);

        let mut replaced_first = first;
        replaced_first.committed_logical_bytes = 5;
        replaced_first.committed_physical_bytes = 10;
        let mut invalid_second = second;
        invalid_second.admission_revoked = true;
        assert_eq!(
            table
                .restore_persistent(&[replaced_first, invalid_second])
                .unwrap_err(),
            QuotaError::InvalidConfiguration
        );
        assert_eq!(table.diagnostics(), baseline);
        assert_eq!(
            table.principal_usage(&principals[0]).unwrap(),
            PrincipalQuotaUsage {
                limits: limits(100, 200),
                committed_logical_bytes: 10,
                committed_physical_bytes: 20,
                reserved_logical_bytes: 0,
                reserved_physical_bytes: 0,
                admission_revoked: false,
            }
        );

        let mut grown_second = second;
        grown_second.committed_logical_bytes = 60;
        grown_second.committed_physical_bytes = 100;
        table
            .restore_persistent(&[replaced_first, grown_second])
            .unwrap();
        let grown = table.diagnostics();
        assert_eq!(grown.committed_logical_bytes, 65);
        assert_eq!(grown.committed_physical_bytes, 110);
        assert_eq!(grown.logical_high_water_bytes, 65);
        assert_eq!(grown.physical_high_water_bytes, 110);

        table.restore_persistent(&[replaced_first, second]).unwrap();
        let reduced = table.diagnostics();
        assert_eq!(reduced.committed_logical_bytes, 35);
        assert_eq!(reduced.committed_physical_bytes, 50);
        assert_eq!(reduced.logical_high_water_bytes, 65);
        assert_eq!(reduced.physical_high_water_bytes, 110);
    }

    #[test]
    fn persistent_restore_rejects_duplicate_missing_reserved_and_underflow_state_atomically() {
        let table = PrincipalQuotaTable::new(2).unwrap();
        let first = PersistentPrincipalPolicy {
            principal: StablePrincipalId::new([0x71; 16]).unwrap(),
            logical_limit_bytes: 100,
            physical_limit_bytes: 200,
            committed_logical_bytes: 10,
            committed_physical_bytes: 20,
            admission_revoked: false,
        };
        let second = PersistentPrincipalPolicy {
            principal: StablePrincipalId::new([0x72; 16]).unwrap(),
            logical_limit_bytes: 100,
            physical_limit_bytes: 200,
            committed_logical_bytes: 30,
            committed_physical_bytes: 40,
            admission_revoked: false,
        };
        let principals = table.restore_persistent(&[first, second]).unwrap();
        let baseline = table.diagnostics();

        assert_eq!(
            table.restore_persistent(&[first, first]).unwrap_err(),
            QuotaError::InvalidConfiguration
        );
        assert_eq!(
            table.restore_persistent(&[first]).unwrap_err(),
            QuotaError::InvalidConfiguration
        );
        let reservation = table.reserve(&principals[0], 1, 1, 200).unwrap();
        assert_eq!(
            table.restore_persistent(&[first, second]).unwrap_err(),
            QuotaError::InvalidConfiguration
        );
        drop(reservation);
        assert_eq!(table.diagnostics().committed_logical_bytes, 40);
        assert_eq!(table.diagnostics().committed_physical_bytes, 60);

        {
            let mut state = table.state.lock();
            state.accounts[0].persistent_logical_bytes = 11;
        }
        assert_eq!(
            table.restore_persistent(&[first, second]).unwrap_err(),
            QuotaError::InvalidConfiguration
        );
        let after = table.diagnostics();
        assert_eq!(
            after.committed_logical_bytes,
            baseline.committed_logical_bytes
        );
        assert_eq!(
            after.committed_physical_bytes,
            baseline.committed_physical_bytes
        );
    }
}
