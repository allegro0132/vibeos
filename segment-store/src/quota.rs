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

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::fmt;
use core::hint::spin_loop;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use vibeos_blob_format::BlobGeometry;
use vibeos_segment_format::PAGE_SIZE;

use crate::cas_codec::{
    BLOB_MANIFEST_HEADER_LEN, BLOB_MAPPING_LEN, CANONICAL_CONTENT_EXTENT_LEN, MANIFEST_EXTENT_LEN,
    OBJECT_MAPPING_LEN,
};

/// Maximum number of boot-local storage principals in one governed runtime.
pub const DEFAULT_MAX_STORAGE_PRINCIPALS: u32 = 256;

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
    committed_logical_bytes: u64,
    committed_physical_bytes: u64,
    reserved_logical_bytes: u64,
    reserved_physical_bytes: u64,
    admission_revoked: bool,
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
    aggregate: AggregateAccounting,
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
        Ok(Self {
            state: Arc::new(QuotaState {
                locked: AtomicBool::new(false),
                data: UnsafeCell::new(QuotaStateData {
                    maximum_principals,
                    accounts,
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
        let seal = Arc::new(PrincipalSeal { _marker: 0xa7 });
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
        let index =
            find_account(&state.accounts, &charge.seal).ok_or(QuotaError::UnknownPrincipal)?;
        {
            let account = &mut state.accounts[index];
            account.committed_logical_bytes = account
                .committed_logical_bytes
                .checked_sub(charge.logical_bytes)
                .expect("a committed charge is released at most once");
            account.committed_physical_bytes = account
                .committed_physical_bytes
                .checked_sub(charge.physical_bytes)
                .expect("a committed charge is released at most once");
        }
        state.aggregate.committed_logical_bytes = state
            .aggregate
            .committed_logical_bytes
            .checked_sub(charge.logical_bytes)
            .expect("aggregate includes every committed charge");
        state.aggregate.committed_physical_bytes = state
            .aggregate
            .committed_physical_bytes
            .checked_sub(charge.physical_bytes)
            .expect("aggregate includes every committed charge");
        charge.released = true;
        Ok(())
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
        Ok(CommittedQuotaCharge {
            state: Arc::clone(&self.state),
            seal: Arc::clone(&self.seal),
            logical_bytes: self.logical_bytes,
            physical_bytes: self.physical_bytes,
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
    seal: Arc<PrincipalSeal>,
    logical_bytes: u64,
    physical_bytes: u64,
    released: bool,
}

impl fmt::Debug for CommittedQuotaCharge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedQuotaCharge")
            .field("logical_bytes", &self.logical_bytes)
            .field("physical_bytes", &self.physical_bytes)
            .field("released", &self.released)
            .finish_non_exhaustive()
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
}
