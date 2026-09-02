//! Bounded Component-owned registrations for native async copy buffers.
//!
//! A registration contains an opaque Core-memory authority and integer range,
//! never a reference into guest memory. Slots are allocated up front and are
//! sealed by the registry identity plus a one-based slot and generation.

use crate::{
    async_state::{AsyncArenaUsage, BufferLease},
    value::AsyncValueTypeId,
};
use alloc::vec::Vec;
use core::{
    num::{NonZeroU32, NonZeroU64},
    sync::atomic::{AtomicU64, Ordering},
};
use vibeos_component_format::{TrapCode, PROFILE_1_LIMITS};
use vibeos_wasm_runtime::{CoreComponentGroup, CoreMemoryAuthority};

const COPY_COUNT_LIMIT: u32 = 1_u32 << 28;
const ENUM8_CASES: u8 = 8;
static NEXT_BUFFER_REGISTRY_ID: AtomicU64 = AtomicU64::new(1);

/// The endpoint role whose memory is retained by one registration.
///
/// Names include the Canonical ABI operation to make reversal at a local-copy
/// boundary explicit: stream writes are sources and stream reads are targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BufferRole {
    SourceWrite,
    TargetRead,
}

/// Stable identity for the validator-derived typed copy plan.
///
/// Complementary read and write bridges for the same stream type share this
/// identity. A slot stores it alongside its memory authority so a lease cannot
/// be replayed through another typed transfer plan with the same scalar shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BufferPlanId(NonZeroU32);

impl BufferPlanId {
    pub(crate) const fn new(raw: u32) -> Option<Self> {
        match NonZeroU32::new(raw) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }
}

/// Read-only preflight result consumed by [`BufferRegistry::issue`].
///
/// It does not reserve or mutate its selected slot. The executor can therefore
/// perform preflight before charging fuel; `issue` revalidates the exact free
/// slot and generation after the charge.
pub(crate) struct PreparedBuffer {
    registry: NonZeroU64,
    slot: NonZeroU32,
    generation: NonZeroU64,
    plan: BufferPlanId,
    memory: CoreMemoryAuthority,
    role: BufferRole,
    pointer: u32,
    elements: u32,
    value_type: AsyncValueTypeId,
}

impl core::fmt::Debug for PreparedBuffer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedBuffer")
            .field("role", &self.role)
            .field("elements", &self.elements)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
struct RegisteredBuffer {
    plan: BufferPlanId,
    memory: CoreMemoryAuthority,
    role: BufferRole,
    pointer: u32,
    elements: u32,
    value_type: AsyncValueTypeId,
}

struct BufferSlot {
    generation: u64,
    retired: bool,
    value: Option<RegisteredBuffer>,
}

/// Fixed-capacity registry for live native async `stream<u8>` buffers.
///
/// `scratch` is fully allocated and initialized in the constructor, but is
/// capped independently of the maximum legal copy. Local copies walk this
/// fixed scratch in the direction required for memmove semantics when two
/// authorities alias the same underlying Wasm memory.
pub(crate) struct BufferRegistry {
    id: NonZeroU64,
    slots: Vec<BufferSlot>,
    live: u32,
    peak: u32,
    maximum: u32,
    scratch: Vec<u8>,
    max_copy_bytes: usize,
    poisoned: bool,
}

impl BufferRegistry {
    pub(crate) fn new(maximum: u32, max_copy_bytes: usize) -> Result<Self, TrapCode> {
        Self::new_with_scratch_limit(
            maximum,
            max_copy_bytes,
            PROFILE_1_LIMITS.max_canonical_value_bytes,
        )
    }

    fn new_with_scratch_limit(
        maximum: u32,
        max_copy_bytes: usize,
        scratch_limit: usize,
    ) -> Result<Self, TrapCode> {
        if maximum == 0
            || maximum > PROFILE_1_LIMITS.max_resources
            || max_copy_bytes == 0
            || max_copy_bytes >= COPY_COUNT_LIMIT as usize
            || scratch_limit == 0
        {
            return Err(TrapCode::LimitExceeded);
        }
        let raw = NEXT_BUFFER_REGISTRY_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1).filter(|next| *next != 0)
            })
            .map_err(|_| TrapCode::LimitExceeded)?;
        let id = NonZeroU64::new(raw).ok_or(TrapCode::LimitExceeded)?;

        let maximum_usize = usize::try_from(maximum).map_err(|_| TrapCode::LimitExceeded)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(maximum_usize)
            .map_err(|_| TrapCode::LimitExceeded)?;
        for _ in 0..maximum {
            slots.push(BufferSlot {
                generation: 1,
                retired: false,
                value: None,
            });
        }

        let scratch_bytes = max_copy_bytes.min(scratch_limit);
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(scratch_bytes)
            .map_err(|_| TrapCode::LimitExceeded)?;
        scratch.resize(scratch_bytes, 0);
        Ok(Self {
            id,
            slots,
            live: 0,
            peak: 0,
            maximum,
            scratch,
            max_copy_bytes,
            poisoned: false,
        })
    }

    #[cfg(test)]
    fn new_for_test(
        maximum: u32,
        max_copy_bytes: usize,
        scratch_bytes: usize,
    ) -> Result<Self, TrapCode> {
        if scratch_bytes > max_copy_bytes {
            return Err(TrapCode::LimitExceeded);
        }
        Self::new_with_scratch_limit(maximum, max_copy_bytes, scratch_bytes)
    }

    pub(crate) const fn live(&self) -> u32 {
        self.live
    }

    #[cfg(test)]
    pub(crate) const fn maximum(&self) -> u32 {
        self.maximum
    }

    pub(crate) const fn usage(&self) -> AsyncArenaUsage {
        AsyncArenaUsage {
            current: self.live,
            peak: self.peak,
            limit: self.maximum,
        }
    }

    #[cfg(test)]
    const fn max_copy_bytes(&self) -> usize {
        self.max_copy_bytes
    }

    pub(crate) const fn scratch_bytes(&self) -> usize {
        self.scratch.len()
    }

    #[cfg(test)]
    pub(crate) const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Validates one exact authorized `stream<u8>` buffer without mutating a
    /// slot. A zero-element buffer deliberately ignores its raw pointer.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn preflight(
        &self,
        modules: &CoreComponentGroup,
        plan: BufferPlanId,
        memory: CoreMemoryAuthority,
        role: BufferRole,
        pointer: u32,
        elements: u32,
        value_type: AsyncValueTypeId,
    ) -> Result<PreparedBuffer, TrapCode> {
        if self.poisoned {
            return Err(TrapCode::Validation);
        }
        validate_count(elements, self.max_copy_bytes)?;
        // This call validates the opaque authority even for an empty buffer.
        let memory_len = modules.authorized_memory_size(&memory)?;
        validate_range(pointer, elements, memory_len)?;

        let (index, slot) = self
            .slots
            .iter()
            .enumerate()
            .find(|(_, slot)| slot.value.is_none() && !slot.retired)
            .ok_or(TrapCode::LimitExceeded)?;
        let slot_number = u32::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1))
            .and_then(NonZeroU32::new)
            .ok_or(TrapCode::LimitExceeded)?;
        let generation = NonZeroU64::new(slot.generation).ok_or(TrapCode::Validation)?;
        Ok(PreparedBuffer {
            registry: self.id,
            slot: slot_number,
            generation,
            plan,
            memory,
            role,
            pointer,
            elements,
            value_type,
        })
    }

    /// Commits a preflight result without allocation.
    pub(crate) fn issue(&mut self, prepared: PreparedBuffer) -> Result<BufferLease, TrapCode> {
        if self.poisoned || prepared.registry != self.id {
            return Err(TrapCode::Validation);
        }
        let index = slot_index(prepared.slot, self.slots.len())?;
        let slot = self.slots.get(index).ok_or(TrapCode::Validation)?;
        if slot.retired
            || slot.value.is_some()
            || slot.generation != prepared.generation.get()
            || self.live >= self.maximum
        {
            return Err(TrapCode::Validation);
        }
        let lease = BufferLease::issue(
            self.id.get(),
            prepared.slot.get(),
            prepared.generation.get(),
            prepared.elements,
        )
        .map_err(|_| TrapCode::Validation)?;
        let next_live = self.live.checked_add(1).ok_or(TrapCode::Validation)?;
        self.slots[index].value = Some(RegisteredBuffer {
            plan: prepared.plan,
            memory: prepared.memory,
            role: prepared.role,
            pointer: prepared.pointer,
            elements: prepared.elements,
            value_type: prepared.value_type,
        });
        self.live = next_live;
        self.peak = self.peak.max(next_live);
        Ok(lease)
    }

    /// Releases one exact lease after checking its expected endpoint role.
    pub(crate) fn release(
        &mut self,
        lease: &BufferLease,
        expected_role: BufferRole,
    ) -> Result<(), TrapCode> {
        let index = self.resolve_index(lease)?;
        let registered = self.slots[index].value.ok_or(TrapCode::Validation)?;
        if registered.role != expected_role || registered.elements != lease.elements() {
            return Err(TrapCode::Validation);
        }
        self.remove_index(index)
    }

    /// Releases one exact lease whose endpoint role was consumed by the
    /// matching async-state event authority.
    pub(crate) fn release_owned(&mut self, lease: &BufferLease) -> Result<(), TrapCode> {
        let index = self.resolve_index(lease)?;
        let registered = self.slots[index].value.ok_or(TrapCode::Validation)?;
        if registered.elements != lease.elements() {
            return Err(TrapCode::Validation);
        }
        self.remove_index(index)
    }

    /// Discards one exact owned lease during fail-stop teardown.
    ///
    /// Teardown already obtained the lease by value from `AsyncState`, so it
    /// does not need to reconstruct the endpoint role. Registry, slot,
    /// generation, and element-count seals remain mandatory. This method must
    /// run before [`Self::poison`], whose fallback invalidates every slot.
    pub(crate) fn discard_owned(&mut self, lease: BufferLease) -> Result<(), TrapCode> {
        self.release_owned(&lease)
    }

    /// Copies a matched write buffer into a matched read buffer.
    ///
    /// Both exact authorities and their complete originally registered ranges
    /// are revalidated before the first write. Each chunk is read completely
    /// before it is written; higher target addresses walk backward and all
    /// other copies walk forward, preserving memmove semantics for aliases.
    pub(crate) fn copy_local(
        &mut self,
        modules: &mut CoreComponentGroup,
        source: &BufferLease,
        target: &BufferLease,
        progress: u32,
    ) -> Result<(), TrapCode> {
        if self.poisoned || progress == 0 || progress >= COPY_COUNT_LIMIT {
            return Err(TrapCode::Validation);
        }
        let source = self.resolve(source)?;
        let target = self.resolve(target)?;
        if source.role != BufferRole::SourceWrite
            || target.role != BufferRole::TargetRead
            || source.plan != target.plan
            || source.value_type != target.value_type
            || progress > source.elements
            || progress > target.elements
        {
            return Err(TrapCode::Validation);
        }
        let bytes = usize::try_from(progress).map_err(|_| TrapCode::Validation)?;
        if bytes > self.max_copy_bytes {
            return Err(TrapCode::Validation);
        }

        let source_len = modules.authorized_memory_size(&source.memory)?;
        let target_len = modules.authorized_memory_size(&target.memory)?;
        validate_range(source.pointer, source.elements, source_len)?;
        validate_range(target.pointer, target.elements, target_len)?;
        validate_range(source.pointer, progress, source_len)?;
        validate_range(target.pointer, progress, target_len)?;

        let source_pointer = usize::try_from(source.pointer).map_err(|_| TrapCode::Validation)?;
        let target_pointer = usize::try_from(target.pointer).map_err(|_| TrapCode::Validation)?;
        let scratch_bytes = self.scratch.len();
        if scratch_bytes == 0 {
            return Err(TrapCode::Validation);
        }

        if target.pointer > source.pointer {
            let mut remaining = bytes;
            while remaining != 0 {
                let chunk_bytes = remaining.min(scratch_bytes);
                let chunk_start = remaining
                    .checked_sub(chunk_bytes)
                    .ok_or(TrapCode::Validation)?;
                let source_offset = source_pointer
                    .checked_add(chunk_start)
                    .ok_or(TrapCode::Validation)?;
                let target_offset = target_pointer
                    .checked_add(chunk_start)
                    .ok_or(TrapCode::Validation)?;
                let scratch = self
                    .scratch
                    .get_mut(..chunk_bytes)
                    .ok_or(TrapCode::Validation)?;
                modules.read_authorized_memory(&source.memory, source_offset, scratch)?;
                modules.write_authorized_memory(&target.memory, target_offset, scratch)?;
                remaining = chunk_start;
            }
        } else {
            let mut copied = 0_usize;
            while copied != bytes {
                let chunk_bytes = bytes
                    .checked_sub(copied)
                    .ok_or(TrapCode::Validation)?
                    .min(scratch_bytes);
                let source_offset = source_pointer
                    .checked_add(copied)
                    .ok_or(TrapCode::Validation)?;
                let target_offset = target_pointer
                    .checked_add(copied)
                    .ok_or(TrapCode::Validation)?;
                let scratch = self
                    .scratch
                    .get_mut(..chunk_bytes)
                    .ok_or(TrapCode::Validation)?;
                modules.read_authorized_memory(&source.memory, source_offset, scratch)?;
                modules.write_authorized_memory(&target.memory, target_offset, scratch)?;
                copied = copied
                    .checked_add(chunk_bytes)
                    .ok_or(TrapCode::Validation)?;
            }
        }
        Ok(())
    }

    /// Copies one authorized write-buffer prefix into host-owned storage.
    ///
    /// The host slice length is the copy progress. Registry seals, endpoint
    /// role, the opaque memory authority, the complete registered range, and
    /// the requested prefix are all revalidated before the host slice is
    /// touched. An empty prefix still validates the authority and registration.
    pub(crate) fn copy_to_host(
        &self,
        modules: &CoreComponentGroup,
        source: &BufferLease,
        output: &mut [u8],
    ) -> Result<(), TrapCode> {
        let source =
            self.resolve_host_copy(modules, source, BufferRole::SourceWrite, output.len())?;
        if output.is_empty() {
            return Ok(());
        }
        let source_pointer = usize::try_from(source.pointer).map_err(|_| TrapCode::Validation)?;
        modules.read_authorized_memory(&source.memory, source_pointer, output)
    }

    /// Revalidates an exact host-to-guest copy without publishing bytes.
    ///
    /// Native transport uses this before it asks a backend to linearize an
    /// input operation. The later commit still calls [`Self::copy_from_host`]
    /// and therefore repeats every seal, role, range, and progress check.
    pub(crate) fn preflight_copy_from_host(
        &self,
        modules: &CoreComponentGroup,
        target: &BufferLease,
        progress: usize,
    ) -> Result<(), TrapCode> {
        self.resolve_host_copy(modules, target, BufferRole::TargetRead, progress)
            .map(|_| ())
    }

    /// Copies one host-owned byte slice into an authorized read-buffer prefix.
    ///
    /// The input slice length is the copy progress. All registry and memory
    /// checks complete before guest memory is touched, so rejected host copies
    /// cannot partially publish bytes into the guest.
    pub(crate) fn copy_from_host(
        &self,
        modules: &mut CoreComponentGroup,
        target: &BufferLease,
        input: &[u8],
    ) -> Result<(), TrapCode> {
        let target =
            self.resolve_host_copy(modules, target, BufferRole::TargetRead, input.len())?;
        if input.is_empty() {
            return Ok(());
        }
        let target_pointer = usize::try_from(target.pointer).map_err(|_| TrapCode::Validation)?;
        modules.write_authorized_memory(&target.memory, target_pointer, input)
    }

    /// Lifts a one-byte eight-case enum without publishing an invalid
    /// discriminant to host code. Admission assigns semantic case names.
    pub(crate) fn lift_enum8(
        &self,
        modules: &CoreComponentGroup,
        source: &BufferLease,
    ) -> Result<u8, TrapCode> {
        let mut discriminant = [0_u8];
        self.copy_to_host(modules, source, &mut discriminant)?;
        if discriminant[0] >= ENUM8_CASES {
            return Err(TrapCode::CanonicalAbi);
        }
        Ok(discriminant[0])
    }

    /// Lowers one host-supplied eight-case enum only after validating its
    /// domain, so a rejected value leaves the guest target untouched.
    pub(crate) fn lower_enum8(
        &self,
        modules: &mut CoreComponentGroup,
        target: &BufferLease,
        discriminant: u8,
    ) -> Result<(), TrapCode> {
        if discriminant >= ENUM8_CASES {
            return Err(TrapCode::CanonicalAbi);
        }
        self.copy_from_host(modules, target, &[discriminant])
    }

    /// Clears every slot and rotates all reusable generations.
    ///
    /// Rotating free slots as well as live slots invalidates read-only
    /// `PreparedBuffer`s that may have been minted before teardown.
    pub(crate) fn discard_all(&mut self) {
        for slot in &mut self.slots {
            rotate_slot(slot);
        }
        self.live = 0;
    }

    /// Permanently prevents further use and discards every registration.
    pub(crate) fn poison(&mut self) {
        self.poisoned = true;
        self.discard_all();
    }

    fn resolve(&self, lease: &BufferLease) -> Result<RegisteredBuffer, TrapCode> {
        let index = self.resolve_index(lease)?;
        let registered = self.slots[index].value.ok_or(TrapCode::Validation)?;
        if registered.elements != lease.elements() {
            return Err(TrapCode::Validation);
        }
        Ok(registered)
    }

    #[allow(dead_code)] // Shared by the staged host-copy entry points above.
    fn resolve_host_copy(
        &self,
        modules: &CoreComponentGroup,
        lease: &BufferLease,
        expected_role: BufferRole,
        progress: usize,
    ) -> Result<RegisteredBuffer, TrapCode> {
        let registered = self.resolve(lease)?;
        if registered.role != expected_role {
            return Err(TrapCode::Validation);
        }
        let progress = u32::try_from(progress).map_err(|_| TrapCode::Validation)?;
        if progress >= COPY_COUNT_LIMIT
            || progress > registered.elements
            || usize::try_from(progress).map_err(|_| TrapCode::Validation)? > self.max_copy_bytes
        {
            return Err(TrapCode::Validation);
        }

        let memory_len = modules.authorized_memory_size(&registered.memory)?;
        validate_range(registered.pointer, registered.elements, memory_len)?;
        validate_range(registered.pointer, progress, memory_len)?;
        Ok(registered)
    }

    fn resolve_index(&self, lease: &BufferLease) -> Result<usize, TrapCode> {
        if self.poisoned || lease.registry() != self.id.get() {
            return Err(TrapCode::Validation);
        }
        let slot = NonZeroU32::new(lease.slot()).ok_or(TrapCode::Validation)?;
        let index = slot_index(slot, self.slots.len())?;
        let entry = self.slots.get(index).ok_or(TrapCode::Validation)?;
        if entry.retired || entry.generation != lease.generation() || entry.value.is_none() {
            return Err(TrapCode::Validation);
        }
        Ok(index)
    }

    fn remove_index(&mut self, index: usize) -> Result<(), TrapCode> {
        let slot = self.slots.get_mut(index).ok_or(TrapCode::Validation)?;
        if slot.value.is_none() || self.live == 0 {
            return Err(TrapCode::Validation);
        }
        rotate_slot(slot);
        self.live -= 1;
        Ok(())
    }
}

fn validate_count(elements: u32, max_copy_bytes: usize) -> Result<(), TrapCode> {
    let elements_usize = usize::try_from(elements).map_err(|_| TrapCode::LimitExceeded)?;
    if elements >= COPY_COUNT_LIMIT || elements_usize > max_copy_bytes {
        return Err(TrapCode::LimitExceeded);
    }
    Ok(())
}

fn validate_range(pointer: u32, elements: u32, memory_len: usize) -> Result<(), TrapCode> {
    if elements == 0 {
        return Ok(());
    }
    let end = u64::from(pointer)
        .checked_add(u64::from(elements))
        .ok_or(TrapCode::MemoryOutOfBounds)?;
    if end > memory_len as u64 || end > u64::from(u32::MAX) + 1 {
        return Err(TrapCode::MemoryOutOfBounds);
    }
    Ok(())
}

fn slot_index(slot: NonZeroU32, length: usize) -> Result<usize, TrapCode> {
    let index = usize::try_from(slot.get() - 1).map_err(|_| TrapCode::Validation)?;
    (index < length)
        .then_some(index)
        .ok_or(TrapCode::Validation)
}

fn rotate_slot(slot: &mut BufferSlot) {
    slot.value = None;
    match slot.generation.checked_add(1) {
        Some(next) if next != 0 => slot.generation = next,
        _ => slot.retired = true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vibeos_wasm_runtime::{OwnerAllocationReservation, ProfileEngine, ValidatedCore};

    const MEMORY_BYTES: usize = 65_536;

    fn ty(raw: u32) -> AsyncValueTypeId {
        AsyncValueTypeId::new(raw).unwrap()
    }

    fn plan(raw: u32) -> BufferPlanId {
        BufferPlanId::new(raw).unwrap()
    }

    fn memory_group() -> (CoreComponentGroup, CoreMemoryAuthority) {
        let engine = ProfileEngine::new();
        let bytes = wat::parse_str("(module (memory (export \"memory\") 1 1))").unwrap();
        let module = ValidatedCore::new_in(
            &engine,
            &bytes,
            OwnerAllocationReservation::profile_default(),
        )
        .unwrap();
        let mut group = CoreComponentGroup::new(&engine, 1).unwrap();
        assert_eq!(group.add_instance(&module, &[]).unwrap(), 0);
        group.seal().unwrap();
        let memory = group.memory_authority(0, "memory").unwrap();
        (group, memory)
    }

    fn two_memory_group() -> (CoreComponentGroup, CoreMemoryAuthority, CoreMemoryAuthority) {
        let engine = ProfileEngine::new();
        let bytes = wat::parse_str("(module (memory (export \"memory\") 1 1))").unwrap();
        let module = ValidatedCore::new_in(
            &engine,
            &bytes,
            OwnerAllocationReservation::profile_default(),
        )
        .unwrap();
        let mut group = CoreComponentGroup::new(&engine, 2).unwrap();
        assert_eq!(group.add_instance(&module, &[]).unwrap(), 0);
        assert_eq!(group.add_instance(&module, &[]).unwrap(), 1);
        group.seal().unwrap();
        let source = group.memory_authority(0, "memory").unwrap();
        let target = group.memory_authority(1, "memory").unwrap();
        (group, source, target)
    }

    #[allow(clippy::too_many_arguments)]
    fn issue(
        registry: &mut BufferRegistry,
        modules: &CoreComponentGroup,
        memory: CoreMemoryAuthority,
        plan: BufferPlanId,
        role: BufferRole,
        pointer: u32,
        elements: u32,
        value_type: AsyncValueTypeId,
    ) -> BufferLease {
        let prepared = registry
            .preflight(modules, plan, memory, role, pointer, elements, value_type)
            .unwrap();
        registry.issue(prepared).unwrap()
    }

    #[test]
    fn constructor_is_bounded_and_preallocates_every_runtime_buffer() {
        assert!(matches!(
            BufferRegistry::new(0, 8),
            Err(TrapCode::LimitExceeded)
        ));
        assert!(matches!(
            BufferRegistry::new(1, 0),
            Err(TrapCode::LimitExceeded)
        ));
        assert!(matches!(
            BufferRegistry::new(PROFILE_1_LIMITS.max_resources + 1, 8),
            Err(TrapCode::LimitExceeded)
        ));
        assert!(matches!(
            BufferRegistry::new(1, COPY_COUNT_LIMIT as usize),
            Err(TrapCode::LimitExceeded)
        ));
        assert!(matches!(
            BufferRegistry::new_for_test(1, 8, 0),
            Err(TrapCode::LimitExceeded)
        ));
        assert!(matches!(
            BufferRegistry::new_for_test(1, 8, 9),
            Err(TrapCode::LimitExceeded)
        ));

        let registry = BufferRegistry::new(3, 17).unwrap();
        assert_eq!((registry.live(), registry.maximum()), (0, 3));
        assert_eq!(
            registry.usage(),
            AsyncArenaUsage {
                current: 0,
                peak: 0,
                limit: 3,
            }
        );
        assert_eq!(registry.slots.len(), 3);
        assert!(registry.slots.capacity() >= 3);
        assert_eq!(registry.scratch.len(), 17);
        assert!(registry.scratch.capacity() >= 17);
        assert_eq!(registry.scratch_bytes(), 17);

        let memory_policy = PROFILE_1_LIMITS.max_memory_pages as usize * 65_536;
        let registry = BufferRegistry::new(1, memory_policy).unwrap();
        assert_eq!(registry.max_copy_bytes(), memory_policy);
        assert_eq!(
            registry.scratch_bytes(),
            PROFILE_1_LIMITS.max_canonical_value_bytes
        );
        assert_eq!(
            registry.scratch.len(),
            PROFILE_1_LIMITS.max_canonical_value_bytes
        );
        assert!(registry.scratch.capacity() < memory_policy);
    }

    #[test]
    fn full_registry_is_a_limit_and_exact_release_reopens_one_slot() {
        let (modules, memory) = memory_group();
        let mut registry = BufferRegistry::new(1, 8).unwrap();
        let lease = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::SourceWrite,
            0,
            1,
            ty(1),
        );
        assert_eq!(registry.live(), 1);
        assert_eq!(
            registry.usage(),
            AsyncArenaUsage {
                current: 1,
                peak: 1,
                limit: 1,
            }
        );
        assert!(matches!(
            registry.preflight(
                &modules,
                plan(1),
                memory,
                BufferRole::TargetRead,
                8,
                1,
                ty(1),
            ),
            Err(TrapCode::LimitExceeded)
        ));
        registry.release(&lease, BufferRole::SourceWrite).unwrap();
        assert_eq!(registry.live(), 0);
        assert_eq!(registry.usage().peak, 1);
        let replacement = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::TargetRead,
            8,
            1,
            ty(1),
        );
        assert_ne!(lease.generation(), replacement.generation());
    }

    #[test]
    fn empty_buffer_ignores_max_pointer_but_positive_ranges_are_eagerly_checked() {
        let (modules, memory) = memory_group();
        let registry = BufferRegistry::new(2, 8).unwrap();
        assert!(registry
            .preflight(
                &modules,
                plan(1),
                memory,
                BufferRole::SourceWrite,
                u32::MAX,
                0,
                ty(1),
            )
            .is_ok());
        assert!(matches!(
            registry.preflight(
                &modules,
                plan(1),
                memory,
                BufferRole::SourceWrite,
                (MEMORY_BYTES - 1) as u32,
                2,
                ty(1),
            ),
            Err(TrapCode::MemoryOutOfBounds)
        ));
        assert!(matches!(
            registry.preflight(
                &modules,
                plan(1),
                memory,
                BufferRole::SourceWrite,
                0,
                9,
                ty(1),
            ),
            Err(TrapCode::LimitExceeded)
        ));
        assert!(matches!(
            registry.preflight(
                &modules,
                plan(1),
                memory,
                BufferRole::SourceWrite,
                0,
                COPY_COUNT_LIMIT,
                ty(1),
            ),
            Err(TrapCode::LimitExceeded)
        ));
    }

    #[test]
    fn prepared_tokens_are_read_only_and_commit_revalidates_the_free_generation() {
        let (modules, memory) = memory_group();
        let mut registry = BufferRegistry::new(1, 8).unwrap();
        let first = registry
            .preflight(
                &modules,
                plan(1),
                memory,
                BufferRole::SourceWrite,
                0,
                1,
                ty(1),
            )
            .unwrap();
        let competing = registry
            .preflight(
                &modules,
                plan(1),
                memory,
                BufferRole::TargetRead,
                8,
                1,
                ty(1),
            )
            .unwrap();
        assert_eq!(registry.live(), 0);
        let lease = registry.issue(first).unwrap();
        assert_eq!(registry.issue(competing), Err(TrapCode::Validation));
        registry.release(&lease, BufferRole::SourceWrite).unwrap();

        let stale = registry
            .preflight(
                &modules,
                plan(1),
                memory,
                BufferRole::SourceWrite,
                0,
                1,
                ty(1),
            )
            .unwrap();
        registry.discard_all();
        assert_eq!(registry.issue(stale), Err(TrapCode::Validation));
    }

    #[test]
    fn foreign_stale_wrong_role_and_aba_leases_fail_without_mutation() {
        let (modules, memory) = memory_group();
        let mut first = BufferRegistry::new(1, 8).unwrap();
        let mut foreign = BufferRegistry::new(1, 8).unwrap();
        let old = issue(
            &mut first,
            &modules,
            memory,
            plan(1),
            BufferRole::SourceWrite,
            0,
            1,
            ty(1),
        );
        assert_eq!(
            foreign.release(&old, BufferRole::SourceWrite),
            Err(TrapCode::Validation)
        );
        assert_eq!(
            first.release(&old, BufferRole::TargetRead),
            Err(TrapCode::Validation)
        );
        assert_eq!(first.live(), 1);
        first.release(&old, BufferRole::SourceWrite).unwrap();
        assert_eq!(
            first.release(&old, BufferRole::SourceWrite),
            Err(TrapCode::Validation)
        );
        let replacement = issue(
            &mut first,
            &modules,
            memory,
            plan(1),
            BufferRole::SourceWrite,
            1,
            1,
            ty(1),
        );
        assert_ne!(old.generation(), replacement.generation());
        assert_eq!(
            first.release(&old, BufferRole::SourceWrite),
            Err(TrapCode::Validation)
        );
        assert_eq!(first.live(), 1);
    }

    #[test]
    fn fail_stop_discard_consumes_exact_owned_authority_without_a_role_guess() {
        let (modules, memory) = memory_group();
        let mut registry = BufferRegistry::new(2, 8).unwrap();
        let foreign = BufferRegistry::new(1, 8).unwrap();
        let source = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::SourceWrite,
            0,
            1,
            ty(1),
        );
        let source_registry = source.registry();
        let source_slot = source.slot();
        let source_generation = source.generation();
        let forged_foreign = BufferLease::issue(
            foreign.id.get(),
            source_slot,
            source_generation,
            source.elements(),
        )
        .unwrap();
        assert_eq!(
            registry.discard_owned(forged_foreign),
            Err(TrapCode::Validation)
        );
        assert_eq!(registry.live(), 1);
        registry.discard_owned(source).unwrap();
        assert_eq!(registry.live(), 0);

        let stale = BufferLease::issue(source_registry, source_slot, source_generation, 1).unwrap();
        assert_eq!(registry.discard_owned(stale), Err(TrapCode::Validation));

        let target = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::TargetRead,
            8,
            1,
            ty(1),
        );
        registry.discard_owned(target).unwrap();
        assert_eq!(registry.live(), 0);
    }

    #[test]
    fn event_release_consumes_exact_authority_without_reconstructing_its_role() {
        let (modules, memory) = memory_group();
        let mut registry = BufferRegistry::new(2, 8).unwrap();
        let source = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::SourceWrite,
            0,
            1,
            ty(1),
        );
        let target = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::TargetRead,
            8,
            1,
            ty(1),
        );

        registry.release_owned(&source).unwrap();
        assert_eq!(registry.live(), 1);
        assert_eq!(registry.release_owned(&source), Err(TrapCode::Validation));
        registry.release_owned(&target).unwrap();
        assert_eq!(registry.live(), 0);
    }

    #[test]
    fn authorized_memory_is_bound_to_its_exact_component_group() {
        let (first_group, first_memory) = memory_group();
        let (second_group, _) = memory_group();
        let registry = BufferRegistry::new(1, 8).unwrap();
        assert!(registry
            .preflight(
                &first_group,
                plan(1),
                first_memory,
                BufferRole::SourceWrite,
                0,
                1,
                ty(1),
            )
            .is_ok());
        assert!(matches!(
            registry.preflight(
                &second_group,
                plan(1),
                first_memory,
                BufferRole::SourceWrite,
                0,
                1,
                ty(1),
            ),
            Err(TrapCode::Validation)
        ));
    }

    #[test]
    fn host_copy_transfers_only_the_requested_stream_prefix() {
        let (mut modules, memory) = memory_group();
        let mut registry = BufferRegistry::new(2, 8).unwrap();
        modules
            .write_authorized_memory(&memory, 32, &[1, 2, 3, 4, 5, 6])
            .unwrap();
        modules
            .write_authorized_memory(&memory, 64, &[9, 9, 9, 9, 9, 9])
            .unwrap();
        let source = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::SourceWrite,
            32,
            6,
            ty(1),
        );
        let target = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::TargetRead,
            64,
            6,
            ty(1),
        );

        let mut output = [0xaa; 3];
        registry
            .copy_to_host(&modules, &source, &mut output)
            .unwrap();
        assert_eq!(output, [1, 2, 3]);

        registry
            .preflight_copy_from_host(&modules, &target, 3)
            .unwrap();
        let mut before_commit = [0_u8; 6];
        modules
            .read_authorized_memory(&memory, 64, &mut before_commit)
            .unwrap();
        assert_eq!(before_commit, [9, 9, 9, 9, 9, 9]);

        registry
            .copy_from_host(&mut modules, &target, &[7, 8, 10])
            .unwrap();
        let mut target_bytes = [0_u8; 6];
        modules
            .read_authorized_memory(&memory, 64, &mut target_bytes)
            .unwrap();
        assert_eq!(target_bytes, [7, 8, 10, 9, 9, 9]);
    }

    #[test]
    fn host_copy_supports_single_byte_future_payloads() {
        let (mut modules, memory) = memory_group();
        let mut registry = BufferRegistry::new(2, 1).unwrap();
        modules.write_authorized_memory(&memory, 80, &[6]).unwrap();
        let source = issue(
            &mut registry,
            &modules,
            memory,
            plan(2),
            BufferRole::SourceWrite,
            80,
            1,
            ty(2),
        );
        let target = issue(
            &mut registry,
            &modules,
            memory,
            plan(2),
            BufferRole::TargetRead,
            81,
            1,
            ty(2),
        );

        let mut close_reason = [0xff];
        registry
            .copy_to_host(&modules, &source, &mut close_reason)
            .unwrap();
        assert_eq!(close_reason, [6]);
        registry
            .copy_from_host(&mut modules, &target, &[3])
            .unwrap();
        let mut written = [0_u8];
        modules
            .read_authorized_memory(&memory, 81, &mut written)
            .unwrap();
        assert_eq!(written, [3]);
    }

    #[test]
    fn enum8_host_codec_rejects_invalid_discriminants_before_publication() {
        let (mut modules, memory) = memory_group();
        let mut registry = BufferRegistry::new(2, 1).unwrap();
        modules.write_authorized_memory(&memory, 80, &[8]).unwrap();
        modules
            .write_authorized_memory(&memory, 81, &[0xaa])
            .unwrap();
        let source = issue(
            &mut registry,
            &modules,
            memory,
            plan(2),
            BufferRole::SourceWrite,
            80,
            1,
            ty(2),
        );
        let target = issue(
            &mut registry,
            &modules,
            memory,
            plan(2),
            BufferRole::TargetRead,
            81,
            1,
            ty(2),
        );

        assert_eq!(
            registry.lift_enum8(&modules, &source),
            Err(TrapCode::CanonicalAbi)
        );
        assert_eq!(
            registry.lower_enum8(&mut modules, &target, 8),
            Err(TrapCode::CanonicalAbi)
        );
        let mut target_byte = [0_u8];
        modules
            .read_authorized_memory(&memory, 81, &mut target_byte)
            .unwrap();
        assert_eq!(target_byte, [0xaa]);

        modules.write_authorized_memory(&memory, 80, &[7]).unwrap();
        assert_eq!(registry.lift_enum8(&modules, &source), Ok(7));
        registry.lower_enum8(&mut modules, &target, 6).unwrap();
        modules
            .read_authorized_memory(&memory, 81, &mut target_byte)
            .unwrap();
        assert_eq!(target_byte, [6]);
    }

    #[test]
    fn host_copy_rejects_wrong_roles_and_oversize_without_mutation() {
        let (mut modules, memory) = memory_group();
        let mut registry = BufferRegistry::new(2, 4).unwrap();
        modules
            .write_authorized_memory(&memory, 0, &[1, 2, 3, 4])
            .unwrap();
        modules
            .write_authorized_memory(&memory, 8, &[9, 9, 9, 9])
            .unwrap();
        let source = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::SourceWrite,
            0,
            4,
            ty(1),
        );
        let target = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::TargetRead,
            8,
            4,
            ty(1),
        );

        let mut wrong_role_output = [0xaa; 4];
        assert_eq!(
            registry.copy_to_host(&modules, &target, &mut wrong_role_output),
            Err(TrapCode::Validation)
        );
        assert_eq!(wrong_role_output, [0xaa; 4]);
        assert_eq!(
            registry.copy_from_host(&mut modules, &source, &[5, 5, 5, 5]),
            Err(TrapCode::Validation)
        );

        let mut oversize_output = [0xbb; 5];
        assert_eq!(
            registry.copy_to_host(&modules, &source, &mut oversize_output),
            Err(TrapCode::Validation)
        );
        assert_eq!(oversize_output, [0xbb; 5]);
        assert_eq!(
            registry.copy_from_host(&mut modules, &target, &[6, 6, 6, 6, 6]),
            Err(TrapCode::Validation)
        );

        let mut source_bytes = [0_u8; 4];
        let mut target_bytes = [0_u8; 4];
        modules
            .read_authorized_memory(&memory, 0, &mut source_bytes)
            .unwrap();
        modules
            .read_authorized_memory(&memory, 8, &mut target_bytes)
            .unwrap();
        assert_eq!(source_bytes, [1, 2, 3, 4]);
        assert_eq!(target_bytes, [9, 9, 9, 9]);
    }

    #[test]
    fn host_copy_rejects_foreign_stale_and_poisoned_seals_without_mutation() {
        let (mut modules, memory) = memory_group();
        let (mut foreign_modules, _) = memory_group();
        let mut registry = BufferRegistry::new(2, 4).unwrap();
        let foreign_registry = BufferRegistry::new(1, 4).unwrap();
        modules
            .write_authorized_memory(&memory, 0, &[1, 2, 3, 4])
            .unwrap();
        modules
            .write_authorized_memory(&memory, 8, &[9, 9, 9, 9])
            .unwrap();
        let source = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::SourceWrite,
            0,
            4,
            ty(1),
        );
        let target = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::TargetRead,
            8,
            4,
            ty(1),
        );

        let mut output = [0xcc; 4];
        assert_eq!(
            foreign_registry.copy_to_host(&modules, &source, &mut output),
            Err(TrapCode::Validation)
        );
        assert_eq!(output, [0xcc; 4]);
        assert_eq!(
            foreign_registry.copy_from_host(&mut modules, &target, &[5, 6, 7, 8]),
            Err(TrapCode::Validation)
        );
        assert_eq!(
            registry.copy_to_host(&foreign_modules, &source, &mut output),
            Err(TrapCode::Validation)
        );
        assert_eq!(output, [0xcc; 4]);
        assert_eq!(
            registry.copy_from_host(&mut foreign_modules, &target, &[5, 6, 7, 8]),
            Err(TrapCode::Validation)
        );

        registry.release(&source, BufferRole::SourceWrite).unwrap();
        let replacement = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::SourceWrite,
            0,
            4,
            ty(1),
        );
        assert_ne!(source.generation(), replacement.generation());
        assert_eq!(
            registry.copy_to_host(&modules, &source, &mut output),
            Err(TrapCode::Validation)
        );
        assert_eq!(output, [0xcc; 4]);
        registry.release(&target, BufferRole::TargetRead).unwrap();
        let replacement_target = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::TargetRead,
            8,
            4,
            ty(1),
        );
        assert_ne!(target.generation(), replacement_target.generation());
        assert_eq!(
            registry.copy_from_host(&mut modules, &target, &[5, 6, 7, 8]),
            Err(TrapCode::Validation)
        );

        registry.poison();
        assert_eq!(
            registry.copy_to_host(&modules, &replacement, &mut output),
            Err(TrapCode::Validation)
        );
        assert_eq!(output, [0xcc; 4]);
        assert_eq!(
            registry.copy_from_host(&mut modules, &replacement_target, &[5, 6, 7, 8]),
            Err(TrapCode::Validation)
        );
        let mut target_bytes = [0_u8; 4];
        modules
            .read_authorized_memory(&memory, 8, &mut target_bytes)
            .unwrap();
        assert_eq!(target_bytes, [9, 9, 9, 9]);
    }

    #[test]
    fn host_copy_accepts_empty_slices_after_revalidating_authority() {
        let (mut modules, memory) = memory_group();
        let mut registry = BufferRegistry::new(2, 1).unwrap();
        let source = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::SourceWrite,
            u32::MAX,
            0,
            ty(1),
        );
        let target = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::TargetRead,
            u32::MAX,
            0,
            ty(1),
        );

        let mut output = [];
        registry
            .copy_to_host(&modules, &source, &mut output)
            .unwrap();
        registry.copy_from_host(&mut modules, &target, &[]).unwrap();
    }

    #[test]
    fn local_copy_requires_exact_plan_type_and_roles() {
        let (mut modules, memory) = memory_group();
        let mut registry = BufferRegistry::new(4, 8).unwrap();
        modules
            .write_authorized_memory(&memory, 0, &[1, 2, 3, 4])
            .unwrap();
        let source = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::SourceWrite,
            0,
            4,
            ty(1),
        );
        let target = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::TargetRead,
            8,
            4,
            ty(1),
        );
        registry
            .copy_local(&mut modules, &source, &target, 4)
            .unwrap();
        let mut copied = [0_u8; 4];
        modules
            .read_authorized_memory(&memory, 8, &mut copied)
            .unwrap();
        assert_eq!(copied, [1, 2, 3, 4]);
        assert_eq!(
            registry.copy_local(&mut modules, &target, &source, 4),
            Err(TrapCode::Validation)
        );
        assert_eq!(
            registry.copy_local(&mut modules, &source, &target, 0),
            Err(TrapCode::Validation)
        );
        assert_eq!(
            registry.copy_local(&mut modules, &source, &target, 5),
            Err(TrapCode::Validation)
        );

        let wrong_plan = issue(
            &mut registry,
            &modules,
            memory,
            plan(2),
            BufferRole::TargetRead,
            16,
            4,
            ty(1),
        );
        assert_eq!(
            registry.copy_local(&mut modules, &source, &wrong_plan, 4),
            Err(TrapCode::Validation)
        );
        let wrong_type = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::TargetRead,
            24,
            4,
            ty(2),
        );
        assert_eq!(
            registry.copy_local(&mut modules, &source, &wrong_type, 4),
            Err(TrapCode::Validation)
        );
    }

    #[test]
    fn local_copy_chunks_backward_across_scratch_for_a_higher_alias() {
        let (mut modules, memory) = memory_group();
        let mut registry = BufferRegistry::new_for_test(2, 10, 3).unwrap();
        let initial = [0_u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        modules
            .write_authorized_memory(&memory, 0, &initial)
            .unwrap();
        let source = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::SourceWrite,
            0,
            10,
            ty(1),
        );
        let target = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::TargetRead,
            2,
            10,
            ty(1),
        );
        let slot_capacity = registry.slots.capacity();
        let scratch_capacity = registry.scratch.capacity();
        assert_eq!(registry.scratch_bytes(), 3);
        registry
            .copy_local(&mut modules, &source, &target, 10)
            .unwrap();
        assert_eq!(registry.slots.capacity(), slot_capacity);
        assert_eq!(registry.scratch.capacity(), scratch_capacity);
        let mut bytes = [0_u8; 16];
        modules
            .read_authorized_memory(&memory, 0, &mut bytes)
            .unwrap();
        assert_eq!(bytes, [0, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15]);
    }

    #[test]
    fn local_copy_chunks_forward_across_scratch_for_a_lower_alias() {
        let (mut modules, memory) = memory_group();
        let mut registry = BufferRegistry::new_for_test(2, 10, 3).unwrap();
        let initial = [0_u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        modules
            .write_authorized_memory(&memory, 0, &initial)
            .unwrap();
        let source = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::SourceWrite,
            2,
            10,
            ty(1),
        );
        let target = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::TargetRead,
            0,
            10,
            ty(1),
        );
        registry
            .copy_local(&mut modules, &source, &target, 10)
            .unwrap();
        let mut bytes = [0_u8; 16];
        modules
            .read_authorized_memory(&memory, 0, &mut bytes)
            .unwrap();
        assert_eq!(
            bytes,
            [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn local_copy_exact_alias_is_stable_across_scratch_chunks() {
        let (mut modules, memory) = memory_group();
        let mut registry = BufferRegistry::new_for_test(2, 10, 3).unwrap();
        let initial = [0_u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        modules
            .write_authorized_memory(&memory, 4, &initial)
            .unwrap();
        let source = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::SourceWrite,
            4,
            10,
            ty(1),
        );
        let target = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::TargetRead,
            4,
            10,
            ty(1),
        );
        registry
            .copy_local(&mut modules, &source, &target, 10)
            .unwrap();
        let mut bytes = [0_u8; 12];
        modules
            .read_authorized_memory(&memory, 4, &mut bytes)
            .unwrap();
        assert_eq!(bytes, initial);
    }

    #[test]
    fn local_copy_chunks_between_distinct_memories_in_either_pointer_order() {
        let (mut modules, source_memory, target_memory) = two_memory_group();
        let mut registry = BufferRegistry::new_for_test(2, 10, 3).unwrap();
        let backward = [10_u8, 11, 12, 13, 14, 15, 16, 17, 18, 19];
        modules
            .write_authorized_memory(&source_memory, 0, &backward)
            .unwrap();
        let source = issue(
            &mut registry,
            &modules,
            source_memory,
            plan(1),
            BufferRole::SourceWrite,
            0,
            10,
            ty(1),
        );
        let target = issue(
            &mut registry,
            &modules,
            target_memory,
            plan(1),
            BufferRole::TargetRead,
            12,
            10,
            ty(1),
        );
        registry
            .copy_local(&mut modules, &source, &target, 10)
            .unwrap();
        let mut copied = [0_u8; 10];
        modules
            .read_authorized_memory(&target_memory, 12, &mut copied)
            .unwrap();
        assert_eq!(copied, backward);
        registry.release(&source, BufferRole::SourceWrite).unwrap();
        registry.release(&target, BufferRole::TargetRead).unwrap();

        let forward = [20_u8, 21, 22, 23, 24, 25, 26, 27, 28, 29];
        modules
            .write_authorized_memory(&source_memory, 20, &forward)
            .unwrap();
        let source = issue(
            &mut registry,
            &modules,
            source_memory,
            plan(1),
            BufferRole::SourceWrite,
            20,
            10,
            ty(1),
        );
        let target = issue(
            &mut registry,
            &modules,
            target_memory,
            plan(1),
            BufferRole::TargetRead,
            0,
            10,
            ty(1),
        );
        registry
            .copy_local(&mut modules, &source, &target, 10)
            .unwrap();
        modules
            .read_authorized_memory(&target_memory, 0, &mut copied)
            .unwrap();
        assert_eq!(copied, forward);
    }

    #[test]
    fn discard_rotates_every_slot_and_poison_is_permanent() {
        let (modules, memory) = memory_group();
        let mut registry = BufferRegistry::new(2, 8).unwrap();
        let prepared_free = registry
            .preflight(
                &modules,
                plan(1),
                memory,
                BufferRole::TargetRead,
                8,
                1,
                ty(1),
            )
            .unwrap();
        let live = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::SourceWrite,
            0,
            1,
            ty(1),
        );
        registry.discard_all();
        assert_eq!(registry.live(), 0);
        assert_eq!(registry.issue(prepared_free), Err(TrapCode::Validation));
        assert_eq!(
            registry.release(&live, BufferRole::SourceWrite),
            Err(TrapCode::Validation)
        );

        let replacement = issue(
            &mut registry,
            &modules,
            memory,
            plan(1),
            BufferRole::SourceWrite,
            0,
            1,
            ty(1),
        );
        registry.poison();
        assert!(registry.is_poisoned());
        assert_eq!(registry.live(), 0);
        assert_eq!(
            registry.release(&replacement, BufferRole::SourceWrite),
            Err(TrapCode::Validation)
        );
        assert!(matches!(
            registry.preflight(
                &modules,
                plan(1),
                memory,
                BufferRole::SourceWrite,
                0,
                1,
                ty(1),
            ),
            Err(TrapCode::Validation)
        ));
    }

    #[test]
    fn generation_exhaustion_retires_a_slot_instead_of_wrapping() {
        let (modules, memory) = memory_group();
        let mut registry = BufferRegistry::new(1, 8).unwrap();
        registry.slots[0].generation = u64::MAX;
        registry.discard_all();
        assert!(registry.slots[0].retired);
        assert!(matches!(
            registry.preflight(
                &modules,
                plan(1),
                memory,
                BufferRole::SourceWrite,
                0,
                1,
                ty(1),
            ),
            Err(TrapCode::LimitExceeded)
        ));
    }
}
