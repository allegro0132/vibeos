//! Pure, fixed-budget M7.5 reachability planning.
//!
//! This module performs no I/O and trusts neither reference counts nor segment
//! live-byte estimates. It consumes already authenticated catalog views and a
//! [`TypedChildSource`] adapter; the adapter is responsible for reading the
//! canonical `VIBEREF1` payload with the production decoder. Raw objects never
//! call the child source and therefore never turn arbitrary bytes into edges.
//!
//! Every edge names an exact `(ObjectId, commit generation, object kind)`.
//! Missing objects, stale generation, kind mismatch, a missing Blob mapping,
//! malformed typed payloads, and exhausted budgets all fail closed. Cycles and
//! diamonds are bounded by marking an exact Object mapping once, while shared
//! physical Blobs are counted once independently of object authority.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use crate::cas_codec::{
    BlobKey, BlobMapping, ObjectMapping, REFERENCE_CODEC_FS_V1, REFERENCE_CODEC_RAW,
    REFERENCE_CODEC_TYPED_V1,
};
use crate::pins::RootKey;

/// One exact edge decoded from a canonical typed manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChildReference {
    pub(crate) object_id: u128,
    pub(crate) commit_generation: u64,
    pub(crate) object_kind: u32,
}

impl ChildReference {
    pub(crate) fn new(
        object_id: u128,
        commit_generation: u64,
        object_kind: u32,
    ) -> Result<Self, MarkError> {
        if object_id == 0 || commit_generation == 0 || object_kind == 0 {
            return Err(MarkError::MalformedReference);
        }
        Ok(Self {
            object_id,
            commit_generation,
            object_kind,
        })
    }

    fn as_key(self) -> Result<RootKey, MarkError> {
        RootKey::new(self.object_id, self.commit_generation, self.object_kind)
            .map_err(|_| MarkError::MalformedReference)
    }
}

/// Abstracts authenticated typed-payload reads from the pure mark planner.
///
/// Implementations MUST use the strict canonical decoder selected by
/// `object.reference_codec`; must reject prefixes, suffixes, duplicate or
/// unordered children, non-zero reserved fields, and any authentication error;
/// and must never return more than `out.len()` children. Returning the exact
/// required child count lets the planner distinguish an empty manifest from a
/// budget overflow without allocating while traversing.
pub(crate) trait TypedChildSource {
    type Error;

    fn read_children(
        &self,
        object: &ObjectMapping,
        out: &mut [ChildReference],
    ) -> Result<usize, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootClass {
    PersistentPolicy,
    Runtime,
    ExplicitSnapshot,
    AuthorityOrMigration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MarkRoot {
    pub(crate) key: RootKey,
    pub(crate) class: RootClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MarkBudget {
    /// Maximum number of distinct exact Object mappings that may be live.
    pub(crate) objects: usize,
    /// Maximum number of distinct physical Blob identities that may be live.
    pub(crate) blobs: usize,
    /// Maximum typed children decoded from one object.
    pub(crate) children_per_object: usize,
    /// Maximum root entries captured across all root classes.
    pub(crate) roots: usize,
}

impl MarkBudget {
    pub(crate) const fn new(
        objects: usize,
        blobs: usize,
        children_per_object: usize,
        roots: usize,
    ) -> Self {
        Self {
            objects,
            blobs,
            children_per_object,
            roots,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MarkError {
    InvalidBudget,
    AllocationFailed,
    UnsortedOrDuplicateCatalog,
    MissingObject,
    StaleObjectGeneration,
    ObjectKindMismatch,
    MissingBlobMapping,
    UnknownReferenceCodec,
    MalformedReference,
    TypedChildRead,
    RootBudgetExceeded,
    ObjectBudgetExceeded,
    BlobBudgetExceeded,
    ChildBudgetExceeded,
}

/// An immutable catalog view captured at one selected checkpoint generation.
/// The planner validates strict ordering rather than trusting a caller-created
/// index. The slices are borrowed, so planning cannot mutate catalog state.
#[derive(Clone, Copy)]
pub(crate) struct CatalogView<'a> {
    pub(crate) checkpoint_generation: u64,
    pub(crate) objects: &'a [ObjectMapping],
    pub(crate) blobs: &'a [BlobMapping],
}

/// Reachability result consumed by the future cleaner.
///
/// `live_blobs` is authoritative. `estimated_live_bytes` and segment hints are
/// intentionally absent: callers may calculate them afterward but may never
/// use them in place of membership in this set.
#[derive(Debug)]
pub(crate) struct MarkPlan {
    epoch_generation: u64,
    live_objects: Vec<RootKey>,
    live_blobs: Vec<BlobKey>,
    object_capacity: usize,
    blob_capacity: usize,
}

impl MarkPlan {
    pub(crate) fn with_budget(
        epoch_generation: u64,
        budget: MarkBudget,
    ) -> Result<Self, MarkError> {
        if epoch_generation == 0 || budget.objects == 0 || budget.blobs == 0 {
            return Err(MarkError::InvalidBudget);
        }
        let mut live_objects = Vec::new();
        live_objects
            .try_reserve_exact(budget.objects)
            .map_err(|_| MarkError::AllocationFailed)?;
        let mut live_blobs = Vec::new();
        live_blobs
            .try_reserve_exact(budget.blobs)
            .map_err(|_| MarkError::AllocationFailed)?;
        Ok(Self {
            epoch_generation,
            live_objects,
            live_blobs,
            object_capacity: budget.objects,
            blob_capacity: budget.blobs,
        })
    }

    pub(crate) const fn epoch_generation(&self) -> u64 {
        self.epoch_generation
    }

    pub(crate) fn live_objects(&self) -> &[RootKey] {
        &self.live_objects
    }

    pub(crate) fn live_blobs(&self) -> &[BlobKey] {
        &self.live_blobs
    }

    pub(crate) fn contains_blob(&self, key: BlobKey) -> bool {
        self.live_blobs.binary_search(&key).is_ok()
    }

    pub(crate) fn allocated_bytes(&self) -> Option<usize> {
        self.live_objects
            .capacity()
            .checked_mul(core::mem::size_of::<RootKey>())?
            .checked_add(
                self.live_blobs
                    .capacity()
                    .checked_mul(core::mem::size_of::<BlobKey>())?,
            )
    }

    fn clear(&mut self, epoch_generation: u64) {
        self.epoch_generation = epoch_generation;
        self.live_objects.clear();
        self.live_blobs.clear();
    }

    /// Force-retain one catalog entry (and its blob) in the live set.
    ///
    /// The mounted object-id high-water is `max(top catalog id + 1,
    /// generation)`. Batched staging binds several ids per checkpoint, so ids
    /// can legitimately outrun the generation floor; the highest catalog
    /// entry is then the only durable carrier of the high-water and must
    /// survive destructive filtering even when unreachable, or a future mount
    /// could reissue live-range ids.
    pub(crate) fn retain_object(&mut self, key: RootKey, blob: BlobKey) -> Result<(), MarkError> {
        if let Err(at) = self.live_objects.binary_search(&key) {
            if self.live_objects.len() >= self.object_capacity {
                return Err(MarkError::AllocationFailed);
            }
            self.live_objects.insert(at, key);
        }
        if let Err(at) = self.live_blobs.binary_search(&blob) {
            if self.live_blobs.len() >= self.blob_capacity {
                return Err(MarkError::AllocationFailed);
            }
            self.live_blobs.insert(at, blob);
        }
        Ok(())
    }
}

/// All temporary vectors are allocated to their fixed maxima at construction.
/// `mark` clears and reuses them, so a GC pass does not grow heap usage.
pub(crate) struct MarkPlanner {
    budget: MarkBudget,
    pending: Vec<RootKey>,
    children: Vec<ChildReference>,
}

impl MarkPlanner {
    pub(crate) fn new(budget: MarkBudget) -> Result<Self, MarkError> {
        if budget.objects == 0
            || budget.blobs == 0
            || budget.roots == 0
            || budget.children_per_object == 0
        {
            return Err(MarkError::InvalidBudget);
        }
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(budget.objects)
            .map_err(|_| MarkError::AllocationFailed)?;
        let mut children = Vec::new();
        children
            .try_reserve_exact(budget.children_per_object)
            .map_err(|_| MarkError::AllocationFailed)?;
        children.resize(
            budget.children_per_object,
            ChildReference {
                object_id: 0,
                commit_generation: 0,
                object_kind: 0,
            },
        );
        Ok(Self {
            budget,
            pending,
            children,
        })
    }

    pub(crate) fn allocated_bytes(&self) -> Option<usize> {
        self.pending
            .capacity()
            .checked_mul(core::mem::size_of::<RootKey>())?
            .checked_add(
                self.children
                    .capacity()
                    .checked_mul(core::mem::size_of::<ChildReference>())?,
            )
    }

    /// Mark the exact transitive closure rooted in all supplied root classes.
    ///
    /// The caller supplies the union of persistent policy, runtime-pin snapshot,
    /// explicit snapshots, and protected authority/migration operations. Root
    /// class is retained for audit upstream but has no liveness precedence:
    /// every entry is equally authoritative.
    pub(crate) fn mark<S: TypedChildSource>(
        &mut self,
        catalog: CatalogView<'_>,
        roots: &[MarkRoot],
        source: &S,
        output: &mut MarkPlan,
    ) -> Result<MarkStats, MarkError> {
        // Never leave a previous successful plan available after a failed pass.
        output.clear(catalog.checkpoint_generation);
        self.pending.clear();
        validate_catalog(catalog)?;
        if roots.len() > self.budget.roots {
            return Err(MarkError::RootBudgetExceeded);
        }
        if output.object_capacity < self.budget.objects || output.blob_capacity < self.budget.blobs
        {
            return Err(MarkError::InvalidBudget);
        }

        // Insert roots into the same bounded work stack used for children.
        // Duplicate entries from distinct classes collapse only after their
        // exact identity has been retained.
        for root in roots {
            let _ = root.class;
            insert_pending(&mut self.pending, root.key, self.budget.objects)?;
        }

        let mut traversed_edges = 0usize;
        while let Some(key) = self.pending.pop() {
            if output.live_objects.binary_search(&key).is_ok() {
                continue;
            }
            let object = fail_closed(output, resolve_exact_object(catalog.objects, key))?;
            fail_closed(output, resolve_blob(catalog.blobs, object.blob_key))?;

            let object_insert = insert_sorted_unique(
                &mut output.live_objects,
                key,
                output.object_capacity,
                MarkError::ObjectBudgetExceeded,
            );
            fail_closed(output, object_insert)?;
            let blob_insert = insert_sorted_unique(
                &mut output.live_blobs,
                object.blob_key,
                output.blob_capacity,
                MarkError::BlobBudgetExceeded,
            );
            fail_closed(output, blob_insert)?;

            match object.reference_codec {
                REFERENCE_CODEC_RAW => {}
                REFERENCE_CODEC_TYPED_V1 | REFERENCE_CODEC_FS_V1 => {
                    let child_count = match source.read_children(&object, &mut self.children) {
                        Ok(count) => count,
                        Err(_) => {
                            output.clear(catalog.checkpoint_generation);
                            return Err(MarkError::TypedChildRead);
                        }
                    };
                    if child_count > self.children.len() {
                        output.clear(catalog.checkpoint_generation);
                        return Err(MarkError::ChildBudgetExceeded);
                    }
                    let decoded = &self.children[..child_count];
                    for pair in decoded.windows(2) {
                        let left = fail_closed(output, pair[0].as_key())?;
                        let right = fail_closed(output, pair[1].as_key())?;
                        if left >= right {
                            output.clear(catalog.checkpoint_generation);
                            return Err(MarkError::MalformedReference);
                        }
                    }
                    for child in decoded.iter().rev() {
                        let child = fail_closed(output, child.as_key())?;
                        traversed_edges = match traversed_edges.checked_add(1) {
                            Some(value) => value,
                            None => {
                                output.clear(catalog.checkpoint_generation);
                                return Err(MarkError::ChildBudgetExceeded);
                            }
                        };
                        if output.live_objects.binary_search(&child).is_err() {
                            if let Err(error) =
                                insert_pending(&mut self.pending, child, self.budget.objects)
                            {
                                output.clear(catalog.checkpoint_generation);
                                return Err(error);
                            }
                        }
                    }
                }
                _ => {
                    output.clear(catalog.checkpoint_generation);
                    return Err(MarkError::UnknownReferenceCodec);
                }
            }
        }

        Ok(MarkStats {
            root_count: roots.len(),
            live_object_count: output.live_objects.len(),
            live_blob_count: output.live_blobs.len(),
            traversed_edges,
        })
    }
}

fn fail_closed<T>(output: &mut MarkPlan, result: Result<T, MarkError>) -> Result<T, MarkError> {
    result.inspect_err(|_| {
        output.live_objects.clear();
        output.live_blobs.clear();
    })
}

fn validate_catalog(catalog: CatalogView<'_>) -> Result<(), MarkError> {
    if catalog.checkpoint_generation == 0 {
        return Err(MarkError::UnsortedOrDuplicateCatalog);
    }
    for pair in catalog.objects.windows(2) {
        if pair[0].object_id >= pair[1].object_id {
            return Err(MarkError::UnsortedOrDuplicateCatalog);
        }
    }
    for pair in catalog.blobs.windows(2) {
        if pair[0].blob_key >= pair[1].blob_key {
            return Err(MarkError::UnsortedOrDuplicateCatalog);
        }
    }
    Ok(())
}

fn resolve_exact_object(
    objects: &[ObjectMapping],
    key: RootKey,
) -> Result<ObjectMapping, MarkError> {
    let index = objects
        .binary_search_by_key(&key.object_id(), |object| object.object_id)
        .map_err(|_| MarkError::MissingObject)?;
    let object = objects[index];
    if object.commit_generation != key.commit_generation() {
        return Err(MarkError::StaleObjectGeneration);
    }
    if object.blob_key.object_kind() != key.object_kind() {
        return Err(MarkError::ObjectKindMismatch);
    }
    Ok(object)
}

fn resolve_blob(blobs: &[BlobMapping], key: BlobKey) -> Result<BlobMapping, MarkError> {
    blobs
        .binary_search_by_key(&key, |blob| blob.blob_key)
        .map(|index| blobs[index])
        .map_err(|_| MarkError::MissingBlobMapping)
}

fn insert_pending(
    pending: &mut Vec<RootKey>,
    key: RootKey,
    capacity: usize,
) -> Result<(), MarkError> {
    if pending.contains(&key) {
        return Ok(());
    }
    if pending.len() == capacity {
        return Err(MarkError::ObjectBudgetExceeded);
    }
    pending.push(key);
    Ok(())
}

fn insert_sorted_unique<T: Copy + Ord>(
    values: &mut Vec<T>,
    value: T,
    capacity: usize,
    overflow: MarkError,
) -> Result<(), MarkError> {
    match values.binary_search(&value) {
        Ok(_) => Ok(()),
        Err(index) => {
            if values.len() == capacity {
                return Err(overflow);
            }
            values.insert(index, value);
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MarkStats {
    pub(crate) root_count: usize,
    pub(crate) live_object_count: usize,
    pub(crate) live_blob_count: usize,
    pub(crate) traversed_edges: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cas_codec::BlobKey;
    use vibeos_segment_format::{ExtentKind, PhysicalPointer, PointerValue, StoreUuid};

    fn blob(seed: u8) -> BlobKey {
        BlobKey::sha256(7, 1, [seed; 32]).unwrap()
    }

    fn object(id: u128, key: BlobKey, reference_codec: u16) -> ObjectMapping {
        ObjectMapping {
            object_id: id,
            blob_key: key,
            commit_generation: 4,
            reference_codec,
        }
    }

    fn blob_mapping(key: BlobKey, ordinal: u32) -> BlobMapping {
        BlobMapping {
            blob_key: key,
            manifest: PhysicalPointer::Value(PointerValue {
                store_uuid: StoreUuid::new([9; 16]).unwrap(),
                segment_no: u64::from(ordinal) + 1,
                segment_generation: u64::from(ordinal) + 1,
                descriptor_relative_page: ordinal + 2,
                payload_relative_page: ordinal + 3,
                payload_pages: 1,
                ordinal,
                exact_byte_len: 128 + 2 * 128,
                extent_kind: ExtentKind::Catalog,
                payload_sha256: [ordinal as u8; 32],
            }),
        }
    }

    fn root(id: u128) -> MarkRoot {
        MarkRoot {
            key: RootKey::new(id, 4, 7).unwrap(),
            class: RootClass::PersistentPolicy,
        }
    }

    struct Graph {
        edges: &'static [(u128, &'static [u128])],
    }

    impl TypedChildSource for Graph {
        type Error = ();

        fn read_children(
            &self,
            object: &ObjectMapping,
            out: &mut [ChildReference],
        ) -> Result<usize, Self::Error> {
            let children = self
                .edges
                .iter()
                .find(|(id, _)| *id == object.object_id)
                .map_or(&[][..], |(_, children)| *children);
            if children.len() > out.len() {
                return Ok(children.len());
            }
            for (slot, id) in out.iter_mut().zip(children) {
                *slot = ChildReference::new(*id, 4, 7).unwrap();
            }
            Ok(children.len())
        }
    }

    fn run(
        objects: &[ObjectMapping],
        blobs: &[BlobMapping],
        roots: &[MarkRoot],
        graph: &Graph,
        budget: MarkBudget,
    ) -> Result<MarkPlan, MarkError> {
        let mut planner = MarkPlanner::new(budget)?;
        let mut output = MarkPlan::with_budget(1, budget)?;
        planner.mark(
            CatalogView {
                checkpoint_generation: 4,
                objects,
                blobs,
            },
            roots,
            graph,
            &mut output,
        )?;
        Ok(output)
    }

    #[test]
    fn shared_blob_is_marked_once_across_independent_objects() {
        let shared = blob(1);
        let objects = [
            object(1, shared, REFERENCE_CODEC_RAW),
            object(2, shared, REFERENCE_CODEC_RAW),
        ];
        let blobs = [blob_mapping(shared, 1)];
        let output = run(
            &objects,
            &blobs,
            &[root(1), root(2)],
            &Graph { edges: &[] },
            MarkBudget::new(4, 2, 2, 4),
        )
        .unwrap();
        assert_eq!(output.live_objects().len(), 2);
        assert_eq!(output.live_blobs(), &[shared]);
        assert!(output.contains_blob(shared));
    }

    #[test]
    fn cycle_and_diamond_terminate_at_exact_visited_set() {
        let keys = [blob(1), blob(2), blob(3), blob(4)];
        let objects = [
            object(1, keys[0], REFERENCE_CODEC_TYPED_V1),
            object(2, keys[1], REFERENCE_CODEC_TYPED_V1),
            object(3, keys[2], REFERENCE_CODEC_TYPED_V1),
            object(4, keys[3], REFERENCE_CODEC_TYPED_V1),
        ];
        let mut blobs = [
            blob_mapping(keys[0], 1),
            blob_mapping(keys[1], 2),
            blob_mapping(keys[2], 3),
            blob_mapping(keys[3], 4),
        ];
        blobs.sort_by_key(|entry| entry.blob_key);
        let graph = Graph {
            edges: &[(1, &[2, 3]), (2, &[4]), (3, &[4]), (4, &[1])],
        };
        let output = run(
            &objects,
            &blobs,
            &[root(1)],
            &graph,
            MarkBudget::new(4, 4, 2, 2),
        )
        .unwrap();
        assert_eq!(output.live_objects().len(), 4);
        assert_eq!(output.live_blobs().len(), 4);
    }

    #[test]
    fn dangling_stale_and_kind_mismatch_edges_fail_closed() {
        let key = blob(1);
        let objects = [object(1, key, REFERENCE_CODEC_TYPED_V1)];
        let blobs = [blob_mapping(key, 1)];
        let graph = Graph {
            edges: &[(1, &[2])],
        };
        assert_eq!(
            run(
                &objects,
                &blobs,
                &[root(1)],
                &graph,
                MarkBudget::new(3, 2, 2, 2)
            )
            .unwrap_err(),
            MarkError::MissingObject
        );

        let stale_root = MarkRoot {
            key: RootKey::new(1, 3, 7).unwrap(),
            class: RootClass::Runtime,
        };
        assert_eq!(
            run(
                &objects,
                &blobs,
                &[stale_root],
                &Graph { edges: &[] },
                MarkBudget::new(2, 2, 2, 2)
            )
            .unwrap_err(),
            MarkError::StaleObjectGeneration
        );

        let wrong_kind = MarkRoot {
            key: RootKey::new(1, 4, 8).unwrap(),
            class: RootClass::ExplicitSnapshot,
        };
        assert_eq!(
            run(
                &objects,
                &blobs,
                &[wrong_kind],
                &Graph { edges: &[] },
                MarkBudget::new(2, 2, 2, 2)
            )
            .unwrap_err(),
            MarkError::ObjectKindMismatch
        );
    }

    #[test]
    fn bounded_objects_children_and_missing_blob_fail_closed() {
        let keys = [blob(1), blob(2)];
        let objects = [
            object(1, keys[0], REFERENCE_CODEC_TYPED_V1),
            object(2, keys[1], REFERENCE_CODEC_RAW),
        ];
        let mut blobs = [blob_mapping(keys[0], 1), blob_mapping(keys[1], 2)];
        blobs.sort_by_key(|entry| entry.blob_key);
        let graph = Graph {
            edges: &[(1, &[2])],
        };

        assert_eq!(
            run(
                &objects,
                &blobs,
                &[root(1)],
                &graph,
                MarkBudget::new(1, 2, 2, 2)
            )
            .unwrap_err(),
            MarkError::ObjectBudgetExceeded
        );
        assert_eq!(
            run(
                &objects,
                &blobs,
                &[root(1)],
                &graph,
                MarkBudget::new(2, 2, 0, 2)
            )
            .unwrap_err(),
            MarkError::InvalidBudget
        );
        assert_eq!(
            run(
                &objects,
                &blobs[..1],
                &[root(2)],
                &Graph { edges: &[] },
                MarkBudget::new(2, 2, 2, 2)
            )
            .unwrap_err(),
            MarkError::MissingBlobMapping
        );
    }

    #[test]
    fn every_mark_budget_accepts_exact_limit_and_rejects_limit_plus_one() {
        let keys = [blob(1), blob(2)];
        let objects = [
            object(1, keys[0], REFERENCE_CODEC_TYPED_V1),
            object(2, keys[1], REFERENCE_CODEC_RAW),
        ];
        let mut blobs = [blob_mapping(keys[0], 1), blob_mapping(keys[1], 2)];
        blobs.sort_by_key(|entry| entry.blob_key);
        let graph = Graph {
            edges: &[(1, &[2])],
        };
        assert_eq!(
            run(
                &objects,
                &blobs,
                &[root(1), root(2)],
                &graph,
                MarkBudget::new(2, 2, 1, 2),
            )
            .unwrap()
            .live_objects()
            .len(),
            2
        );
        assert_eq!(
            run(
                &objects,
                &blobs,
                &[root(1), root(2)],
                &graph,
                MarkBudget::new(2, 2, 1, 1),
            )
            .unwrap_err(),
            MarkError::RootBudgetExceeded
        );
        assert_eq!(
            run(
                &objects,
                &blobs,
                &[root(1)],
                &graph,
                MarkBudget::new(2, 1, 1, 1),
            )
            .unwrap_err(),
            MarkError::BlobBudgetExceeded
        );
        assert_eq!(
            run(
                &objects,
                &blobs,
                &[root(1)],
                &graph,
                MarkBudget::new(2, 2, 0, 1),
            )
            .unwrap_err(),
            MarkError::InvalidBudget
        );
        let too_many_children = Graph {
            edges: &[(1, &[2, 3])],
        };
        assert_eq!(
            run(
                &objects,
                &blobs,
                &[root(1)],
                &too_many_children,
                MarkBudget::new(3, 2, 1, 1),
            )
            .unwrap_err(),
            MarkError::ChildBudgetExceeded
        );
    }

    #[test]
    fn unsorted_or_duplicate_object_and_blob_catalogs_fail_closed() {
        let keys = [blob(1), blob(2)];
        let unsorted_objects = [
            object(2, keys[1], REFERENCE_CODEC_RAW),
            object(1, keys[0], REFERENCE_CODEC_RAW),
        ];
        let sorted_blobs = [blob_mapping(keys[0], 1), blob_mapping(keys[1], 2)];
        assert_eq!(
            run(
                &unsorted_objects,
                &sorted_blobs,
                &[root(1)],
                &Graph { edges: &[] },
                MarkBudget::new(2, 2, 1, 1),
            )
            .unwrap_err(),
            MarkError::UnsortedOrDuplicateCatalog
        );
        let sorted_objects = [
            object(1, keys[0], REFERENCE_CODEC_RAW),
            object(2, keys[1], REFERENCE_CODEC_RAW),
        ];
        let duplicate_blobs = [blob_mapping(keys[0], 1), blob_mapping(keys[0], 2)];
        assert_eq!(
            run(
                &sorted_objects,
                &duplicate_blobs,
                &[root(1)],
                &Graph { edges: &[] },
                MarkBudget::new(2, 2, 1, 1),
            )
            .unwrap_err(),
            MarkError::UnsortedOrDuplicateCatalog
        );
    }
}
