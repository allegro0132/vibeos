use alloc::vec::Vec;

use vibeos_core::cap::CSpace;
use vibeos_core::sync::SpinLock;

use crate::{
    AuthorityError, BlobError, BlobResource, ClockError, ClockResource, ComponentAuthority,
    ComponentHostResource, RandomError, RandomResource, StructuredLogError, StructuredLogEvent,
    StructuredLogResource,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentCallError<E> {
    Authority(AuthorityError),
    Resource(E),
}

/// Stateless operation-time entry points used by a future component dispatcher.
/// They carry no capabilities or backend handles of their own.
pub struct ComponentHostServices;

impl ComponentHostServices {
    pub fn clock_now_ns(
        authority: &ComponentAuthority,
        cspace: &SpinLock<CSpace>,
    ) -> Result<u64, ComponentCallError<ClockError>> {
        authority
            .with_resource::<ClockResource, _, _>(
                cspace,
                ClockResource::OPERATION_RIGHTS,
                ClockResource::now_ns,
            )
            .map_err(ComponentCallError::Authority)?
            .map_err(ComponentCallError::Resource)
    }

    pub fn random_fill_exact(
        authority: &ComponentAuthority,
        cspace: &SpinLock<CSpace>,
        destination: &mut [u8],
    ) -> Result<(), ComponentCallError<RandomError>> {
        authority
            .with_resource::<RandomResource, _, _>(
                cspace,
                RandomResource::OPERATION_RIGHTS,
                |random| random.fill_exact(destination),
            )
            .map_err(ComponentCallError::Authority)?
            .map_err(ComponentCallError::Resource)
    }

    pub fn blob_len(
        authority: &ComponentAuthority,
        cspace: &SpinLock<CSpace>,
    ) -> Result<u64, ComponentCallError<BlobError>> {
        authority
            .with_resource::<BlobResource, _, _>(
                cspace,
                BlobResource::OPERATION_RIGHTS,
                BlobResource::len,
            )
            .map_err(ComponentCallError::Authority)?
            .map_err(ComponentCallError::Resource)
    }

    pub fn blob_read(
        authority: &ComponentAuthority,
        cspace: &SpinLock<CSpace>,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, ComponentCallError<BlobError>> {
        authority
            .with_resource::<BlobResource, _, _>(cspace, BlobResource::OPERATION_RIGHTS, |blob| {
                blob.read(offset, length)
            })
            .map_err(ComponentCallError::Authority)?
            .map_err(ComponentCallError::Resource)
    }

    pub fn structured_log_write(
        authority: &ComponentAuthority,
        cspace: &SpinLock<CSpace>,
        event: &StructuredLogEvent<'_>,
    ) -> Result<(), ComponentCallError<StructuredLogError>> {
        authority
            .with_resource::<StructuredLogResource, _, _>(
                cspace,
                StructuredLogResource::OPERATION_RIGHTS,
                |log| log.write(event),
            )
            .map_err(ComponentCallError::Authority)?
            .map_err(ComponentCallError::Resource)
    }
}
