//! Exact 4096-byte page I/O over a capability-scoped block range.

use core::fmt;
use vibeos_segment_format::{Page, PAGE_SIZE};
use vibeos_storage_device::{
    validate_flush, validate_request, BlockIo, BlockRangeCapability, ContractError, DeviceGeometry,
    DeviceInfo, MutationFailure, MutationResult, Operation, RangeSession,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageDeviceInfo {
    pub device_id: [u8; 16],
    pub range_first_logical_block: u64,
    pub logical_block_count: u64,
    pub logical_block_size: u32,
    pub page_count: u64,
}

pub trait PageDevice {
    type Error;

    fn info(&self) -> PageDeviceInfo;
    async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error>;
    async fn write_page(&self, page: u64, input: &Page) -> MutationResult<(), Self::Error>;
    /// Read consecutive pages. Backends remain source-compatible through this
    /// bounded, ordered fallback; block backends override it with one request.
    async fn read_pages(&self, first_page: u64, output: &mut [Page]) -> Result<(), Self::Error> {
        for (offset, page) in output.iter_mut().enumerate() {
            let page_number = first_page.checked_add(offset as u64).unwrap_or(u64::MAX);
            self.read_page(page_number, page).await?;
        }
        Ok(())
    }
    /// Write consecutive pages without implying a flush. The caller retains
    /// the same publication/barrier responsibility as for `write_page`.
    async fn write_pages(
        &self,
        first_page: u64,
        input: &[Page],
    ) -> MutationResult<(), Self::Error> {
        for (offset, page) in input.iter().enumerate() {
            let page_number = first_page.checked_add(offset as u64).unwrap_or(u64::MAX);
            self.write_page(page_number, page).await?;
        }
        Ok(())
    }
    async fn flush(&self) -> MutationResult<(), Self::Error>;
}

/// A page device whose exact block authority can be enlarged by an adjacent
/// capability. Store code still cannot address the extra pages until a sealed
/// checkpoint admits them.
pub trait GrowablePageDevice: PageDevice {
    /// Validate the exact suffix capability and its boot/device incarnation
    /// without changing the device view.
    fn validate_growth(
        &self,
        durable_logical_block_count: u64,
        additional: BlockRangeCapability,
    ) -> Result<(), Self::Error>;

    /// Join `additional` to the range named by the currently selected store
    /// checkpoint. Implementations accept only an exact old binding or the
    /// exact enlarged binding, so cold recovery and retry after an interrupted
    /// checkpoint are idempotent without admitting unrelated capacity.
    fn admit_growth(
        &mut self,
        durable_logical_block_count: u64,
        additional: BlockRangeCapability,
    ) -> Result<PageDeviceInfo, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockPageError<E> {
    Contract(ContractError),
    Backend(E),
}

impl<E: fmt::Display> fmt::Display for BlockPageError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(f, "page I/O contract failed: {error}"),
            Self::Backend(error) => write!(f, "page I/O backend failed: {error}"),
        }
    }
}

pub struct BlockPageDevice<I> {
    io: I,
    binding: RangeSession,
    authority: BlockRangeCapability,
    info: PageDeviceInfo,
    geometry: DeviceGeometry,
    flush_required: bool,
}

impl<I: BlockIo> BlockPageDevice<I> {
    pub fn new(io: I, authority: BlockRangeCapability) -> Result<Self, BlockPageError<I::Error>> {
        let info = io.info().map_err(BlockPageError::Backend)?;
        if authority.session() != info.session() {
            return Err(BlockPageError::Contract(ContractError::StaleIncarnation));
        }
        let range = authority.range();
        let range_session = RangeSession::bind(range, info).map_err(BlockPageError::Contract)?;
        let geometry = info.geometry();
        let logical = u64::from(geometry.logical_block_size());
        if !(PAGE_SIZE as u64).is_multiple_of(logical) || !geometry.has_ordered_durability() {
            return Err(BlockPageError::Contract(ContractError::InvalidGeometry));
        }
        let blocks_per_page = PAGE_SIZE as u64 / logical;
        if blocks_per_page > u64::from(geometry.max_transfer_blocks())
            || !range.block_count().is_multiple_of(blocks_per_page)
        {
            return Err(BlockPageError::Contract(ContractError::InvalidGeometry));
        }
        range_session
            .validate_current(info)
            .map_err(BlockPageError::Contract)?;
        Ok(Self {
            io,
            binding: range_session,
            authority,
            info: PageDeviceInfo {
                device_id: range.device_id().get().to_le_bytes(),
                range_first_logical_block: range.first_block(),
                logical_block_count: range.block_count(),
                logical_block_size: geometry.logical_block_size(),
                page_count: range.block_count() / blocks_per_page,
            },
            geometry,
            flush_required: geometry.supports_flush(),
        })
    }

    pub fn into_inner(self) -> I {
        self.io
    }

    fn validate_growth_device_info(
        &self,
        raw: DeviceInfo,
        additional: BlockRangeCapability,
    ) -> Result<u64, BlockPageError<I::Error>> {
        self.binding
            .validate_current(raw)
            .map_err(BlockPageError::Contract)?;
        if raw.read_only() {
            return Err(BlockPageError::Contract(ContractError::ReadOnly));
        }
        let geometry = raw.geometry();
        if geometry != self.geometry || !geometry.has_ordered_durability() {
            return Err(BlockPageError::Contract(ContractError::InvalidGeometry));
        }
        let logical = u64::from(geometry.logical_block_size());
        if logical != u64::from(self.info.logical_block_size)
            || !(PAGE_SIZE as u64).is_multiple_of(logical)
        {
            return Err(BlockPageError::Contract(ContractError::InvalidGeometry));
        }
        let blocks_per_page = PAGE_SIZE as u64 / logical;
        if blocks_per_page > u64::from(geometry.max_transfer_blocks())
            || !additional
                .range()
                .block_count()
                .is_multiple_of(blocks_per_page)
        {
            return Err(BlockPageError::Contract(ContractError::InvalidGeometry));
        }
        if additional.session() != raw.session() {
            return Err(BlockPageError::Contract(ContractError::StaleIncarnation));
        }
        raw.admits(additional.range())
            .map_err(BlockPageError::Contract)?;
        Ok(blocks_per_page)
    }

    fn request_pages(
        &self,
        operation: Operation,
        first_page: u64,
        page_count: usize,
    ) -> Result<vibeos_storage_device::ValidatedRequest, BlockPageError<I::Error>> {
        let page_count_u64 = u64::try_from(page_count)
            .map_err(|_| BlockPageError::Contract(ContractError::ArithmeticOverflow))?;
        let page_end = first_page
            .checked_add(page_count_u64)
            .ok_or(BlockPageError::Contract(ContractError::ArithmeticOverflow))?;
        if page_count == 0 || page_end > self.info.page_count {
            return Err(BlockPageError::Contract(ContractError::OutsideRange));
        }
        let info = self.io.info().map_err(BlockPageError::Backend)?;
        let blocks_per_page = (PAGE_SIZE as u32) / info.geometry().logical_block_size();
        let first = first_page
            .checked_mul(u64::from(blocks_per_page))
            .ok_or(BlockPageError::Contract(ContractError::ArithmeticOverflow))?;
        let block_count = blocks_per_page
            .checked_mul(
                u32::try_from(page_count)
                    .map_err(|_| BlockPageError::Contract(ContractError::ArithmeticOverflow))?,
            )
            .ok_or(BlockPageError::Contract(ContractError::ArithmeticOverflow))?;
        let byte_len = PAGE_SIZE
            .checked_mul(page_count)
            .ok_or(BlockPageError::Contract(ContractError::ArithmeticOverflow))?;
        validate_request(self.binding, info, operation, first, block_count, byte_len)
            .map_err(BlockPageError::Contract)
    }

    fn request(
        &self,
        operation: Operation,
        page: u64,
    ) -> Result<vibeos_storage_device::ValidatedRequest, BlockPageError<I::Error>> {
        self.request_pages(operation, page, 1)
    }
}

impl<I: BlockIo> PageDevice for BlockPageDevice<I> {
    type Error = BlockPageError<I::Error>;

    fn info(&self) -> PageDeviceInfo {
        self.info
    }

    async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
        let request = self.request(Operation::Read, page)?;
        self.io
            .read(request, output)
            .await
            .map_err(BlockPageError::Backend)
    }

    async fn write_page(&self, page: u64, input: &Page) -> MutationResult<(), Self::Error> {
        let request = self
            .request(Operation::Write { fua: false }, page)
            .map_err(MutationFailure::not_submitted)?;
        self.io
            .write(request, input)
            .await
            .map(|_| ())
            .map_err(|error| error.map(BlockPageError::Backend))
    }

    async fn read_pages(&self, first_page: u64, output: &mut [Page]) -> Result<(), Self::Error> {
        if output.is_empty() {
            return Ok(());
        }
        let request = self.request_pages(Operation::Read, first_page, output.len())?;
        self.io
            .read(request, output.as_flattened_mut())
            .await
            .map_err(BlockPageError::Backend)
    }

    async fn write_pages(
        &self,
        first_page: u64,
        input: &[Page],
    ) -> MutationResult<(), Self::Error> {
        if input.is_empty() {
            return Ok(());
        }
        let request = self
            .request_pages(Operation::Write { fua: false }, first_page, input.len())
            .map_err(MutationFailure::not_submitted)?;
        self.io
            .write(request, input.as_flattened())
            .await
            .map(|_| ())
            .map_err(|error| error.map(BlockPageError::Backend))
    }

    async fn flush(&self) -> MutationResult<(), Self::Error> {
        if !self.flush_required {
            return Ok(());
        }
        let info = self
            .io
            .info()
            .map_err(|error| MutationFailure::not_submitted(BlockPageError::Backend(error)))?;
        let request = validate_flush(self.binding, info)
            .map_err(|error| MutationFailure::not_submitted(BlockPageError::Contract(error)))?;
        self.io
            .flush(request)
            .await
            .map_err(|error| error.map(BlockPageError::Backend))
    }
}

impl<I: BlockIo> GrowablePageDevice for BlockPageDevice<I> {
    fn validate_growth(
        &self,
        durable_logical_block_count: u64,
        additional: BlockRangeCapability,
    ) -> Result<(), Self::Error> {
        let current_range = self.binding.range();
        let additional_range = additional.range();
        if !self.authority.same_authority_domain(additional) {
            return Err(BlockPageError::Contract(
                if self.authority.session().device_id() != additional.session().device_id() {
                    ContractError::WrongDevice
                } else if self.authority.session() != additional.session() {
                    ContractError::StaleIncarnation
                } else {
                    ContractError::OutsideRange
                },
            ));
        }
        let raw = self.io.info().map_err(BlockPageError::Backend)?;
        let blocks_per_page = self.validate_growth_device_info(raw, additional)?;
        let durable_end = current_range
            .first_block()
            .checked_add(durable_logical_block_count)
            .ok_or(BlockPageError::Contract(ContractError::ArithmeticOverflow))?;
        if additional_range.first_block() < durable_end {
            return Err(BlockPageError::Contract(ContractError::OverlappingRange));
        }
        if additional_range.first_block() != durable_end {
            return Err(BlockPageError::Contract(ContractError::OutsideRange));
        }
        let enlarged_count = durable_logical_block_count
            .checked_add(additional_range.block_count())
            .ok_or(BlockPageError::Contract(ContractError::ArithmeticOverflow))?;
        if current_range.block_count() != durable_logical_block_count
            && current_range.block_count() != enlarged_count
        {
            return Err(BlockPageError::Contract(ContractError::OutsideRange));
        }
        if current_range.block_count() == durable_logical_block_count {
            let enlarged = self
                .authority
                .join_adjacent(additional)
                .map_err(BlockPageError::Contract)?
                .range();
            RangeSession::bind(enlarged, raw).map_err(BlockPageError::Contract)?;
        } else if !current_range.contains(additional_range) {
            return Err(BlockPageError::Contract(ContractError::OutsideRange));
        }
        if !enlarged_count.is_multiple_of(blocks_per_page) {
            return Err(BlockPageError::Contract(ContractError::InvalidGeometry));
        }
        Ok(())
    }

    fn admit_growth(
        &mut self,
        durable_logical_block_count: u64,
        additional: BlockRangeCapability,
    ) -> Result<PageDeviceInfo, Self::Error> {
        self.validate_growth(durable_logical_block_count, additional)?;
        let current_range = self.binding.range();
        let additional_range = additional.range();
        let durable_end = current_range
            .first_block()
            .checked_add(durable_logical_block_count)
            .ok_or(BlockPageError::Contract(ContractError::ArithmeticOverflow))?;
        if additional_range.first_block() < durable_end {
            return Err(BlockPageError::Contract(ContractError::OverlappingRange));
        }
        if additional_range.first_block() != durable_end {
            return Err(BlockPageError::Contract(ContractError::OutsideRange));
        }
        let raw = self.io.info().map_err(BlockPageError::Backend)?;
        let blocks_per_page = self.validate_growth_device_info(raw, additional)?;
        let enlarged_count = durable_logical_block_count
            .checked_add(additional_range.block_count())
            .ok_or(BlockPageError::Contract(ContractError::ArithmeticOverflow))?;
        if current_range.block_count() != durable_logical_block_count
            && current_range.block_count() != enlarged_count
        {
            return Err(BlockPageError::Contract(ContractError::OutsideRange));
        }

        if current_range.block_count() == durable_logical_block_count {
            let enlarged_authority = self
                .authority
                .join_adjacent(additional)
                .map_err(BlockPageError::Contract)?;
            let enlarged = enlarged_authority.range();
            // The supplied capability must cover the complete appended suffix;
            // joining it never discovers capacity from the raw device alone.
            if enlarged
                .attenuate(durable_logical_block_count, additional_range.block_count())
                .map_err(BlockPageError::Contract)?
                != additional_range
            {
                return Err(BlockPageError::Contract(ContractError::OutsideRange));
            }
            self.binding = RangeSession::bind(enlarged, raw).map_err(BlockPageError::Contract)?;
            self.authority = enlarged_authority;
        } else if !current_range.contains(additional_range) {
            return Err(BlockPageError::Contract(ContractError::OutsideRange));
        }

        if !enlarged_count.is_multiple_of(blocks_per_page) {
            return Err(BlockPageError::Contract(ContractError::InvalidGeometry));
        }
        self.info.logical_block_count = enlarged_count;
        self.info.page_count = enlarged_count / blocks_per_page;
        Ok(self.info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::future::Future;
    use core::pin::pin;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Poll, Waker};
    use std::future::{ready, Ready};
    use std::sync::{Arc, Mutex};
    use std::task::Wake;
    use vibeos_storage_device::{
        BlockRangeProvisioner, DeviceId, DeviceSession, ValidatedFlush, ValidatedRequest,
        WriteCache, WriteDurability,
    };

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        let mut future = pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[derive(Clone)]
    struct MutableBlockIo {
        info: Arc<Mutex<DeviceInfo>>,
        mutations: Arc<AtomicUsize>,
    }

    impl MutableBlockIo {
        fn new(info: DeviceInfo) -> Self {
            Self {
                info: Arc::new(Mutex::new(info)),
                mutations: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn replace_info(&self, info: DeviceInfo) {
            *self.info.lock().unwrap() = info;
        }

        fn mutations(&self) -> usize {
            self.mutations.load(Ordering::Acquire)
        }
    }

    impl BlockIo for MutableBlockIo {
        type Error = ();
        type ReadFuture<'a> = Ready<Result<(), Self::Error>>;
        type WriteFuture<'a> = Ready<MutationResult<WriteDurability, Self::Error>>;
        type FlushFuture<'a> = Ready<MutationResult<(), Self::Error>>;

        fn info(&self) -> Result<DeviceInfo, Self::Error> {
            Ok(*self.info.lock().unwrap())
        }

        fn read<'a>(
            &'a self,
            _request: ValidatedRequest,
            _output: &'a mut [u8],
        ) -> Self::ReadFuture<'a> {
            ready(Ok(()))
        }

        fn write<'a>(
            &'a self,
            _request: ValidatedRequest,
            _input: &'a [u8],
        ) -> Self::WriteFuture<'a> {
            self.mutations.fetch_add(1, Ordering::AcqRel);
            ready(Ok(WriteDurability::RequiresFlush))
        }

        fn flush(&self, _request: ValidatedFlush) -> Self::FlushFuture<'_> {
            self.mutations.fetch_add(1, Ordering::AcqRel);
            ready(Ok(()))
        }
    }

    fn geometry(max_transfer_blocks: u32, supports_flush: bool) -> DeviceGeometry {
        DeviceGeometry::new(
            512,
            Some(4096),
            8,
            0,
            max_transfer_blocks,
            None,
            WriteCache::Volatile,
            supports_flush,
            false,
            None,
        )
        .unwrap()
    }

    fn session(incarnation: u64) -> DeviceSession {
        DeviceSession::new(DeviceId::new(7).unwrap(), incarnation).unwrap()
    }

    fn info(session: DeviceSession, read_only: bool, geometry: DeviceGeometry) -> DeviceInfo {
        DeviceInfo::new(session, 4_096, read_only, geometry).unwrap()
    }

    #[test]
    fn growth_rechecks_read_only_session_and_geometry_before_addressability() {
        let current = session(1);
        // SAFETY: this fixture is the sole provisioning policy for its
        // in-memory device/session and derives both adjacent children.
        let ranges = unsafe { BlockRangeProvisioner::new(current, 0, 4_096) }.unwrap();
        let initial = ranges.derive(0, 2_048).unwrap();
        let suffix = ranges.derive(2_048, 2_048).unwrap();
        let io = MutableBlockIo::new(info(current, false, geometry(8, true)));
        let mut device = BlockPageDevice::new(io.clone(), initial).unwrap();

        let rejected = [
            info(current, true, geometry(8, true)),
            info(session(2), false, geometry(8, true)),
            info(current, false, geometry(16, true)),
            info(current, false, geometry(8, false)),
        ];
        for candidate in rejected {
            io.replace_info(candidate);
            assert!(device.admit_growth(2_048, suffix).is_err());
            assert_eq!(device.info().logical_block_count, 2_048);
            assert_eq!(io.mutations(), 0);
        }
    }

    #[test]
    fn block_page_batch_is_one_validated_backend_request() {
        let current = session(1);
        // SAFETY: this fixture owns the complete in-memory device authority.
        let ranges = unsafe { BlockRangeProvisioner::new(current, 0, 4_096) }.unwrap();
        let authority = ranges.derive(0, 4_096).unwrap();
        let io = MutableBlockIo::new(info(current, false, geometry(256, true)));
        let device = BlockPageDevice::new(io.clone(), authority).unwrap();
        let pages = [[0x31; PAGE_SIZE], [0x72; PAGE_SIZE]];

        block_on(device.write_pages(7, &pages)).unwrap();
        assert_eq!(io.mutations(), 1, "two pages must remain one block request");
    }
}
