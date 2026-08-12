//! Exact 4096-byte page I/O over a capability-scoped block range.

use core::fmt;
use vibeos_segment_format::{Page, PAGE_SIZE};
use vibeos_storage_device::{
    validate_flush, validate_request, BlockIo, BlockRange, ContractError, MutationFailure,
    MutationResult, Operation, RangeSession,
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
    async fn flush(&self) -> MutationResult<(), Self::Error>;
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
    info: PageDeviceInfo,
    flush_required: bool,
}

impl<I: BlockIo> BlockPageDevice<I> {
    pub fn new(io: I, range: BlockRange) -> Result<Self, BlockPageError<I::Error>> {
        let info = io.info().map_err(BlockPageError::Backend)?;
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
            info: PageDeviceInfo {
                device_id: range.device_id().get().to_le_bytes(),
                range_first_logical_block: range.first_block(),
                logical_block_count: range.block_count(),
                logical_block_size: geometry.logical_block_size(),
                page_count: range.block_count() / blocks_per_page,
            },
            flush_required: geometry.supports_flush(),
        })
    }

    pub fn into_inner(self) -> I {
        self.io
    }

    fn request(
        &self,
        operation: Operation,
        page: u64,
    ) -> Result<vibeos_storage_device::ValidatedRequest, BlockPageError<I::Error>> {
        if page >= self.info.page_count {
            return Err(BlockPageError::Contract(ContractError::OutsideRange));
        }
        let info = self.io.info().map_err(BlockPageError::Backend)?;
        let blocks_per_page = (PAGE_SIZE as u32) / info.geometry().logical_block_size();
        let first = page
            .checked_mul(u64::from(blocks_per_page))
            .ok_or(BlockPageError::Contract(ContractError::ArithmeticOverflow))?;
        validate_request(
            self.binding,
            info,
            operation,
            first,
            blocks_per_page,
            PAGE_SIZE,
        )
        .map_err(BlockPageError::Contract)
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
