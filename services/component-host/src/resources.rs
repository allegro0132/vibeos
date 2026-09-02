use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::str;
use core::sync::atomic::{AtomicU64, Ordering};

use vibeos_core::cap::{Resource, Rights};

use crate::{ComponentHostResource, HostResourceKind};

pub const MAX_RANDOM_FILL_BYTES: usize = 4096;
pub const MAX_BLOB_READ_BYTES: usize = 4096;
pub const MAX_LOG_TARGET_BYTES: usize = 64;
pub const MAX_LOG_MESSAGE_BYTES: usize = 2048;
pub const MAX_LOG_FIELDS: usize = 16;
pub const MAX_LOG_FIELD_KEY_BYTES: usize = 64;
pub const MAX_LOG_FIELD_VALUE_BYTES: usize = 256;
pub const MAX_LOG_EVENT_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockBackendFault;

pub trait ClockBackend: Send + Sync {
    fn now_ns(&self) -> Result<u64, ClockBackendFault>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockError {
    BackendFault,
    NonMonotonic,
}

/// Monotonic clock authority. The backend is private and cannot be recovered
/// from the resource.
pub struct ClockResource {
    backend: Arc<dyn ClockBackend>,
    last_ns: AtomicU64,
}

impl ClockResource {
    pub fn new(backend: Arc<dyn ClockBackend>) -> Self {
        Self {
            backend,
            last_ns: AtomicU64::new(0),
        }
    }

    pub fn now_ns(&self) -> Result<u64, ClockError> {
        let now = self
            .backend
            .now_ns()
            .map_err(|_| ClockError::BackendFault)?;
        let mut previous = self.last_ns.load(Ordering::Acquire);
        loop {
            if now < previous {
                return Err(ClockError::NonMonotonic);
            }
            match self.last_ns.compare_exchange_weak(
                previous,
                now,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(now),
                Err(observed) => previous = observed,
            }
        }
    }
}

impl Resource for ClockResource {
    fn kind(&self) -> &'static str {
        "component-clock"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ComponentHostResource for ClockResource {
    const HOST_KIND: HostResourceKind = HostResourceKind::Clock;
    const OPERATION_RIGHTS: Rights = Rights::READ;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomBackendFault;

pub trait RandomBackend: Send + Sync {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomBackendFault>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomError {
    TooLarge { requested: usize, maximum: usize },
    Allocation,
    BackendFault,
}

/// Bounded random-byte authority. Output is staged so a backend fault cannot
/// expose a partially filled caller buffer.
pub struct RandomResource {
    backend: Arc<dyn RandomBackend>,
}

impl RandomResource {
    pub fn new(backend: Arc<dyn RandomBackend>) -> Self {
        Self { backend }
    }

    pub fn fill_exact(&self, destination: &mut [u8]) -> Result<(), RandomError> {
        if destination.len() > MAX_RANDOM_FILL_BYTES {
            return Err(RandomError::TooLarge {
                requested: destination.len(),
                maximum: MAX_RANDOM_FILL_BYTES,
            });
        }
        if destination.is_empty() {
            return Ok(());
        }
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(destination.len())
            .map_err(|_| RandomError::Allocation)?;
        staged.resize(destination.len(), 0);
        self.backend
            .fill(&mut staged)
            .map_err(|_| RandomError::BackendFault)?;
        destination.copy_from_slice(&staged);
        Ok(())
    }
}

impl Resource for RandomResource {
    fn kind(&self) -> &'static str {
        "component-random"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ComponentHostResource for RandomResource {
    const HOST_KIND: HostResourceKind = HostResourceKind::Random;
    const OPERATION_RIGHTS: Rights = Rights::READ;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobBackendFault;

pub trait BlobBackend: Send + Sync {
    fn len(&self) -> Result<u64, BlobBackendFault>;
    fn is_empty(&self) -> Result<bool, BlobBackendFault> {
        self.len().map(|length| length == 0)
    }
    fn read_exact(&self, offset: u64, destination: &mut [u8]) -> Result<(), BlobBackendFault>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobError {
    TooLarge {
        requested: usize,
        maximum: usize,
    },
    RangeOverflow,
    OutOfBounds {
        offset: u64,
        length: usize,
        blob_length: u64,
    },
    Allocation,
    BackendFault,
}

/// Read-only, bounded blob authority.
pub struct BlobResource {
    backend: Arc<dyn BlobBackend>,
}

impl BlobResource {
    pub fn new(backend: Arc<dyn BlobBackend>) -> Self {
        Self { backend }
    }

    pub fn len(&self) -> Result<u64, BlobError> {
        self.backend.len().map_err(|_| BlobError::BackendFault)
    }

    pub fn is_empty(&self) -> Result<bool, BlobError> {
        self.len().map(|length| length == 0)
    }

    pub fn read(&self, offset: u64, length: usize) -> Result<Vec<u8>, BlobError> {
        if length > MAX_BLOB_READ_BYTES {
            return Err(BlobError::TooLarge {
                requested: length,
                maximum: MAX_BLOB_READ_BYTES,
            });
        }
        let length_u64 = u64::try_from(length).map_err(|_| BlobError::RangeOverflow)?;
        let end = offset
            .checked_add(length_u64)
            .ok_or(BlobError::RangeOverflow)?;
        let mut bytes = Vec::new();
        if length != 0 {
            bytes
                .try_reserve_exact(length)
                .map_err(|_| BlobError::Allocation)?;
            bytes.resize(length, 0);
        }
        let blob_length = self.len()?;
        if end > blob_length {
            return Err(BlobError::OutOfBounds {
                offset,
                length,
                blob_length,
            });
        }
        if length != 0 {
            self.backend
                .read_exact(offset, &mut bytes)
                .map_err(|_| BlobError::BackendFault)?;
        }
        Ok(bytes)
    }
}

impl Resource for BlobResource {
    fn kind(&self) -> &'static str {
        "component-blob"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ComponentHostResource for BlobResource {
    const HOST_KIND: HostResourceKind = HostResourceKind::Blob;
    const OPERATION_RIGHTS: Rights = Rights::READ;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogField<'a> {
    pub key: &'a [u8],
    pub value: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StructuredLogEvent<'a> {
    pub level: LogLevel,
    pub target: &'a [u8],
    pub message: &'a [u8],
    pub fields: &'a [LogField<'a>],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedLogField<'a> {
    pub key: &'a str,
    pub value: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ValidatedLogEvent<'a> {
    pub level: LogLevel,
    pub target: &'a str,
    pub message: &'a str,
    pub fields: &'a [ValidatedLogField<'a>],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StructuredLogSinkFault;

/// Receives only UTF-8 records whose individual and aggregate sizes have
/// already passed the public bounds below.
pub trait StructuredLogSink: Send + Sync {
    fn write(&self, event: &ValidatedLogEvent<'_>) -> Result<(), StructuredLogSinkFault>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StructuredLogError {
    EmptyTarget,
    EmptyFieldKey {
        index: usize,
    },
    InvalidTargetUtf8,
    InvalidMessageUtf8,
    InvalidFieldKeyUtf8 {
        index: usize,
    },
    InvalidFieldValueUtf8 {
        index: usize,
    },
    TargetTooLong {
        length: usize,
        maximum: usize,
    },
    MessageTooLong {
        length: usize,
        maximum: usize,
    },
    TooManyFields {
        count: usize,
        maximum: usize,
    },
    FieldKeyTooLong {
        index: usize,
        length: usize,
        maximum: usize,
    },
    FieldValueTooLong {
        index: usize,
        length: usize,
        maximum: usize,
    },
    EventTooLarge {
        length: usize,
        maximum: usize,
    },
    Allocation,
    BackendFault,
}

/// Strict UTF-8, bounded structured-log authority.
pub struct StructuredLogResource {
    sink: Arc<dyn StructuredLogSink>,
}

impl StructuredLogResource {
    pub fn new(sink: Arc<dyn StructuredLogSink>) -> Self {
        Self { sink }
    }

    pub fn write(&self, event: &StructuredLogEvent<'_>) -> Result<(), StructuredLogError> {
        if event.target.is_empty() {
            return Err(StructuredLogError::EmptyTarget);
        }
        if event.target.len() > MAX_LOG_TARGET_BYTES {
            return Err(StructuredLogError::TargetTooLong {
                length: event.target.len(),
                maximum: MAX_LOG_TARGET_BYTES,
            });
        }
        if event.message.len() > MAX_LOG_MESSAGE_BYTES {
            return Err(StructuredLogError::MessageTooLong {
                length: event.message.len(),
                maximum: MAX_LOG_MESSAGE_BYTES,
            });
        }
        if event.fields.len() > MAX_LOG_FIELDS {
            return Err(StructuredLogError::TooManyFields {
                count: event.fields.len(),
                maximum: MAX_LOG_FIELDS,
            });
        }

        let target =
            str::from_utf8(event.target).map_err(|_| StructuredLogError::InvalidTargetUtf8)?;
        let message =
            str::from_utf8(event.message).map_err(|_| StructuredLogError::InvalidMessageUtf8)?;
        let mut total = event.target.len().checked_add(event.message.len()).ok_or(
            StructuredLogError::EventTooLarge {
                length: usize::MAX,
                maximum: MAX_LOG_EVENT_BYTES,
            },
        )?;
        let mut fields = Vec::new();
        fields
            .try_reserve_exact(event.fields.len())
            .map_err(|_| StructuredLogError::Allocation)?;
        for (index, field) in event.fields.iter().enumerate() {
            if field.key.is_empty() {
                return Err(StructuredLogError::EmptyFieldKey { index });
            }
            if field.key.len() > MAX_LOG_FIELD_KEY_BYTES {
                return Err(StructuredLogError::FieldKeyTooLong {
                    index,
                    length: field.key.len(),
                    maximum: MAX_LOG_FIELD_KEY_BYTES,
                });
            }
            if field.value.len() > MAX_LOG_FIELD_VALUE_BYTES {
                return Err(StructuredLogError::FieldValueTooLong {
                    index,
                    length: field.value.len(),
                    maximum: MAX_LOG_FIELD_VALUE_BYTES,
                });
            }
            let key = str::from_utf8(field.key)
                .map_err(|_| StructuredLogError::InvalidFieldKeyUtf8 { index })?;
            let value = str::from_utf8(field.value)
                .map_err(|_| StructuredLogError::InvalidFieldValueUtf8 { index })?;
            total = total
                .checked_add(field.key.len())
                .and_then(|length| length.checked_add(field.value.len()))
                .ok_or(StructuredLogError::EventTooLarge {
                    length: usize::MAX,
                    maximum: MAX_LOG_EVENT_BYTES,
                })?;
            fields.push(ValidatedLogField { key, value });
        }
        if total > MAX_LOG_EVENT_BYTES {
            return Err(StructuredLogError::EventTooLarge {
                length: total,
                maximum: MAX_LOG_EVENT_BYTES,
            });
        }

        self.sink
            .write(&ValidatedLogEvent {
                level: event.level,
                target,
                message,
                fields: &fields,
            })
            .map_err(|_| StructuredLogError::BackendFault)
    }
}

impl Resource for StructuredLogResource {
    fn kind(&self) -> &'static str {
        "component-structured-log"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ComponentHostResource for StructuredLogResource {
    const HOST_KIND: HostResourceKind = HostResourceKind::StructuredLog;
    const OPERATION_RIGHTS: Rights = Rights::WRITE;
}
