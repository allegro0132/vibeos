//! Pinned scalar encodings for Vibe's native async Canonical ABI revision.
//!
//! These helpers deliberately model only the values exchanged with Core
//! Wasm. Resource tables, waitable ownership, and callback scheduling live in
//! the executor and must validate their own generational identities.

/// A canonical stream or future operation parked on a waitable.
pub const BLOCKED: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CallbackCode {
    Exit = 0,
    Yield = 1,
    Wait = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EventCode {
    None = 0,
    Subtask = 1,
    StreamRead = 2,
    StreamWrite = 3,
    FutureRead = 4,
    FutureWrite = 5,
    TaskCancelled = 6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CopyResult {
    Completed = 0,
    Dropped = 1,
    Cancelled = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum AsyncAbiError {
    InvalidCallbackCode = 1,
    InvalidCopyResult = 2,
    ProgressLimit = 3,
    BlockedHasNoEvent = 4,
    InvalidEndpointPair = 5,
}

impl AsyncAbiError {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallbackResult {
    pub code: CallbackCode,
    /// Present only for `Wait`; the packed ABI stores it above the low nibble.
    pub waitable_set: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamCopyResult {
    pub result: CopyResult,
    /// Number of elements copied, stored in the upper 28 bits.
    pub progress: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointPair {
    pub readable: u32,
    pub writable: u32,
}

pub const fn pack_endpoint_pair(pair: EndpointPair) -> Result<u64, AsyncAbiError> {
    if pair.readable == 0 || pair.writable == 0 || pair.readable == pair.writable {
        return Err(AsyncAbiError::InvalidEndpointPair);
    }
    Ok(pair.readable as u64 | ((pair.writable as u64) << 32))
}

pub const fn unpack_endpoint_pair(raw: u64) -> Result<EndpointPair, AsyncAbiError> {
    let pair = EndpointPair {
        readable: raw as u32,
        writable: (raw >> 32) as u32,
    };
    if pair.readable == 0 || pair.writable == 0 || pair.readable == pair.writable {
        return Err(AsyncAbiError::InvalidEndpointPair);
    }
    Ok(pair)
}

pub const fn unpack_callback_result(raw: u32) -> Result<CallbackResult, AsyncAbiError> {
    let waitable_set = raw >> 4;
    match raw & 0x0f {
        0 => Ok(CallbackResult {
            code: CallbackCode::Exit,
            waitable_set: None,
        }),
        1 => Ok(CallbackResult {
            code: CallbackCode::Yield,
            waitable_set: None,
        }),
        2 => Ok(CallbackResult {
            code: CallbackCode::Wait,
            waitable_set: Some(waitable_set),
        }),
        _ => Err(AsyncAbiError::InvalidCallbackCode),
    }
}

pub const fn pack_callback_wait(waitable_set: u32) -> Result<u32, AsyncAbiError> {
    if waitable_set >= (1_u32 << 28) {
        return Err(AsyncAbiError::InvalidCallbackCode);
    }
    Ok((waitable_set << 4) | CallbackCode::Wait as u32)
}

pub const fn pack_stream_copy_result(
    result: CopyResult,
    progress: u32,
) -> Result<u32, AsyncAbiError> {
    if progress >= (1_u32 << 28) {
        return Err(AsyncAbiError::ProgressLimit);
    }
    Ok((progress << 4) | result as u32)
}

pub const fn unpack_stream_copy_result(raw: u32) -> Result<StreamCopyResult, AsyncAbiError> {
    if raw == BLOCKED {
        return Err(AsyncAbiError::BlockedHasNoEvent);
    }
    match unpack_copy_result(raw & 0x0f) {
        Ok(result) => Ok(StreamCopyResult {
            result,
            progress: raw >> 4,
        }),
        Err(error) => Err(error),
    }
}

pub const fn unpack_future_copy_result(raw: u32) -> Result<CopyResult, AsyncAbiError> {
    if raw == BLOCKED {
        return Err(AsyncAbiError::BlockedHasNoEvent);
    }
    if raw & !0x0f != 0 {
        return Err(AsyncAbiError::InvalidCopyResult);
    }
    unpack_copy_result(raw)
}

const fn unpack_copy_result(raw: u32) -> Result<CopyResult, AsyncAbiError> {
    match raw {
        0 => Ok(CopyResult::Completed),
        1 => Ok(CopyResult::Dropped),
        2 => Ok(CopyResult::Cancelled),
        _ => Err(AsyncAbiError::InvalidCopyResult),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_results_use_the_pinned_low_nibble_encoding() {
        assert_eq!(
            unpack_callback_result(0),
            Ok(CallbackResult {
                code: CallbackCode::Exit,
                waitable_set: None,
            })
        );
        assert_eq!(
            unpack_callback_result(1),
            Ok(CallbackResult {
                code: CallbackCode::Yield,
                waitable_set: None,
            })
        );
        assert_eq!(pack_callback_wait(0x0fff_ffff), Ok(0xffff_fff2));
        assert_eq!(
            unpack_callback_result(0xffff_fff2),
            Ok(CallbackResult {
                code: CallbackCode::Wait,
                waitable_set: Some(0x0fff_ffff),
            })
        );
        // The upper 28 bits are ignored for EXIT/YIELD by the pinned spec.
        assert_eq!(
            unpack_callback_result(0xffff_fff0),
            Ok(CallbackResult {
                code: CallbackCode::Exit,
                waitable_set: None,
            })
        );
        assert_eq!(
            unpack_callback_result(3),
            Err(AsyncAbiError::InvalidCallbackCode)
        );
    }

    #[test]
    fn stream_results_round_trip_maximum_progress() {
        let raw = pack_stream_copy_result(CopyResult::Cancelled, 0x0fff_ffff).unwrap();
        assert_eq!(raw, 0xffff_fff2);
        assert_eq!(
            unpack_stream_copy_result(raw),
            Ok(StreamCopyResult {
                result: CopyResult::Cancelled,
                progress: 0x0fff_ffff,
            })
        );
        assert_eq!(
            pack_stream_copy_result(CopyResult::Completed, 1_u32 << 28),
            Err(AsyncAbiError::ProgressLimit)
        );
    }

    #[test]
    fn blocked_and_adjacent_copy_codes_are_not_completion_events() {
        assert_eq!(
            unpack_stream_copy_result(BLOCKED),
            Err(AsyncAbiError::BlockedHasNoEvent)
        );
        assert_eq!(
            unpack_future_copy_result(BLOCKED),
            Err(AsyncAbiError::BlockedHasNoEvent)
        );
        assert_eq!(
            unpack_stream_copy_result(3),
            Err(AsyncAbiError::InvalidCopyResult)
        );
        assert_eq!(
            unpack_future_copy_result(0x10),
            Err(AsyncAbiError::InvalidCopyResult)
        );
    }

    #[test]
    fn endpoint_pairs_use_readable_low_and_writable_high() {
        let pair = EndpointPair {
            readable: 7,
            writable: 11,
        };
        assert_eq!(pack_endpoint_pair(pair), Ok(0x0000_000b_0000_0007));
        assert_eq!(unpack_endpoint_pair(0x0000_000b_0000_0007), Ok(pair));
        assert_eq!(
            unpack_endpoint_pair(0x0000_000b_0000_0000),
            Err(AsyncAbiError::InvalidEndpointPair)
        );
    }
}
