// TODO
pub const DEFAULT_WINDOW: u32 = 1000;
pub const DEFAULT_MAX_PACKET: u32 = 1000;

/// Maximum SSH packet size, from RFC4253.
///
/// Used to size buffers when using `alloc`
#[allow(unused)]
pub(crate) const SSH_MAX_PACKET: usize = 35000;

// TODO: Perhaps instead of MAX_CHANNELS we could have a type alias
// of either heapless::Vec<> or std::vec::Vec<>
//
// This size is arbitrary and may be increased, though note that some code paths assume
// a linear scan of channels can happen quickly, so may need reworking for performance.
/// The VibeOS server profile admits one SSH channel per connection.
pub const MAX_CHANNELS: usize = 1;

// Enough for longest 23 of "screen.konsole-256color" on my system
// Unsure if this is specified somewhere
pub const MAX_TERM: usize = 32;

pub const DEFAULT_TERM: &str = "xterm";

pub const RSA_DEFAULT_KEYSIZE: usize = 2048;
pub const RSA_MIN_KEYSIZE: usize = 1024;

/// Maximum username for client or server
///
/// 31 is the limit for various Linux APIs like wtmp
/// A larger limit can be set with `larger` crate feature
#[cfg(not(feature = "larger"))]
pub const MAX_USERNAME: usize = 31;

/// Maximum username for client or server
///
/// 31 is the limit for various Linux APIs like wtmp
#[cfg(feature = "larger")]
pub const MAX_USERNAME: usize = 256;

/// Maximum user-authentication packets accepted on one connection.
///
/// This leaves room for OpenSSH's `none`, unsigned public-key probe, and
/// signed public-key request while bounding attacker-controlled verification
/// work.
pub const MAX_AUTH_ATTEMPTS: u8 = 6;
