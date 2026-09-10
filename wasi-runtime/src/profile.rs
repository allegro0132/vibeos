//! Trusted build-time command ceilings. Component profile limits are unchanged.
use vibeos_component_format::{ProfileLimits, PROFILE_1_LIMITS};

pub const MODULE_BYTES: usize = if cfg!(feature = "python-wasi") {
    16 * 1024 * 1024
} else {
    512 * 1024
};
pub const MEMORY_BYTES: usize = if cfg!(feature = "python-duo") {
    16 * 1024 * 1024
} else if cfg!(feature = "python-wasi") {
    64 * 1024 * 1024
} else {
    16 * 1024 * 1024
};
pub const ALLOCATION_BYTES: usize = if cfg!(feature = "python-duo") {
    40 * 1024 * 1024
} else if cfg!(feature = "python-wasi") {
    512 * 1024 * 1024
} else {
    32 * 1024 * 1024
};
pub const DECLARATIONS: ProfileLimits = if cfg!(feature = "python-wasi") {
    ProfileLimits {
        max_functions: 32768,
        max_types: 4096,
        max_table_elements: 32768,
        max_core_nesting: 1024,
        max_data_segments: 4096,
        max_call_depth: 512,
        ..PROFILE_1_LIMITS
    }
} else {
    PROFILE_1_LIMITS
};
