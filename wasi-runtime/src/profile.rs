//! Trusted build-time command ceilings. Component profile limits are unchanged.
use vibeos_component_format::{ProfileLimits, PROFILE_1_LIMITS};

#[cfg(all(feature = "esbuild-wasi", feature = "python-duo"))]
compile_error!("esbuild-wasi requires the QEMU large-memory profile, not python-duo");

pub const MODULE_BYTES: usize = if cfg!(feature = "esbuild-wasi") {
    24 * 1024 * 1024
} else if cfg!(feature = "python-wasi") {
    16 * 1024 * 1024
} else {
    512 * 1024
};
pub const MEMORY_BYTES: usize = if cfg!(feature = "esbuild-wasi") {
    128 * 1024 * 1024
} else if cfg!(feature = "python-duo") {
    16 * 1024 * 1024
} else if cfg!(feature = "python-wasi") {
    64 * 1024 * 1024
} else {
    16 * 1024 * 1024
};
pub const ALLOCATION_BYTES: usize = if cfg!(feature = "esbuild-wasi") {
    768 * 1024 * 1024
} else if cfg!(feature = "python-duo") {
    40 * 1024 * 1024
} else if cfg!(feature = "python-wasi") {
    512 * 1024 * 1024
} else {
    32 * 1024 * 1024
};
pub const DECLARATIONS: ProfileLimits = if cfg!(any(feature = "python-wasi", feature = "esbuild-wasi")) {
    ProfileLimits {
        max_functions: 32768,
        max_types: 4096,
        max_table_elements: 32768,
        // Go lowers large functions to nested blocks (observed maximum 3,213).
        max_core_nesting: if cfg!(feature = "esbuild-wasi") { 4096 } else { 1024 },
        // Go's official esbuild artifact has 100,000 active data segments.
        // The byte-size and owner-allocation ceilings still bound admission.
        max_data_segments: if cfg!(feature = "esbuild-wasi") { 131072 } else { 4096 },
        max_call_depth: 512,
        ..PROFILE_1_LIMITS
    }
} else {
    PROFILE_1_LIMITS
};
