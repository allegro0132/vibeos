//! Link with --wrap=memcpy and a __heap_end symbol bounding cached RAM.
//! The copy profiler additionally wraps memmove and calls rv2_account_copy.
#[cfg(not(feature = "copy-profile"))]
core::arch::global_asm!(
    include_str!("packet_copy.S"),
    cached_start = const crate::ethernet::CACHED_RAM_AFTER_ARENA,
);

#[cfg(feature = "copy-profile")]
core::arch::global_asm!(
    ".set rv2_profile_copy, 1",
    include_str!("packet_copy.S"),
    include_str!("perf_copy.S"),
    cached_start = const crate::ethernet::CACHED_RAM_AFTER_ARENA,
);
