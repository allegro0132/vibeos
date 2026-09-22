# V8 plus Rust firmware link, after C++ defaults and synchronization

The real smoke entry remains forced into the diagnostic firmware link. This
attempt uses the rebuilt integrated target archives after patch 0022 and the
current Rust wait/semaphore bridges. The link still fails, but reports only
18 undefined symbols. The 3088 discarded-section relocation errors from the
first attempt are absent, and all seven native synchronization symbols resolve.
No undefined-symbol suppression or fabricated runtime stubs were used.

Remaining interfaces are listed in results.json: newlib syscalls and aligned
allocation, entropy, and V8 FOpen/GetCurrentProcessId/OpenTemporaryFile. The
complete linker log is included. This is still the diagnostic fixture image,
not a runnable V8 gate, and no runtime execution is claimed. The default
firmware must not be confused with a failed audit's output artifact.
