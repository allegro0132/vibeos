# Native standard-stream descriptors

QEMU RV64GC/LP64D, four harts, 128 MiB: PASS. The native fixture verifies pipe
kind for fds 0–2, invalid-fd rejection, close, repeated-close rejection, rejected
read/write/metadata after close, denied metadata after grant revocation, cleanup
close after revocation, and closed/drained transport endpoints. Prior native
and entropy checks also pass. Close state is shared by operation clones of an
explicit StdioGrant; separately created grants have separate descriptor state.

Target C++ compilation passes. Host mock tests verify newlib fstat's FIFO mode,
read/write permission bits, block size, EFAULT and unchanged metadata on error;
isatty returns ENOTTY for pipes and EBADF for bad fds; lseek returns ESPIPE for
pipes; close maps backend errors. The QEMU test executes Rust bridge functions,
not actual newlib FILE operations. No V8/Node execution is claimed.

This does not add regular files, tty descriptors, duplication, close-on-exit
launcher integration, or CSpace revocation admission. M1 remains incomplete.
