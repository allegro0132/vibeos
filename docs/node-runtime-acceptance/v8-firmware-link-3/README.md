# V8 file-platform integration — link still incomplete

Patch 0023 supplies V8 FOpen, OpenTemporaryFile and GetCurrentProcessId.
The target libbase archive builds successfully, with configuration validation.
The real firmware link resolves all previously missing V8 OS methods. Sixteen
symbols remain: newlib syscalls, posix_memalign and native entropy. `_unlink`
is newly required by real newlib tmpfile; it has not been stubbed away.

FOpen follows the upstream regular-file restriction and preserves fstat errors
through close. Temporary files use newlib's open/unlink path. Neither path can
be considered capability-safe until the invocation-scoped syscall backend is
implemented and tested. The process ID is the sole native thread's stable
invocation ID under the first port's no-workers/no-subprocesses boundary.

This is compile/link evidence only. Filesystem behavior, cleanup, permission
revocation, temporary-directory policy and real V8 execution remain untested.
