# V8 firmware link diagnostic 7

With standard-stream descriptor adapters, the forced actual V8 firmware link
fails with four remaining syscall symbols: _exit, _kill, _open, _unlink.
_close, _fstat, _isatty and _lseek now resolve. There are no other reported linker
error classes. This is still diagnostic fixture firmware, not a runnable V8
acceptance image; no V8 runtime acceptance or milestone completion is claimed.

QEMU descriptor lifecycle evidence is recorded under ../native-fd. File access
and fatal process termination still require implementations, and a dedicated
real-V8 image must exclude the fixture static flag page before execution.
