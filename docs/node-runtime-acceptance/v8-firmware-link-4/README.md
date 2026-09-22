# V8 firmware link diagnostic 4

Patch 0024 connects newlib time, process identity and entropy to admitted native
bridges, and implements posix_memalign using pinned newlib memalign. Entropy is
staged in up to four 64-byte requests; a failed request leaves caller storage
unchanged. Native grant validation now explicitly drops its validation lease.

Target libbase compilation passed. Mock host contract tests passed for clock
failure, identity, 256-byte entropy chunking, late failure, bounds, null output,
zero-length grant failure, alignment validation and allocator errno preservation.
Run `python3 scripts/test-native-libc.py` to repeat those host checks.

The actual firmware link still FAILS (exit 101). Undefined symbols decreased
from 16 to 11: _close, _exit, _fstat, _isatty, _kill, _lseek, _open, _read,
_sbrk, _unlink, _write. No other linker error classes were reported.

This is the fixture firmware forced to link the actual V8 gate, not a runnable
V8 acceptance image. No QEMU run is claimed here. The newlib heap, capability
file/stream backend, termination semantics and target execution remain required.
M1 is not passed and this diagnostic is not a completed milestone.
