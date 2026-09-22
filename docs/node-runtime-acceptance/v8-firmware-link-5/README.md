# V8 firmware link diagnostic 5

After linking the bounded native newlib heap bridge, the forced real-V8
firmware link still fails (exit 101), now with 10 undefined syscalls:
_close, _exit, _fstat, _isatty, _kill, _lseek, _open, _read, _unlink, _write.
The `_sbrk` dependency is resolved. No other linker error classes appear.

This is diagnostic fixture firmware, not a runnable V8 image. QEMU heap-bridge
execution is recorded separately under ../native-libc-heap; it does not prove
newlib allocator or V8 execution. M1 remains incomplete.
