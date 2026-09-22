# V8 firmware link diagnostic 6

After adding native read/write bridges and newlib adapters, the forced actual
V8 firmware link fails with eight remaining syscall symbols: _close, _exit,
_fstat, _isatty, _kill, _lseek, _open, _unlink. The _read and _write dependencies
are now resolved. No other linker error classes are reported.

The fixture firmware is a link diagnostic, not a runnable V8 image. QEMU
standard-stream bridge evidence is recorded separately under ../native-stdio.
It does not establish actual newlib stdio or V8 execution; M1 remains pending.
