# V8 firmware link diagnostic 8

The forced actual V8 firmware link now resolves fatal _exit and unsupported
signal _kill. It still fails with two undefined symbols, _open and _unlink;
there are no other reported linker error classes. This diagnostic fixture is
not a runnable V8 acceptance image. M1 remains incomplete.

The separate native-exit QEMU test records whole-image shutdown from the native
stack and the lack of native-status propagation to the host process. It does
not establish normal Node exit, V8 execution, or isolated fatal recovery.
