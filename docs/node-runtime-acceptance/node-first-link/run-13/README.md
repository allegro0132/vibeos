# Node link attempt 13

Complete firmware linking still fails with 37 unresolved libuv
symbols. File sync, IPC/TTY exclusions and stream-mode handling resolve
11 names since run 12. Inputs unchanged: True.

This is link diagnostics only. The separate real-V8/libuv QEMU gate passes in
libuv-ipc-tty-unavailable. Node has not linked or executed.
