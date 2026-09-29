# Node link attempt 12

Complete firmware linking still fails with 48 unresolved libuv
symbols. Link operations and explicit Unix metadata rejection resolve
10 names since run 11. Inputs unchanged: True.

This is link diagnostics only. Real V8/libuv QEMU tests pass separately in
libuv-metadata-unavailable; Node itself has not linked or executed.
