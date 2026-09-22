# V8 firmware link diagnostic 9

Capability-backed unlink now resolves in the forced real-V8 firmware link.
The link still fails with one undefined symbol, _open; there are no other
reported linker error classes. The image remains a fixture link diagnostic,
not runnable V8 acceptance. M1 remains incomplete.

QEMU native unlink evidence is under ../native-unlink and explicitly excludes
mid-publication revocation, durable-backend behavior, newlib execution and V8.
