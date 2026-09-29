# Node link attempt 21

Complete firmware linking still fails with two unresolved libuv symbols:
uv_fs_copyfile and uv_fs_statfs. System identity/hostname/CPU/load entry points
resolve four names since run 20. Archive inputs remained unchanged during
linking. Node OS assertions compile but have not executed. Separate real-V8/libuv
QEMU evidence is in libuv-system. No Node execution milestone is claimed.
