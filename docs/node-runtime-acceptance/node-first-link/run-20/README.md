# Node link attempt 20

Complete firmware linking still fails with 6 unresolved libuv symbols.
uv_fs_mkdtemp and uv_fs_mkstemp resolve since run 19. Archive inputs remained
unchanged during linking. Separate real-V8/libuv target execution is recorded
in libuv-temp. Node itself has not linked or executed; no Node milestone yet.
