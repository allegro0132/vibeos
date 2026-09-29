# Node link attempt 16

Complete firmware linking still fails with 22 unresolved libuv symbols.
Seven process metadata/initialization names resolve since run 15. Archive inputs
remained unchanged during linking. Real V8/libuv process metadata checks execute
in QEMU; see libuv-process. Executable-path lookup is explicitly unsupported,
with the upstream Node argv[0] fallback retained. Prospective Node JavaScript
title/identity checks compile but have not executed. No Node milestone yet.
