# Default exit regression after explicit-exit support

Built the same Node gate source with expected exit 0 and explicit exit disabled.
QEMU passes all project, stdin, Buffer/Promise/timer, zlib, exit-event and native
teardown checks. The observed event and native return are both 0, and waiters=0.
This verifies the normal loop-drain branch after the embedding exit-handler and
explicit-exit test changes; it does not qualify cancellation or repeated runs.
