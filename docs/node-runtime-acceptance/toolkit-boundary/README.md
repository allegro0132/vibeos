# Production toolkit directory boundary checks

`scripts/test-toolkit-boundary-qemu.py` boots the production toolkit image and
uses ordinary VSH `node`/`tsx` commands. A secret is created beside the granted
project directory. The test checks that ordinary Node receives no tool mount,
then runs a TypeScript fixture with the separately read-only tool grant.

The fixture attempts parent-directory reads, realpath and writes; synchronous
tool-file modification/open/unlink/rename; directory creation under the tool
root; a write after changing cwd into that root; and an asynchronous tool-file
write. It then verifies the original tool contents and ordinary project writes.
A separate explicitly broader Node invocation checks the sibling secret is
unchanged. This does not use a privileged native test command.

`run-1/` records an overly strict assertion for Node's JavaScript
`realpathSync("../secret")`. Node normalizes it to `/secret` in the invocation's
virtual namespace and receives ENOENT, rather than passing a raw parent selector
to the capability backend. The sibling file is not exposed. Only that realpath
case now permits ENOENT as well as EACCES; direct traversal and all tool writes
still require EACCES. The original failure log is retained.

`run-2/` then exposed a missing JavaScript binding: `process.chdir()` inherited
Node's non-process-owner worker restriction, despite the existing libuv virtual
cwd backend. The embedding layer now installs a narrowly scoped chdir binding
after bootstrap, retaining the non-owning environment flags. It validates string
and NUL arguments, delegates to capability-backed `uv_chdir`, and leaves
`process.cwd()` on Node's existing uncached getter. This does not enable process
abort, credential setters or global process ownership. Target revalidation is
required for this fix.

`node-cwd-regression/` passes the existing production Node/VSH regression
after the cwd binding change: modules, files, stdin/redirection, timers, exit
codes, exception position, CPU/idle cancellation and relaunch. The boundary
run 3 additionally passes cwd argument validation and the ten permission
rejections, then detects unequal synchronous/Promise file contents.

`run-4/` identifies the latter as truncated asynchronous reading, not a tool
write: the original and final synchronous reads are identical at 3620 bytes,
while the Promise read returns only 1024 bytes. The native bridge intentionally
bounds reads to a small chunk, but Node's regular-file Promise reader treats
that short result as EOF. The libuv adapter now accumulates chunks in the
caller's buffer, over bounded event-loop turns, until the buffer fills or real
EOF is observed. Each native request still revalidates the capability. No
additional full-size copy buffer is allocated.

`run-5/` passes all ten permission rejections, ungranted-tool invisibility,
project/tool cwd behavior, cwd argument validation and unchanged sibling data.
Both synchronous and Promise reads now return identical 3620-byte tool data.
An additional 8194-byte nonuniform UTF-8 fixture passes binary/decoded reads,
explicit positional reads, EOF counts and preservation of the file position.
The WASI transform is reclaimed with zero capabilities and waiters. The run
retains new libuv build input hashes and the exact ELF/link evidence.

Runs 1 and 2 use the production ELF qualified in `../tsx-qemu/run-4/`; later
runs retain their corrected runtime/UV link evidence in runs 3 and 5. These checks
are a subset of M4: live revocation, cancellation, output backpressure and
100-cycle native/toolkit lifecycle qualification still require their own
evidence. A new complete clean rebuild is required because the libuv input
changed during the first clean-build attempt; that earlier attempt cannot
qualify the final runtime.
