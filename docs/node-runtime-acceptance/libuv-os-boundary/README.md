# OS query boundaries and explicit home

Process/thread resource accounting, Unix passwd lookup, process priority
read/write and network interface/address identifier queries return ENOTSUP.
Missing required pointers return EINVAL. No fake CPU usage, account, priority
or interface data is produced. Interface cleanup accepts NULL; this backend
does not produce interface snapshots.

uv_os_homedir follows upstream HOME-first lookup using only the invocation's
explicit environment. A missing HOME returns ENOTSUP because no Unix account
database is available. It neither infers a home from cwd nor queries the host.
The value is metadata, not a new filesystem grant; path access remains subject
to the normal virtual-root capability checks.

QEMU checks seven unavailable operations, unchanged output structures/pointers/
counts/buffers, invalid arguments and NULL cleanup. It verifies missing HOME,
explicit HOME, short-buffer required size, successful copy and unset behavior.
Real V8 and cumulative libuv tests pass: 123 parks, zero waiters, normal shutdown
and 305733376-byte allocator peak. Prospective Node CPU-usage rejection and
process.env/os.homedir tests are added but have not executed. Complete Node and
TypeScript acceptance remain pending.
