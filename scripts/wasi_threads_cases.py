"""Expected outcomes of the generated wasi-threads fixtures.

`wasi-runtime/examples/fixtures.rs` emits the modules; every gate that drives
them (`test-wasi-qemu.py --threads`, `test-wasi-threads-fixtures.py`) takes
the (name, exit status) table from here so the two cannot drift.
"""
FIXTURES = [
    ('threads-atomics', 0), ('threads-counter', 0), ('threads-wait-timeout', 0), ('threads-exit', 7),
    ('threads-spawn-cap', 3), ('threads-grow', 0), ('threads-fault', 125), ('threads-busy', 124),
    ('threads-defined-shared', 126), ('threads-no-start', 126),
]
# The prebuilt pthreads program (tests/wasi/threads.c): arguments, status, stdout.
PTHREADS = [
    ([], 0, b'sum=3000 cond=1\n'),
    (['exit'], 7, b''),
    (['spawnmany'], 0, b'eagain=1 created=3\n'),
]
