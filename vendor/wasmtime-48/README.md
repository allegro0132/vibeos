# Wasmtime 48 source port

Source is copied from the published `wasmtime-environ`,
`wasmtime-internal-cranelift` and `wasmtime` 48.0.0 crates, upstream commit
`f1412a598f96f3c261a19118d94caffcb0c36235` (paths `crates/environ`,
`crates/cranelift` and `crates/wasmtime`).
The original Apache-2.0 WITH LLVM-exception LICENSE is retained. `UPSTREAM.json`
records the original file hashes, and the `environ-no-std.patch`,
`cranelift-no-std.patch` and `runtime-no-std.patch` files record local edits.
`Cargo.toml.orig` is the unmodified published source manifest; the normalized
`Cargo.toml` is the active patched manifest.

Current changes permit the compilation environment to build with core/alloc:

- Separate compilation from std and keep WAT diagnostic printing std-only.
- Disable wasm-encoder's default std feature while retaining component encoding.
- Use core/alloc primitives and existing no_std hash/index-map wrappers.
- Keep CLIF filesystem paths and source path metadata behind std.
- Explicitly dereference a borrowed trampoline type for hash lookup; initialize
  default nested maps explicitly and order the component type borrow before its
  owner to satisfy the wrapper's drop checking.

The Cranelift integration additionally separates native ISA discovery, timing,
CLIF filesystem output and simulated DWARF paths from core/alloc compilation.
The bare-metal mutex uses spin locking with no poisoning (aborting panics).
Existing std builds keep standard mutexes, native discovery and diagnostics.
The Wasmtime crate no longer forces std through `cranelift`; std explicitly
forwards to the compiler instead. Compilation uses core/alloc, while file-based
APIs and CLIF configuration are std-only. The no_std code builder's optional
path argument has an uninhabited type, requiring callers to pass `None`; binary
and DWARF byte inputs remain available. Optimization/inlining/linking and fuel
or bounds-check generation have not been intentionally changed.

This fork is patched by the independent `wasmtime-runtime` workspace and the
root workspace for the optional `wasmtime-native` kernel integration. Existing
Wasmi paths retain their dependencies; the standalone Debian benchmark workspace
continues to use its pinned upstream source.
Runtime platform hooks, kernel compiler integration and WASI adaptation are incomplete;
see `../../wasmtime-runtime/README.md` for the end-to-end gates.

The port also vendors `cranelift-codegen` 0.135.0 with the focused
`riscv64-fs1-abi.patch`: f9/fs1 belongs in DEFAULT_CALLEE_SAVES, not
DEFAULT_CLOBBERS. The [RISC-V hardware floating-point ABI](https://riscv-non-isa.github.io/riscv-elf-psabi-doc/)
requires preservation of f8–f9 and f18–f27. The kernel regression injects
clobbers of every FP register at a native Wasm trap and checks all 12 saved
registers on return. This is an intentional code generation correctness change;
older byte-equality results against vanilla upstream predate this fix. Current
codegen/module comparisons apply the same explicit ABI fix to the reference;
the standalone Debian historical benchmark dependencies remain untouched.

`runtime-registry-reclaim.patch` releases the global code registry's fallible
B-tree slab/forest capacity when the last code image is unregistered. This
prevents cold-start cache allocations from remaining charged to an invocation
that has otherwise finished. Destruction occurs after releasing the registry
lock. It does not make partially constructed or forcibly reclaimed instances
safe; the command-service allocation-domain audit is still required.

`runtime-custom-code-registry.patch` applies after `runtime-no-std.patch` and
`runtime-registry-reclaim.patch`. The opt-in `custom-code-registry` feature
replaces only the global code registry with embedder hooks; the default registry
and store-local registry retain their behavior. Registration transfers one Arc
strong reference, lookup retains under the embedder lock, and removal transfers
the reference back for destruction after unlocking. VibeOS uses 16 fixed slots
bound to frozen code mappings and allocation domains. No registry collection is
allocated in an invocation arena. This is a local platform ABI, not an upstream
Wasmtime API. The patch was replayed against the recorded original file hashes
and verified byte-for-byte for all three changed/added files.

Private kernel fault tests admit an entire isolated runtime graph, both after
a call returns and during a synchronous host callback with active TLS. Exact-task
cleanup restores the outer call TLS snapshot before registry references and
mapping handles are forgotten and the code pool/arena reclaimed. The kernel also verifies isolated async fibers when suspended, faulting after
resumption, and faulting during cancellation destruction. These fixtures export
no external host resources; they do not authorize arbitrary service recovery.

`riscv64-inline-copy.patch` fixes constant bulk-memory copies on RISC-V targets
without V. Upstream 48 introduces `i8x16` loads/stores even for non-SIMD Wasm;
the RV64GC backend cannot lower those stores and panics compiling the real Rust
WASI standard-library hello example. Use at most i64 chunks unless `has_v` is
enabled. Bounds checks and all-loads-before-stores memmove ordering are retained.
The patch targets `wasmtime-cranelift/src/func_environ.rs` and is independent of
the core/alloc changes. `wasi-runtime/examples/fixtures.rs` generates the `copy`
SSH regression with unaligned, overlapping and disjoint copies, lengths around
16/128-byte boundaries, and a host memmove oracle for every destination byte.
Earlier comparisons against vanilla compiler glue predate this correctness fix.

`runtime-custom-fuel-yield.patch` is an opt-in `custom-fuel-yield` runtime
extension. A Store may install a synchronous function/token decision after each
normal refuel, before the async yield. Returning true keeps the current fiber;
false preserves the standard wake-and-yield path. The reserve, quantum, final
OutOfFuel trap and non-fuel I/O/GC yields are unchanged. No callback is installed
by default. VibeOS's experimental `wasmtime-command-fuel-batch` policy checks
job authority/cancellation and executor competition every 10000 fuel and forces
a yield by the 32nd quantum. Outer batching is disabled in that mode so the
bounds cannot multiply. Its token borrows the SYSTEM job until the Store/fiber
is gone and the child joined; it owns no external reference in the arena.
The patch chain was replayed from hash-verified published runtime files.
`fuel-custom` verifies identical exhaustion, 99 callback boundaries with or
without batching, a maximum of 32 boundaries per poll, cancellation and reuse.
