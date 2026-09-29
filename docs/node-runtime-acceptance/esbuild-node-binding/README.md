# Node JavaScript to esbuild WASI binding

The optional toolkit image installs an invocation-owned, frozen native binding
at `globalThis[Symbol.for("vibeos.esbuild")]`. It accepts bounded binary transform
requests through `transformSync(Uint8Array)` and `transform(Uint8Array)`. These
are transport functions; they are not a replacement for the official esbuild
JavaScript API. That API adapter and upstream tsx integration remain pending.

`run-1/` records actual QEMU execution of the official esbuild WASI module from
real Node/V8, with 1 GiB RAM and four harts:

- Ordinary `node` cannot transform without the separate tool grant.
- A synchronous request returns actual generated JavaScript.
- Two Promise requests complete serially while a 10 ms interval advances
  (81 timer callbacks in this run).
- Mixing an outstanding Promise request with a synchronous request completes
  both and preserves submission order.
- `process.exit(7)` cancels the active WASI request and joins its cleanup before
  destroying the Node environment. A subsequent invocation transforms normally.
- All seven WASI jobs report `reclaimed=true caps=0 waiters=0`; each reports a
  96,523,904-byte peak guest owner allocation. This is not total system memory.

The binding uses a libuv prepare handle for JavaScript completion callbacks;
the native readiness predicate advances only the Rust future on the retained
native stack. It never invokes JavaScript from the Rust scheduler. The queue is
bounded to 16 requests. Normal teardown cancels and joins active work instead
of jumping across C++ frames.

The link uses the previously qualified `fresh-57` V8/Node archives and a newly
built libuv archive from `bridge-platform`, which includes the external
readiness hook. Runtime bridge C++ is compiled afresh. `link-results.json`
records these inputs and the resulting ELF hash. Full clean-build and final
regression qualification remain required before closing M3.

After run 1, queue handoff was tightened to admit the next request immediately
when one finishes, and the test gained a two-request case with no timer to
provide incidental wakeups. Run 1 does not qualify that subsequent edit.

`run-2/` qualifies the queue handoff change and all previous cases on the new
ELF. The additional two-request, no-timer Promise case passes. All nine WASI
jobs are reclaimed with zero capabilities and waiters, including the cancelled
job; exit 7 and a fresh successful invocation pass again. The source hash list
now also includes runtime C++ and the libuv readiness backend. No upstream
esbuild JavaScript API or tsx execution is implied by these binary-transport
tests.

Reproduce with `scripts/check-v8-firmware-link.py --gate --node --node-shell
--js-esbuild-probe --toolkit TOOLKIT --uv-archive UV_ARCHIVE --source NODE_SOURCE
--work target/FRESH_LINK`, then `scripts/test-esbuild-node-qemu.py --kernel
target/FRESH_LINK/node-shell.elf --work target/FRESH_TEST`. The probe feature
alone exposes `node-tool-probe`; production Node commands do not gain tool
authority from these tests. This evidence does not close M3, the security and
lifecycle milestone, or the complete V8/Node/TypeScript plan.
