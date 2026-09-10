# Python inside VibeOS

The opt-in `python-wasi` QEMU image executes **CPython 3.14.0 compiled to
WASI Preview 1** through the existing `wasm-run` command, file store and SSH
transport. The interpreter runs inside VibeOS using bounded, software-float
Wasmi. This is the CPython/WASI route, not the Pyodide JavaScript/Emscripten
distribution or its binary wheel ABI.

On physical Milk-V Duo, the compact full CPython 3.14.0 module has now executed
the arithmetic and JSON/math/fractions standard-library cases successfully
through Wasmi, with exit 0 and clean resource reclamation. Continuous invocation
is not yet reliable: the third case was rejected during initialization with
status 124. This is a partial physical result, not a completed acceptance suite.
Raw evidence is under `tests/python-wasi/results/duo-freereuse`.

## Build the guest

Use the official [CPython 3.14.0 source release](https://www.python.org/downloads/release/python-3140/)
and [wasi-sdk 33](https://github.com/WebAssembly/wasi-sdk/releases/tag/wasi-sdk-33).
The source archive `Python-3.14.0.tar.xz` has SHA-256
`2299dae542d395ce3883aca00d3c910307cd68e0b2f7336098c8e7b7eee9f3e9`.
Build a native Python from that same release first; it generates version-matched
frozen bytecode. These are build-host tools, never runtime dependencies in VibeOS.

```sh
mkdir -p target/python-build-host
cd target/python-build-host
/absolute/path/Python-3.14.0/configure --without-ensurepip --disable-test-modules
make -j8
cd ../..
python3 scripts/build-python-wasi.py \
  --source /absolute/path/Python-3.14.0 \
  --build-python "$PWD/target/python-build-host/python.exe" \
  --sdk /absolute/path/wasi-sdk-33.0-arm64-macos
```

On Linux the native executable is normally `python` instead of `python.exe`.
On Homebrew systems where native Python detects gettext headers, its native link
may also need `make -j8 LIBS='-L/opt/homebrew/opt/gettext/lib -lintl -ldl'`.
The cross build isolates pkg-config from host libraries and links CPython's
configured WASI library closure. The output is
`target/python-wasi/python.wasm`; `build.json` records its digest and compiler.
The builder does not rewrite Wasm imports or remove unsupported instructions
after compilation. `--skip-configure` explicitly reuses a configured work directory.

## Run

```sh
WASI_PYTHON=1 scripts/run-wasi-qemu.sh
```

In another terminal:

```sh
python3 scripts/wasi-client.py --python upload target/python-wasi/python.wasm
python3 scripts/wasi-client.py --python run python.wasm -c 'print(6 * 7)'
python3 scripts/wasi-client.py --python run python.wasm -c \
  'import json, math; print(json.dumps({"answer": math.isqrt(1764)}))'
printf 'print("hello from stdin")\n' | python3 scripts/wasi-client.py --python run python.wasm -
```

The launcher selects one hart and a 1 GiB RAM map for this interpreter image.
The UART command is `wasm-run @home/wasm/python.wasm -c "print(6 * 7)"`.
The `--python` client option raises its upload ceiling and permits a 120-second
SSH liveness window during module loading/translation, with a 600-second command
deadline; the server's compiled profile remains authoritative. Uploaded modules persist in the launcher's
disk. Each execution creates a fresh invocation, including after Python exceptions.
The development image uses the repository's public SSH test identity and loopback
port forwarding, as described in [WASI.md](WASI.md).

## Supported execution and boundaries

The guest uses CPython's public isolated embedding API and explicit UTF-8 argument
decoding. It supports `-c`, stdin scripts (`-`), Python arguments, binary standard
streams, separate stderr, exceptions and exit statuses. The frozen library list
is in `scripts/freeze-python-wasi.py`; it includes encodings, JSON, collections,
regular expressions, fractions, decimal, datetime and their packaged helpers.
Native builtins such as `math` come from CPython's normal static WASI build.

There are no preopened directories, filesystem grants, networking, dynamically
loaded extensions, pip, Pyodide packages or interactive terminal input. Importing
an unfrozen module fails normally. Freezing a module does not grant its external
operations: for example, filesystem calls from `os` remain unavailable.
The profile has no entropy grant, so the embedding explicitly selects
`PYTHONHASHSEED=0` semantics (deterministic string hashing); `os.urandom` remains
unsupported. This is a stdio-only Python command profile, not a full Python OS
environment. Native Wasmtime and the experimental RV64 cache are rejected for
this image until separately qualified with CPython.

| Resource | Python image | Ordinary WASI image |
| --- | --- | --- |
| QEMU RAM / linker map | 1 GiB | 128 MiB |
| Module upload / load | 16 MiB | 512 KiB |
| Linear memory | 64 MiB | 16 MiB |
| Guest allocation owner | 512 MiB | 32 MiB |
| Functions / table elements | 32,768 / 32,768 | 1,024 / 4,096 |
| Wasm call depth | 512 | 128 |
| Total fuel / poll quantum | 10 billion / 100,000 | 10 million / 10,000 |
| SSH wire bytes per direction | 32 MiB | 512 KiB |
| WASI SSH execution deadline | 600 seconds | 120 seconds |

Python needs a larger bounded quantum because a real initialization block exceeds
10,000 fuel. Output remains capped at 64 KiB, and concurrency remains one command.
Cancellation, authority revalidation, immutable source snapshots and arena cleanup
use the existing command lifecycle. Component-profile limits are unchanged.
Module validation and translation are synchronous within the first guest poll;
fuel quanta bound execution after initialization, not compiler latency. Large
module setup can therefore delay I/O and cancellation until that poll returns.
Standard descriptors in both WASI backends report `UNKNOWN`, the WASI file type
for these byte pipes, so libc does not mistake them for interactive terminals.

## Acceptance

```sh
cargo test --locked --offline -p vibeos-wasi-runtime -p vibeos-wasi-command
cargo test --locked --offline -p vibeos-wasi-runtime -p vibeos-wasi-command \
  --features vibeos-wasi-runtime/python-wasi
cargo build --locked --offline -p vibeos-wasi-runtime --features python-wasi --example run
python3 scripts/test-python-wasi.py --runner target/debug/examples/run \
  --work target/python-wasi/host-acceptance
# With the Python QEMU image running:
python3 scripts/test-python-wasi.py --work target/python-wasi/qemu-acceptance
# Or let the harness boot and stop the already-built image:
python3 scripts/test-python-wasi.py --boot --work target/python-wasi/qemu-acceptance
```

The same nine exact-output cases cover arithmetic, frozen and native libraries,
Unicode arguments, stdin scripts, stdout/stderr with exit 7, denied filesystem
access, exception reporting and successful reuse after failure. Host execution
checks the actual guest but cannot establish kernel scheduling, storage or arena
behavior; QEMU additionally exercises SSH upload, persistent loading and the real
guest lifecycle. Results and per-case stdout/stderr are retained in the work
directory. The stdin case failed with the old terminal file type; the Unicode
case failed without UTF-8 preinitialization. Declaration-limit tests reject one
function or table element beyond the compiled ceiling.

Verified on 2026-09-09: all nine cases passed on the host and in the single-hart
RISC-V QEMU image, using the same 10,073,226-byte module (SHA-256
`be59a6f2db568e3c8e1b6a92212ca183c79c91f682e36ab44496f8c205703a82`).
The QEMU log contains nine `reclaimed=true caps=0 waiters=0` terminals.
Both default and Python command-profile suites passed 25 tests each; the
standalone standard-library fixture test was intentionally ignored because the
real CPython cases were run separately. The board-map and SSH authorization
tests passed, as did native Wasmtime execution of the stdio metadata fixture
and the existing C standard-library command. Local evidence is in
`target/python-wasi/{host,qemu}-acceptance/`, with build and regression logs in
`target/pyodide/`.

## Milk-V Duo CPython image (awaiting physical qualification)

`--python` is a separate Duo image using the existing Wasmi engine. It does not
include the Wasmtime backend. The previously qualified Wasmtime/CoreMark image
remains in its own output directory. The production SSH provisioning policy is
preserved; QEMU test credentials are not enabled.

```sh
scripts/build-milkv-duo.sh --python
# In the approved SDK Docker container, with output directory writable:
scripts/package-milkv-duo-sdk.sh --python /home/work
```

The output directory is `target/milkv-duo-python`, with `boot.sd` and
`vibeos-milkv-duo-python-sd.img`. The LZMA boot-window checks apply. Replacing only
`boot.sd` on a powered-off board's SD card preserves the data partition; a full
image write resets uploaded files and SSH provisioning.

The `python-duo` runtime profile admits 16 MiB modules and the Python declaration
limits while bounding linear memory to 16 MiB and the kernel allocation owner to
40 MiB. It retains 10 billion total fuel and 100,000 fuel per poll. The original
32-times-module-size admission estimate is bypassed only for this profile:
CPython's frozen data makes that estimate overly conservative. Structural
validation and the kernel allocation-owner quota remain enforced. Other profiles
retain their original estimates and limits.

The existing CPython 3.14.0 module (SHA-256
`be59a6f2db568e3c8e1b6a92212ca183c79c91f682e36ab44496f8c205703a82`)
passes all nine host Python acceptance cases with this runtime profile, including
JSON/math, Unicode argv, stdin, exceptions and exit 7. The diagnostic example
`cargo run --release -p vibeos-wasi-runtime --features python-duo --example memory
-- target/python-wasi/python.wasm -c 'print(42)'` measures requested allocator
bytes, not allocator metadata, fragmentation, kernel memory or board peak RAM.
Host peaks were approximately 35.6 MiB including the input module buffer; this
is feasibility evidence, not proof of operation on the 64 MiB board.

Physical boot, upload and execution qualification is pending. The ordinary Duo
Wasmtime image rejects the existing 10 MiB CPython upload. No Python execution on
Duo is claimed until the new image is installed and the real SSH/UART tests pass.

### First physical attempt and loader correction

The first Duo image accepted and durably uploaded the 10,073,226-byte module,
but failed before Python execution: growing the SYSTEM file buffer requested a
12 MiB allocation, charged as 16 MiB, and exhausted the heap. Host requested-byte
measurements had not included this growth transient or allocator size classes.
This attempt is a failure, not physical Python acceptance.

The corrected loader reserves the pinned file length once using fallible
allocation, verifies the final length, and the SSH job takes ownership of that
buffer without another full-module copy. Local callers retain SYSTEM ownership
isolation, with fallible copying. A regression checks exact reservation and both
short/long snapshot mismatches.

For Duo, build the same CPython interpreter and frozen module list with:

```sh
python3 scripts/build-python-wasi.py \
  --source target/pyodide/Python-3.14.0 \
  --build-python target/pyodide/build-host/python.exe \
  --sdk target/toolchains/wasi-sdk-33.0-arm64-macos \
  --work target/python-duo-wasi --opt-level z \
  --without-legacy-cjk-codecs --frozen-opt-level 2
```

This omits the optional legacy CJK codec extensions (UTF-8/Unicode remain), and
compiles frozen standard-library bytecode at optimization level 2, removing its
docstrings and assertions. User scripts keep their normal optimization setting.
The resulting module is 8,165,626 bytes. All nine host cases pass with eager
Wasmi translation; no lazy translation is enabled in the delivered image.
Wasmi's internal function ceiling now matches the separately validated profile
ceiling, since size optimization increases the number of small functions.

The updated allocation diagnostic also estimates the 64-bit allocator's
56-byte header, alignment, power-of-two charge and reallocation transient.
Worst case across the host suite: 45,625,856 bytes including the module buffer;
37,234,816 bytes for invocation allocations. The owner quota is 40 MiB. These
estimates exclude kernel services and fragmentation, so physical qualification
of the corrected image remains necessary. Raw first-attempt UART evidence is
in `target/duo-python/physical`; original artifacts are retained under
`target/milkv-duo-python/previous-load-oom`.

### Second physical attempt: initialization and cache budget

The load-fix image uploaded the 8,165,626-byte module successfully and passed the
former SYSTEM-buffer growth point. Wasmi initialization then exhausted the heap
on owner 9 while allocating a 4,787,105-byte data buffer (8 MiB charged). Python
had not begun execution. Evidence is in `target/duo-python/physical-loadfix`.

The CPython image now limits the storage read cache to 64 pages rather than 512.
Each boxed 4096-byte page occupies an 8192-byte allocator block, so this removes
up to 3.5 MiB of cache charge. Other images retain 512 pages. This is a cache
capacity change, not a change to durable storage or write semantics.

The Duo module additionally uses `--compact-encodings`: frozen codecs are ASCII,
Latin-1, UTF-8/16/32 and Unicode escape variants, plus their initialization and
alias tables. Other encoding modules are unavailable. Import bootstrap code uses
CPython's existing intrinsic frozen copy. The full CPython interpreter and the
nine tested library/stdio cases remain supported. This variant is 7,558,394 bytes,
SHA-256 `9ef6b0ec3b49675a6a1f51b7fd1a3406aa6bf549736951f4a3b2c07e1873e5ab`.
Its largest initialized data segment is 4,179,873 bytes, below the 4 MiB allocation
boundary including the allocator header. Host allocator-charge estimates peak at
45,332,352 bytes including the module buffer; add kernel service memory and the
new smaller cache separately. All nine host cases pass. Physical execution of
this cache-budget correction remains pending; neither previous attempt is a
successful Python-on-Duo run.

### Third physical attempt and allocator reproduction

The cache-fix image still exhausted the heap during initialization, requesting a
1 MiB charged block for a 655,360-byte buffer. The root issue was not solely live
memory size: the allocator reused only exact size classes and stranded larger
freed upload buffers after its bump cursor reached the end.

The allocator now splits a larger free block when the exact class and remaining
bump space cannot satisfy an allocation. This path visits only size-class heads
and at most one split per class; it does not scan free lists. Same-class and bump
allocations retain their original fast path. In-place reallocations are permitted
only within the same size class and allocation domain; cross-owner reallocations
still allocate and transfer accounting. No general coalescing is introduced.
Wasmi linear memory uses exact reserve on growth instead of geometrically doubling
its Vec capacity. These changes preserve the configured guest-memory ceiling.

`wasi-runtime/examples/duo-heap.rs` runs the actual kernel allocator over exactly
50,442,240 bytes (the Duo image's heap span), reserves an extra 4 MiB SYSTEM
charge, and allocates/frees an upload-sized 16 MiB block before loading CPython.
This reproduces transient/size-class pressure, not just requested-byte estimates.
The allocator regression failed before the split fix and passes afterward;
42 allocator tests and 8 Wasmi memory tests pass. The fixed-heap runner executes
`print(42)` successfully without allocation failure. Arithmetic, JSON/math,
Unicode arguments, stdin and stream/exit tests are covered in the constrained
suite. The heavier dataclasses/inspect/pathlib combination reaches MemoryError
under this conservative fixed-heap setup; it is a resource boundary, not a passed
library case. Error-reporting paths may also handle a failed growth attempt.

The preallocation/lazy-translation experiments are not enabled. The delivered
profile retains eager translation, 16 MiB guest memory, 40 MiB owner quota and
100,000 fuel per poll.

### Allocator-fix physical attempt

The allocator-fix image accepted the 7,558,394-byte upload, but the first
arithmetic invocation returned SSH status 124 with `WASI admission rejected:
Limit`. UART confirmed `reclaimed=true caps=0 waiters=0`; the board remained
responsive. A direct retry of the persisted module with `print(42)` also
returned 124 without Python output. After reclamation, `mem` reported about
2 MiB live, a 34,172,288-byte peak, and only about 150 KiB remaining bump space.
Remaining bump space is not total free memory. Fragmentation is a hypothesis;
the generic instantiation error does not identify the failed allocation.

Evidence is in `target/duo-python/physical-allocatorfix`. The host reproduction
does not yet reproduce this physical rejection. The next check is a cold power
cycle followed by execution of the persisted module without another upload.
Software reboot is avoided because of the documented Duo warm-reset hang.
There is still no successful physical CPython execution result.

### Cold-boot check and free-block reuse order

Cold boot preserved the uploaded module and SSH authorization. After the storage
scan and SSH listener completed startup, running the saved arithmetic case with
no upload still returned 124 during initialization, with clean reclamation.
The initial SSH connection timeout occurred before the listener was ready and
is recorded separately. Evidence: `target/duo-python/physical-coldboot`.

A second allocator regression shows that deferring larger-block splitting until
bump exhaustion can prevent a later large allocation even when earlier small
allocations could have used freed blocks. Exact-class reuse now falls back to
the smallest available larger class before consuming bump space. Search and
splitting remain bounded by the number of size classes; there is no coalescing.
The new regression fails with the previous ordering and passes with this change;
all 43 heap tests pass. The constrained CPython suite retains its eight expected
results and the heavier helper case's MemoryError boundary. Its arithmetic
run leaves 5,928,320 bytes of bump space instead of 1,613,184.

This establishes a fragmentation improvement, not a confirmed explanation of
the board's instantiation rejection. The new kernel additionally prints the
heap snapshot and available last-allocation failure on admission rejection.
The free-reuse image still requires physical testing. Replacing only `boot.sd`
on the existing card preserves the already uploaded module and authorization;
the complete SD image is also available for a fresh installation.

### Free-reuse physical result

The board presented a new SSH identity and no saved Python module, so this run
provisioned the previously authorized client key over serial and uploaded the
same 7,558,394-byte CPython module again. Upload succeeded. The arithmetic case
printed `328350` and `1267650600228229401496703205376`; the standard-library case
printed `{"answer": 42}`, `5/6`, and `3`. Both returned 0, and UART recorded
`reclaimed=true caps=0 waiters=0`. End-to-end command times, including file load
and interpreter initialization, were 14.54 and 21.46 seconds respectively.
These are not Python-only execution benchmarks.

The third invocation, Unicode arguments, returned 124 before Python started.
It is not evidence of a Unicode handling failure. Admission diagnostics showed
10,630,656 bytes live after failed construction, a 39,476,736-byte peak,
49,651,072 bytes of consumed bump space, and 787,072 bytes of remaining bump
space. `allocation_failure=None` means the most-recent-failure diagnostic did
not retain a cause; it does not establish that allocation succeeded. Fragmentation
remains suspected, and free blocks still cannot coalesce. Reclamation was clean
and the board remained responsive. Remaining cases were not run after this
failure. The full interpreter is now physically demonstrated, while repeated
execution and the complete stdio/Unicode suite remain unfinished.
