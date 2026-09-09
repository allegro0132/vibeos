# Python inside VibeOS

The opt-in `python-wasi` QEMU image executes **CPython 3.14.0 compiled to
WASI Preview 1** through the existing `wasm-run` command, file store and SSH
transport. The interpreter runs inside VibeOS using bounded, software-float
Wasmi. This is the CPython/WASI route, not the Pyodide JavaScript/Emscripten
distribution or its binary wheel ABI.

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
