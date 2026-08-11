# Testing VibeOS

Four layers, cheapest first. Run them all before pushing.

```sh
cargo test --workspace         # fast portable tests, no QEMU
./scripts/differential.sh      # verify committed output with pinned real rustc
./scripts/qemu-test.sh         # golden cases plus the differential oracle
./scripts/qemu-usb-test.sh     # PCI/XHCI HID, BOT/SCSI, INTx, and hotplug
./scripts/qemu-tcp-test.sh     # N1 static/DHCP IPv4 and TCP echo over QEMU hostfwd
./scripts/qemu-tcp-test.sh recovery # N2 stack/driver generation-recovery gate
./scripts/qemu-ssh-security-test.sh # N3 QEMU entropy/identity boundary gate
./scripts/qemu-ssh-test.sh     # N4/N5 real OpenSSH exec and rejection gate
./scripts/bench.py             # fixed QEMU/TCG run checked against the baseline
./scripts/bench.py --smp-scaling # equal-work four-hart throughput acceptance
./scripts/status.sh            # derive current test/corpus counts on the host
```

Normal `run.sh`/`qrun.sh` builds boot the least-authority `vsh` component. The
golden and benchmark runners explicitly build the kernel with
`--features legacy-shell`; production/default images therefore do not expose
the broad diagnostic command dispatcher.

`status.sh` lists runnable and ignored host tests separately and derives corpus
and transcript counts from the tree. Target checks are not guessed from source:
`./scripts/qemu-test.sh selftest` reports the count observed in that QEMU run.

| Layer | What it covers | Where |
|---|---|---|
| Host unit tests | Sv39 PTE/satp encoding and invalid-leaf rejection; SBI RFENCE request/error handling, local fence/MXR state, and exact online physical-hart masks; capability algebra including page-aligned COW table replacement and exact backend callback ordering, cross-space revocation, explicit leases, persistent witnesses, atomic recovered-graph installation, and tombstoned slot generations; unified authority/object journal decoding, partitioned global root selection, exhaustive prefix/flush recovery, canonical ProgramArtifact/VIBEEXE decoding and no-write-on-error in-place relocation, cross-kind ID/transaction collisions, and allocation-amplification inputs; modern virtio block/net feature negotiation, descriptor direction, RX length/header validation, exact tokens, multi-flight queue wrap, device-wide reset/quarantine, and reset-before-reuse; non-zero packet-session coordinates, fail-closed identity exhaustion, in-flight-TX rebind refusal, stale device/stack stamp rejection, fresh traffic after stale ingress, and rebound-driver rejection of stamped egress; fixed-point scheduler lifecycle, four-queue ownership, per-hart running/current-task/domain state, and IPI lost-wakeup models; work stealing, wake/remote-cancel/fault boundaries and cross-hart fault survival; reason coalescing, stale SSIP, offline/online handoff, physical hart mapping, and send-failure retry; atomic IRQ publication, SPSC byte ordering, SpinLock contention/generation recovery/hart ownership; fault arenas; wait/timer registration ownership; per-hart heap provenance and OOM diagnostics; typed channels; bounded vsh parsing, Jobs, scripting, substitutions, and exact script manifests; and the compiler | `core/tests/`, `compiler/tests/` |
| In-kernel self-test | Live Sv39 identity/permission walks plus all-hart `satp` and MXR readback; R-X kernel text, R-- `.rodata` endpoints, RW-NX free code/capability-pool pages, execute-only compiled pages, every non-empty published capability table and all live table-pool pages R--, and a full RAM scan excluding writable-executable leaves; invalid per-hart stack guards, endpoint RW-NX stack mappings, fixed slot stride, and the 8 KiB generated-code abort reserve; zeroed same-address code and capability-table reuse; real timer interrupts and wakeups, cancellation cleanup, sixteen fault/restart cycles with bounded heap and code-pool use and no interrupted Drop, normal/abort release of exclusive generated-memory claims, component allocation isolation/reclaim, `ComponentId`/`TaskId`/CSpace binding, retained fault state, the live capability graph, and machine code actually executing | `kernel/src/selftest.rs`, via `selftest` in the shell |
| Golden transcripts | End-to-end shell behaviour, including arrow-key history and mid-line editing; the live shared page-table, stack-guard, strict W^X, and read-only data/table reports; sealed local/cross-hart execution, COW capability mutation, cross-hart lookup/revoke, and zeroed same-address reuse; expected-fatal real guard-page, W^X instruction/load/store, `.rodata` store, and capability-table store faults; retained cancelled state, revoke-during-invocation lease boundaries, durable-log recovery, real virtio-blk read/write/flush, virtio-net raw-L2 exchange and fault recovery, timeout reset, cancellation/fault restart, capability-addressed object commit/read/revoke, three boots of one persistent CSpace, and two boots of a saved source/VIBEEXE artifact against the same disk | `tests/cases/`, `tests/golden/` |
| PCI/XHCI acceptance | Real QEMU ECAM discovery, 64-bit BAR sizing/assignment, PCI INTx through PLIC, XHCI command/event/transfer rings, USB descriptor enumeration, HID keyboard input into the shell, keyboard unplug/replug recovery, BOT/SCSI capacity and sector I/O, and host-side verification of the complete written sector | `scripts/qemu-usb-test.sh` |
| Differential vs real rustc | Whether generated code computes the *right answer* | `tests/programs/`, `scripts/differential.sh` |
| Fuzzing | Whether the front end can be made to panic | `compiler/tests/fuzz.rs` |
| Mutation checks | Whether the above actually catch anything | ad hoc; see below |

The `block` QEMU case is intentionally stronger than a transcript: every case
gets a fresh raw disk, sector 7 is seeded by the host, and after `blk test` exits
the host compares all 512 bytes of sector 8. `block_recovery` suppresses one real
QueueNotify to exercise the timer/reset path, injects a component fault after DMA
publication, and separately verifies cancellation plus explicit restart.

The `store` case is likewise stronger than its transcript. The host first seeds
506 valid records containing a 180,720-byte object, leaving exactly six journal
slots. Four injected raw component faults must each reach the task/domain-bound
pre-write hook after this dense recovery, clear the exact store claim, reclaim
each arena, and reach a stable heap plateau. Store calls require 4 MiB of free
caller headroom before claiming the writer; the shell and probe each have an 8 MiB
quota. The next command commits and reads a
deterministic 900-byte object, filling all 512 slots. After shutdown,
`store-image.py` independently checks the fixed sectors 64--575, platform StoreId,
canonical kinds 1--8, shared ID/transaction classes, chain/CRC/commit binding,
and both exact payloads. Its positive interleaving and negative parity fixtures
run before the real backing image is accepted.

The `persistent_cspace` case reboots three times against one unchanged raw disk.
Boot 1 persists and installs a `root -> child -> grandchild` object-capability
graph; boot 2 reads it, flushes a tombstone for the child ancestor, and proves
both child and grandchild absent; boot 3 keeps that tombstone effective and
reuses child slot 1 only at generation 1. Every boot also checks that the target
`persistent-test` CSpace has no Store `WRITE` authority and that its first dependent
observation occurs only after recovery reaches `Ready`. After the third shutdown,
`persistent-cspace-image.py` independently parses the raw journal. Its host-side
self-test applies all 512 strict byte-prefix cuts to each of 19 canonical fixture
records (9,728 cuts) and requires every cut to recover exactly the preceding
flushed boundary before checking malformed graph and root-policy fixtures.
Core tests additionally prove that persistent quarantine denies generic lookups,
invalidates `Revocable` tokens, preserves an already acquired invocation lease,
and retains resource entries without running `Drop`. The service's stable
task/domain/token ledger lets raw-fault cleanup clear only the exact abandoned
reservation without touching another caller.

The `program_persistence` case reboots twice against one unchanged raw disk.
Boot 1 publishes the fixed `hello` source plus canonical relocatable VIBEEXE as
one read-only ProgramArtifact root and runs it. Boot 2 proves a repeat save
appends nothing, recovers the exact slot-0/generation-0 capability, recompiles the
source with the current trusted compiler, requires byte-identical VIBEEXE, and
runs using only reconstructed console `WRITE` and memory `READ|WRITE` authority.
After shutdown, `program-image.py` independently validates the journal, artifact,
hashes, relocation table, stable imports, publication order, authority manifest,
and strict 512-byte prefix cuts. See `docs/PROGRAM_PERSISTENCE.md`.

The `net` and `net_recovery` cases are also stronger than their transcripts.
Only those cases add a modern virtio-net device. Before QEMU starts, the harness
launches `scripts/net-peer.py` on an ephemeral localhost TCP port and connects
QEMU's socket netdev to it. The peer parses the four-byte big-endian QEMU frame
length and compares every byte of the 60-byte raw Ethernet messages. `net`
requires HELLO, CHALLENGE, and ACK in order. `net_recovery` first observes the
HELLO exposed before an injected component fault, withholds its response, and
then requires a second HELLO plus the complete exchange after the shared device
epoch advances. A canonical evidence file is checked separately from the guest
golden; TAP, root privileges, and host network access are never used.

`qemu-tcp-test.sh` is the separate QEMU protocol-stack harness. Its default N1
mode builds only the `tcp-echo` image, attaches QEMU user networking, binds host
forwarding to an ephemeral `127.0.0.1` port, and targets static guest
`10.0.2.15:2222`. Before opening the TCP peer, the harness exercises the
Linux-style vsh command layer, verifies the initial static address, switches
`net0` to DHCP, and requires QEMU's `10.0.2.15/24` dynamic lease. The peer then
sends a deterministic binary payload containing
NUL, control, and high-bit bytes, tolerates fragmented TCP reads, and accepts
only an exact echo. Portable tests separately drive two smoltcp interfaces
through capability-addressed packet endpoints to cover ARP, a 3,000-byte TCP
exchange, endpoint pressure, and operation-time revocation.

The `recovery` mode defines the N2 acceptance gate in that same harness. It
keeps a live TCP stream while first faulting the stack and then faulting the
virtio-net driver. After the stack fault it requires the same device epoch and
a greater stack generation; after the driver fault it requires both coordinates
to advance. At each transition the retired stream must not echo a post-fault
nonce, a fresh stream must echo exact bytes, and packets staged with that
transition's retired coordinate must increment separate stale-ingress and
stale-egress rejection counts. Silence, EOF, or reset is sufficient for the
retired-stream assertion; the gate does not require a clean TCP close or RST.

The fault, session-reporting, and stale-packet controls are compiled only by
the `tcp-echo-recovery-test` feature. They are ambient vsh commands in that
acceptance image and are absent from normal `tcp-echo`, default, and future SSH
images. The injected stale frames enter the typed endpoints after replacement
binding; they are deterministic evidence for the stack-ingress and
driver-egress checks, not an emulation of a delayed DMA completion or late IRQ.
The harness is QEMU/virtio-only and provides no Milk-V Duo DWMAC hardware
evidence. This document describes the gate and its blind spots; it does not
assert that the current run passed, nor does it test an entropy source, host
key, or SSH protocol.

`qemu-ssh-security-test.sh` is the separate N3 security-boundary gate. It boots
the explicitly marked test-identity image twice with QEMU's `/dev/urandom`-
backed modern virtio-rng device. Each boot must complete one bounded capability
request, separate equal seed material into distinct ChaCha20 stream domains,
enforce independent READ and INVOKE signer grants, accept one exact binary
client key, and reject another. The host key must remain stable while a signed
transport-sample marker must differ between boots. That marker is a freshness
smoke test for the wired QEMU transport, not an entropy-quality proof. The
fixed identities and generation are test-only; this gate does not provide
per-device provisioning, authenticated persistence, rollback resistance, a
Milk-V hardware source, or an SSH wire protocol.

`qemu-ssh-test.sh` is the separate N4/N5 wire-level gate. It builds only the
QEMU `ssh-test` image, forwards a dynamically selected localhost port to the
fixed guest listener at `10.0.2.15:2222`. Readiness is not an open-port check:
the peer preloads the exact test host key and retries an authenticated `true`
exec through the real OpenSSH client. It validates the verbose transcript's
exact host fingerprint (`SHA256:Tpigy/2zLGErAlymNq6E6LHkGOIA5S1+gJsEi5VteN8`)
and negotiated profile. An explicit `SSH_HOST_PORT` override is available. The
peer forces `curve25519-sha256`, `ssh-ed25519`, and
`chacha20-poly1305@openssh.com` with an empty host ssh config (`-F /dev/null`).
It requires exact `echo` output, exit status 0 from `true`, exit status 1 from
`false`, denial of the deterministic rejected key, and explicit rejection of
shell, PTY, and subsystem requests. A second complete QEMU boot must pass the
same strict authenticated probe with the same exact host key.
`scripts/openssh-test-key.py` creates both client fixtures with mode 0600 and
never prints their private material.

The serial side is an independent assertion: a successful boot must print
`ssh-test listening on 10.0.2.15:2222`; completed authorized commands print
`ssh-test exec complete: status <n>`; and `FAIL ssh-test:` is fatal. A
`ssh-test connection reset: <reason>` line is connection-local diagnostic
output and is expected for hostile or deliberately rejected probes. The gate
uses QEMU user networking with `restrict=on`, IPv6 disabled, and an
`/dev/urandom`-backed virtio-rng device. Its fixed identities are public test
vectors, not production provisioning or Milk-V Duo evidence. It also does not
replace the malformed-packet fuzzing, resource-exhaustion, deadline, reset, and
disconnect-race work listed for the complete N5 milestone.

The QEMU harness now defaults every integration case to four multithreaded TCG
vCPUs and requires the boot-time `4 hart(s) online` barrier, shared Sv39
activation marker, W^X/MXR/RFENCE marker, and `.rodata`/4 MiB COW capability-table
marker before accepting a shell transcript.
`smp_queues` places non-stealable waiters on logical harts 1--3,
proves each parks and resumes on its exact executor, drains the placement
doorbells, then wakes all three from the boot-pinned shell. It requires one new
successful SBI doorbell per target and receiver-side acknowledgement/idle evidence.
The same case runs a synchronized four-hart scheduler-lock sample and requires a
coherent, nonzero contention delta; the final full-suite run observed 1,688
contended acquisitions out of 2,170. Numeric telemetry is normalized only for the
golden diff and is separately parsed from the raw serial log. M5.4's nested host
model still checks running/current-task/domain isolation, remote cancellation, and
cross-hart fault survival without pretending host threads reproduce target IRQs.

`guard_page` is the deliberate exception to the usual clean-shell-exit shape. The
boot-pinned shell prints hart 0's invalid 4 KiB guard address and stores to it. The
raw-log validator requires exception cause 15 (`store page fault`), requires the
reported `stval` to equal the printed probe address exactly, and requires the
hart-specific guard marker. This proves that hardware blocked the store whose
address landed in the guard; it does not simulate a corrupted `sp` or a jump over
the single-page guard. A real bad-`sp` overflow may fault recursively while trap
entry saves registers on the same stack, so M6.2 claims guard-page enforcement,
not complete stack-clash protection, reliable recovery, or diagnostics.

`wx` is the non-fatal W^X lifecycle case. The boot-pinned shell links code into
an RW-NX page, seals it execute-only, and obtains 41 on both the boot hart and a
task pinned to logical hart 1. It then drops the image, requires the complete
same-address page to have been cleared, links code returning 42 there, and executes
the new image on hart 1 without a per-run `fence.i`. The transcript reports the
actual PTE state and the transition/remote-fence deltas; the in-kernel RAM scan
must find no writable-executable leaf.

The three `wx_*_fault` cases are separate expected-fatal boots because each proves
one hardware denial: instruction fetch from writable RW-NX storage (cause 12), load
from sealed execute-only storage with MXR clear (cause 13), and store to sealed
storage (cause 15). For each, the raw-log validator requires the printed probe
address to equal `stval` and requires the W^X-specific trap marker. A normalized
golden alone is insufficient because it deliberately hides addresses.

`ro` is the non-fatal M6.4 lifecycle case. It requires both `.rodata` endpoint
pages to be R--, then performs capability mint, derive, hart-1 lookup, revoke, and
stale lookup denial while every published replacement remains R--. It also requires
the first-fit pool to reuse the same address after the retired table has returned to
RW-NX, dropped its slots, and been completely cleared, and checks the expected
all-hart TLB-shootdown deltas.

`rodata_write_fault` and `cap_table_write_fault` are separate expected-fatal boots.
Each performs a real store and must report cause 15 (`store page fault`); the raw-log
validator requires `stval` to equal the printed `.rodata` or published-table address
exactly and requires the matching read-only marker. The normalized transcript is
necessary but not sufficient because it hides those addresses.

The protection is intentionally narrower than complete capability-graph
immutability. It covers the published `Slot` snapshot—generation, rights, object
pointer, and derivation pointer—while CSpace lifecycle scalars and
`Derivation.alive` remain RW supervisor metadata. Candidate construction and commit
are synchronous and use SYSTEM allocation; ordinary errors leave the old table
authoritative, while an exceptional candidate allocation/protection failure may be
conservatively leaked rather than rolled back across a non-local exit.

The sixteen audited fault/restart cycles now abandon a sealed code allocation as
well as heap data and a held CSpace lock. After all-hart task quiescence, raw
recovery must unseal, zero, and release exactly that allocation domain without
running the interrupted future's destructor; live code-pool pages must return to
their pre-probe baseline every cycle.

## Performance baseline

The shell's `bench` command measures two-endpoint IPC round trips, timer-IRQ to
task-poll latency, capability lookup at derivation depths 0 through 32, global
heap high-water, compiler throughput, and generated code/data size and runtime.
Every timing distribution reports warmup/sample counts plus min, p50, p95, max,
and integer mean in raw `rdtime` ticks.

`scripts/bench.py` boots the release kernel with `virt`, `rv64`, one hart,
single-threaded TCG, and deterministic `icount`; it rejects missing, duplicate,
or schema-changed metrics before comparing the checked-in
`benchmarks/qemu-tcg-rv64.json`. Latency/size regressions are upper-bounded and
throughput is lower-bounded. Relative budgets are combined with small absolute
allowances for timer quantisation; heap and generated buffers use the documented
larger byte allowances.

```sh
./scripts/bench.py                 # collect and check; never rewrites truth
./scripts/bench.py --update        # intentional baseline replacement
./scripts/bench.py --input log.txt # validate/recheck a saved transcript
./scripts/bench.py --smp-scaling   # four exact-hart workers; require >=1.25x
./scripts/bench.py --selftest      # positive and fail-closed SMP parser fixtures
```

The scaling mode intentionally does not share the deterministic one-hart
baseline. It boots `-smp 4` with multithreaded TCG, waits for all three remote
workers before releasing the boot hart, and compares identical integer work run
serially and in parallel. Each measurement spans tens of milliseconds rather
than a scheduler quantum. The final M5.5 run measured 773,610 serial ticks and
275,290 parallel ticks (`2.810x`); CI enforces only the conservative `1.25x`
floor so host noise cannot turn the observation into an overfit baseline.

The guest IPC number is a repeatable VibeOS trend measurement, not yet a claim
against a Linux pipe: a host pipe measured on another ISA/runtime would not be a
controlled comparison.

## Why four layers

Each layer catches what the one above it structurally cannot.

Host tests cannot reproduce interrupt ordering, because the host arch shim makes
interrupts a no-op — so timer and wakeup behaviour belongs to the in-kernel
self-test. Neither host tests nor the self-test can check the *semantics* of
emitted machine code as thoroughly as running a program whose every output value
is known, which is what the `conform` golden transcript is for.

This is not hypothetical. Changing one frame offset in the code generator:

```rust
-  self.emit(ld(T0, S0, off));
+  self.emit(ld(T0, S0, off + 8));
```

passes **every host test**, including the confinement audit — the instruction is
still a structurally valid load through the frame pointer. The QEMU conformance
run catches it immediately:

```
-call 42 3628800
+call 2149628476 8634481114540408832
```

`2149628476` is `0x8020xxxx`: a kernel address, read off the stack by a compiled
program. That is the privilege-escalation class this project's design rests on
preventing, and only the integration layer sees it.

## Differential testing against real rustc

Every program in `tests/programs/` is valid Rust *and* valid in the VibeOS
subset, so `rustc` is a free oracle for the code generator — the strongest check
available for something this security-critical.

`scripts/differential.sh` compiles each with the exact real `rustc` pinned in
`rust-toolchain.toml`, runs it, and verifies the committed output byte-for-byte.
It is read-only unless passed `--update`; a missing expectation fails instead of
silently becoming truth. The QEMU `differential` case feeds the same source
through `rustc edit` inside VibeOS and requires identical bytes. The case file is
regenerated from the corpus on every run, so the two cannot drift.

Keeping the corpus inside the intersection of the two languages is a real
constraint, and getting it wrong is caught immediately — rustc rejected the
first draft because bare integer literals infer as `i32` while the subset is
`i64`-only. See `tests/programs/README.md` for the rules.

## Updating goldens

```sh
./scripts/differential.sh --update  # real-rustc corpus expectations
./scripts/qemu-test.sh --update      # all cases
./scripts/qemu-test.sh conform       # run one case
./scripts/qemu-test.sh net           # raw L2 exchange plus host evidence
./scripts/qemu-test.sh net_recovery  # post-publish fault and fresh-epoch retry
./scripts/qemu-tcp-test.sh           # independent N1 hostfwd byte-stream gate
./scripts/qemu-tcp-test.sh recovery  # independent N2 stack/driver recovery gate
./scripts/qemu-ssh-security-test.sh  # independent N3 entropy/identity gate
./scripts/qemu-ssh-test.sh           # independent N4/N5 OpenSSH wire gate
./scripts/qemu-test.sh program_persistence # two boots plus raw artifact evidence
./scripts/qemu-test.sh smp_queues   # logical queues + boot-hart SBI/SSIP, one CPU
./scripts/qemu-test.sh guard_page   # expected-fatal store-page-fault + exact stval
./scripts/qemu-test.sh wx           # seal, cross-hart execute, clear, same-address reuse
./scripts/qemu-test.sh wx_execute_fault # expected-fatal instruction-page-fault + exact stval
./scripts/qemu-test.sh wx_read_fault    # expected-fatal load-page-fault + exact stval
./scripts/qemu-test.sh wx_write_fault   # expected-fatal store-page-fault + exact stval
./scripts/qemu-test.sh ro           # .rodata + COW table lifecycle across harts
./scripts/qemu-test.sh rodata_write_fault # expected-fatal `.rodata` store + exact stval
./scripts/qemu-test.sh cap_table_write_fault # expected-fatal table store + exact stval
```

Read the diff before updating. The `--update` flag is the only thing standing
between a deliberate behaviour change and a silent regression.

## Adding a test

- **A bug that reached `main` gets a regression test in the same commit as its
  fix.** Both bugs found so far are in the suite: the dropped self-wake
  (`core/tests/runtime.rs`) and the invisible running task (both there and in
  `kernel/src/selftest.rs`).
- **Diagnostics are asserted verbatim.** Error messages are a UI; a silently
  reworded error is a regression a user notices first.
- **New compiler syntax gets a line in `samples::CONFORMANCE`** with a printable,
  hand-checkable value — not just a "does it compile" test.

## Checking that a test can fail

A test that cannot fail is worse than no test, because it looks like coverage.
To check one, break the code it covers and confirm it goes red:

```sh
# in core/src/cap.rs, temporarily:
-  if !e.rights.contains(need) {
+  if false {
cargo test -p vibeos-core --test cap     # must FAIL
```

Mutations verified to be caught: dropped self-wake, bypassed rights check,
non-cascading revoke, unbumped generation, permitted amplification, memory access
through a non-frame register, dropped `li64` chunk, wrong store opcode, corrupted
precedence table, dropped heap free-list entry.

Mutations **not** caught by host tests, caught only under QEMU: wrong frame
offset. That gap is the reason the golden transcripts are not optional.
