# Mars segmentation and receive coalescing

Status: experimental; no 900 Mbps or CPU-efficiency qualification.

## Hardware and current boundary (2026-09-14)

The physical MAC's `HW_FEATURE1` snapshot is `159668484` (`0x09845904`).
Bit 18 is set: the controller advertises TSO. This is a capability observation,
not evidence of successful segmentation. The current channel TX configuration
has no TSE enable, and `descriptor::tx_with_checksum` emits normal FIRST/LAST
single-frame descriptors. CIC checksum insertion is not TSO.

`core::net::Packet` is an owned 1514-byte Ethernet buffer. `StampedPacket`
preserves device epoch and stack generation through the capability queues.
The smoltcp adapter advertises Ethernet MTU 1514 (IP MTU 1500), and its TX token
accepts only a single such frame. Increasing the MTU would change the wire
contract, not implement segmentation offload.

Upstream references consulted on 2026-09-14:

- [stmmac hardware capability definitions](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/dwmac4.h)
- [TSO and MSS context descriptor preparation](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/dwmac4_descs.c)
- [descriptor fields](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/dwmac4_descs.h)
- [Linux TCP receive coalescing rules](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_offload.c)
- [segmentation offload contracts](https://docs.kernel.org/networking/segmentation-offloads.html)

These links track upstream master, not the pinned Mars boot SDK. The new Rust
code is an independent implementation; Linux is used to check hardware fields
and protocol requirements.

## Bounded GRO experiment

The `bounded-gro` feature is default-off and propagates from Mars firmware through
kernel/netstack to net-protocol. It owns one reusable 32 KiB protocol buffer per
interface and one lookahead frame. Each aggregate contains at most 16 segments;
the existing 32-wire-frame dequeue budget per cooperative poll is retained. It
flushes immediately when the current queue is empty. There is no timer delay,
DMA buffer borrowing, or change to the raw packet capability/data format.

Only unfragmented, DF IPv4/TCP data is eligible. Header fields, flow addresses,
ACK, window and supported options must agree; sequence numbers must be contiguous
including wrapping. No options and NOP/NOP/timestamp are supported. A changed
option, flow, ACK, window, ECN, control flag, fragment or sequence gap ends the
aggregate. PSH or a short final segment terminates aggregation. All constituent
frames pass session-stamp and checksum admission; software checksums are rebuilt
when software RX verification is in use. Hardware checksum trust uses the existing
qualified-ingress contract, not a new assumption based solely on an enable bit.

An aggregate enters smoltcp once, reducing per-segment TCP parsing and listener
service calls. This is receive coalescing, not merely a larger poll batch. It still
copies payloads into the aggregation buffer and does not remove driver/queue
costs. `ngro` reports approximate once-per-second counters for live interfaces:
raw accepted frames, merged additional segments, and aggregates of two or more.
The counters are not lifetime totals across stack restart.

## TSO work still required

TSO is **not enabled by this change**. It needs all of the following together:

1. A distinct owned large-TCP-transmit message with header offsets, MSS,
   checksum mode, logical payload length and immutable session identity. Keep
   the raw Ethernet MTU and existing capability format compatible.
2. Stack generation of a large logical segment while retaining MSS-sized TCP
   congestion/window/retransmit accounting. Current smoltcp TX tokens emit
   already segmented frames; driver-side reassembly alone leaves that cost.
3. A bounded DMA pool and atomic reservation of MSS-context plus data descriptor
   slots. Validate 32-bit DMA reachability for every buffer; publish data before
   OWN/tail, and retain the entire allocation until the final data completion.
   Handle context completion separately from normal LAST/error writeback.
4. Capability-gated channel TSE configuration, TCP header words and total payload
   fields; reset must invalidate the cached MSS. Maintain the existing ordinary
   frame path and provide software segmentation fallback.
5. Host packet capture at MTU 1500 proving MSS, sequence/IP-ID/flags/checksums,
   changing-payload integrity, short tails, backpressure, reset/revocation and
   link recovery before measuring efficiency and throughput.

Two nearly saturated cores at roughly 600 Mbps are an unresolved efficiency
problem. DMA, checksum offload, TSO, GRO, batching and multiqueue are distinct
mechanisms; none by itself establishes a mature gigabit implementation.

## Physical comparison on replacement en13 NIC

All runs used IP MTU 1500, 1000/full, the same board and host, RAM-loaded FITs,
checksum experiments and the extended profiler compiled in but unarmed unless
specified. Both comparison FITs used the temporary kernel `opt-level=3` override;
that workspace override has been removed. Production firmware defaults are
restored and `bounded-gro` remains off.

| Test | Without GRO | Bounded GRO |
| --- | ---: | ---: |
| iperf host to board, 20 s | 602.30 Mbps | 626.83 / 624.34 Mbps |
| iperf board to host, 20 s | 613.05 Mbps | 617.44 / 620.52 Mbps |
| independent TCP sink, 512 MiB | 655.37 Mbps | 678.95 Mbps |
| independent TCP source, 512 MiB | 616.36 Mbps | 624.50 Mbps |
| profiled iperf host to board, 20 s | 522.55 Mbps | 549.90 Mbps |

These are sequential diagnostic trials, not confidence intervals. The difference
between iperf and the independent service remains relevant. Across the two GRO
iperf rounds and two independent transfers, `ngro` reported 2,825,088 accepted
wire frames, 1,444,788 merged additional segments and 918,866 aggregates. Counts
include both traffic directions' incoming data/control packets; do not treat
this mixed sample as an RX-only aggregation ratio.

Profiling uses 4 MHz elapsed timer ticks, **not CPU cycles**. The middle 13 seconds
of receive traffic still consume approximately two cores when exclusive scopes
and waits are summed. `protocol_poll` rises from 55.66% to 71.26% of one core's
wall time while `stack`/frontend overhead falls; the protocol scope now also
contains gathering, header comparison and aggregation copies. It does not
isolate TCP parsing, so this must not be called a TCP regression or a demonstrated
CPU-efficiency solution. RX hardware scope remains 29.46% versus 31.27%, with
higher measured throughput. Completion reaping is below 1% in this comparison.

Validation: 3 coalescer tests and 27 protocol integration tests passed, including
changing-payload delivery through real smoltcp sockets with a nonzero merge
assertion, sequence wrap, checksum rejection, header changes, session revocation,
and the original 32-wire-frame poll budget. Default-off protocol tests (24),
profile parser tests (4), and driver dependency boundaries passed. This is not
long-duration hardware data-integrity or full Mars qualification.

Evidence directory: `target/mars-acceptance/20260913-gigabit/`:

- `20260914-kernel-speed-profile-*`, `20260914-kernel-speed-independent-*`
- `20260914-gro-budget-bench/`, `20260914-gro-budget-independent-*`
- `20260914-gro-budget-after-independent.log`, `20260914-gro-rx-profile-*`
- `20260914-gro-rx-phase-comparison.json`

FIT SHA-256:

- no GRO: `8be3fc0e129e2dc6b84256fe9a9f9511880c7b7d330d568b1e5111ab619eb622`
- GRO: `03fd5921284a48307a6767b37d5426d211d86a52f901da6829871e086f231997`

Build overrides and source archive are recorded in
`target/mars-reference/20260914-gro-comparison-manifest.json`. The GRO FIT is
currently RAM-booted; SPI and the user's SD image were not changed. TSO remains
unimplemented and the 900 Mbps / CPU-efficiency objective remains open.

## TSO driver implementation checkpoint

The EQoS driver now has a default-off `Controller::set_tso` / `Ring::set_tso`
configuration and `Ring::transmit_tso(Request)` path. This is **not yet connected
to HAL packet capabilities or smoltcp output**, and the running physical FIT has
not changed. End-to-end TSO and its throughput remain unverified.

The borrowed request validates a bounded (32 KiB maximum) logical IPv4/TCP packet,
DF/no fragmentation, data-only ACK/PSH flags, header sizes and MSS 64 through
`1500 - IPv4 header - TCP header`. It preserves caller bytes. Transmit reserves
context + header + all payload slots in the existing permanent DMA pool, validates
all descriptors before hardware operations, publishes context OWN last, and rings
one tail. Reaping retains every group buffer until every descriptor is CPU-owned
and the final data descriptor reports success; a final error quarantines the
whole group. Failed stop does not release it. An MSS context is emitted for each
request, avoiding stale cached MSS across reset.

The final layout deliberately uses a **header-only first data descriptor** and
payload continuations with word 1 zero. Current upstream stmmac uses this layout
instead of using word 1 as a second payload address: implemented DMA address width
can exceed 32 bits even when all allocated addresses are low. An earlier local
codec draft using two buffers was replaced before any physical execution.
See [stmmac TSO transmit and validation](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/stmmac_main.c)
for the header layout and minimum MSS constraint.

Controller admission requires the TSO feature and TX checksum capability, full
duplex, TSE register readback, and the configured low-address bus mode. The backend
reports TSO usable only after successful configuration and start. Default backends
reject it. This does not prove physical segmentation or checksum correctness.

74 EQoS model tests pass, covering normal paths plus TSO encodings, request bounds,
cross-ring group publication, partial/out-of-order completion observations,
atomic full-queue rejection, final error quarantine and reset. The Mars bare-metal
`cargo check --offline --locked --release --features image,ethernet,trng-probe`
and dependency-boundary check pass. Evidence:

- `target/mars-reference/20260914-tso-header-only-tests.log`
- `target/mars-reference/20260914-tso-header-only-firmware-check.log`

Still required before enabling in a firmware: end-to-end owned large-send contract,
stack MSS/congestion/retransmission accounting, software segmentation fallback,
TSO header/checksum preparation qualification, and physical capture proving MTU,
sequence/flags/checksums and changing-payload integrity. No performance gain is
claimed for the unconnected driver path.

## Portable transmit contract checkpoint

`hal::tcp_segmentation::TcpSegments` now describes a borrowed logical IPv4/TCP
send with explicit MSS and a 32 KiB bound while preserving IP MTU 1500. The EQoS
request delegates format validation to this shared contract and adds its hardware
MSS lower bound. `write_segment(index, output)` provides stateless software
segmentation: a retried index produces identical bytes, all segments get their
own IP length/ID and TCP sequence, PSH appears only on the final segment, and both
checksums are rebuilt. Generic software segmentation supports MSS below 64 even
though EQoS hardware admission does not.

`core::net_segmentation::StampedSegments` owns its backing allocation and checks
the complete device/stack identity on each request, including retries.
`SoftwareTransmit` tracks accepted segment progress without advancing on
QueueFull. These types are for a new queue integration; they do not replace the
existing Packet/StampedPacket representation or bypass capability admission.
There is not yet a producer/consumer queue carrying these messages in the image.

The optional `network::Device::segmentation` HAL operation is connected through
the kernel invocation adapter to the Mars TSO driver under `tso-experiment`.
Duo and absent-device tables expose None. A successful hardware operation admits
the entire logical request; QueueFull admits none, and no caller slice survives
the call in DMA. The default Mars ethernet feature does not enable this experiment.
The software segmentation codec is implemented, but a policy loop routing queued
messages through hardware or fallback is still required.

Validation: 113 HAL/EQoS tests and 2 ownership/retry tests pass. Tests include
independent checksum verification, changing payload reconstruction, sequence and
IP-ID wrap, options preservation, MTU enforcement, repeated-index output,
no-write-on-invalid-output, adapter QueueFull propagation, and session mismatch
on retry. Mars check with `image,ethernet,trng-probe,tso-experiment` and Duo check
with `milkv-iperf3-server` pass. Mars target was explicitly inspected through Cargo
configuration as `riscv64imac-unknown-none-elf` (build-std core/alloc/compiler_builtins).
The inherited packet-adapter HAL tests now include the actual no-op profiler
module so they compile against the instrumented kernel adapter.

Evidence in `target/mars-reference/`:

- `20260914-segmentation-final-tests.log`
- `20260914-owned-segmentation-tests.log`
- `20260914-segmentation-firmware-check.log`
- `20260914-segmentation-duo-check.log`
- `20260914-segmentation-check-target.txt`

No new physical throughput result is claimed. The running board remains the
previous GRO FIT. TCP large-send generation, queue ordering/backpressure,
congestion/window/retransmission accounting and hardware checksum/segmentation
capture qualification remain open before an end-to-end TSO benchmark.

## Physical TSO segmentation checkpoint (2026-09-14)

A diagnostic one-shot mailbox now submits an explicitly addressed changing-payload
IPv4/TCP request through the exclusive driver owner. It is gated by
`tso-experiment` and is not the TCP stack's normal transmit producer.
The diagnostic scratch buffer is fixed-size, never directly DMA-owned, and avoids
the driver's heap allocation quota. The mailbox distinguishes taken from submitted;
a new driver incarnation invalidates an unfinished request. An idle new ring cannot
prove an old request completed. Two lifecycle regression tests pass.

The first 4097-byte payload probe produced three correct wire segments. The first
32714-byte payload attempt failed before DMA because its heap allocation exceeded
the component quota; driver restart also exposed a false-completion diagnostic
bug. That attempt is a failure, regardless of its old `state=3` report. Both issues
were fixed before the next test.

The fixed FIT SHA-256 is
`69fa93c54f21b742932ce11708725361a6db488fe02035cc257c91a6da9e1aa3`.
It was hash-verified and RAM-booted on Mars with the replacement en13 NIC and a
1000 Mbps full-duplex link. The 32714-byte payload at MSS 1460 produced 23 correct
segments: 22 x 1460 bytes and a final 594 bytes. Full-frame capture independently
verified changing payload, sequence continuity, increasing IP ID, final-only PSH,
IPv4 and TCP checksums, and IP lengths no greater than 1500. DMA completion was
also reported; tcpdump reported zero kernel drops. Header checksum placeholders
are explicitly cleared by the driver without modifying the caller's packet.

Evidence:

- `target/mars-acceptance/20260913-gigabit/20260914-tso-wire-probe/`
- `target/mars-acceptance/20260913-gigabit/20260914-tso-wire-large/` (failed attempt)
- `target/mars-acceptance/20260913-gigabit/20260914-tso-wire-large-fixed/`
- `target/mars-reference/20260914-tso-probe-fixed-ramboot.log`
- `target/mars-reference/20260914-tso-probe-fixed-build.log`
- `target/mars-reference/20260914-tso-probe-state-tests.log`
- `target/mars-reference/20260914-tso-normalized-tests.log` (75 EQoS tests)
- `target/mars-reference/20260914-tso-capture-tests.log` (3 capture validator tests)
- `target/mars-reference/20260914-tso-fixed-source.tar.gz`
- `target/mars-reference/tso-probe-features.json` (temporary build feature override)

This is a raw TCP segmentation probe to a closed test port, not an established
TCP throughput test. Normal TCP large-send production and queue integration,
congestion/window/retransmission accounting, sustained ring reuse, error recovery
under load, and CPU-efficiency measurements remain required. The production
feature list has been restored; no SPI or SD content was changed. The currently
running board is the diagnostic fixed TSO FIT. The 900 Mbps goal is incomplete.

## Normal TCP queue integration experiment (2026-09-14)

The default-off `tso-coalesce-experiment` connects normal TCP traffic to hardware
TSO without changing smoltcp's window, congestion or retransmission accounting.
`core::net_tx_coalesce::TxCoalescer` combines only contiguous, already-generated
plain-header IPv4/TCP data frames from the existing capability queue. Matching
MAC/IP addresses, ports, ACK, advertised window, QoS and TTL are required.
PSH, a short final payload, incompatible headers or a different session end the
batch. TCP options retain the raw path pending physical qualification. DF IP IDs
may be regenerated by TSO; sequence numbers, payload and final PSH are preserved.

At most 16 frames form a batch; at most 32 admission calls are attempted per
driver turn. Each retains the existing bounded stale-packet filtering loop. The policy never waits for future packets. The first incompatible frame is
retained ahead of successors. A single frame uses ordinary transmit. QueueFull
retains the batch intact, and retries check the immutable session stamp and retain
queue authority through DMA submission. Device authority and session publication
remain under the existing policy locks. Non-TSO devices retain ordinary transmit.
A reusable 32 KiB staging allocation is charged to an explicit experimental
128 KiB driver budget (the ordinary driver budget remains 64 KiB).

Three host regression tests cover payload/sequence reconstruction including wrap,
flow/header/session incompatibility without mutation, retry immutability, bounded
batching, short tails and PSH boundaries. Both experimental and default Mars
bare-metal checks pass. The experiment FIT SHA-256 is
`b8417eea698b54a065e7291b3d5305681bf532288cd4d68e9971c9226b5591d1`.

Two established TCP source transfers of 64 MiB verified every byte at the host.
The second capture drained BPF before stopping: 51,658 captured/filter packets,
zero kernel drops, complete coverage of all 67,108,864 payload bytes, no gaps,
no corrupted payload, no bad IPv4/TCP checksum and no IP packet exceeding 1500.
TSO counts increased by 4,088 groups / 47,096 wire frames during that transfer.
The first capture stopped too early and missed tail packets; it is not complete
wire evidence even though host verification passed and BPF reported zero drops.

Evidence:

- `target/mars-reference/20260914-tso-coalesce-tests.log`
- `target/mars-reference/20260914-tso-coalesce-final-check.log`
- `target/mars-reference/20260914-tso-coalesce-default-check.log`
- `target/mars-reference/20260914-tso-coalesce-build.log`
- `target/mars-reference/20260914-tso-coalesce-source.tar.gz`
- `target/mars-reference/tso-coalesce-features.json`
- `target/mars-acceptance/20260913-gigabit/20260914-tso-coalesce-drained/`
- `target/mars-reference/20260914-tso-coalesce-coverage-analysis.json`
- `target/mars-acceptance/20260913-gigabit/20260914-tso-coalesce-after-bench.log`

This integration still performs per-wire-packet protocol generation and queue
operations, then adds a staging copy. It is a compatibility/qualification step,
not evidence that native large-send generation or CPU-efficiency work is finished.

Matched-profile comparison used the previous fixed TSO-probe FIT
`69fa93c54f21b742932ce11708725361a6db488fe02035cc257c91a6da9e1aa3`
as baseline: hardware TSO configured but no normal queue coalescing. Both builds
use the diagnostic checksum/ring/profile feature base, default kernel optimization
profile and no GRO. Each ran two 20-second single-stream iperf tests per direction
on en13, without packet capture during measurement:

| Receiver throughput (Mbps) | Baseline rounds | Coalescing rounds | Mean change |
| --- | --- | --- | --- |
| Board RX | 553.15, 554.51 | 569.78, 569.41 | +2.85% |
| Board TX | 554.53, 552.72 | 508.06, 507.59 | -8.27% |

This is a TX regression, not a successful throughput optimization. These builds
are not the earlier kernel-opt-3/GRO candidates and must not be directly used to
estimate a delta against their 600+ Mbps results. Keep coalescing default-off.
The experiment establishes sustained normal-TCP descriptor-group operation, but
cannot distinguish the cost of coalescing/scanning/copying from submission costs
without finer profiling. Native large-send production must remove per-frame work
instead of retaining it and adding another merge stage. CPU-cycle efficiency and
900 Mbps remain unqualified. The board was left running the baseline fixed-probe
FIT after the comparison; SD and SPI remain unchanged.

Comparison evidence:

- `target/mars-reference/20260914-tso-coalesce-comparison.json`
- `target/mars-acceptance/20260913-gigabit/20260914-tso-coalesce-bench/`
- `target/mars-acceptance/20260913-gigabit/20260914-tso-baseline-bench/`
- `target/mars-reference/20260914-tso-baseline-ramboot.log`

## Native TCP generation and fallback checkpoint (2026-09-14)

The workspace now vendors smoltcp 0.13.1 with a default-off segmentation feature;
see `vendor/smoltcp/VIBEOS-PATCH.md` for provenance, exact source checksum and
semantics. `native-tcp-segmentation` is propagated through Mars, kernel, netstack
and net-protocol. It remains absent from default firmware features.

The TCP producer emits one logical plain IPv4/TCP ACK/PSH request with explicit
MSS metadata, up to 32 KiB including Ethernet headers. Wire MTU remains 1500;
SYN's MSS is unchanged. The producer limits each request by the receive window
and congestion window remaining after subtracting in-flight bytes. Emit failure
retains sequence state, while partial ACK and retransmission retain unacknowledged
payload. FIN, control packets, timestamp options and peer MSS below 64 retain the
ordinary path. The initial test expecting 32 KiB under Reno's initial window
correctly failed at 2048 bytes; the large-buffer test now explicitly selects no
congestion control, while a separate Reno test enforces its real window.

PacketDevice now owns one pending logical request. Software fallback reconstructs
at most 32 wire segments per flush into the existing bounded stamped endpoint;
it retains the index on QueueFull and blocks successor tokens until all segments
are admitted. Revocation invalidates a pending request and a token acquired before
revocation cannot publish later. Software checksums, sequence wrap and final PSH
are verified. Native generation is exercised by an actual TCP conversation in
the host integration tests, with changing payload through frontend wrap and
backpressure; this is not only a synthetic metadata test. Audit-enabled builds
record the resulting wire identities once at logical generation.

Validation:

- 354 smoltcp unit tests: `target/mars-reference/20260914-native-tcp-unit5.log`.
- 30 protocol integration + 3 GRO unit tests with both features enabled:
  `target/mars-reference/20260914-native-tcp-protocol-tests3.log`.
- 24 default protocol tests: `target/mars-reference/20260914-native-tcp-default-tests.log`.
- Mars native segmentation bare-metal check:
  `target/mars-reference/20260914-native-tcp-mars-check.log`.
- Duo original iperf image check with `--no-default-features`:
  `target/mars-reference/20260914-native-tcp-duo-check2.log`.
- Source archive: `target/mars-reference/20260914-native-tcp-source.tar.gz`.

The hardware operation still needs a direct ordered queue consumer for this owned
request. The current fallback intentionally emits ordinary MTU packets; enabling
it does not by itself enable end-to-end hardware TSO. No new physical image was
booted or benchmarked in this checkpoint. The board remains on the prior baseline
FIT. Next required work is direct session-stamped large-send queue integration,
backpressure/revocation/restart qualification and matched physical throughput plus
CPU-efficiency measurements. The 900 Mbps objective remains incomplete.

## Cross-domain transmit storage and ordered queue (2026-09-14)

A direct queue cannot safely carry the existing `StampedSegments` Box from the
producer's reclaimable arena: fault cleanup could free the buffer while a driver
still holds the queued object. That type remains suitable for same-task software
fallback. The new `core::net_segment_pool::SegmentPool` preallocates runtime-owned
32 KiB slots, with a configurable bound of 1..32 slots. Pool creation enters the
SYSTEM allocation scope. Transferred tickets contain only pool identity, slot,
generation and immutable packet session; they contain no producer-owned pointer.

Each slot has a recoverable lock. Producers serializing one slot and consumers
copying another can overlap. Reservation scans start round-robin. Invalid output
is never published; old tickets fail after reuse, pool changes or either session
coordinate changes. Consumer success releases a slot, while backpressure retains
the complete request. DMA must copy from the pool into its own buffers before
success: the pool is not direct DMA storage.

Recovery invalidates exact producer and active-consumer incarnations, including
faults before an operation records its identity. The unsafe recovery hook requires
all affected tasks to be terminal with cross-hart quiescence acknowledged, before
arena release/rebinding. An actual forgotten-guard test initially hung because
ordinary SpinLock::new is not recoverable. It was stopped, the constructor was
changed to new_recoverable, and the test then passed. Normal panic unwinding alone
would not have revealed this defect.

`core::net_transmit::TransmitEndpoint` is a separate capability resource with one
FIFO carrying `Transmit::Frame(StampedPacket)` or `Transmit::Segments(Ticket)`.
This preserves ordering without a second side queue or an on-wire marker. Existing
raw endpoints and public TCP client contracts are unchanged. Pool exhaustion and
queue exhaustion are independent bounded backpressure conditions. Queued stale
tickets cannot access a reused slot after fault recovery.

Validation: 7 pool integration tests, 2 FIFO/restart tests and 2 internal recovery/
generation tests pass. They cover whole-request retry, incomplete serialization,
producer/consumer fault retirement, different-slot overlap, stale session/pool/
generation rejection, and recovery of a deliberately abandoned lock. Evidence:

- `target/mars-reference/20260914-native-pool-queue-tests2.log`
- `target/mars-reference/20260914-native-pool-recovery-tests2.log`
- `target/mars-reference/20260914-native-pool-final-mars-check.log`

These resources are not yet instantiated by firmware or wired into PacketDevice
and the driver. Integration still must bind capabilities, reserve before issuing
a transmit token, retain pending tickets, hold the session barrier through DMA
submission, and call recovery/retirement hooks on both fault and normal teardown.
No new physical image or throughput result is claimed. The native direct hardware
path and 900 Mbps/CPU-efficiency objective remain incomplete.

## Pooled protocol producer checkpoint (2026-09-14)

PacketDevice and all public stack constructors now accept `PacketTransmit`, with
source-compatible conversion from existing raw endpoint authorities. The opt-in
pooled variant holds a TransmitEndpoint authority and the supervisor-provided
allocation domain. The kernel netstack platform can resolve that resource type;
firmware does not yet instantiate it.

A transmit token reserves a pool slot before admitting serialization or consuming
an ingress packet. Unused/raw tokens return the reservation. A native logical send
serializes directly into the slot and enqueues one ticket; it no longer creates a
producer-arena Box or software-segments the request. QueueFull retains the complete
reservation and prevents successor tokens until publication succeeds. Successful
publication transfers responsibility to the queue/driver. PoolFull prevents token
creation even when queue capacity remains. Legacy raw endpoints retain software
segmentation fallback.

Revocation before serialization publishes nothing. Because smoltcp TxToken must
still return its serializer's value, that exceptional path uses task-local scratch;
it does not write through revoked pool authority. Revoked reservations require the
trusted supervisor retirement hook before rebinding. Normal abandoned tokens cancel
while authority remains live. Audit-enabled images record wire identities once;
the extra audit reconstruction is absent from normal builds.

The pooled producer is exercised by a real TCP model transfer of 600,007 changing
bytes, with frontend backpressure and wrap. The model observes actual Segments
tickets, emulates wire segmentation using the shared codec, verifies complete data,
and checks the pool is empty afterward. This is a host model, not a Mars DMA test.
Additional tests cover unused reservations, pool exhaustion, single-ticket 32 KiB
publication, queue-full retries, FIFO preservation and revoked-token retirement.

Validation:

- 34 protocol integration + 3 GRO tests, including audit feature:
  `target/mars-reference/20260914-pooled-producer-audit-tests.log`.
- Same suite without audit: `target/mars-reference/20260914-pooled-producer-tests3.log`.
- 24 default protocol tests: `target/mars-reference/20260914-pooled-producer-default-tests.log`.
- Mars native configuration check: `target/mars-reference/20260914-pooled-producer-mars-check.log`.
- Duo original configuration check: `target/mars-reference/20260914-pooled-producer-duo-check.log`.

The remaining runtime connection is firmware policy creation/grants plus the
hardware consumer's pending-ticket handling, session-barrier checks, success-only
release, and recovery/normal teardown hooks. No new firmware was booted and no new
physical throughput is claimed. The running board remains the previous baseline.


## Direct TSO runtime and main-based submodule (2026-09-14)

The runtime integration supersedes the incomplete producer checkpoints above.
The firmware now creates the opt-in pooled FIFO; the hardware consumer validates
session stamps, retains whole requests under backpressure, releases slots only
after copying into driver-owned DMA buffers, and retires slots on teardown/recovery.

On the earlier 0.13.1 baseline, FIT SHA-256
`9c30117067db63acede5954952d3ad1ccaf3c355697e2780d87c46a5e8f7f46a`
achieved 920.18 and 925.13 Mbps TX and 603.09 and 603.60 Mbps RX in two
20-second rounds at MTU 1500. A separate 64 MiB constant-byte transfer verified
all bytes and full TCP sequence coverage, with no bad IP/TCP checksums or oversized
wire frames. This is limited integrity evidence, not a long-duration qualification.
TX profiling still recorded about 4.86 seconds of packet-driver-control lock wait.
Two high-load cores remain an efficiency problem; elapsed timer ticks are not CPU
cycles. The status-snapshot follow-up image was built but not booted in this step.

`vendor/smoltcp` is now a submodule of
https://github.com/allegro0132/smoltcp, branch `codex/vibeos-tcp-segmentation`,
based directly on main `efcba2efc87b6dcc8a2953de5768dbcc83b8fac6`.
The gitlink pins the exact patch commit. Initialize it after checkout with:

```sh
git submodule update --init --recursive
```

This updates the dependency to smoltcp 0.14.0. The port retains upstream generic
segmentation offload and congestion-window accounting. Validation: 381 IPv4
smoltcp tests, 34 VibeOS protocol tests and 3 bounded-GRO tests pass; the Mars
RISC-V check with direct TSO, status snapshots and bounded GRO also passes.
Enabling upstream generic segmentation, IPv6, multicast and Reno together yields
482 passes and one failure in `test_segmentation_offload`; that failure reproduces
on unmodified main. Minimal generic-offload feature combinations also expose
upstream IPv6/multicast test gating issues. These are not reported as passing.
Evidence is under `target/mars-reference/20260914-smoltcp-main-*.log`.

The main-based port has not yet been physically benchmarked. The preceding
920–925 Mbps measurements must not be attributed to this new submodule revision.


## Main-port physical regression and status-snapshot comparison

The main-port FIT `dbe2f27db8c09e0108f6445c4d06ebbfb4ec0c7e1c672700ab0d15e41490871c`
was RAM-booted with hash verification. The same 64 MiB payload/sequence/checksum/
MTU checks passed (892.59 Mbps with capture). Two 20-second rounds measured
RX 609.25/611.21 Mbps and TX 928.46/874.48 Mbps. The second TX run contains a
one-second interval at 48.3 Mbps; most other intervals remain near 920 Mbps.
This pause is unresolved and prevents a stability claim.

The matched TX profile measured 885.33 Mbps with 4.74 seconds of stack waiting on
packet-driver-control. Across a 30-second window containing 20 seconds of load,
harts 0/1 accumulated 20.74/20.44 seconds of activity. These are elapsed timer
measurements, not hardware CPU-cycle counters or load-only utilization.

An image changing only network-status-snapshot was also RAM-booted:
`71db7b8a4f19048e89aa16fe2d03aaf165519ac11c39d6e007fcca0ec16787cf`.
Its first profile used verbose background output, so it is not a controlled CPU
comparison: TX 690.21 Mbps, 36.82 aggregate hart activity seconds. Driver calls
rose from 78,508 to 170,845 despite lower throughput; this motivates investigating
polling/scheduling behavior rather than assuming lock removal is sufficient.
Unprofiled TX was 699.08/650.03 Mbps, RX 612.08/612.25 Mbps. After explicitly
setting quiet as in the baseline, a fresh 20-second TX test still measured only
666.94 Mbps. Its 64 MiB captured transfer passed full integrity/coverage at
775.53 Mbps. The feature remains disabled; it is a measured regression, not a
successful optimization. The faster main-port baseline was restored with FIT hash verification; a fresh
10-second TX check measured 923.23 Mbps with quiet enabled.

Evidence: `target/mars-reference/20260914-main-direct-tso*-*.log`,
`target/mars-reference/20260914-main-direct-tso*-source.json`, and
`target/mars-acceptance/20260913-gigabit/20260914-main-direct-tso*`.
Next priorities remain the intermittent TX stall, excessive polling/CPU overhead,
RX processing and GRO integration, lifecycle recovery and sustained load testing.


## One-minute TX capture and normal driver recovery (2026-09-14)

On the restored main-based direct TSO image, one continuous 60-second reverse
iperf3 transfer measured 929.72 Mbps. All one-second intervals exceeded 900 Mbps.
The host captured 5,422,875 packets with a 128-byte snaplen and zero kernel drops.
Streaming header analysis of the bulk data flow observed 6,973,149,124 bytes,
4,925,271 data packets, no sequence-forward holes or overlaps, no host zero
windows, and no data gap over 100 ms. Sequence comparisons account for 32-bit
wrap. This was a host NIC capture, not a wire tap; truncated headers cannot
validate payload or TCP checksums. The earlier isolated stall was not reproduced,
so this run does not explain or close that issue.

Normal driver cancellation/restart was tested twice via the shell. An idle cancel
followed by restart advanced component generation 1 -> 2 and device epoch 1 -> 2,
retiring five old capabilities. The running netstack and services recovered
without restarting the board: 10-second RX/TX measured 609.96/922.02 Mbps.

A second cancel occurred during a live reverse TCP transfer whose initial three
intervals measured 915/916/906 Mbps. Restart advanced generation/epoch to 3.
The interrupted connection returned a broken-pipe error without host-forced
termination. A fresh independent TCP connection then verified every byte of a
64 MiB constant-byte transfer, complete sequence coverage, valid IPv4/TCP
checksums and MTU compliance, with zero capture-kernel drops. This exercises
normal cancellation and TSO queue retirement. Fresh 10-second iperf3 sessions
then measured RX 610.39 Mbps and TX 924.31 Mbps. It does not qualify panic recovery,
abandoned locks, PHY unplug/replug or long-duration stability.

Evidence:
- `target/mars-reference/20260914-main-tx-stall.log`
- `target/mars-reference/20260914-main-tx-stall-headers.json`
- `target/mars-reference/20260914-main-active-recovery.log`
- `target/mars-reference/20260914-main-after-active-recovery-test.log`
- `target/mars-acceptance/20260913-gigabit/20260914-main-active-recovery/`
- `target/mars-acceptance/20260913-gigabit/20260914-main-after-active-recovery/`


## GRO comparison and verified ingress (2026-09-14)

Enabling only bounded-gro on the main direct-TSO baseline produced FIT
`cd0eadd8237d325a7182b81010ef628852ac152970afc4e22b5d6f59543660ba`.
The quiet 20-second RX profile measured 536.34 Mbps versus 519.77 Mbps without
GRO, but aggregate core activity remained about 41.25 versus 41.24 core-seconds
in the 30-second sampling window. GRO recorded 264,602 merged segments and
129,963 aggregates from 918,782 RX frames. Unprofiled RX was 609.17/609.05 Mbps,
TX 904.32/870.83 Mbps. This does not establish a useful throughput improvement;
GRO remains disabled in the compatibility profile. Eligible singleton packets
currently still copy into the aggregation buffer; any optimization of that cost
must retain ordering, checksum checks, revocation behavior and bounded work.

The independent TCP probe now supports V2 mode 2: the application verifies byte
`i` equals `i % 251` across all receive calls before returning a successful count.
Mismatch resets the connection. V1 mode 2 is rejected, and existing byte-count
modes remain unchanged. Five component tests pass, including fragmented reads,
pattern wrap, corruption rejection without success output and V2 admission.
`scripts/mars-tcp-verify.py` supplies valid or deliberately corrupted streams and
writes a new JSON result. Verification cost is not reported as network throughput.

The GRO + verified-sink FIT
`def17838b8c0e06938efb8bb093bf2824f5ea81041ac52967bf7e3299eea82e3`
was hash-verified and RAM-booted. Physical sequence: 64 MiB valid input confirmed
in full; a 1 MiB request with byte 34,567 changed to 255 was rejected after
admission (BrokenPipeError); a fresh 4 MiB valid transfer passed afterward.
Approximate GRO counters advanced from [13,0,0] to [45999,38377,7106]. Thus the
valid byte checks exercised real GRO delivery rather than only its feature flag.
This is bounded integrity evidence, not a long-duration qualification.

Evidence: `target/mars-reference/20260914-main-tso-gro*`,
`target/mars-reference/20260914-gro-verify-*.json`,
`target/mars-reference/20260914-gro-verified-sink.log`, and
`target/mars-reference/20260914-verified-sink-tests.log`.
The board currently runs the verified-sink diagnostic image. The production
compatibility profile is restored, with GRO and status snapshots disabled.


## 2026-09-15 Linux RX comparison and IRQ integration

See [RX-LINUX-COMPARISON.md](RX-LINUX-COMPARISON.md) for source references,
ownership gaps, implementation details, evidence and current test status.
Added optional RX watchdog/IRQ scheduling, descriptor OWN recheck, static HAL
IRQ operations independent of the mutable engine, and outbound queue wakeup.
The experiment remains off by default. The first integration regressed RX to
~563 Mbps with outbound notification missing from its wait; the corrected path
measured ~598 Mbps RX and 915–924 Mbps TX. This is not a demonstrated RX
throughput gain over the prior ~610 Mbps polling baseline, nor page-pool RX.

Both experimental images passed valid/corrupt/valid TCP ingress checks.
The corrected image also passed driver cancellation/restart during RX load,
then a fresh 64 MiB integrity check and RX/TX 597/922 Mbps recovery tests.
These are bounded tests, not the outstanding full Mars qualification.
No SPI or SD writes were performed. Experimental FITs were hash-checked and
RAM-booted. Same-source polling control measured RX 609.63 / 609.33 Mbps, versus
597.83 / 597.66 Mbps with corrected IRQ scheduling. IRQ stays disabled by
default; this stage did not improve saturated RX throughput.


### 2026-09-15 detached RX driver foundation

Added independent RX buffer counts, O(1) slot recycling, generation-checked
handoff/borrow tickets, ring replacement before publication, and a read view
which does not borrow ENGINE. The detached ring path performs no payload copy.
Live consumer borrows survive DMA reset; stale queues and abandoned exchanges
cannot free newly allocated generations. Raw permanent-storage reattachment
avoids aliasing live payload readers with a whole-storage mutable reference.
98 EQoS model tests and the Mars compile check pass. This path is not yet wired
through firmware/HAL, the capability receive queue or smoltcp. The board is
unchanged, still running the polling control; no new throughput claim is made.
See RX-LINUX-COMPARISON.md for remaining integration and exact test logs.


### RX pool firmware integration and physical testing

The subsequent `rx-pool-experiment` connects the detached ring to static HAL
loans, stamped capability transport and borrowing smoltcp tokens. The default
profile remains unchanged. The first physical experiment passed patterned TCP
receive validation and active-driver cancellation/restart followed by another
64 MiB validation, with all 4,981,154 loans returned and 128 spare buffers free.
Initial two-round results were RX 882.08/883.26 Mbps and TX 830.29/835.11 Mbps.
The TX regression prevents treating this experiment as a production replacement.
See RX-LINUX-COMPARISON.md for the same-source control and remaining bottlenecks.


The next revision avoids the RX_META lock on empty descriptor polls. Matching
ELF attribution confirms this lock's measured wait fell from 2.38 to 0.55 s.
Two 20 s tests measured RX 892.44/892.47 and TX 898.24/901.75 Mbps. A subsequent
60 s per-direction test measured RX 893.58 and TX 909.36 Mbps. All 9,904,794
loans were returned. The feature remains opt-in pending broader qualification;
the previously observed boot-time TRNG failure is still unresolved.
