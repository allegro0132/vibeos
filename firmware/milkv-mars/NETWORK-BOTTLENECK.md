# Mars network bottleneck investigation

This investigation replaces parameter-by-parameter throughput tuning. The
objective remains roughly 900 Mbps single-direction TCP at MTU 1500 with a
working gigabit network. Finite integrity checks are correctness evidence,
not an explanation of the throughput ceiling.

## Baseline and provenance

The baseline is the RAM-booted direct-RX-fill image, FIT SHA-256
`1d0ddff086567034802d5ff20590b2f43b84685f12d44854ddd22ef99f599bfa`.
It uses the existing two-hart network pipeline, 128-slot DMA rings, TX/RX
checksum experiments, read-only RX recycling and single TX descriptor sync.
No hardware parameters or NIC offloads were changed for this capture.

Evidence root: `target/mars-acceptance/20260913-gigabit/`.

- `20260914-layer-baseline-capture/`: pcap, capture statistics, 20-second
  direction-pair throughput JSON, host start/end timestamps.
- `20260914-layer-baseline-tcp-v2.json`: authoritative header analysis.
  The earlier non-v2 analysis incorrectly interpreted tshark's textual SYN
  booleans; it is superseded. Four analyzer model tests cover window direction,
  stream separation, unknown scaling and Boolean/hex SYN encodings.
- `20260914-layer-capture-state.log`: board DMA status during/after capture.
- `20260914-rx-fill-source.patch` and `.tar.gz`: shared-worktree source snapshot.

Reproduction tools are `scripts/mars-tcp-capture.py` and
`scripts/mars-tcp-analyze.py`; both require explicit capture/output inputs.
The capture tool needs capture permission. It never reads credentials,
changes NIC settings, boots the board, or flashes storage.

## First TCP evidence

The host capture contains 2,289,870 packets, with zero kernel capture drops.
The paired measured throughput was 592.09 / 625.12 Mbps (host-to-board /
board-to-host), close to the preceding uncaptured 594.58 / 615.94 pair.
This is a sanity check on capture impact, not a statistical overhead bound.
Both ends' SYNs and window scaling were captured for both data streams.
Data-stream summaries exclude the separate iperf control streams.

| Observation | Host to board | Board to host |
| --- | ---: | ---: |
| Wireshark retransmission/fast/spurious flags | 0 | 0 |
| Zero-window / zero-window-probe flags | 0 | 0 |
| Window-full flags | 104 | 0 |
| In-flight bytes, median / p95 | 46,720 / 116,800 | 17,520 / 34,228 |
| Receiver-advertised window, median | 73,816 | 2,947,136 |
| Observed flight / latest peer window, median / p95 | 73.0% / 97.3% | 0.59% / 1.16% |
| Gaps between captured data packets >= 1 ms | 1,447 | 255 |
| Largest captured data gap | 33.42 ms | 48.48 ms |

No data segment exceeded MSS 1460 in this capture. The DMA status observations
remained `0x00000c04`, MTL overflow status zero, and checksum reject count zero.
The roughly 600 Mbps ceiling therefore occurred without observed sticky RX
overflow in this run. Earlier overflow remains evidence of intermittent
starvation, not proof that the MAC/DMA is the throughput bottleneck.

Inference: the board's receive-side drain cadence is worth tracing because its
advertised window frequently shrinks and flight approaches that window.
This does **not** justify enlarging the configured TCP buffer: application
consumption, frontend synchronization, protocol work, and scheduler delays can
all shrink the available window. On board-to-host traffic the host receive
window is ample, so that window is unlikely to explain the ceiling in this
run. Sender congestion window, queued application bytes, and protocol/send
service cadence remain unknown; low in-flight bytes alone cannot choose one.

The capture location is the host NIC API, not a wire tap. Packet timestamps
can be batched; gap percentiles and ACK timing are not exact wire timing.
The forward data-to-ACK median/p95 was 0.784/1.438 ms at this capture point.
For reverse data, the host's data-to-ACK timing mostly measures its local ACK
turnaround and must not be reported as the board's measured RTT. Header-only
capture and host offloads also preclude packet checksum qualification here.
Wireshark flags are heuristics; see the primary
[TCP analysis documentation](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html)
and [offload caveats](https://wiki.wireshark.org/CaptureSetup/Offloading).

## Required next evidence, still incomplete

1. Record per-stage execution separately from lock wait: firmware RX/TX,
   protocol processing, stream frontend, test application and executor.
   Existing `executor-profile` measures elapsed 4 MHz timer ticks, including
   lock waits; it is **not** a CPU cycle or instruction profile. Existing
   `SpinLockStats` counts contention but does not measure wait duration.
   Add diagnostic-only duration/queue instrumentation, calibrate its overhead,
   and use a common board timestamp for queue full/high-water events, service
   gaps and DMA status transitions. Do not sum overlapping timings as work.
2. Correlate the TCP capture with board transmit/receive buffer occupancy,
   congestion window, retransmission state, ACK processing and pending work.
   Export bounded in-memory samples outside the timed interval where possible;
   serial formatting/output must not become the measured bottleneck.
3. Cross-check with an independent capability-based TCP sink/source, preserving
   actual application receive/copy and send semantics. Use comparable buffers,
   single and multiple independent flows, receiver byte counts and separate
   integrity checks. The current iperf compatibility server explicitly rejects
   `parallel > 1`; `iperf3 -P` cannot supply this comparison. The existing echo
   app's 1 KiB chunk and 10 ms idle polling are also not a fair throughput
   comparator. Changes to these limitations must be identified in the results.

No further cache, ring, window or scheduler tuning should be selected before
these measurements identify a dominant limit. CPU/queue attribution is under calibration below; the independent multi-flow
comparison is not yet implemented or qualified.

## Bounded software timeline implementation and first calibration

The opt-in `network-profile` feature adds `nprof SECONDS` (1..60, once per
boot) and a deferred `nprof` dump after the window. Preallocated 100 ms buckets
record exclusive executor/task/firmware/frontend elapsed ticks, contended
core SpinLock acquisition duration, packet queue high water/full attempts and
approximately once-per-second DMA status. Logical-hart totals are exported
separately. Stage scopes are synchronous and hart-affine; an executor-owned
outer scope restores attribution after a fault skips inner destructors.
Nested work and measured waits are subtracted from parents to avoid summing
inclusive time twice. Uncontended acquisition and interrupts remain part of
stage work. This is not instruction sampling or actual CPU-cycle counting.

Host tests cover nested accounting, wait exclusion, one-shot admission,
window clipping, abandoned inner scopes and exact dump completeness. The
analyzer rejects missing/duplicate rows and disagreement between per-hart and
per-bucket totals. `scripts/mars-network-profile.py` preserves the complete
timeline instead of reporting only whole-run percentages.

The first diagnostic FIT hash was
`4da94a8f42fa87d3df5698b665be04d7ad32c88a57078a161e303f7a44608829`.
On this same image, with periodic firmware logging suppressed in both cases,
20-second unarmed / armed direction pairs measured:

| State | Host to board | Board to host |
| --- | ---: | ---: |
| Unarmed | 531.59 Mbps | 600.31 Mbps |
| Armed | 494.59 Mbps | 465.64 Mbps |

Arming reduced RX by about 7% and TX by about 22%. This observer effect is too
large for unqualified attribution to the original 600 Mbps bottleneck. The
original data remain in `20260914-nprof-*`; do not treat the exported phase
percentages as the uninstrumented distribution. In that perturbed workload,
packet queues reached 62/45 entries with no full attempts; DMA observations
were clear in bucket 0, RBU appeared in bucket 10, and FIFO overflow in bucket
20. The error transition is bounded by those one-second samples, not known
at an exact packet or instant. Queue occupancy only covers the packet channels,
not the TCP socket/frontend buffers.

Inspection found that this first profiler wrote different harts' counters
into shared cache lines. The next calibration isolates counters and scope
bookkeeping by logical hart, aligns them to cache lines, merges only on dump,
and bypasses timer reads when unarmed/expired. This changes the observer,
not the network configuration. Its overhead and directional attribution must
be validated before selecting a networking change. Independent TCP sink/source
and multi-flow cross-checks remain outstanding.

### Per-hart and contended-only calibration

Per-hart isolation FIT
`4e77ecffb48ee74abde6e160a36a64215e1b00536adcc1565ab7fc4f5ae1d099`
restored unarmed throughput to 582.92/628.87 Mbps, but arming still reduced it
to 496.86/491.51. Isolation alone did not solve the observer effect.

The next FIT,
`f17027a0d62c7447db66de2d7cad78e0a5894ab6debc97147a6ffbc2b043651b`,
starts lock timing only after first observing contention (weak-CAS spurious
failures do not start it). It also classifies network-side
`drive_tcp_frontend` separately from the remaining net-stack task work.
The respective unarmed / armed pairs were 582.89/614.92 and 520.12/526.96
Mbps: a residual 10.8% RX and 14.3% TX slowdown. Treat these as perturbed-load
measurements, not exact uninstrumented CPU fractions. There is no measured
CPU-cycle counter here. The prior full-kernel opt-level-3 experiment is already
rejected in NETWORK-PERFORMANCE.md and should not be blindly repeated.

Evidence uses `20260914-nprof-contended-*`. `*-regions.json` summarizes the
middle 16 seconds of each 20-second direction, excluding two-second margins
for handshake/command alignment. Raw 600-bucket data, logical-hart totals,
calibration timestamps, source snapshots and FIT hashes are retained.

| Steady-window measurement (timer ticks / one core's elapsed window) | Host to board | Board to host |
| --- | ---: | ---: |
| Remaining net-stack work, logical hart 1 | 63.1% | 54.7% |
| Contended locks while in remaining stack work, hart 1 | 2.5% | 33.5% |
| Driver task work excluding named RX/TX invocations, hart 0 | 45.7% | 45.9% |
| Named firmware RX invocation work, hart 0 | 29.9% | 3.8% |
| Named firmware TX invocation work, hart 0 | 2.1% | 34.1% |
| Iperf application work excluding frontend calls, hart 0 | 9.9% | 5.2% |
| Frontend work, both harts combined | 21.7% | 17.1% |
| Frontend contended waits, both harts combined | 4.5% | <0.01% |

The table's rows are disjoint work/wait categories, but span multiple cores;
they must not be treated as percentages of a single total core. Driver work
still includes controller ownership polling (`tx_owned`), authority/queue
operations and other unclassified driver activity. Remaining stack work also
includes binding/status/packet-endpoint operations, not just TCP computation.
The generic core-lock timing does not identify which lock caused a wait.

RX's middle window reached inbound depth 64 with 309 full attempts; TX's
window reached inbound/outbound depth 13/45 with no full attempts. The complete
window had 376 inbound full attempts. DMA observations remained RBU/overflow
clear throughout this run. Backpressure and hardware overflow therefore must
be examined separately; the retained-ingress policy prevents interpreting a
full retry as a lost packet. No payload-integrity test was performed inside
this profiling window. Selftest after expiry passed 395/0.

The next tests remain an independent single/four-flow TCP source/sink, and
exact lock attribution rather than another network parameter adjustment.
Low application execution time does not exclude service-side limitations:
both app and stack have 1 ms idle polling, while iperf's frontend queues are
64 KiB. Sleep/ready gaps and frontend occupancy have not been measured, so
those facts are hypotheses, not a demonstrated rate cap.

## Independent TCP probe and close-order regression (2026-09-14)

The opt-in `components/tcp-probe` service uses four distinct ports (5300–5303),
64 KiB RX/TX frontend queues and 32 KiB application I/O, with persistent sink
buffers. It shares the capability adapter and TCP stack, but no iperf3 parser,
control protocol or application state. See its README for framing and timing.
The host client uses exact byte counts and a worker-start barrier; aggregate
rate is total bytes divided by the common completion interval. Loopback of
that client reached 24.5–31.2 Gbps single-flow and 10.4 Gbps with four flows.

The first probe FIT (`97ff2e274aac03e6c3cdfabd4cc507947e76b6d9d8e5c3461f319be30a761084`)
kept the previous experimental hardware features and the profiler unarmed.
Same-image iperf3 received 584.99/631.84 Mbps (host→board/board→host).
The independent single-flow probe measured 585.04/400.30 Mbps; four-flow sink
reached 622.84 Mbps. The four-flow source **failed** with premature EOF
(268,424,644 of 268,435,456 requested bytes on the reported stream). Testing
stopped; that source run is not a successful throughput result. Single-flow
source's board enqueue interval was 13.465 s versus host receive interval
21.459 s; the discrepancy needs startup/tail timing, not a CPU-limit claim.

Inspection identified an independent correctness bug in the shared frontend:
`drive_tcp_frontend` could apply socket close while bytes remained queued in
the capability frontend behind a full socket. Socket close only drains the
socket's own queue. The new regression fills that socket, appends a patterned
frontend tail, requests close, and checks complete payload-before-FIN delivery.
It failed before the fix (`Some(Close)` instead of deferred close). The fix
retains the close request until the frontend is empty, refuses new writes once
close is pending, and publishes non-writable state before clearing the request.
Reset remains immediate. Default and large-window protocol suites each pass
22 tests; the frontend suite passes five tests. This fixes byte loss; it does
not by itself establish the cause of the approximately 600 Mbps plateau.

A second diagnostic change records the exact contended SpinLock address in a
bounded per-hart table, with per-stage wait and occurrence counters. Unknown
or excess identities accumulate in an explicit address-zero row. The packet
control lock publishes its actual address for matching. No allocation or
printing occurs during sampling; addresses of arena locks may be reused and
must not be treated as permanent resource identities. The parser checks each
hart's identity totals against its existing wait totals. This still measures
timer ticks, and requires fresh same-image observer-overhead calibration.

The replacement FIT is `fe3cfdd624873e9d10f353d1b6a200683563883d6fc1b9e59f729564bab880f9`.
Its source patch/archive and build output are under `target/mars-reference/`
with prefix `20260914-tcp-drain`; physical results are recorded separately.

The replacement was **not loaded**: the old probe image stopped responding
to two serial attempts (including reboot), and three ICMP probes timed out.
A user power cycle was requested. The cause of the board-wide loss of response
is unknown; the reproduced close-order defect does not establish that cause.
An additional full-transport reset regression passed and confirms Reset bypasses
the graceful drain; the probe's three model tests and 25 core network tests
also passed. New exact-lock data and corrected four-flow rates remain pending.

### Connection-admission timing model

A subsequent offline protocol test reproduces the prior-close / 2-second pause /
next-connection sequence. The pending socket completes its handshake in 2 ms,
but application admission waits another 7,800 ms. The vendored smoltcp close
retention is 10,000 ms; the exclusive listener only promotes the pending socket
after the previous primary becomes listenable. This is consistent with the
approximately eight-second difference in the first physical source test, but
that capture did not record first-byte timing, so it is not proof that all of
its delay occurred at startup. Evidence: `target/mars-reference/tcp-probe-timewait-model.log`.

The host probe now preserves end-to-end timing and additionally computes a
source receiver payload interval, excluding the first chunk from its byte count
because its timestamp follows that receive. Multiple streams use one common
wall interval; individual rates are not summed. Sink host send intervals are
not presented as board receive intervals. Three synthetic timing tests cover
startup/staggered streams, direction semantics and insufficient samples.
The board still did not answer the continuation's serial recheck; corrected
physical rates, exact lock attribution and the unresponsive-board cause remain
unverified. No hardware or network tuning parameter was changed in this step.
