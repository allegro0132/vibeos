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

## Corrected-close physical tests and exact lock attribution

The `tcp-drain` FIT was RAM-booted with both FIT component hashes checked.
The first TFTP attempt failed because the Mac test address had temporarily
not been assigned; en7 subsequently returned at 192.168.77.1/24 without an
interface configuration change. The retry booted at 1000 Mbps full duplex.
Four-flow 16 MiB-per-flow source/sink smoke tests passed exact byte counts.
Three subsequent single/four-flow pairs in both directions transferred 12 GiB
with exact counts and no premature EOF; the continuous serial log contained
no fault. This is byte-count delivery evidence, not a full payload-integrity
or long-duration system qualification. Iperf before/after was 581.67/623.00
and 579.66/623.07 Mbps (host→board/board→host).

V1 probe startup skew was observed physically: four source flows could wait
7.7–8.0 seconds for their first byte. Single-source payload intervals were
621.43, 614.38, and 620.61 Mbps, compared with roughly 391–394 Mbps when the
admission wait was included. Four-flow admission was staggered, so even its
common payload interval is not a clean simultaneous-flow comparison. V2 now
adds application READY and host GO; the barrier runs after all application
READY responses. Legacy V1 remains supported. Four component model tests and
three client timing tests passed; V2 host loopback exceeded 26 Gbps single-flow
and 10.3 Gbps four-flow. V2 board validation is recorded below.

The exact-lock capture used the same `tcp-drain` image, before/after arming:
unarmed 579.04/622.88 Mbps; armed 527.26/555.83 Mbps, a loss of 8.94%/10.77%.
Of 6,287.44 ms of stack-stage lock waiting on logical hart 1, **6,020.14 ms
(95.75%)** was on the named packet-driver CONTROL lock at `0x405e69a0`.
That lock had 129,181 contended acquisitions on hart 1, averaging 46.60 us.
This identifies the object instead of inferring it from an aggregate stage.
The normal `network_info` call reads status/telemetry under the same CONTROL
that protects DMA batch publication and session transitions. In the middle
16-second TX interval, all stack-stage waits occupied 26.72% of one core's
wall time. Per-lock counters cover the whole window, not individual buckets;
do not label every TX wait as CONTROL using an exact percentage from them.
This proves an avoidable serialization candidate, not that it explains the
entire 900 Mbps gap. Timer-tick units and observer effect still apply.

Inbound high-water reached 64 without full attempts in this capture; outbound
had three full attempts in bucket 228. Every sampled DMA status was 0xc84 and
MTL status 0x10000, already set in the first observation. These sticky flags
cannot date overflow/RBU to this sampling window or correlate a new event to
a queue stall; previous traffic may have set them. No event-clear experiment
was performed. The raw 600 buckets and exact-lock/hart totals were validated
by the parser and retained under prefix `20260914-nprof-locks`.

Post-capture selftest passed 395/0, and a subsequent five-second iperf pair
measured 570.63/619.81 Mbps. A default-off control-lock experiment is being tested separately from
application readiness changes; it must preserve authority/session transitions
and fault recovery.


## V2 synchronized baseline and packet evidence

FIT `17ec7a002c0bd0861d28080a0a03606769faeca1618fc4fda2dfdf71519a2acf`
completed three single/four-flow pairs, 12 GiB total with exact byte counts.
Every host start timestamp followed all service READY timestamps for its run;
first-payload delays were below 7.52 ms. Single-flow RX was 594.45–595.81 Mbps
and TX 575.21–616.19 Mbps. Four-flow aggregate RX was 611.20–612.90 Mbps and
TX 509.85–574.16 Mbps. Iperf before/after was 582.21/544.24 and 584.28/603.97
Mbps; TX variability must be retained rather than selecting the fastest result.
Raw files and summary use prefix `20260914-tcp-ready`.

A separate 128-byte-header capture measured source rates 616.66/575.38 Mbps
(single/four) with zero tcpdump kernel drops. Median host advertised receive
window was 4,194,240 bytes; observed flight occupied a small fraction of it,
with no zero-window flags. Four streams contained 1,090, 1,396, 1,659 and 1,175
same-start sequence repetitions (a lower bound excluding resegmentation).
Of these, 802, 1,185, 1,472 and 900 had already been cumulatively ACKed at the
host capture point, with median ACK-to-repeat delay 0.85–1.01 ms. Host ACK
observation does not prove that the board had received or processed the ACK.
Wireshark retransmission categories overlap and must not be added. Single-flow
had heuristic overlap/retransmission flags but no same-start repetitions in
this restricted analysis. READY/GO and connection admission intervals remain
in the raw trace and must be excluded for bulk-only gap statistics.

These observations make receive-window capacity an unlikely explanation for
this source test, but do not yet distinguish delayed ACK processing, transport
retransmission policy, and controller replay. They do not prove that removing
CONTROL contention alone will reach the target. Capture and exact-sequence
analysis are retained as `20260914-tcp-ready-capture`,
`20260914-tcp-ready-tcp.json` and `20260914-tcp-ready-duplicate-sequences.json`.

The `network-status-snapshot` experiment publishes only online, quarantine and
device epoch under a separate short recoverable lock. Writers still hold
CONTROL and publish before lifecycle operations complete, including protocol
failure. Packet admission, DMA publication and capability lease checks remain
unchanged. Hardware telemetry is called under its existing HAL concurrent-safe
contract, without a new poll or sampling timeout. Both locks participate in
fault recovery. The measured experiment was rejected and removed from the working sources;
its exact patch and FIT remain archived below.


## Status-lock A/B/A: rejected, with reproducible retransmission stalls

The status-snapshot FIT was
`62fcd8a12963606cbe3b5488a2f45d3a79ff67d7e56df7d726b738362c91f7e0`.
Three synchronized probe pairs transferred 12 GiB with exact byte counts:
single RX 570.32–570.88 Mbps, single TX 166.40–252.66 Mbps;
four-flow RX 596.63–598.50 Mbps, TX 533.75–535.99 Mbps.
Iperf before/after measured 538.93/79.33 and 537.18/92.22 Mbps.
The source regression therefore also affects the independent test service.

The 60-second exact-lock sample recorded no contended acquisitions on CONTROL
or the new runtime-info lock. The middle TX region's stack waits fell to
0.051% of one core's wall time, but stack work also fell to 13.63%.
Outbound queue full attempts rose to 1,803 in that region (inbound zero),
with high-water 64. This contradicts treating lock removal as sufficient for
higher throughput. Calibration was 536.13/91.84 Mbps unarmed and
496.41/96.82 Mbps armed; the reverse increase is not negative profiler cost,
but variation in a stalled test. Sticky DMA flags still cannot date loss.

A header-only source capture measured 187.70/532.32 Mbps and identified
14 single-flow data gaps near 1 or 2 seconds, totaling 23.97 seconds.
The following segment resumed at the sequence requested by preceding host
cumulative ACKs. That capture dropped 7,111 packets at the capture kernel;
it may establish observed duplicates, but cannot establish missing-wire data.

A subsequent **full-packet** single-source capture used a 4 MiB capture buffer
and transferred 512 MiB at 277.99 Mbps, after a driver cancel/restart.
It captured 411,943 packets with **zero capture-kernel drops**. All 381,062
captured board TCP packets had valid IPv4/TCP checksums and normal MTU sizes.
All observed portions of the known 0xa5 bulk payload matched; READY and result
trailers were excluded. This is a constant-pattern observation, not changing
payload DMA qualification. Three data gaps were 1.997, 0.998 and 1.997 seconds;
no earlier captured segment covered the first requested sequence after each
gap. Thus checksum corruption in captured traffic does not explain these
holes. Zero capture drops does not rule out loss before the host capture point,
including the host NIC. The evidence supports retransmission-timeout stalls,
without yet identifying where the original packets disappeared.

Selftest passed 395/0. Explicit driver cancellation was followed by a restart
that published component generation 2 and device epoch 2, restored 1000/full and
completed the full-packet transfer. The old `net info` output is not an offline-state oracle: missing raw grants
also produce its legacy offline message, even with running network tasks.
The successful restart and subsequent transfer check ordinary lifecycle recovery,
not a deliberate fault while holding the new snapshot lock. No optimization
is promoted on the strength of this experiment. The rejected source patch is
`target/mars-reference/20260914-status-snapshot-rejected.patch`; its build,
profile, captures and results use prefix `20260914-status-snapshot`.

The original V2 baseline FIT was RAM-booted again with both component hashes
verified, to complete A/B/A. Initial iperf recovered to 584.30/604.34 Mbps.
Final iperf was 582.47/604.41 Mbps; independent single-flow RX/TX was
592.64/573.77 Mbps and four-flow aggregate RX/TX 611.11/573.59 Mbps.
All four 1 GiB aggregate probe transfers completed. Return-run results are
retained under `20260914-baseline-return`.
Next diagnosis should compare protocol/driver accepted TX sequences and MAC
completion counters against host captures; neither a larger TCP window nor
another cache-sync reduction is justified by these observations.


## TX path audit: loss after software admission

The one-shot audit records canonical headers at protocol construction and
successful HAL driver submission. Host parsing shares a tested golden vector.
It excludes payload/checksum contents and ordering, and is default-off.
See [TX-AUDIT.md](TX-AUDIT.md) for scope, counter modes and capture requirements.

Baseline FIT `3d94b045dd1d025307f4184e084e5047f7df165ed782a7aacafdb95213f85f0b`
measured 614.18 Mbps unarmed and 602.54 Mbps armed (both full captures), a
1.90% observed cost in this pair. All three records matched exactly:
376,834 frames, 536,870,929 TCP payload bytes, identical sum/XOR fingerprints,
one SYN and one FIN. Both captures had zero kernel drops. Selftest was 395/0.

The rejected status-lock change was then reintroduced solely to reproduce its
stalls under the same audit. FIT
`1f1f9ff415607c70753bb695d2b738c59ab2e32b3cb5474b460a38533bf62e38`
measured 397.12/409.65 Mbps unarmed/armed. Its armed full capture dropped 554
packets, so its host mismatch cannot locate loss. Rebooting the exact same FIT
and retaining complete headers with a 160-byte snaplen produced zero capture
drops: protocol and driver each recorded 373,359 frames, while host capture
contained 373,343, a deficit of 16 full-MSS packets (23,360 TCP payload bytes).
Protocol/driver fingerprints matched. This excludes the software queue boundary
as the observed loss point, subject to the fingerprint's stated limitations.

A further image added read-only MMC snapshots served under the existing
exclusive driver ownership, after TX reaping. At both ends pending descriptors
were zero and MMC mode was unchanged at zero. Software total accepted frames
and the MAC total good-and-bad TX frame counter both increased by 373,595.
The filtered TCP counts were 373,594 at protocol/driver and 373,577 at the host,
a 17-packet deficit, with zero capture-kernel drops. Rate was 395.67 Mbps.
No driver fault, cancellation, underflow or carrier-error increment was observed.
The one extra total frame lies outside the filtered TCP audit.

The MAC good-only frame counter remained zero despite received traffic; its
semantics/support remain unqualified, so this is **not proof of good wire
transmission**. Total frame accounting narrows the investigation toward MAC
output, PHY/link and the host receive path before BPF, without yet selecting
one. Host en7 interface errors were reported as zero but that does not prove
that its driver exposes every hardware/USB drop. An alternative receiving
host/NIC was requested for cross-checking. The current PHY intentionally
advertises no pause; read-only local/partner advertisement diagnostics are
being added before considering a negotiation-policy change.

Evidence prefixes: `20260914-tx-audit`, `20260914-tx-audit-status`,
`20260914-tx-audit-status-headers`, and `20260914-tx-mac-audit`. The final MAC
comparison combines start and stop logs in
`20260914-tx-mac-audit-combined.log`; the first parser run containing only stop
was correctly marked ineligible for hardware comparison. The corrected result
is `20260914-tx-mac-audit-validated.json`. No 900 Mbps completion is claimed.

The read-only advertisement image was built as
`56b9a0e81f88ced5f4be3945e915def0682588b401b82d6084abb44f21501901`
but has **not** been loaded. After the MAC image's 395/0 selftest, the next
reboot command and serial recheck returned zero bytes, and two ICMP probes
timed out. No competing serial owner was found. The cause is unresolved;
passing selftest does not establish subsequent liveness. A power cycle was
requested. The current continuation produced new boundary evidence before
this first recurrence of the hardware blocker; no completion is claimed.

Local validation: 81 EQoS/shared-Ethernet checks, 24 protocol checks with audit
compiled, four host audit-parser checks, three core audit checks, and the
kernel/driver dependency-boundary check passed. These checks do not replace
the pending PHY reading, receiver cross-check, fault recovery qualification,
or the 900 Mbps target.

### 2026-09-14 recovered PHY audit and pause experiment

The user power-cycled the board; serial, software reboot interception and RAM
boot recovered. FIT `56b9a0e81f88ced5f4be3945e915def0682588b401b82d6084abb44f21501901`
was loaded and verified at 1000/full. Evidence:
`target/mars-acceptance/20260913-gigabit/20260914-tx-phy-ready2-audit/armed/`.
512 MiB V2 source: 447.15 Mbps with status-snapshot and TX audit enabled.
Protocol and driver fingerprints match (373863 frames); host captures 373841,
a deficit of 22 frames / 31792 payload bytes, with zero BPF kernel drops.
Total accepted delta 373864 equals MMC good+bad delta; both pending counts zero.
Good-only MMC remains zero and is unqualified, not evidence of valid wire output.
PHY reg4 is 0x0141, reg5 is 0xdde1: the partner advertises symmetric/asymmetric
pause, while the local PHY advertises neither.

A default-off `symmetric-pause-experiment` now advertises symmetric pause only.
Both advertisements must contain bit 10 before firmware configures both MAC
pause directions, while stopped. Half duplex is rejected; automatic MTL pause
generation is disabled for sub-4-KiB RX FIFOs, while MAC receive pause is allowed.
MTL thresholds and MAC register meanings follow Linux stmmac
[dwmac4_dma.c](https://raw.githubusercontent.com/torvalds/linux/master/drivers/net/ethernet/stmicro/stmmac/dwmac4_dma.c)
and [dwmac4.h](https://raw.githubusercontent.com/torvalds/linux/master/drivers/net/ethernet/stmicro/stmmac/dwmac4.h).
This is a hypothesis test for missing frames below software admission, not a
proven performance fix. The status-snapshot regression remains experimental.

First pause trial `eb85d9716af4877bf7ee0ba6ad2c29f1087f263ea0179d9a1ed026f2b04e2435`
rejected configuration before traffic. Follow-up diagnostic FIT
`791c645dad77ea5f50c4f978bd6adc96cf8d152919fba42b0f76c1cfa4bede8f`
reported `[FEATURE1, MTL_RX_OP, MAC_TX_FLOW, MAC_RX_FLOW] =
[159668484, 7340032, 0, 0]`; FEATURE1 encodes a 2 KiB RX FIFO, consistent
with the validated board description. The initial experiment incorrectly
rejected *all* pause on small FIFO. Linux only gates MTL automatic generation
at 4 KiB; the revised experiment retains that restriction and enables MAC
receive pause after symmetric negotiation. Neither failed trial has a throughput
result. U-Boot `md.l` reads returned zero even after DHCP and are not used as
FIFO evidence; the exclusively owned firmware register snapshot is authoritative.

Revised small-FIFO FIT
`f4762a2a3e504b67c8addf9d0eec39bec3234374be813d503f1bac6b28f0dc06`
booted 1000/full without component faults. Flow readback was
`[159668484, 7340144, 4294901762, 1]`: RX MTL automatic pause remains off,
MAC TX pause enabled with 0xffff quanta, MAC RX pause enabled. PHY reg4=0x0541,
reg5=0xdde1. The 512 MiB V2 source test achieved 440.78 Mbps. Protocol/driver
fingerprints matched; host missed 3 frames / 4380 payload bytes (zero BPF drops).
Accepted total delta 372263 matched MMC total, pending zero. This single trial
has fewer missing frames than the preceding 22-frame observation but no
throughput gain, so it does not establish pause as the cause or a performance
fix. Both flow and status-snapshot experiments remain off by default.
Evidence: `target/mars-acceptance/20260913-gigabit/20260914-tx-pause-small/`.
83 shared-Ethernet/EQoS tests and the driver dependency boundary check passed.

### 2026-09-14 replacement NIC (en13) cross-check

User replaced the host adapter. New interface: en13, MAC 00:e0:4f:83:87:aa,
USB 10/100/1000 LAN, 1000/full, MTU 1500. Existing bootpd was moved from en7
to en13 with backup `target/mars-reference/20260914-bootpd-before-en13.plist`.
Host service is manual 192.168.77.1/24, router 0.0.0.0; default route remains
192.168.1.1 via en0. The initial temporary ipconfig address was overwritten on
link changes; the failed first audit is excluded. The earlier post-pause
baseline check was interrupted by the adapter swap and is also excluded.

Same baseline FIT `17ec7a002c0bd0861d28080a0a03606769faeca1618fc4fda2dfdf71519a2acf`:
1 GiB single sink 560.33 Mbps, single source 590.82 Mbps; four-source aggregate
1 GiB 538.07 Mbps. All application byte counts match. These short trials do not
show a material gain over the existing baseline range.

Same PHY/status/TX-audit FIT
`56b9a0e81f88ced5f4be3945e915def0682588b401b82d6084abb44f21501901`:
512 MiB source 468.00 Mbps, zero capture kernel drops. Protocol, driver and host
all have 372166 frames / 536870929 payload bytes, with identical sum/XOR
fingerprints. Accepted total delta 372167 equals MAC total, pending zero,
no underflow/carrier increments. PHY local 0x0141, partner 0xcde1. The earlier
22-frame deficit with the previous adapter did not reproduce in this trial.
This supports investigating the former receive path but does not prove its
hardware defective; there is still a separate throughput limitation with the
slow status-snapshot experiment even when all captured frames match.

Evidence: `target/mars-acceptance/20260913-gigabit/20260914-en13-baseline-check/`
and `20260914-en13-phy-retry/armed/audit.json`. Neither 900 Mbps nor full Mars
qualification is achieved. Restore the faster baseline for continued use.

Final state: baseline FIT restored over en13, 1000/full; selftest 395 passed,
0 failed (`20260914-en13-final-selftest.log`). DHCP remains enabled on en13.

## 2026-09-14: finer profiling and bounded GRO

See [NETWORK-OFFLOAD.md](NETWORK-OFFLOAD.md) for the hardware TSO capability,
remaining transmit-contract work, implemented default-off receive coalescer,
model tests and physical comparison. TSO is advertised by the physical MAC but
not enabled in the current TX ring. DMA/checksum support does not establish TSO.

The extended profiler distinguishes egress queue admission, completion reaping,
packet construction and protocol polling. The kernel's size-optimized generic
packet-queue instances were also compared with `opt-level=3`: unarmed iperf
RX/TX changed from 541.87/562.52 to 602.30/613.05 Mbps on the same diagnostic
source. The temporary global kernel profile override is restored, not silently
promoted to every firmware. Fine-grained instrumentation materially affects
performance; compare matching unarmed images and record the observer cost.

Bounded GRO really merges data before TCP processing, but physical RX gains were
only about 4% in unarmed iperf and 3.6% in the independent sink trial. Two cores
remain nearly occupied in the profiled receive window. This is evidence that
coalescing alone, at the current protocol-side queue boundary with extra payload
copies, does not solve the efficiency problem. Do not accept this as completed
gigabit support or claim a proven single remaining bottleneck.
