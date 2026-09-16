# Mars RX: Linux comparison and implementation state

Reviewed 2026-09-15. Linux references describe upstream stmmac; they are not
measurements from Linux running on this particular board.

| Area | Linux stmmac | Current VibeOS Mars |
| --- | --- | --- |
| RX scheduling | IRQ schedules budgeted NAPI polling; RX interrupts are masked during polling and re-enabled on completion | Default remains cooperative polling; optional RX experiment masks IRQs while busy and arms them on idle, with a 1 ms deadline fallback |
| Mitigation | RX watchdog is selected for supported cores unless the platform disables it | Experimental 100 us watchdog (78 CSR ticks at 198 MHz), connected through static HAL operations and PLIC |
| RX memory | page_pool supplies reusable DMA pages; skb page/fragment ownership delays recycling | Default path copies into Packet; experimental RX pool passes an immutable loan of original DMA bytes |
| Stack delivery | skb buffers reach NAPI GRO | Experimental stamped ticket queue feeds borrowing smoltcp tokens; pooled frames bypass contiguous-copy GRO |
| Refill | Replacement buffers permit the original page to remain stack-owned | Experimental firmware uses independent mappings and 128 spare buffers, retaining live borrows across reset |

Sources: [stmmac_main.c](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/stmmac_main.c)
(`stmmac_napi_poll_rx`, `stmmac_rx`, `stmmac_rx_refill`, `use_riwt`),
[dwmac4_dma.h](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/dwmac4_dma.h),
[dwmac4_lib.c](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/dwmac4_lib.c),
[page_pool API](https://docs.kernel.org/networking/page_pool.html).
Linux has multiple receive paths, including header allocation/copy fallbacks;
this comparison does not claim every Linux receive is entirely zero-copy.

## Baseline findings before RX pool integration

- `drivers/eqos-net/src/controller.rs`: configure keeps DMA IRQ masked. New
  watchdog setter changes only a stopped controller and verifies readback.
- `drivers/eqos-net/src/ring.rs`: `receive_inner` synchronizes for CPU, calls
  `copy_rx`, then rearms and writes the RX tail for each frame.
- `kernel/src/dwmac_net.rs`: receive obtains CONTROL and endpoint authority for
  each frame; experimental IRQ mode parks after an empty turn.
- `core/src/net.rs`: Packet owns a fixed inline buffer. Compiler-generated moves
  may cause additional copies, but their exact count has not been measured.
- `components/net-protocol/src/lib.rs`: smoltcp receives a contiguous frame and
  stores TCP stream data; frontend delivery then copies stream data onward.
  Passing a DMA page through the driver boundary will not remove those later
  stream/application copies by itself.

## IRQ implementation and original pool integration design

`rx_irq.rs` supplies GMAC4 versus GMAC4.10+ summary-enable encodings, RX-only
mask/acknowledgement, watchdog conversion in 256-clock units, and arm/readback/
status recheck. RX acknowledgements preserve TX causes and fatal-bus evidence.
A pending RX or fatal event prevents the helper from indicating an armed idle
state. The helper's boolean is explicitly **not permission to sleep**.

The HAL now provides static register-only mask/ack/arm operations that do not
borrow ENGINE from the top half. The adapter admits only the PLIC dispatch hart,
registers the waiter before arming, masks local IRQs during arm/OWN recheck, and
acknowledges causes accumulated while polling. Busy turns keep polling in batches
of at most 32; empty turns await RX IRQ, outbound queue notification or a 1 ms deadline for link/TX completion checks. IRQ
registration is removed on session drop/recovery; fatal causes stop the session.
This is an experimental scheduling path, not a complete Linux NAPI equivalent.
The existing generic WaitQueue still has allocation/locking costs.

For page-pool-style delivery, add an independently sized RX buffer pool and a
private descriptor-to-buffer mapping. Detach only CPU-owned completed buffers,
synchronize before exposure, and give the descriptor a replacement buffer.
Queue entries carry immutable pool/slot/generation/session identities. A
protocol borrow must pin its buffer; last release returns it to the pool.
Pool exhaustion provides bounded backpressure. Reset must retain old borrowed
buffers until released, even after driver/stack cancellation or a fault. A stale
release must never free a newly assigned generation. DMA may write only to
buffers currently assigned to hardware. JH7110 cache operations remain in its
platform DMA implementation.

Preserve the old inline Packet path for existing backends and client contracts.
Introduce a receive transport variant, analogous to the direct TSO transport,
rather than exposing raw DMA pointers as ordinary Packets. Keep capability
checks and session barriers in the adapter; storage/recycling mechanics belong
to the driver/pool. Batch queue admission/refill after ownership is correct.

GRO singleton copying was independently removed: first-frame storage stays in
its original Packet until a second compatible frame is accepted. No successor
means no aggregate copy. Reordering/checksum/MTU/budget tests still pass. This
change is not yet physically benchmarked and is secondary to IRQ/pool work.

## Evidence and gates

- 4 GRO tests plus 34 protocol integration tests pass after deferred copying.
- RX IRQ/controller models cover arrival during arm, status preservation,
  revision encodings, watchdog overflow and stopped-only configuration.
- Logs: `target/mars-reference/20260914-lazy-gro-tests.log`,
  `target/mars-reference/20260915-rx-irq-tests2.log`,
  `target/mars-reference/20260915-rx-primitives-mars-check.log`.
- RX IRQ integration has been RAM-booted; deferred GRO remains unmeasured.
- Integration tests: `20260915-rx-irq-integration-tests2.log`; Mars and Duo
  checks: `20260915-rx-irq-integration-check2.log`, `20260915-rxirq-duo-check.log`.
- FIT SHA256: `5df58a35c8f370a583138adcbc158d9b766ad72036f0aeead7bd0af18ee10ab6`.
  Uses direct TSO baseline features plus `rx-interrupt-experiment`, without GRO
  or status snapshots. Feature selection: `target/mars-reference/rxirq-features.json`.
- Valid 64 MiB / corrupt 1 MiB / valid 4 MiB ingress passed; IRQ count grew
  10 -> 105, busy rechecks 214059 -> 214060. Large startup recheck count remains
  a separate link-down behavior to fix.
- Low-rate ping: 20/20 replies, IRQ 109 -> 128, busy rechecks unchanged at 214060.
  Average RTT 1.970 ms. This proves interrupt delivery, not optimal latency.
- Initial unprofiled RX: 562.58 / 563.04 Mbps, below the prior ~610 Mbps polling
  baseline. Keep experimental and do not advertise a throughput improvement.

Acceptance must measure packet/IRQ/poll counts, empty polls, packets per batch,
queue/pool watermarks, core time per received GiB, RX overruns and TCP behavior.
Repeat valid/corrupt/valid ingress tests, bidirectional load and lifecycle tests.
Compare low packet rate and saturated RX separately: NAPI mainly avoids needless
polling at low load; sustained-load gains require efficient batching and fewer
buffer/queue operations. Do not infer 900 Mbps RX from register configuration.

### First IRQ integration measurement

Two 20 s runs: RX 562.58 / 563.04 Mbps; TX 903.77 / 849.01 Mbps.
With profiling, RX 482.31 Mbps versus 519.77 Mbps in the earlier polling
profile. Aggregate active core time divided by received GiB: 36.76 s versus
34.08 s (4 MHz elapsed timer accounting, not CPU cycle counters). Inbound
high-water 59 versus 61, zero full attempts; outbound high-water 23 versus 4.
Neither an IRQ storm nor an ingress queue-full event was observed during this
sample. This does not prove the cause of the regression.

An integration omission was found: new outbound ACK/TX work could not wake the
RX wait, leaving the 1 ms timer as its fallback. The next revision selects the
existing channel message notification alongside RX IRQ and timer. A listener
precedes an authority-checked queue test; the event handle carries no message
access. It also avoids treating a deliberately stopped link-down ring as RX
completion. These fixes need a new physical comparison. The watchdog interval
and descriptor count are unchanged.

Logs: `target/mars-reference/20260915-rxirq-bench.log`,
`20260915-rxirq-profile-comparison.json`, `20260915-rxirq-lowrate.log`,
`20260915-rxirq-verified-sink.log`. Queue notification and wait lifecycle tests
pass (`20260915-rxirq-tx-wake-tests.log`, `20260915-rxirq-wait-lifecycle-tests.log`).

### TX notification revision

FIT SHA256 `07f07e70cfef1d1e7f2526d83a837382c08ada2620893a095c87c63d3fdef74e`.
Valid 64 MiB / corrupt 1 MiB / valid 4 MiB checks again passed. IRQ count
12 -> 53, TX notification/check wakeups 3 -> 172. Busy rechecks at first
post-boot sample were zero (previous revision 214059), then increased to 2
across the integrity tests. This supports the link-down fix and proves TX
notifications are being used; it does not yet establish performance gains.

Two 20 s runs after TX wake integration: RX 597.83 / 597.66 Mbps;
TX 924.07 / 914.87 Mbps. This improves the incomplete first IRQ revision,
but remains below the earlier ~610 Mbps polling RX result. A current-source
polling control was built to separate source-version effects. Production
feature selection remains unchanged; no IRQ throughput win is claimed.

Profiled TX-wake revision RX: 509.05 Mbps, aggregate core seconds per received
GiB 34.88, outbound high-water 3, inbound high-water 56; neither queue full.
This recovers much of the first integration regression, but does not demonstrate
lower CPU cost than polling. Active RX cancellation retired five capabilities,
advanced driver generation and device epoch from 1 to 2, and the interrupted
host transfer exited with error without forced termination. Fresh-session
checks are recorded separately; this is cancellation, not injected fault proof.

Fresh sessions after cancellation/restart passed 64 MiB ingress validation,
RX 597.08 Mbps and TX 922.30 Mbps (10 s each). IRQ and TX wake counters
continued increasing. Logs: `20260915-rxirq-txwake-recovery.log`,
`20260915-rxirq-txwake-after-recovery.log` in `target/mars-reference`.

### Same-source polling control

FIT SHA256 `35e4c619b8c889db4ea00fce81fdbc38503188af6a31f18766a6363d81012cb4`.
Same source and direct-TSO feature set, with `rx-interrupt-experiment` disabled.
Two 20 s runs: RX 609.63 / 609.33 Mbps; TX 920.21 / 875.42 Mbps.
The corrected IRQ experiment's mean RX is approximately 1.9% lower. TX still
varies between runs in both modes; two runs are not a stability qualification.
Keep IRQ off by default; hardware interrupt delivery/lifecycle work is usable
experimental infrastructure, not an accepted RX throughput optimization.

The board has been left running this RAM-only polling control. Production
Cargo feature selection is restored. DMA page-pool delivery, batch ownership
transfer and removal of inline Packet copies remain unimplemented.

Final same-source profile: polling RX 514.77 Mbps versus IRQ+TX-wake 509.05
Mbps with instrumentation enabled. Core seconds per received GiB: 34.38 versus
34.88. Both still spend approximately 20.4–20.8 active seconds on each of two
main harts during the 20 s transfer inside a 30 s observation window. Polling
queue highs were inbound 62/outbound 3, IRQ 56/3, with zero full attempts in
both samples. Thus IRQ scheduling has not removed the saturated CPU bottleneck.
These are elapsed timer samples with profiling overhead; throughput figures
above from unprofiled runs should not be mixed with them.

Final comparison: `target/mars-reference/20260915-rx-final-profile-comparison.json`.
Current polling control also passed a fresh 64 MiB ingress verification
(`20260915-rx-poll-control-valid.json`). Model checks, Mars/Duo compile checks,
channel/waiter lifecycle tests and transmit regression tests passed. No real
DMA fault injection, cable-flap qualification, page-pool reuse test, or full
hour-long system acceptance was completed in this stage.


## Detached-buffer driver foundation (historical stage before integration)

The EQoS driver now has the first required pieces of page-pool-style delivery:

- `rx_buffers::Buffers<D, N>` separates descriptor mappings from RX slots.
  An O(1) free list reserves a replacement before detaching a completion.
  Pool identity and non-wrapping slot generations reject stale/foreign tickets.
  A unique consumer borrow prevents duplicate consumption and early recycling.
- `Ring::initialize_pooled` explicitly admits the larger allocation, resets DMA
  before reclaiming old descriptor ownership, and retains live CPU borrows.
  A table stays bound to its physical allocation across restart. Legacy receive
  and initialization cannot silently reuse buffers after pooled mode is selected.
- `Ring::receive_detached` synchronizes completion/payload, publishes replacement
  descriptor ownership and tail, and only then returns a ticket and checksum
  metadata. It never invokes `copy_rx`. Full leaves the original completion in
  place; malformed frames are rearmed without exposing payload bytes.
- `Storage<D, N>` / `Pool<C, D, N>` independently size RX storage, validate all
  spare slots and the complete 32-bit DMA span, and preserve default geometry.
  `RxView` accesses original bytes through a bounded read-only callback without
  borrowing the mutable engine. Access is unsafe until an adapter supplies the
  matching live buffer borrow and synchronization/ownership proof.

Models cover replacement ordering/no payload copy, pool pressure, repeated
wraps, live borrows across reset, reset failure, abandoned exchanges, borrower
fault cleanup, stale/foreign ticket rejection, generation exhaustion, spare
address bounds, and direct original-byte reads alongside disjoint descriptor
writes. All 98 EQoS tests pass (`target/mars-reference/20260915-rx-pool-final-tests.log`),
and Mars still compiles (`20260915-rx-pool-final-mars-check.log`). No Miri component is
installed; the ordinary RAM model does not prove physical DMA/cache coherence.

Remaining integration is substantive: static firmware ownership/borrow locking,
HAL ticket operations, stamped receive transport and smoltcp token consumption,
checksum-offload admission equivalent to the current Engine::receive path,
consumer fault cleanup tied to exact executor incarnations, and actual pool
pressure/traffic/restart validation. Payload borrows must end before recycling;
revocation alone never proves an in-flight borrower has stopped. This code is
not yet a zero-copy running network path and supplies no throughput result.
The running board remains the preceding same-source polling-control image.

`Pool::from_raw` supports reattachment without constructing a whole-allocation
mutable reference while detached CPU byte borrows are live. It requires the old
engine to be quiescent and the same ownership table to protect old RX slots.
The model verifies original-byte reads remain intact during disjoint descriptor
writes and raw reattachment. Runtime firmware must use this handoff (or keep the
same permanent pool instance), not recreate `&mut Storage` over live readers.


## RX pool integration and first physical checks (2026-09-15)

The opt-in `rx-pool-experiment` now assembles the complete detached receive path:
HAL unique loans and static operations, a stamped/revocable ticket queue in core,
smoltcp tokens borrowing original DMA bytes, and permanent firmware pool metadata.
The 128-descriptor profile has 256 RX buffers (606208-byte DMA slab). The ELF
checker admits only 32/128 descriptor profiles with either equal or double RX
storage, retaining alignment, writable-load and permanent 32-bit bounds checks.
All six image-checker tests pass, including truncated spare backing rejection.

Replacement ownership is published before the completed buffer is handed off.
Only loan release returns borrowed storage to the free list; queue revocation
cannot recycle live readers. Restart retains borrowed slots and does not zero
previously initialized DMA storage. Fault cleanup uses the full executor owner
incarnation. Cache preparation is tracked explicitly, independently of ticket
generation. CPU-side ownership metadata still uses a lock; this is not a
lock-free path. TCP stream buffering still copies bytes, and pooled frames bypass
the current contiguous-copy GRO implementation. This does not implement Linux
skb fragments or complete page_pool/GRO semantics.

The experimental FIT SHA-256 is
`8bc567e7b84efcf98be11d6f774023a6a744520137f01cf517703ea1a11046c7`.
It booted via RAM/TFTP at 1000 Mbps full duplex. The independent verifier passed
64 MiB of patterned data, rejected deliberately corrupted input, then passed a
fresh 4 MiB transfer. Afterwards received/acquired/released were all 48937,
with full=0, dropped=0, free=128, ready=0 and borrowed=0. These counts describe
this finite test, not an absence of MAC-level drops under all workloads.
Evidence: `target/mars-reference/20260915-rx-pool-verify-run.log` and adjacent JSON.
Production Cargo feature selection is restored; RX IRQ remains disabled here.


The pool image also passed cancellation/restart during ingress traffic. The old
connection exited with an error without forced host termination; the driver
restarted at epoch 2. A subsequent 64 MiB verification passed, with all 4,981,154
loans returned, no pool exhaustion, and 128 free buffers. Evidence:
`target/mars-reference/20260915-rx-pool-recovery-run.log`,
`20260915-rx-pool-recovery-valid.json`, `20260915-rx-pool-recovery-counts.log`.

Instrumented pool RX measured 793.89 Mbps and 22.25 active core-seconds per GiB
(elapsed 4 MHz timer samples, not CPU cycles). Inbound queue reached 64 and
recorded 70491 full attempts, whereas outbound high water was 2 with no full
attempts. The protocol-poll scope accumulated 10,297,073 contended-wait ticks;
the dominant unnamed lock at 0x405ed680 accounted for 9,153,493 of these.
Its identity must be resolved against the matching ELF before attributing it
to pool metadata. The evidence establishes consumer-side backpressure and
synchronization work; it does not establish which function dominates without
that attribution. Instrumentation affects throughput and should not be mixed
with unprofiled benchmark numbers.


### Same-source throughput control

Both profiles use the same source tree, MTU 1500, direct TSO and checksum/cache
features. Their only feature-list difference is `rx-pool-experiment`.
Each value is a separate 20 s single-stream run, receiver-reported Mbps:

| Profile | RX round 1 | RX round 2 | TX round 1 | TX round 2 |
| --- | ---: | ---: | ---: | ---: |
| Copy control | 555.89 | 555.94 | 909.84 | 856.14 |
| Detached RX pool | 882.08 | 883.26 | 830.29 | 835.11 |

The RX mean gain is 58.78% over this same-source control. This control itself is
slower than the earlier ~610 Mbps image: the shared token/transport refactor is
not performance-neutral for legacy receive and requires investigation. TX also
shows a lower result with pooling, though earlier tests showed intermittent TX
stalls and these samples alone do not identify its mechanism. Neither regression
is accepted as production behavior. The experimental feature stays off by default.
The control FIT is
`36b9cddd26ec4ea9aedc053ffbf1ac804ec3f0f5b499bfed61071c108a02bd13`.
Machine-readable comparison: `target/mars-reference/20260915-rx-pool-comparison.json`.


Same-source instrumented control: 489.07 Mbps, 36.24 active core-seconds/GiB,
inbound high-water 59 without full attempts, outbound high-water 25. Pool:
793.89 Mbps, 22.25 core-seconds/GiB, a 38.59% reduction in measured active time
per GiB. Both main harts still spend roughly the transfer duration active; this
is higher useful throughput, not proof of reduced CPU saturation. The pool's
full inbound queue shifts the next investigation toward consumer pacing and
lock ownership. Matching profile summaries are saved alongside the comparison.
The board is left running the same-source copying control after these tests.
No SPI, SD or persistent U-Boot environment writes occurred.


## Lock attribution and legacy token correction

Rebuilt the preceding pool ELF from the unchanged source/feature profile and
verified its binary is byte-for-byte equal to the tested payload (SHA-256
`69e35e8d3d76cdfa1f4a91367ad965157a1d8fca26ea14cd4218faaeaa5a9a83`).
The matching symbol table resolves 0x405ed680 to
`vibeos_milkv_mars::network::RX_META`; the ELF is archived as
`target/mars-reference/20260915-rx-pool.elf`. Thus the previously unnamed dominant
lock really is shared RX pool metadata, not a speculative attribution.

The next experiment checks descriptor OWN before acquiring pool metadata when
polling. Empty polls do not touch allocation/borrow state. Fault and malformed
completion states still take the normal receive path; a completed frame is
revalidated there. This adds another descriptor synchronization on nonempty
polls, so its throughput cost must be measured rather than presumed beneficial.
Legacy builds restore owning receive tokens, while pooled builds keep small
borrowed tokens; only the pooled raw fallback stores a frame in the device.
Default protocol tests (24), GRO/native legacy tests (4+34) and pooled tests
(4+36) passed. Physical results for this revision follow below.


The first RAM boot of the empty-poll-lock experiment verified both FIT hashes,
then halted before kernel/network initialization:
`MARS_TRNG_PROBE FAIL ... prepare=Err(Protocol) ... blocks=0`.
The fail-closed entropy probe subsequently attempted SBI halt; SPI firmware
reported `pmic_ops: cannot read pmic power register`. No RX performance result
exists for this revision yet. A cold power cycle was requested. The probe was
not bypassed, and this does not qualify or disqualify the RX change itself.
Evidence: `target/mars-reference/20260915-rx-lock-ramboot.log`.
Both new ELFs are retained (`20260915-rx-lock.elf`, `20260915-rx-owning.elf`) to
allow exact symbol attribution in subsequent profiles.


### Cold-recovery test of empty RX polling without pool locking

After the user power-cycled the board, FIT
`0cc0fc3a442dc115efdd9cf08e3e96efb09b95f0039b18249314e4fcc61b072f`
booted successfully through RAM/TFTP. Both FIT hashes were verified and the
link resolved to 1000 Mbps full duplex. A 64 MiB valid transfer, deliberate
corruption rejection, and a subsequent 4 MiB valid transfer passed. All 49028
loans were acquired and released, with 128 spare buffers free and no pool full
or dropped counters. Logs: `20260915-rx-lock-retry1-ramboot.log` and
`20260915-rx-lock-verify-run.log` under `target/mars-reference`.
This successful boot does not resolve the previous intermittent TRNG failure.


The empty-poll-lock experiment measured RX 892.44/892.47 Mbps and TX
898.24/901.75 Mbps in two 20 s single-stream runs at MTU 1500. This improves
both directions over the prior pool image (RX 882.08/883.26, TX 830.29/835.11),
without changing ring/window/cache settings. These are bounded throughput
runs, not sustained system qualification. Evidence:
`target/mars-reference/20260915-rx-lock-bench/summary.json`.


Matching-symbol profile comparison shows total RX_META contended wait falling
from 2.3808 to 0.5481 seconds. Queue-full attempts fell from 70491 to 77 (both
reached depth 64), with outbound high-water 2 and no full attempts. Profiled RX
increased from 793.89 to 811.91 Mbps; active core-seconds/GiB decreased from
22.25 to 21.84. These are instrumented timer measurements and lock/queue
observations, not CPU cycle counts. This supports avoiding allocator metadata
on empty polls, while leaving remaining per-frame locking as future work.
`target/mars-reference/20260915-rx-lock-profile-comparison.json` contains the
comparison. Both matching ELFs are archived for the named-lock attribution.


A subsequent 60 s per-direction run measured RX 893.58 Mbps and TX 909.36
Mbps, receiver-reported. The 60 host-sender RX intervals ranged from 873.05 to
897.09 Mbps. Retransmission counts were unavailable; absence is not zero.
After the tests all 9,904,794 loans had been returned (free=128, ready=0,
borrowed=0, pool full=0, admission dropped=0). This is bounded single-stream
network testing; it does not replace concurrent storage/WASM stress, cable-flap
recovery or the remaining cold-start/entropy qualification.
Evidence: `target/mars-reference/20260915-rx-lock-sustained/summary.json` and
`20260915-rx-lock-final-counts.log`.


### Owning-token legacy control

FIT `73bba94a95af3c21cf0ce4b893fcb7f772ec107068d70b0697e45bf99cf33915`
booted and passed a fresh 64 MiB integrity test. Two 20 s runs measured RX
572.88/574.54 Mbps and TX 919.91/919.35 Mbps. Restoring owning tokens improves
legacy RX over 555.89/555.94 Mbps, but does not restore the historical ~610 Mbps
baseline. The remaining legacy-path regression is explicitly unresolved.
Evidence: `target/mars-reference/20260915-rx-owning-bench/summary.json`,
`20260915-rx-owning-valid.json`, `20260915-rx-path-comparison.json`.
The IRQ feature and pool feature remain opt-in; no production-default promotion
is implied by the ~900 Mbps pool experiment. Complete system and long-duration
qualification remain outstanding.


At the end of this test sequence the board was RAM-booted back into the
empty-poll-lock pool FIT (`0cc0fc3a...61b072f`), resolved 1000 Mbps full duplex,
and passed another 64 MiB verification. It is left running that experimental
image; default Cargo features remain unchanged. Final boot and integrity logs:
`20260915-rx-lock-final-ramboot.log`, `20260915-rx-lock-final-valid.json`.


## CPU-load experiments: queue transition notification

`Endpoint` now notifies blocked receivers on empty-to-nonempty and blocked
senders on full-to-space transitions. Waiters still register before checking
the protected condition, and every transition wakes all registered waiters.
Additional messages/space while already runnable no longer acquire a separate
wait-queue lock on every packet. The notification handle remains a hint, not
message ownership or a capability bypass. New MPMC tests cover waking both
consumers, repeated draining, waking competing producers and loser rearming.
Core tests: 428 passed, 1 ignored; protocol pooled/GRO/native suite: 4+36 passed.

Fixed-load comparison uses 20 seconds of host-to-board TCP paced at 300 Mbps
inside a 30-second NPROF window. Measurements include that window's idle/setup
work and profiler overhead; these elapsed timer ticks are not CPU cycles.
The preceding pool image received 299.97 Mbps with main-hart active times
16.422/10.511 s. Transition notification received 299.95 Mbps at 16.275/10.283 s.
This single-pair reduction is small (~1.5%), not evidence that polling is solved.
Two unprofiled 20-second notification-image runs measured RX 905.81/906.28 and
TX 900.25/898.36 Mbps. Both notification and subsequent IRQ images passed
valid/corrupt/valid verification with all DMA loans returned.

Notification FIT: `f7e8f9d68589a5e614e429e9e46f463097d2e3b7255dc94a6ca5f3916e56338d`.
Notification+IRQ FIT: `b2fe1b6d4aea0b445338eaade3e6860d51318be4b350ad684c32f1375767ab06`.
The IRQ experiment adds only the existing `rx-interrupt-experiment` feature to
the notification image; ring/window/checksum/cache settings are unchanged.
Evidence files use `20260915-cpu-*` under `target/mars-reference` and
`target/mars-acceptance/20260913-gigabit`.


The 300 Mbps IRQ sample received 299.95 Mbps with active core time
14.348/10.908/0.014/0.014 seconds, total 25.28 versus baseline 27.01 (6.4% lower).
Transition notification alone totals 26.60 (1.5% lower). These are initial
single-window comparisons, not confidence bounds or sustained CPU guarantees.
Detailed data: `target/mars-reference/20260915-cpu-300-comparison.json`.

However IRQ mode measured RX 917.55/918.50 Mbps and TX 842.56/840.77 Mbps in two
20-second runs. The repeated TX regression makes this configuration unsuitable
for promotion. IRQ counters confirm actual operation: 14040 interrupts, 193010
arms, 2264 busy rechecks, 166305 timer wakes, 13504 TX-queue wakes over the whole
boot/test period (not solely the profile window). The comparison does not yet
attribute the TX loss to ACK latency versus scheduling/locking. IRQ stays off.
The retained change is transition notification, with approximately 906 Mbps RX
and 899 Mbps TX. Large CPU reduction remains unresolved.

Code inspection identifies further work requiring measurement: TX descriptor
ownership currently marks a driver turn runnable even without progress, and
protocol/frontend loops retain polling grace. RX-only interrupt parking cannot
remove those paths. `WaitQueue::wake_all` also takes and drops its waiter Vec;
registered-waiter allocation/reuse deserves profiling before any redesign.
No claim is made that these observations explain all remaining active CPU time.


## TSO completion scanning

The TX reaper previously synchronized the completed prefix of a TSO group on
every unsuccessful completion poll. It now probes the final descriptor first.
If its OWN is still set, no group buffer can be reclaimed and the scan ends
immediately. After OWN clears, all prefix descriptors are still synchronized
and checked; completion ordering is not assumed, and last-descriptor errors
still quarantine the group. One cached tail snapshot is reused for validation.

The new model checks repeated incomplete polls use exactly one descriptor
synchronization, retain all buffers, reject a still-owned prefix even when the
tail completes first, and release the group only when every descriptor is done.
All 101 EQoS tests pass, including existing wrapping/partial/error cases.
The firmware builds and boots, and valid/corrupt/valid ingress verification
passes. This verification is not a new patterned TX payload qualification.
Physical CPU results follow below; fewer descriptor reads alone do not prove
less total active CPU time if scheduler polling fills the freed time.
Evidence prefix: `target/mars-reference/20260915-cpu-tx-tail-*`.


TSO-tail physical result: profiled TX 925.27 versus control 933.65 Mbps,
with effectively unchanged active core time (20.690/20.376 vs 20.706/20.417 s)
and 19.08 vs 18.95 core-seconds/GiB. Unprofiled TX was 835.53/878.33 Mbps,
RX 903.88/903.34. There is no demonstrated CPU win, so the ring change and its
specific test were reverted; archived binaries/logs retain the experiment.
The code now follows the preceding validated reaper again.

## Protocol task event-driven experiment

Opt-in `network-event-experiment` connects packet-queue events plus application
accept/send/receive/close/reset notifications to the netstack task. Notifications
are emitted after releasing frontend locks. Zero-byte, WouldBlock and stale
operations do not invent progress. The task captures event epochs before each
protocol/frontend check, then waits only if no work is immediately runnable.
A 1 ms timer preserves bounded carrier/config/revocation observation. Active
work still yields cooperatively. Notification handles have no data authority,
and every next turn performs the original capability/session checks.
Event handles and wait-future storage are reserved once; this change does not
add a per-turn Vec allocation. WaitQueue waiter registration still has its
existing allocation behavior. The old polling mode is retained by default.
New tests cover before-first-poll notification, app reads releasing capacity,
close/reset, stale tokens, and reentrant wakers outside the listener lock.
Seven frontend tests and the 4+36 pooled protocol suite pass; the event-enabled
netstack and Mars firmware compile. Physical results follow below.


Initial event-mode results: 299.98 Mbps with 25.84 total active core-seconds
(main harts 15.216/10.538), versus notification-only 26.60 (16.275/10.283).
Protocol poll calls fell from 90153 to 63713, but protocol-scope time rose from
4.823 to 5.287 seconds; fewer polls are not proof of less processing cost.
Unprofiled RX was 863.50/864.31 Mbps and TX 938.50/890.26 Mbps. This first version
prepared every notification listener on busy turns too; it is not promoted.
It passed driver cancellation/restart under RX, a fresh 64 MiB verification,
and returned all 4,092,426 loans. Logs: `20260915-cpu-events-recovery-*`.

The revised event loop first identifies an idle candidate, then captures all
event epochs and repeats the full protocol/frontend/authority check before
parking. Busy turns avoid preparing listeners. At most one extra check occurs
per idle transition; there is no unbounded synchronous spin. Select polling
returns at the first ready timer/event, avoiding unnecessary other waiter polls.
The timer fallback and original authority checks remain. This supersedes the
initial description's capture-before-every-turn policy. Compile/tests pass;
the revision's physical results are recorded separately as `cpu-events-idle`.


The idle-only listener preparation revision measured 299.95 Mbps with active
core times 15.190/11.238/0.022/0.023 s (26.47 total). An unprofiled 20-second
pair measured RX 913.26 and TX 889.88 Mbps. The small CPU difference versus
notification-only 26.60 s does not establish a substantial load reduction.
The event path remains experimental/off by default; its lifecycle foundation
is retained, but it is not the CPU solution claimed by this work.

## iperf3 reusable I/O scratch storage

A further inspection confirmed that control reads, data reads/draining and
control writes still constructed zeroed 32 KiB arrays per poll. In particular,
reading an idle control connection during a data test paid that cost repeatedly.
`Server` now owns one initialized scratch buffer and reuses it for synchronous
I/O. Only the returned receive length and freshly filled transmit prefix are
read. A mock-platform test checks short reads, WouldBlock, partial writes, and
absence of stale suffix transmission; all five iperf3 tests pass. The scratch
is reset only when a server instance is initialized/replaced, not each poll.
The next physical profile disables event and IRQ experiments and otherwise
uses the notification-only pool configuration, isolating service overhead.
This is a benchmark-service fix, not evidence that stack processing itself
became cheaper. Independent TCP verification remains a separate acceptance step.


Reusable scratch alone received 299.94 Mbps. The application scope fell from
3.958 to 1.639 seconds versus notification-only (~59%), but total active time
was 26.79 vs 26.60 seconds. Executor+driver scopes rose from 8.425 to 10.082 s.
This sample shows why removing real computation does not necessarily lower
active CPU time in a polling pipeline; it is not an overall CPU reduction.
Unprofiled 20-second runs measured RX 886.43/885.99 and TX 917.63/864.63 Mbps.
The scratch fix remains appropriate for the test implementation, but its result
must not be advertised as a network-stack CPU gain. A separate IRQ combination
is evaluated with the same scratch code and event mode disabled.
Scratch FIT: `d4a431b3f73eb775b996c9aef9321f7077069877493cbeecefe5b943cfae381e`.
All comparison scopes/times are in `20260915-cpu-final-comparison.json`.


The scratch + RX IRQ combination (event-driven stack disabled) received
299.95 Mbps. In the same 30-second recording containing 20 seconds of traffic,
active core times were 13.760/11.354/0.021/0.023 seconds: 25.159 total,
versus baseline 27.012 (~6.9% lower in this single sample), IRQ-only 25.283,
and scratch-only 26.789. This is a modest measured difference, not a repeatable
large CPU reduction or a 20-second CPU utilization percentage. Application
exclusive scope was 2.421 seconds; executor+driver 7.496, protocol poll 4.997.
The 4 MHz elapsed-time profiler includes instrumentation and setup/idle work.
Independent 64 MiB patterned RX, deliberate corruption at byte 34567, and
4 MiB post-error recovery passed; all 48,936 RX loans were returned before
profiling (free=128, ready=0, borrowed=0).
FIT SHA-256: `39e2cc27424e572153950d949aae39c2b5232f2670bc3687d23c8b4696d499ee`.

Two unprofiled 20-second rounds on scratch + IRQ measured RX 891.83/899.20
and TX 911.49/860.27 Mbps. The TX variability persists; this combination is
not promoted to the production ethernet profile. The board is left running
this RAM-booted diagnostic image; neither SD nor SPI was written.

The retained source changes are transition-only channel notifications, reusable
iperf3 I/O storage, and opt-in stack/application notification plumbing.
The TSO tail-first reap experiment was reverted after it failed to improve CPU
and regressed throughput. Event-driven stack and RX IRQ modes remain opt-in.
Further CPU work should close the remaining polling loop: application-side
data/space notifications and safe TX-completion wakeups, followed by pooled
RX batching/GRO with explicit loan ownership. These are not implemented by
this change. A reduction in application scope alone must not be reported as
a whole-system CPU improvement. Full Mars network qualification is outstanding.

After both throughput rounds, all 3,912,270 acquired RX loans were returned;
free=128, ready=0, borrowed=0, pool full=0 and dropped=0. These are RX pool
counters, not proof of zero loss at every hardware/TCP layer.


## Application readiness wait experiment

`application-event-experiment` adds a second, network-to-application notification
queue to each TCP listener and enables idle waits in iperf3. State changes,
empty-to-readable RX, and full-to-writable TX publish notifications after the
listener lock is released. Existing app-to-network events remain separate.
The service captures epochs only after an idle candidate, then repeats its
complete I/O check before parking. A 1 ms deadline retains timeout/revocation
observation. The capability adapter admits notification access with RECV rights;
notifications carry no byte access or connection authority. Every actual I/O
operation retains its capability and generation checks. Busy turns still yield.
Nine net-api tests cover both notification directions, including early events,
readiness transitions, suppression of redundant wakes and reentrant callbacks;
five iperf3 tests pass with the event feature enabled. The experimental firmware
adds only application events to the scratch + IRQ comparison configuration,
leaving protocol event mode disabled. No CPU gain is assumed before profiling.

The app-wait RAM image passed patterned 64 MiB RX, deliberately corrupt RX,
and 4 MiB recovery; all 48,942 RX loans were returned before profiling.
FIT SHA-256: `b1eb70112984f77dbeb1bda2cc70a4caf18508068d5424d1ccda4768e2391a51`.
At 299.98 Mbps, active core seconds were 10.990/10.094/0.039/0.039
(total 21.162), versus scratch + IRQ 25.159: ~15.9% lower in this single
same-scope comparison, and ~21.7% below the initial 27.012 baseline.
Application scope calls fell from 306,555 to 102,313; driver calls from
128,336 to 114,975. Application exclusive time fell 2.421 -> 1.412 s;
executor 4.099 -> 2.712 s; protocol poll 4.997 -> 4.750 s. The profile is
still 30 seconds containing 20 seconds of traffic, with elapsed-time probes,
not a direct CPU-cycle or load-percentage measurement. Repeated CPU samples
and broader latency/recovery qualification remain necessary.

Two unprofiled 20-second app-wait rounds measured RX 852.20/848.74 Mbps
and TX 880.99/889.92 Mbps. Compared with scratch + IRQ RX 891.83/899.20,
the RX regression repeats; CPU savings are accompanied by lower saturation
throughput. Keep this feature opt-in. The result motivates measuring wake
and handoff batch costs, not claiming the 900 Mbps goal complete or silently
raising timer delays. Busy RX cancellation/restart admitted driver generation
1 -> 2, with no task faults; a subsequent fresh 64 MiB patterned TCP transfer
passed. The board now runs the app-wait diagnostic image in RAM.

Post-restart 5-second smoke connections completed both directions (RX 845.75,
TX 618.75 Mbps). These short recovery samples are not throughput qualification;
the low TX sample remains recorded rather than discarded.

Final pool counters: received=4,420,928, acquired=released=4,420,927,
free=128, ready=0, borrowed=0, full=0, dropped=0. No outstanding loan remained
after the recovery tests; received and acquired counters differ across reset.


## Inline single-waiter storage

Inspection of `WaitQueue::wake_all` found that every nonempty wake detached
and freed the waiter Vec; the next registration allocated again. The queue
now keeps one waiter inline and uses a fallible overflow Vec for additional
waiters. Epoch, exact registration IDs, task-owned cleanup and callbacks
outside the queue lock are unchanged. This removes waiter-array allocation
for the common one-consumer case, not all scheduler/owned-registration
allocations. The structure is larger by one optional waiter per queue.
Core regression: 428 passed, one ignored. Two additional tests cover repeated
inline rearm without an overflow allocation, multi-waiter cancellation, and
old-future cleanup after replacement. Nine network notification tests pass.
The physical comparison keeps the app-wait feature set and changes only this
storage representation; throughput or CPU benefits are not assumed.

Inline-wait FIT: `8eaaf0f9de1948b871cbee977cef54dd5fb98987fbeb72860a333e1385494e46`.
Patterned RX, deliberately corrupt RX and subsequent recovery all pass;
48,939 acquired RX loans were returned before profiling. At 299.97 Mbps,
active core seconds were 11.194/10.593/0.029/0.028 (total 21.844), versus
app-wait 21.162. Application calls 104,150 and driver calls 117,153 are also
slightly higher. This sample does not demonstrate a CPU benefit from removing
the waiter-array allocation; it is not established as the RX CPU bottleneck.

Two 20-second rounds measured RX 848.86/848.91 and TX 936.06/885.77 Mbps.
RX is unchanged from app-wait, the CPU sample is not better, and the first
high TX sample did not repeat. The generic WaitQueue experiment is therefore
reverted; its exact diff is archived as
`target/mars-reference/20260915-cpu-inline-wait-experiment.patch`, alongside
the matching ELF, FIT, test logs and profiles. The current source uses the
original WaitQueue again; the board temporarily still runs the tested inline
RAM image. No SD/SPI change occurred. This experiment narrows the next action:
pooled RX explicitly bypasses GRO in `PacketDevice::receive`; integrating
bounded coalescing with loan lifetime/revocation tests is the next RX work.

Final inline-image RX pool counters: received=acquired=released=3,759,321;
free=128, ready=0, borrowed=0, full=0, dropped=0.


## Pooled RX GRO integration

The DMA-loan branch of PacketDevice now uses bounded GRO when both pooled-rx
and bounded-gro are selected. A lone frame remains a borrowed slice. Actual
merges copy into the existing 32 KiB buffer, up to 16 segments, and release
each additional merged loan immediately. At most the original loan and one
unmergeable lookahead loan are retained. No wait for future packets is added.
Control, gaps, options and checksum eligibility retain the existing fallback.
The 32-wire-frame poll budget now applies to pooled ingress too. Authority
revocation during collection aborts the aggregate; the next receive boundary
clears retained loans after revocation. Pending lookahead requests another poll.
`Buffer::begin` clears stale aggregate state even on ineligible first frames.

Tests cover merged payload/order, immediate release, original-pointer single
frames after an aggregate, lookahead revocation, wire-frame budget, and real
TCP with changing payloads and an assertion that pooled merging occurred.
The old standalone GRO test also failed against HEAD in an isolated baseline:
its 4 KiB sender repeatedly refilled to PSH boundaries. The fixture now keeps
a 64 KiB transmit backlog and batches client polls; no eligibility rule or
merge assertion was relaxed. Legacy GRO, pooled GRO without native TSO,
pooled without GRO and the combined native-TSO profile all pass.
The physical image adds bounded-gro to the app-wait configuration; the generic
inline WaitQueue experiment remains reverted.

The pooled-GRO image passed 64 MiB patterned RX, deliberately corrupt RX
and 4 MiB recovery; all 48,935 acquired loans returned before profiling.
At 299.98 Mbps, active core seconds were 11.098/10.259/0.018/0.019
(total 21.394), versus app-wait without GRO 21.162. Protocol-poll exclusive
time fell 4.750 -> 4.517 s, but whole-system active time did not improve in
this sample. After the profile, NGRO recorded rx_frames=563,940,
merged_segments=504,425 and aggregates=53,458 (approximate snapshots).
Thus the path is active; high merge counts alone are not evidence of CPU
reduction. The extra bounded aggregation copy and per-wire-frame admission
remain costs. These elapsed 4 MHz timer scopes are not CPU cycle measurements.

Two unprofiled 20-second rounds measured RX 897.41/898.35 and TX
937.83/939.63 Mbps. Compared with app-wait without GRO RX 852.20/848.74
and TX 880.99/889.92, this combination restores RX near the effort target
while the fixed-rate CPU sample remains similar (21.394 vs 21.162 s).
This is two short throughput samples and one CPU sample, not full physical
qualification or proof of a repeatable CPU reduction at saturation.
FIT SHA-256: `bbac3cd1f8e6cfcc0829beda71411a9faedf03b87487db16d11a823b84ded5fd`.

A further mock revokes inbound authority from the second DMA acquire during
collection. No receive token is published and both acquired loans are released.
Combined pooled-GRO/native-TSO tests now pass 4 unit + 39 integration tests.
Physical cancellation/restart during RX advanced driver generation 1 -> 2
without task faults; a fresh 64 MiB patterned connection passed afterward.
The restored driver is used for the following 60-second-per-direction run.

After recovery, 60-second runs measured RX 892.14 and TX 920.96 Mbps.
Final pool counters: received=9,247,421; acquired=released=9,247,420;
free=128, ready=0, borrowed=0, full=0, dropped=0. One received ticket was
not acquired across reset. The current-stack NGRO snapshot was
rx_frames=5,065,687, merged_segments=4,194,361, aggregates=433,890; its
lifetime differs from the boot-wide pool counters after driver/stack recovery.
The board remains on the pooled-GRO RAM image. Default firmware features
are unchanged. Full-load CPU comparison, repeat profiles, long concurrent
stress and the broader Mars qualification remain outstanding.


## Saturated RX CPU audit

A fresh RAM boot of the exact pooled-GRO FIT was used for one 30-second
profile containing 20 seconds of unlimited single-stream RX. Background
console output was muted first. This is distinct from the unprofiled tests.
The profiler reduced observed throughput to 791.53 Mbps; active core times
were 20.779/20.556/0.028/0.028 seconds, total 41.391. The matching earlier
rx-lock profile used the same window/test lengths and received 811.91 Mbps
with 41.287 core seconds. Normalized cost was 22.457 vs 21.838 core-seconds
per GiB. This does not demonstrate saturated CPU savings; the previous
300 Mbps comparison must not be extrapolated to full-load utilization.
The two network cores still spend nearly the whole traffic interval active.
Instrumentation overhead means neither sample substitutes for the independent
unprofiled throughput numbers. Full comparison is archived in
`target/mars-reference/20260915-pooled-gro-fullrx-comparison.json`.

In the new sample, exclusive protocol-poll scope was 10.816 s, RX 7.441 s,
frontend 6.416 s and driver 5.558 s. Contended wait at address `0x405f26f0`
was 2.686 s on hart 1 plus 0.059 s on hart 0. `llvm-nm -n -C` against the
exact archived `20260915-cpu-pooled-gro.elf` identifies that address as
`vibeos_milkv_mars::network::RX_META`. This lock is held throughout
`poll_rx_ticket` -> `receive_detached`, including payload cache sync,
replacement-descriptor publication and tail MMIO. Protocol acquire/release
needs the same lock. Next work should separate short ownership-table
transitions from these serialized hardware operations while preserving
Prepared/Detached states, exclusive engine/reset ownership and late-loan
cleanup. Removing the measured wait alone cannot explain all remaining CPU
work; any refactor still needs identical-load and integrity/recovery controls.
No performance code changed during this saturated audit.


## Scoped RX ownership metadata experiment

The RX ring adds a statically dispatched `rx_buffers::Access` contract. Its
short closures cover pool/mapping validation, replacement reservation and
post-tail ticket publication. Cache maintenance, descriptor writes, barriers
and tail MMIO run outside those closures. The former direct Buffers API
remains supported. The unsafe implementation contract requires a stable table
and engine/reset exclusion across the whole operation; ordinary unrelated
loan return may interleave with the hardware work. Detached/Prepared states
persist across a failed final metadata commit until proven DMA stop/reset.
Mars implements Access with RX_META and moves frame validation plus atomic
telemetry outside that lock. The ticket remains private until validation and
length publication complete. The design trades a longer critical section
for additional short lock acquisitions; it needs measured validation.

EQoS model regressions pass, with new tests preventing hardware operations
inside metadata closures, returning an unrelated loan between stages, and
recovering after post-tail metadata failure without reusing a live borrow.
Firmware library tests pass (3). Host binary testing with rx-pool alone is
not a valid firmware target (optional kernel absent); the actual ethernet
firmware build supplies the appropriate target/features.
The next physical image keeps the pooled-GRO/app-wait/IRQ feature set and
changes only this ownership-lock integration. No performance gain is assumed.

The scoped-metadata image passed patterned 64 MiB RX, deliberately corrupt
RX and subsequent 4 MiB recovery. All 48,938 loans returned before profiling.
At saturated RX with the same 30-second/20-second profile, throughput rose
791.53 -> 847.78 Mbps, with total active time 41.391 -> 41.368 core seconds.
Cost per GiB fell 22.457 -> 20.958 (~6.7%). Both network cores still remain
nearly fully active during traffic; this is better throughput per active CPU
time, not a claim of low full-load utilization. The current sample follows
integrity traffic, whereas the previous full-load sample followed a fresh
quiet boot; repeated matched controls remain necessary.

Exact-ELF `llvm-nm` identifies RX_META at 0x405f26f0 in both images. Its
protocol-hart wait fell 2.686 -> 0.298 s; driver-hart wait rose 0.059 ->
0.400 s. Total RX_META wait fell 2.745 -> 0.697 s. More short acquisitions
are visible in exclusive work (RX 7.441 -> 9.927 s), so removing waits alone
must not be reported as the entire performance effect. Comparison JSON:
`target/mars-reference/20260915-rx-scoped-metadata-comparison.json`.

Two unprofiled 20-second rounds measured RX 948.19/948.68 and TX
883.43/882.78 Mbps. RX improves repeatedly versus pooled-GRO
897.41/898.35, but TX regresses versus 937.83/939.63. Do not promote
the combination as a universal improvement. Additional short acquisitions
on incoming ACKs are a candidate cost, not an established TX root cause.
FIT SHA-256: `33f8ba8be3886cf6a6aa38682a796be4e319ab6d36960b17d2ec1bb5f268905e`.

Live RX cancellation/restart advanced driver generation 1 -> 2 with no
faulted tasks. A new 64 MiB patterned connection then passed. The longer
per-direction run uses this restarted engine. Another unresolved measurement
issue is instrumentation overhead: scoped profiles materially lower throughput.
The executor currently exposes per-turn elapsed ticks only with profiling;
its run loop has no WFI residency counter. A future low-overhead idle-residency
measurement would help distinguish normal-load CPU utilization from the
instrumented lock/timeline diagnosis. No such counter is implemented here.

Post-recovery 60-second runs measured RX 948.81 and TX 938.38 Mbps.
The longer TX result recovers the earlier target range, despite two ~883 Mbps
short runs before recovery. Duration and reset both changed, so the source
of this TX variation is unresolved; do not discard either set of observations.
Final pool counters: received=acquired=released=10,650,623; free=128,
ready=0, borrowed=0, full=0, dropped=0. EQoS regressions total 102 passed,
plus 3 firmware library tests. The board remains on the scoped-metadata RAM
FIT. Firmware feature defaults are unchanged, and no SD/SPI write occurred.
The refactor is retained within the existing opt-in pooled path. Its measured
RX lock/throughput improvement is not full-load CPU qualification.


## WFI residency measurement

The opt-in idle-profile feature counts per-hart WFI entry/exit intervals,
with no packet/lock instrumentation. Single-hart writers publish atomic
sequence-protected snapshots; readers include an ongoing WFI interval and
return unavailable after bounded retries rather than reporting zero load.
Interrupt service stays outside the WFI interval because exit is recorded
before restoring SIE. Cache-line-separated counters avoid per-hart false
sharing. This is a WFI interval proxy including bounded bookkeeping, not
CPU cycles or electrical power-state residency.

`nidle` reports all configured harts with individual timestamps/online state.
`scripts/mars-cpu-residency.py` rejects missing/unavailable/inconsistent or
reset snapshots and computes interval differences.
`scripts/mars-residency-bench.py` accepts explicit serial/address/output
parameters and brackets idle/RX/TX measurements with snapshots. It restores
serial settings, writes fresh evidence directories, and fails incomplete
network tests. Snapshot command overhead is included in the interval.
431 core tests (including ongoing idle, concurrent exit and timer wrap) and
three parser tests pass. The physical image replaces network-profile with
idle-profile; exact ELF inspection shows IDLE_PROFILE and no enabled network
profiler symbols. FIT: `b8376b4af1f68c9a9d622f4bab1f6b201d717b53c740d94c0a3d231295d04f4c`.

Two 20-second RX runs measured 942.49/942.27 Mbps, with core 0 active
99.79/99.74% and core 1 active 99.05/99.00%. TX measured 877.31/885.07
Mbps with core 0 active 94.69/95.21%, core 1 89.19/89.95%. Thus the
near-full occupation of the two network cores is not merely an artifact of
the detailed profiler. The initial 10-second idle interval measured
9.78/6.01/1.29/1.15% across four cores; startup/background work is included.
The protocol task still uses PollBudget in this configuration; existing
network-event-experiment has not yet been combined with app waits/GRO here.

A subsequent 10-second idle interval repeated 9.77/5.95/1.20/0.93% active
across the four cores. At 299.98 Mbps RX, core 0 was active 48.86%, core 1
47.84%, others ~0.01%. A fresh 64 MiB patterned transfer passed after
measurement. Final valid RX_POOL counters were received=acquired=released
4,067,856, free=128, ready=0, borrowed=0, full=0, dropped=0. The serial
counter log has an undecodable prefix before the valid command response;
residency measurement snapshots themselves passed strict parsing.
No low-CPU completion claim is justified. The next experiment should combine
the already implemented protocol event wait with application waits and this
GRO/short-lock path, using the new measurement to expose idle polling cost.
Default firmware features remain unchanged; board stays on the WFI image in RAM.


## Combined protocol event waiting: CPU residency comparison

On 2026-09-15, added only `network-event-experiment` to the preceding
idle-profile configuration (application waits, GRO, short RX metadata locks,
RX interrupts and pooled buffers retained). FIT SHA-256:
`c0503f79237c453e2d0709898ef6b1461d2893fa9b67bd06a9d9f473611a7329`.
Both configurations omit the detailed network profiler. WFI interval proxy
limitations above apply; these are sequential board runs, not a randomized
causal estimate.

| Workload | Baseline Mbps; h0/h1 active | Protocol events Mbps; h0/h1 active |
| --- | --- | --- |
| RX 20 s, round 1 | 942.49; 99.79%/99.05% | 942.73; 99.71%/99.02% |
| RX 20 s, round 2 | 942.27; 99.74%/99.00% | 942.12; 99.70%/99.00% |
| TX 20 s, round 1 | 877.31; 94.69%/89.19% | 936.12; 99.81%/99.07% |
| TX 20 s, round 2 | 885.07; 95.21%/89.95% | 887.12; 95.22%/94.34% |
| RX capped at 300 Mbps, 20 s | 299.98; 48.86%/47.84% | 299.98; 50.11%/48.51% |

Event-image idle h0/h1 active percentages were 10.34/8.37 initially and
10.15/8.57 before the capped run; baseline repeats were 9.78/6.01 and
9.77/5.95. No CPU reduction is demonstrated. The variable TX throughput
must not be presented as a stable gain. A subsequent 64 MiB patterned
transfer passed. This combination is not adopted as a default or a CPU
optimization; protocol events remain opt-in.

Evidence: `target/mars-reference/20260915-idle-events-comparison.json`,
`20260915-idle-events-{full,300}/`, `20260915-idle-events-integrity.json`,
exact ELF `20260915-idle-events.elf`, and RAM boot/hash logs. No SD/SPI
writes. Restoration to the preceding idle-residency RAM image is recorded
separately in `20260915-idle-events-restore-ramboot.log`.

A concrete remaining busy path is `kernel/src/dwmac_net.rs` marking
`immediate_work` whenever TX descriptors remain DMA-owned, including TCP
ACK traffic. The current wait contract is RX-specific. Removing this busy
condition alone would delay completion/reclamation until an unrelated wake
or timer. A future change needs TX completion notification, arm/recheck
coverage, and recovery tests, plus measured attribution of empty TX turns;
this observation does not yet prove it dominates CPU time. Batch ownership
handoff is another candidate requiring measurement, not another ring-size
adjustment.


## TX ownership-only turn attribution

A separate opt-in `tx-wait-profile` feature adds `ntxwait` counters for
successful driver turns: other runnable work, TX ownership only, and idle.
Each bucket contains count and elapsed timer ticks. The final runnable
condition remains the same OR of packet/backpressure work and TX ownership;
only attribution separates the two flags. No TX completion IRQ or scheduling
change is introduced. The first bucket includes backpressure and must not
be called exclusively productive work. The elapsed scope includes link
checks, reclamation, lock wait and preemption; it excludes outer authority
checks and executor scheduling. Approximate non-atomic snapshots and two
timer reads/two counter updates per turn perturb measurement. A low count
or duration cannot exclude overhead outside this scope.

RAM FIT SHA-256 on 2026-09-15:
`7ab3ce42d418e9a09eb4897c7c4a317ba63f883edb32ba8d87a8793488151728`.
Configuration: preceding idle-residency baseline plus tx-wait-profile,
without protocol event waiting or detailed network-profile. The feature
now explicitly implies packet-network; that dependency was already enabled
in the tested image. Exact ELF saved as `20260915-tx-wait.elf`.

| 20-second workload | Mbps | Other turns / elapsed seconds | TX-only turns / elapsed seconds | Idle turns / elapsed seconds |
| --- | --- | --- | --- | --- |
| RX capped at 300 Mbps | 299.98 | 108808 / 4.828 | 0 / 0 | 35927 / 0.319 |
| Full RX | 942.97 | 147952 / 13.549 | 0 / 0 | 122 / 0.001 |
| Full TX | 932.06 | 97613 / 12.909 | 41638 / 0.495 | 185 / 0.002 |

TX-only is 29.86% of full-TX turns but 3.69% of measured driver time.
No TX-only turns occurred in either RX test. Thus adding TX completion
interrupts is not supported as the first remedy for the measured RX CPU
load. It could still save some TX/scheduler work, which these scopes do not
fully quantify. Keep it behind actual attribution rather than infer a major
gain from the turn count alone. Next separate RX processing, TX submission
and queue backpressure within the other-work bucket.

WFI-proxy h0/h1 active percentages were 48.37/47.00 at 300 Mbps RX,
99.80/99.08 at full RX and 99.77/93.59 at full TX. These single instrumented
samples are not CPU improvement claims. A subsequent fresh 64 MiB patterned
transfer passed. Evidence directories:
`target/mars-reference/20260915-tx-wait-{300,full}/` contain snapshots,
iperf JSON, CPU summaries and `tx-wait-analysis.json`; the reproducible
analysis is `target/mars-reference/analyze-tx-wait.py`. Capture with
`scripts/mars-residency-bench.py --tx-wait-stats` only on an image that enables
the corresponding feature. Board remains on this diagnostic RAM image;
default firmware Ethernet profile is restored, with no SD/SPI writes.


## Sampled driver phase attribution

The opt-in `driver-stage-profile` configuration samples every 64th driver
turn. `ndrvstage` reports TX phase, RX phase, the nested receive_ticket HAL
callback, acquired/published tickets, inbound queue-full events and empty
receive results. Unsampled turns retain only the sampling branch in addition
to the separately enabled TX-wait profiler. Accumulators publish only after
successful sampled turns. The RX callback includes descriptor handling,
DMA synchronization, metadata locks and checksum validation, not just MMIO.
RX-other includes CONTROL acquisition, stamping, queue delivery and sampling
bookkeeping. Outer capability acquisition and executor scheduling remain
outside these scopes. Systematic sampling may alias workload periodicity;
percentages are sampled driver elapsed scopes, not whole-system CPU usage.
Do not multiply sample durations by 64 to claim a measured CPU total.

2026-09-15 RAM FIT SHA-256:
`55830ba691490f235c3aad0937e6847841ad0472cf6df3636a26c82f07eaccdb`.
Exact ELF: `target/mars-reference/20260915-driver-stage.elf`.
The first build failed on an attribute attached to a binary expression;
using a named conditional argument fixed it. The subsequent target build
passed. Default Ethernet features were restored after packaging.

| 20-second workload | Mbps | Sampled turns | TX scope | RX callback scope | Other RX scope | Published / queue full |
| --- | --- | --- | --- | --- | --- | --- |
| RX capped at 300 Mbps | 299.98 | 2192 | 21.94% | 62.24% | 15.83% | 9424 / 125 |
| Full RX | 942.75 | 2292 | 12.33% | 71.18% | 16.50% | 31308 / 2 |
| Full TX | 879.94 | 2034 | 89.62% | 6.88% | 3.50% | 2122 / 0 |

Published can exceed acquired within sampled turns because an earlier,
unsampled turn may have retained a pending ticket. Queue-full is counted
only at the inbound endpoint, not all queues or hardware buffer pressure.
These observations prioritize splitting DMA/descriptor handling and buffer
metadata within receive_ticket over increasing inbound queue capacity.
They do not prove a particular cache operation or lock dominates.

WFI h0/h1 active percentages were 48.55/47.35 at 300 Mbps RX,
99.75/99.03 at full RX, and 94.93/89.38 at full TX. TX variation remains
unresolved. A fresh 64 MiB patterned transfer passed after measurements.
Evidence lives in `target/mars-reference/20260915-driver-stage-300-retry/`
and `20260915-driver-stage-full/`, including `driver-stage-analysis.json`;
analysis helper `target/mars-reference/analyze-driver-stage.py` preserves
raw count/timing differences and limitations.

The first 300 Mbps attempt timed out reading nidle after the idle interval,
before any iperf traffic. It is retained as a failed run, not a benchmark.
Subsequent serial quiet/nidle commands responded; the board was not rebooted.
The benchmark helper now recognizes a prompt followed by background output
and saves raw serial response bytes on future timeouts. The earlier timeout
cause is not conclusively established because that helper had not saved its
partial response. Retry completed in a new evidence directory. The parser
regression tests and git diff check pass. The board remains on this diagnostic
RAM image; no SD/SPI writes or low-CPU completion claim.


## Reuse the RX view within one invocation

The RX HAL callback previously acquired RX_META separately just to copy its
immutable RxView after detaching the ticket. RxAccess now captures that view
under its first metadata guard and retains it only for the current callback.
This removes one metadata lock acquisition per completed packet. It does not
retain a payload reference, move validation before DMA synchronization, or
hold a metadata lock across hardware operations. HAL engine authority excludes
pool replacement/reset until the callback ends; the ticket stays private
through validation. A new RxAccess is created on every call, including after
recovery. No caching of a view across device generations is introduced.

Unprofiled comparison uses the same idle-residency feature set, without
network-profile, TX-wait or driver-stage profiling (verified in exact ELF).
New FIT SHA-256:
`9c9eb201afa4091ebf731efe13b1fc741ed285baea82438e845dd2bccfff8680`.
ELF: `target/mars-reference/20260915-rx-view.elf`.

At 300 Mbps RX, two 20-second runs measured h0/h1 active percentages of
46.23/45.54 and 46.19/46.13. The older baseline sample was 48.86/47.84,
but a reverse comparison was performed rather than treating that alone as
proof: booting the saved baseline FIT
`b8376b4af1f68c9a9d622f4bab1f6b201d717b53c740d94c0a3d231295d04f4c`
and repeating the same two-run test gave 47.98/47.83 and 48.33/46.93.
Across those reverse-control runs, mean active core-seconds per GiB fell
from 27.452 to 26.466, a 3.59% reduction. This is a modest measured benefit
in sequential 300 Mbps tests, not a randomized estimate or proof that
saturated CPU load is solved. The initial approximate 5% observation is
superseded by the more conservative 3.6% reverse comparison.

Full RX remained 942.57/942.58 Mbps, h0/h1 ~99.75/99.03% active.
Full TX was 933.89/871.08 Mbps; earlier throughput variability persists.
The EQoS host suite passed 102 tests and the actual firmware build passed.
After returning to the new image, cancellation during RX traffic followed
by driver restart advanced generation 1 to 2. A fresh 64 MiB patterned
transfer then passed. This tests operational recovery alongside the
source-level invocation-lifetime argument, not unrestricted fault coverage.

Evidence: `target/mars-reference/20260915-rx-view-{300,full}/`,
`20260915-rx-view-baseline-control-300/`,
`20260915-rx-view-comparison.json`, `20260915-rx-view-recovery.log`,
`20260915-rx-view-recovered-integrity.json`, exact symbols and RAM/hash logs.
The original and reverse-control results are both retained. Default firmware
Ethernet features are restored; physical testing uses RAM only.

Post-recovery fresh RX/TX connections measured 942.73/932.67 Mbps for
20 seconds each; evidence `20260915-rx-view-recovered-full/`. The interrupted
old iperf process exited with status 1 without forced termination, as expected
for driver cancellation. Final RX_POOL received=acquired=released=2,062,176,
free=128, ready=0, borrowed=0, full=0, dropped=0. The view reuse change is
retained. Board remains on the new RAM image, generation 2. Low-CPU and full
physical qualification remain incomplete.


## Rejected descriptor completion reuse experiment

The normal pooled path performs receive_pending followed by receive_detached;
each independently synchronizes the same RX descriptor line. A default-off
experiment retained only synchronized OWN-clear status between those calls.
Negative probes remained fresh, payload synchronization and metadata barriers
remained in receive, and shutdown/reset discarded cached status. Linux's
[dwmac4 descriptor implementation](https://raw.githubusercontent.com/torvalds/linux/master/drivers/net/ethernet/stmicro/stmmac/dwmac4_descs.c)
(reviewed 2026-09-15) likewise gates completion on OWN and returns OWN during
rearm; this is context for the ownership argument, not proof of Mars cache
behavior or this optimization.

Four additional software-model tests covered one-time status consumption,
negative-to-ready transitions, retained payload/metadata synchronization,
full-pool retry, malformed completion draining, failed stop and TX-fault reset.
All 106 EQoS tests and the experimental firmware build passed. No existing
model assertion was weakened. However, physical performance did not justify
keeping the additional cached state:

| 300 Mbps RX, 20 s | Previous RX-view h0/h1 active | Completion reuse h0/h1 active |
| --- | --- | --- |
| Round 1 | 46.23% / 45.54% | 47.64% / 46.58% |
| Round 2 | 46.19% / 46.13% | 47.64% / 44.17% |

Mean active core-seconds/GiB was 26.466 versus 26.742. This is no demonstrated
CPU gain, not a statistically established regression. The experiment was
withdrawn before further saturation/recovery qualification; its passing
model tests do not establish a performance benefit. Source and its four
additional tests are archived in
`target/mars-reference/20260915-rx-completion-experiment.patch`, not retained
in the working implementation. Comparison data:
`20260915-rx-completion-300/`, `20260915-rx-completion-comparison.json`.
Experimental FIT SHA-256:
`0e193501430113c26185a352cbc15e9b0fc218f79b76eeb58798794b3e5b51c0`;
exact ELF `20260915-rx-completion.elf` and build/model logs are preserved.

Board was restored via verified RAM boot to the retained RX-view FIT
`9c9eb201afa4091ebf731efe13b1fc741ed285baea82438e845dd2bccfff8680`.
A new 64 MiB patterned transfer passed after restoration, recorded in
`20260915-rx-completion-restored-integrity.json`. No SD/SPI writes occurred.
The previously measured 3.6% RX-view benefit remains the retained change;
no additional CPU gain is claimed from removing duplicate descriptor sync.


## Explicit controller diagnostics and cache batching review

Review of [Linux sifive_ccache.c](https://raw.githubusercontent.com/torvalds/linux/master/drivers/cache/sifive_ccache.c)
on 2026-09-15 confirms FLUSH64 writes are batched between range-level barriers.
The current JH7110 Cache::flush already follows that shape: no per-line
barrier or completion polling is added by Mmio::write64. No cache barrier
change was made in this review.

The firmware still had legacy, always-enabled controller timers in tx_owned,
transmit and copied receive callbacks, plus periodic MARS_NET_PROFILE and
checksum/register status reports. These are now behind the explicit
`controller-profile` feature, disabled by default. Essential device timeout
clocks, link transition/fault reports, hardware checksum policy and packet
telemetry remain. The detailed network profiler and WFI counters have their
own independent features. Earlier descriptions of unprofiled/WFI images
meant the detailed network/lock profiler was absent; those images still had
these legacy controller timers.

The actual default-off target build passed. The same performance composition
plus controller-profile passed an explicit release cargo check for the
RISC-V target, preserving diagnostic compilation. Exact default-off ELF
contains none of MARS_NET_PROFILE, MARS_NET_RX_CHECKSUM, MARS_NET_RX_VERIFY,
MARS_NET_DMA_STATUS or MARS_NET_RX_REJECT. To request legacy diagnostics,
add controller-profile to the Cargo features when building from
firmware/milkv-mars (the compatibility build scripts do not expose this flag).

Physical FIT SHA-256:
`bb27dac8ec2ec2962638ce20025afdb35c67c0e702ecabf0a95b968fb7c16855`.
At 300 Mbps RX, two 20-second measurements reported h0/h1 active percentages
47.71/48.05 and 47.09/48.02. Mean active core-seconds/GiB was 27.440, versus
26.466 for the preceding RX-view measurements. No further CPU improvement
is demonstrated; the earlier 3.6% RX-view estimate must not be silently
carried forward as the measured performance of this new image. These are
sequential measurements, not a statistically established causal regression.
The diagnostic feature separation is retained as a clean measurement boundary,
not presented as a performance win.

Full RX/TX measured 947.76/937.17 Mbps for 20 seconds each. h0/h1 active
percentages were 99.74/99.53 and 99.78/95.27 respectively. Near-full work-core
occupation persists even after the old controller timers are removed.
A subsequent fresh 64 MiB patterned transfer passed. Evidence:
`target/mars-reference/20260915-controller-quiet-{300,full}/`,
`20260915-controller-quiet-comparison.json`,
`20260915-controller-quiet-integrity.json`, exact ELF and build logs;
`20260915-controller-profile-check.log` records the enabled-feature check.
Board stays on the new quiet RAM image. No SD/SPI writes; full physical
qualification and substantial saturated CPU reduction are still incomplete.


## Borrow outbound authority in transient transmit tokens

PacketTxToken now borrows PacketTransmit from its PacketDevice rather than
cloning it at every token creation (including paired reply tokens for RX).
The device was already mutably borrowed through the pending/stats fields for
the entire token lifetime, so owning a second authority handle added no useful
lifetime. Actual sends still revalidate authority. TSO reservations retain
independent owned authority because they can outlive a token under backpressure.
The normal RX loan acquisition path has no per-packet heap allocation; this
change removes redundant atomic reference-count operations, not a payload copy.

Protocol tests passed in all three checked configurations: pooled RX + GRO +
native segmentation + large window (4 unit / 39 integration), default (24
integration), and legacy GRO (4 unit / 27 integration). Existing tests cover
revocation after token issue, queue pressure, reservation release and GRO
loan retirement. Actual Mars build and RAM/hash validation passed. FIT SHA-256:
`e762f8b33d4c90bb0407f93101c933562aa772b69d624044e7d8c1d0339f5c80`.
Exact ELF: `target/mars-reference/20260915-borrowed-token.elf`.

At 300 Mbps, h0/h1 active percentages were 46.52/46.96 and 46.82/47.51,
versus preceding quiet-controller samples 47.71/48.05 and 47.09/48.02.
This small sequential difference is not presented as a stable CPU gain.
Full RX/TX were 948.94/937.16 Mbps for 20 seconds each, h0/h1 active
99.85/99.66% and 99.66/93.79%. A fresh 64 MiB patterned transfer passed.
Evidence directories `target/mars-reference/20260915-borrowed-token-{300,full}/`,
comparison JSON, integrity JSON and build/test logs retain all measurements.
The borrowing simplification is retained; saturated CPU reduction remains open.
Board stays on this new RAM image; default Ethernet profile restored.

The next structural target is bounded batch RX. Current pooled receive uses
multiple short RX_META guards per packet, plus queue/borrow/release guards.
Batching should reserve replacement slots under one metadata guard, perform
DMA synchronization/rearm outside it, then publish completed tickets under
one guard. Runtime must stamp the entire returned batch while holding the
session publication barrier and retain stamped pending tickets under queue
pressure. An unstamped firmware-prefetch queue could relabel old packets
across a session change and is not an acceptable shortcut. Any batch extension
needs bounded storage, explicit partial/error semantics, reset/loan-retention
models and a fallback for existing single-frame backends. This is next work,
not implemented or qualified by the token change above.


## Bounded batch RX: model coverage, failed first hardware check

The opt-in `rx-batch-experiment` now returns up to eight detached frames per
HAL call. Replacement reservation and completion publication each use one
metadata guard per batch; DMA synchronization and descriptor rearm stay
outside those guards. Runtime stamps the entire returned batch under CONTROL,
and preserves those stamps for unpublished tickets under queue pressure.
Existing single-frame backends use the optional-operation fallback.

EQoS model tests pass (107), including FIFO/wrap, bounded batches, partial pool
exhaustion, malformed-prefix draining and publication failure quarantine before
and after the metadata closure. Core receive tests pass (5), including pending
batch generation preservation; protocol pooled/GRO/native segmentation checks
pass (4 unit / 39 integration). Mars batch build and non-batch fallback target
check pass. These checks do not establish hardware correctness.

The first RAM batch image, FIT SHA-256
`c5e247948a5b1a207bd7edaae7891657c74fbab91678879a4f615fe659000a90`,
passed U-Boot payload/DTB hashes and reported 1000 Mbps full duplex. Its first
64 MiB patterned verification timed out after 30 seconds. Subsequent quiet,
ps and reboot serial probes produced no response. The benchmark process failed
at its initial quiet command before sending performance traffic. There are no
CPU or throughput results for this batch image, and the fault cause is unknown.
The original verifier did not record its failing phase; the timeout alone does
not prove any payload was accepted. The verifier now records phase, admission
and submitted byte count for future runs (submitted is not board-confirmed).

Evidence is under `target/mars-reference/20260915-rx-batch*`, including the
exact ELF, first-integrity JSON, empty failure serial logs and benchmark timeout
log; boot serial is under
`target/mars-acceptance/20260913-gigabit/20260915-rx-batch-boot.log`.
Disassembly shows a 0x8a0-byte poll_rx_batch frame; the linker reserves 252 KiB
usable kernel stack per hart. This observation does not establish complete
call-chain stack usage or rule out corruption. A cold power cycle is requested
because bounded serial recovery also failed. Keep the batch feature opt-in and
do not claim a CPU improvement or hardware qualification. No SD/SPI writes.


## Cold-cycle batch reproduction and recovery (2026-09-15)

After the requested cold cycle, serial and software reboot responded again.
The previously verified borrowed-token baseline was RAM-loaded with hashes
checked and passed a fresh 64 MiB patterned test. Reloading the **unchanged**
batch FIT then passed 64 KiB and 64 MiB tests with continuous serial capture.
The earlier hang has not been reproduced or explained; it is not fixed merely
because these retries passed.

Two 20-second batch RX runs at 299.98 Mbps reported h0/h1 active percentages
44.55/40.63 and 48.35/39.64. Mean total active core seconds per GiB was 24.875,
versus the historical borrowed-token mean 26.990. This preliminary 7.8% lower
fixed-load CPU time does not establish a net improvement: the next saturated
20-second RX result was only 862.04 Mbps (h0/h1 99.70/99.27%), while TX reached
937.30 Mbps (99.82/99.18%). A same-session reverse baseline comparison follows.

Cancellation during RX and driver restart advanced generation 1 to 2 and
installed fresh capability grants. The interrupted iperf exited nonzero on its
own (expected interruption); a fresh 64 MiB patterned transfer passed afterward.
Final pool counts were received=acquired=released=2,987,918, full=dropped=0,
free=128, ready=borrowed=0. This covers one cancellation/restart, not arbitrary
fault injection or long-duration stability.

Evidence: `target/mars-reference/20260915-rx-batch-reproduce-*`,
`20260915-rx-batch-recovery-{run.log,integrity.json,pool.log}` and
`target/mars-acceptance/20260913-gigabit/20260915-rx-batch-recovery/`.
The batch feature remains opt-in; the saturated RX regression and unexplained
initial hang prevent promoting it to the standard image. SD/SPI are untouched.


### Same-session reverse comparison rejects the apparent CPU gain

Reloading the identical borrowed-token baseline FIT and repeating two 20-second
300 Mbps runs gave h0/h1 43.26/40.16% and 43.63/40.27%. Its mean active core
seconds per GiB was **24.042**, versus batch **24.875**: batch used **3.47% more**
in this sequential comparison. The apparent 7.8% saving against historical
samples is therefore not attributable to batching and must not be reported as
an optimization. Saturated baseline RX/TX were **949.08/938.91 Mbps**, whereas
the batch runs were **862.04/937.30 Mbps**. These are short sequential samples,
not confidence intervals, but they do not justify adopting this implementation.

Evidence: `target/mars-reference/20260915-rx-batch-reverse-{300,full}/`,
`20260915-rx-batch-same-session-comparison.json` and reverse RAM boot logs.
Board is now back on baseline FIT
`e762f8b33d4c90bb0407f93101c933562aa772b69d624044e7d8c1d0339f5c80`.
Default Ethernet feature selection remains unchanged; batch stays opt-in and
unqualified. Before another batch rewrite, measure actual batch occupancy and
phase costs: fewer lock acquisitions alone have not translated into lower CPU
cost. The initial unexplained hang and long-duration qualification remain open.


### Batch occupancy diagnostic

Added opt-in `rx-batch-profile` (implies batch RX) with nine cumulative atomic
buckets. `nrpool` prints them before taking RX_META; receive performs no serial
logging or timing reads. The histogram counts normal ring returns after the
ready probe, before packet validation. Fast idle probes, Full and error returns
are excluded; bucket zero is therefore not an idle-poll counter. Counts survive
driver restarts and must be differenced. Independent atomic reads are not a
simultaneous snapshot; read outside offered traffic as done here.

Target build and RAM payload/DTB hash checks passed. FIT SHA-256:
`315e57e2c73917776616bb714f0f3192a6995e29b0191ede0f40c969d4bcf2e7`. A fresh 64 MiB patterned transfer passed before
measurement. At 300 Mbps, the histogram delta was
`[0,4599,112437,22564,9970,3900,2325,6331,12524]`: 515,004 frames in
174,650 successful callbacks, mean **2.949**. At saturated RX it was
`[0,5448,291775,56315,22227,12717,14230,11291,47834]`: 1,457,525 frames in
461,837 callbacks, mean **3.156**. Two-frame batches account for approximately
64% and 63% of calls. Full eight-frame batches account for approximately 7%
and 10%. The diagnostic full RX result was 851.12 Mbps; this instrumented
image is not used to claim an uninstrumented CPU/performance result.

Evidence: `target/mars-reference/20260915-rx-batch-occupancy-measure/`,
its parent build/boot logs, and exact `20260915-rx-batch-occupancy.elf`.
Default feature selection is restored; board currently runs this diagnostic
RAM image. No SD/SPI writes. The data motivates examining work over unused
array slots and per-batch handoff costs, but does not yet isolate a dominant
cost or prove a fix. Batch RX is still not qualified for default use.


### Compact runtime batch stamp (experiment)

StampedBatch now stores one immutable publication-time PacketStamp with the
original ticket array. Pop constructs a Stamped value using that stored stamp;
it never queries the current session. Existing five core receive tests pass,
including holes, backpressure/rebinding, and retained-loan release. Target build,
RAM hashes and 64 MiB patterned integrity passed. FIT: `0eb72860f5069cbfd7a38f11370571ba0b35a58f71a7d7fd090169ac8302eba3`;
exact ELF: `target/mars-reference/20260915-compact-batch.elf`.
Two 300 Mbps runs reported h0/h1 48.20/46.25% and 48.11/47.38%, which do NOT
prove CPU improvement. Saturated RX/TX reached 947.75/935.94 Mbps with h0/h1
99.73/99.52% and 99.66/97.36%, restoring target-range RX in this short sample.
The change is retained inside the unqualified batch path for further comparison,
not promoted as a CPU win. Evidence: `20260915-compact-batch-{300,full}/`,
build, core-test, integrity and RAM boot logs under target/mars-reference.
Default Ethernet feature selection is restored. Board currently runs compact
batch RAM, without the occupancy profiler; no SD/SPI writes.

### Revisit the GMAC cache-coherency assumption before more batch tuning

Read StarFive's JH7100 Cache Coherence V1.0 PDF, page 6 (Hardware Solution for
JH7110 SOC), including the rendered table: row 13 GMACx2 explicitly lists
Coherency Y and front port. This is a hardware-design document, not a measurement
of our actual Mars setup. Source:
https://raw.githubusercontent.com/starfive-tech/beaglev_doc/main/JH7100%20Cache%20Coherence%20V1.0.pdf
Local PDF/text and rendered diagram are under target/mars-reference.
Linux upstream jh7110.dtsi (downloaded 2026-09-15) has no dma-noncoherent
property on GMAC; absence alone is not proof of coherency or Linux's default.
The March 2026 RISC-V RFC also distinguishes coherent front-port traffic from
noncoherent video/sys-port traffic:
https://lists.infradead.org/pipermail/linux-riscv/2026-March/087202.html
Its uncached alias discussion must not be generalized to all JH7110 devices.

Current platform/jh7110/src/cache.rs unconditionally FLUSH64s RX payloads and
bidirectional descriptors. That policy may be unnecessary for GMAC. Next verify
upstream DMA defaults, actual controller/AXI configuration and the production
SoC memory map; then test a GMAC-specific coherent service with ordering fences
and all existing ownership checks retained. Do not globally remove cache
maintenance for SD/video/other devices, or claim the diagram proves the current
hardware setup. Multi-core patterned RX/TX, repeated recovery and sustained
load must qualify any changed coherence policy before promotion.


### GMAC-specific coherent DMA service, first physical checks

Linux arch/riscv/Kconfig selects ARCH_DMA_DEFAULT_COHERENT; the downloaded
upstream JH7110 GMAC DT nodes do not override it. This supports the StarFive
front-port diagram, rather than the earlier blanket noncoherent assumption.
Source: https://raw.githubusercontent.com/torvalds/linux/master/arch/riscv/Kconfig

Added a separate GmacCoherent<R> DMA service, selected only by optional Mars
`gmac-coherent-experiment`. Its unsafe constructor requires a JH7110 GMAC
front-port device, normal cached physical RAM and no active ownership transition.
It preserves span admission and all full ordering barriers, without FLUSH64.
The existing Cache service and all other peripheral bindings retain their
original behavior. Seven cache model tests pass, including normal noncoherent
behavior and coherent admission/ordering checks. Hardware semantics are not
proved by those models.

Actual target build, RAM hashes and initial 64 MiB patterned verification pass.
FIT `737fdc351f2aec2fc1dd2faf9f0ac9068e89d9ef33110abf3176ea78a94451a9`; exact ELF
`target/mars-reference/20260915-gmac-coherent.elf`. Boot explicitly reports
`MARS_NET_DMA coherent-front-port=true`. Two 300 Mbps samples gave h0/h1
46.97/47.44% and 42.23/40.58%, too variable to claim a CPU reduction.
Saturated RX/TX reached 948.40/946.36 Mbps; h0/h1 active percentages were
99.82/99.61% and 99.83/87.63%. RX CPU saturation remains unresolved; the TX
observation needs repeated same-session comparison.

Cancellation/restart under RX advanced driver generation 1 to 2. Following
recovery, 512 MiB of changing RX pattern was verified while a 20-second reverse
iperf TX ran concurrently. RX confirmed every byte (8.174 seconds board time),
and both client processes completed successfully. The TX service's constant
payload is not a changing-pattern TX integrity proof. This is not long-duration
qualification and the optional coherent policy is not promoted by these checks.

Evidence: target/mars-reference/20260915-gmac-coherent-{300,full}/,
cache-tests/build/ramboot/recovery logs, duplex-integrity directory and exact ELF;
recovery serial files under target/mars-acceptance/20260913-gigabit/.
Default feature selection restored; board stays on the coherent experimental
RAM image. No SD/SPI writes. Repeated CPU measurements, changing-pattern TX,
fault scenarios and prolonged mixed workload remain to be completed.


## Updated target and coherent-path frontend profile

The active target is now MTU 1500, single-direction TCP above 900 Mbps with
aggregate CPU cost below one core as the effort target. Sum all measured hart
active percentages; do not substitute a low-load result or a per-hart percentage.
WFI residency is still a proxy, not an instruction/cycle measurement.

A 30-second deferred NPROF capture containing 20-second RX traffic at 946.61 Mbps
on the coherent path recorded exclusive elapsed seconds: protocol_poll 11.998,
frontend 7.793, driver 6.175, rx callback 5.543, executor 3.423 and application
2.387. Frontend contended wait was 1.290 seconds; RX_META accounted for about
0.405 seconds across RX and protocol scopes. Exact ELF symbol mapping identifies
0x405f4480 as RX_META and 0x405fd128 as SCHED; the dominant frontend lock
0x41821fe8 is dynamic and has NOT been symbolically identified. Queue high water
was inbound=64/outbound=2; 4,040 inbound full retries are not packet drops.
The totals aggregate cores and include diagnostic cost and idle edges; they are
not a clean CPU-cycle decomposition. There were 740,136 network-side frontend
calls against 61,678 protocol polls. The source drives all listeners before and
after interface polling, even for empty directions.
Evidence: target/mars-acceptance/20260913-gigabit/20260915-gmac-coherent-rx-profile-*
and target/mars-reference/20260915-gmac-coherent-profile.elf/symbols.txt.

### Coalesced frontend drive snapshot

network_begin_drive publishes connection state and captures RX capacity/TX queued
bytes under one metadata guard. The original network_update_state API remains a
wrapper. drive_tcp_frontend uses conservative turn-local budgets to skip empty
directions; actual copies still validate live queue capacity, and new work is
observed next turn through existing polling/readiness. Device authority is checked
at entry, including empty turns, and before real transfers; close requests retain
their live check. No borrowed socket memory escapes the synchronous operation.
Default protocol tests (24), pooled/GRO/native segmentation tests (4 unit/39
integration), and frontend activity-event tests pass. A new test checks stale
snapshots, later application progress, capacity bounds, reset and generation reuse.

Build and RAM hashes pass. FIT `e0dbd97811e6cc7b036e54c2efa82bcf3b3bff616bf7f73a8be51a0b6ca627bd`; exact ELF
`target/mars-reference/20260915-frontend-drive.elf`. Initial 64 MiB pattern passed.
Two 300 Mbps samples gave h0/h1 45.62/36.70% and 42.30/39.56%. At the target
rate, RX was 909.96 and 909.92 Mbps with aggregate non-WFI occupancy approximately
**1.947 and 1.904 cores**. TX reached 945.90 Mbps with h0/h1 99.84/88.36%.
Thus bandwidth exceeds 900 Mbps but the below-one-core goal is NOT achieved.
Low-load observations do not prove target-rate CPU success or a stable causal
improvement over earlier images without a reverse comparison.
Evidence: target/mars-reference/20260915-frontend-drive-{300,910,tx}/ and related
build, test, integrity and boot logs. Board stays on this test RAM image; default
Ethernet build feature selection is restored. No SD/SPI writes.


## Split pooled receive from protocol execution; isolate hart context lines

PacketDevice::receive now enters the existing PacketQueue diagnostic stage.
It includes pooled acquisition, GRO, authority checks, pending TX flushing and
reply reservation, and ends before RxToken consumption. The metric therefore
is not pure queue wait. Profile-enabled pooled/GRO/native protocol tests passed.
A fresh target build, RAM hashes and 64 MiB pattern passed. The subsequent
20-second RX run reached 947.42 Mbps inside a 30-second capture. Exclusive
elapsed totals: receive entry 7.204 s, remaining protocol_poll 5.102 s, frontend
7.421 s, driver 6.223 s, RX hardware callback 5.597 s. Receive-entry contended
wait was 0.320 s; frontend wait 1.311 s. These are aggregate instrumented times,
not CPU cycles. Evidence: target/mars-acceptance/20260913-gigabit/
20260915-receive-stage-rx-profile-* and corresponding target/mars-reference logs.
Exact ELF disassembly confirms memcpy has an aligned word-copy loop and a
misalignment shift/merge path, not an unconditional byte-at-a-time copy loop.

Inspection found per-hart allocation owner/arena and task recovery keys packed
into shared cache lines. The preceding ELF lists each four-hart array as only
32 bytes. They now use 64-byte-aligned per-hart records; owner/arena share the
same hart's line, and recovery identity retains its own record. All existing
atomic orderings, interrupt masks, scope lifetimes and recovery rules remain.
Full core tests pass, including fault recovery/cancellation and compile-fail
lifetime tests. New ELF arrays are 256 bytes each, 64-byte aligned. No generic
lock behavior or authority checks were relaxed.

Target build, RAM hashes and 64 MiB verification passed. FIT `528350654608e19f2d127cf9c9884bd97b33dd5a56c15e8a636f60660bf36ffc`;
exact ELF target/mars-reference/20260915-hart-context.elf.
At 909.96 Mbps, h0/h1 active percentages were 97.32/90.69% and 97.16/91.85%,
about **1.880 and 1.890 total cores**. This is only slightly below prior sequential
samples and does not prove a repeatable causal gain. The below-one-core target
is not met. Evidence: target/mars-reference/20260915-hart-context-910/.

### Read-only CPU clock baseline

After software reboot, U-Boot md.l read SYS CRG 0x13020000:
`01000000 00000001 00000002`, and SYS SYSCON 0x13030018:
`034fea80 0000007d 45555555 042ba603`.
Existing PLL decoding gives integer PLL0 = 24 MHz * 125 / 3 = **1 GHz**;
CPU root selects PLL0 and CPU core divider is 1. The upstream clock driver
confirms oscillator/PLL0 CPU mux and CPU-core divider:
https://raw.githubusercontent.com/torvalds/linux/master/drivers/clk/starfive/clk-starfive-jh7110-sys.c
This is a post-reboot register snapshot; VibeOS's current network setup does
not reprogram CPU root/PLL0. No clock or voltage was changed. Record 1 GHz as
the observed boot baseline rather than assuming the nominal maximum CPU rate.
Raw evidence: target/mars-reference/20260915-cpu-clock-registers.log.
The same hart-context RAM FIT was hash-checked and booted again afterward.
Default build feature selection restored, board stays on this image, SD/SPI
untouched. Repeated target-rate comparisons and broader qualification remain.


## RX entry substage diagnostic (2026-09-15)

Added optional network-profile scopes for receive-loan acquisition (including
queue/capability admission), GRO begin/append/finish, TX reservation and egress
flush. Existing stage indices are preserved; the deferred dump now declares
16 stages. The analyzer accepts the earlier 8/12-stage recordings as well as
16-stage data and rejects truncated arrays. Five analyzer tests, default
protocol integration tests (24), and profile-enabled pooled/GRO/native tests
(4 unit, 39 integration) passed. Normal builds retain zero-sized no-op scopes.

The new RAM FIT passed both payload hashes and a 64 MiB changing-pattern TCP
check. This is a diagnostic build of the current workspace, including other
ongoing changes, not an isolated performance A/B experiment. A 20-second RX
transfer in a 30-second capture reached only 696.06 Mbps, appreciably below
the preceding uninstrumented runs. Additional per-packet scopes perturb the
pipeline, so the following elapsed times cannot establish production CPU
costs or causally rank optimization gains:

| Stage | Exclusive aggregate seconds | Contended wait seconds |
| --- | ---: | ---: |
| GRO begin/append/finish | 3.536 | 0 |
| Receive loan acquisition | 1.893 | 0.145 |
| Remaining receive entry | 2.242 | 0.057 |
| TX reservation | 0.248 | 0 |
| Egress flush | 0.143 | 0 |

Flush/reservation totals include their other call sites too. Loan release is
outside acquisition and remains charged to its caller. These are 4 MHz timer
intervals, include instrumentation/interrupts, and are not hardware cycles.
The inbound queue reached 64 entries with 276959 full retry attempts; these
are not 276959 lost frames. Backpressure spans almost the entire traffic
interval. Do not infer the production pipeline has the same distribution.
Next measurement should sample bounded events or use lower-overhead counters
before changing ownership/queue behavior based on these numbers. No reduction
in production CPU usage is demonstrated by this diagnostic change.

Evidence: target/mars-acceptance/20260913-gigabit/20260915-rx-detail-rx-profile-*
and target/mars-reference/20260915-rx-detail-{build,tests,default-tests,ramboot,run}.log,
20260915-rx-detail-integrity.json, and exact 20260915-rx-detail.elf.
Diagnostic FIT SHA-256: `9d99e14b8ed0a74340612c64c54b6c81e47ea615891ad08f40323a38d61a99e6`.
After capture, RX pool received/acquired/released each equaled 1240003;
free=128, ready=borrowed=full=dropped=0. Software reboot and RAM restore of
hart-context FIT 528350654608e19f2d127cf9c9884bd97b33dd5a56c15e8a636f60660bf36ffc
passed hashes and 1000 Mbps full-duplex initialization. The restored image
passed a fresh 64 MiB pattern check (20260915-rx-detail-restore-integrity.json).
Board stays on that uninstrumented image. Default Cargo Ethernet selection
was restored; no SD/SPI writes. The below-one-core objective remains unmet.


## Reduce receive diagnostic perturbation with per-hart sampling

The four RX-detail child scopes now select one in 64 calls independently per
hart and stage. Unselected calls do not read the timer or update timeline
buckets. The gate uses bounded per-hart atomic counters without allocation,
locks or console output; normal builds remain no-ops. Deferred logs explicitly
record NPROF_SAMPLING, which the analyzer validates (including duplicate,
malformed and unsupported metadata). Old exhaustive 8/12/16-stage dumps remain
readable. Sampled time is NOT multiplied into exclusive timeline totals:
unsampled child work remains in its parent. Deterministic sampling can alias
periodic traffic; sample means are not an unbiased causal measurement.

Five parser tests and profile-enabled protocol tests (4 unit, 39 integration)
passed. SDK fetch failed with a GitHub TLS error; the local SDK was verified
clean at pinned 1fd6bac9f2efde47fbb8afd28d2903c49f893e3f. The payload was built
offline with build-milkv-mars.sh and packaged using the existing stage25
container plus the earlier hash-verified Mars DTB. This produced a RAM-test
FIT only, not a new complete SD image. Exact ELF is archived separately.

RAM payload hashes, 1000 Mbps full-duplex startup and 64 MiB pattern passed.
A 20-second RX transfer within the 30-second sampled capture reached
**946.31 Mbps**, recovering from the previous exhaustive-detail 696.06 Mbps.
This shows gross instrumentation slowdown is reduced; it does not demonstrate
lower production CPU consumption or prove that remaining probe cost is zero.

| Sampled stage | Selected calls | Recorded exclusive seconds | Mean selected call, microseconds |
| --- | ---: | ---: | ---: |
| rx_loan | 27894 | 0.044258 | 1.587 |
| rx_gro | 28749 | 0.073715 | 2.564 |
| tx_reserve | 4755 | 0.004690 | 0.986 |
| tx_flush | 5812 | 0.003634 | 0.625 |

Whole-window frontend=7.234 s, driver=6.189 s, RX callback=5.459 s,
protocol_poll=5.064 s, remaining receive entry=7.145 s. The latter contains
unsampled loan/GRO/reservation/flush work; do not sum an extrapolated child
estimate with that parent. These aggregate timer intervals include interrupts
and instrumentation, not hardware CPU cycles. TX reservation/flush are small
in the selected samples; further work should focus on the common receive and
frontend path without assuming GRO alone explains the CPU gap.
RX pool received=acquired=released=1666739, full=dropped=ready=borrowed=0,
free=128 after the capture.

Evidence: target/mars-reference/20260915-rx-sample-{cached-build,fit,ramboot,tests,run}.log,
20260915-rx-sample-integrity.json, 20260915-rx-sample.elf, and
 target/mars-acceptance/20260913-gigabit/20260915-rx-sample-rx-profile-*.
FIT SHA-256: `c972dc1b17654f18a593de8c1ccdc057df4c5fc09eda252b79c4809b063c8808`.
Both profile-enabled and profile-disabled pooled/GRO/native protocol tests
passed (4 unit and 39 integration in each configuration). Restored the earlier
hart-context FIT after capture; hashes, gigabit startup, and a fresh 64 MiB
pattern passed (20260915-rx-sample-restore-*). Default Ethernet feature mapping
is restored. Board stays on the uninstrumented image; SD/SPI unchanged.
The below-one-core objective remains unverified and unmet by the latest
available production-load measurements.


## Rejected passive-listener synchronization experiment

The sampled profile's hart 1 had exactly 811836 frontend-drive calls for
67653 protocol polls: six listeners driven both before and after each poll.
The other 349995 frontend-stage calls were application-side I/O and must not
be attributed to listener traversal. Four independent probe listeners are
normally passive during iperf. An opt-in experiment cached successful Listen
synchronization per BoundListener, checking live transport state and revocable
frontend authority on every turn while skipping repeated passive queue locks.
Fresh bindings initialized the hint false; non-Listen states took the full path.
Host tests covered initial sync, reset/re-listen and revocation after cached
passive state, and passed in experimental/default configurations.

The unprofiled experiment FIT passed hashes, gigabit startup and 64 MiB TCP
pattern verification. However iperf control connections closed unexpectedly
both in the attempted 910 Mbps benchmark and a second short unpaced run.
Tasks remained running with zero recorded faults/cancellations. There is no
valid experiment throughput/CPU result. Do not treat the narrow host tests or
independent single-port TCP success as proof of shared-port iperf correctness.

A same-workspace build disabling the experiment successfully completed a short
iperf test and two 20-second 910 Mbps RX runs: 909.90 and 909.96 Mbps;
h0/h1 active occupancy 97.42/99.00% and 97.51/99.24%, respectively (about
1.964 and 1.968 total cores). These are outside-WFI proxies, not CPU cycles.
The control restores functionality; the exact experiment failure mechanism
is not established. The runtime changes and feature switches were reverted,
with their complete patch archived for diagnosis, not promoted as an
optimization. Next diagnosis can capture the existing iperf phase-error event
while reproducing the shared-port control connection failure.

Control boot first encountered U-Boot DHCP retries despite active en13 link
and a running host bootpd. Explicit temporary U-Boot addresses (board .15,
server .1) pinged successfully and loaded the hash-verified FIT; no saveenv
or SPI writes. VibeOS remained reachable at 192.168.77.10 for the successful
control tests. This DHCP observation is separate from the unresolved earlier
iperf failure and is not evidence that the fast path is correct.

Artifacts in target/mars-reference/: 20260915-idle-listener-rejected.patch,
20260915-idle-listener{,-control}.elf, corresponding build/fit/ramboot/test logs,
20260915-idle-listener-910/ (failed test), 20260915-idle-listener-iperf-recheck.json,
and 20260915-idle-listener-control-910/ (successful control).
Experiment FIT fc3045bd6d464564d7134144a0a52668354da58e5e9aaf6a5e6b4e2eeb67bb09;
control FIT f83005decda62ba0918a86a9c3f002872c7bd1ecce3c9fc93aedd27deb78de26.
Board stays on the control RAM image, default build mapping restored, SD/SPI
untouched. Below-one-core objective remains unmet.
Fresh post-control 64 MiB pattern verification passed; evidence is
20260915-idle-listener-control-integrity.json.


## Reproduction did not establish a passive-listener regression

Rebooted the exact previously failing experiment FIT (fc3045bd...) without
changing its code. The first U-Boot ARP attempt after link negotiation timed
out, but the next explicit ping succeeded and the subsequent FIT hashes and
boot passed. A short iperf run with simultaneous serial capture succeeded at
947.52 Mbps. A fresh 64 MiB independent TCP pattern passed, followed by another
successful short iperf at 941.95 Mbps. No iperf phase-error event was captured.
Two complete 20-second 910 Mbps runs then passed at 909.92/909.96 Mbps;
h0/h1 active percentages were 97.30/96.77 and 97.37/91.94, or roughly
1.941/1.893 aggregate cores. These overlap earlier measurements and do not
establish a stable CPU gain over the control's 1.964/1.968 cores.

This changes the previous interpretation: the failed controls did not prove
the passive-listener hint caused a regression. The error remains intermittent
and unexplained; absence of failure on this boot does not establish reliability.
No runtime patch was reintroduced and the experimental feature remains absent.
Both the negative evidence and later successful exact-image reproduction are
retained. Further tests should classify progress versus empty polling before
inferring that reducing frontend work necessarily reduces non-WFI occupancy.

Evidence: target/mars-reference/20260915-idle-listener-repro{,2}-ramboot.log,
20260915-idle-listener-{repro,after-probe}-{serial.log,iperf.json},
20260915-idle-listener-repro-integrity.json and
20260915-idle-listener-repro-910/. The unchanged experiment patch remains in
20260915-idle-listener-rejected.patch for diagnosis only.
Restoration of the control FIT f83005de... passed hashes, gigabit startup,
and a new 64 MiB pattern check (20260915-idle-listener-repro-control-integrity.json).
First post-negotiation U-Boot ARP again timed out; a subsequent bounded retry
succeeded. Raw restore logs use the repro-control/repro-control2 prefixes.
Board remains on control; default source/configuration unchanged; no SD/SPI
writes. The complete gigabit/CPU goal remains active and not achieved.


## Loaded-window poll decision classification

Added optional per-hart/stage scheduling counters: runnable with a work hint,
empty retry, wait attempt, interface turns with ingress, interface turns with
frontend progress, and protocol input packet count. Work hints can include
pending/backpressured work; wait attempts need not actually block. Ingress
packet counts are after optional GRO, not Ethernet wire frames. The hooks
preserve the original PollBudget decision logic and remain no-ops without
network-profile. No locks, allocation or output occur in the counter hook.
The deferred parser validates six counters, stage/hart identity and duplicate
rows without changing timer totals. PollBudget, profiled netstack/event-driven
iperf tests and six parser tests passed.

The diagnostic payload/FIT built, both RAM payload hashes passed, and a 64 MiB
pattern check passed. Iperf ran for 30 seconds, with NPROF armed for 20 seconds
after traffic had started; dumping waited until traffic exited. Overall RX
was 946.04 Mbps. Interior 6..22 second intervals ranged 939.35..949.56 Mbps,
mean 947.02 Mbps, so the capture was not merely an idle/slow-path sample.

| Task/hart | Work-hint runnable | Empty retry | Wait attempt |
| --- | ---: | ---: | ---: |
| driver / h0 | 173095 | 0 | 53 |
| iperf application / h0 | 107472 | 34123 | 51920 |
| stack / h1 | 57963 | 113 | 67 |

Stack ingress progressed on 57959 interface turns and frontend work on 57946,
out of 58143 scheduling decisions (single interface). Thus roughly 99.68% of
stack turns processed input; only 0.19% were empty retries. The 177782 protocol
inputs include GRO aggregation and must not be read as wire packet rate.
Inbound queue high-water was 64, with 1778 full retry attempts; outbound high
was 2 with no full attempts. Driver work-hint counts alone cannot distinguish
TX ownership, backpressure and completed RX, but this sample does not support
an explanation dominated by empty protocol grace polling. Counts do not
assign CPU-time percentages: expensive rare empty turns are not bounded here.
No production CPU reduction is claimed by these diagnostic changes.

After traffic, RX pool received=acquired=released=2476168, full=dropped=0,
free=128, ready=borrowed=0. Evidence: target/mars-acceptance/20260913-gigabit/
20260915-poll-decision-rx-profile-* and target/mars-reference/
20260915-poll-decision-{build,fit,ramboot,run,tests,netstack-tests,iperf-tests}.log,
20260915-poll-decision-integrity.json and exact 20260915-poll-decision.elf.
Diagnostic FIT SHA-256: `97cb4782a03f6a592360ab479622e8be6958615f4837e5f5a56c88dcd4d428fd`.

Next concrete controller comparison: our detached batch path intentionally
still rings RX tail per descriptor (drivers/eqos-net/src/ring.rs); upstream
stmmac_rx_refill prepares/owns descriptors in a loop and publishes RX tail
afterward. This suggests evaluating fewer MMIO tail writes with explicit
partial-failure/wrap/ownership tests, not assuming it already saves CPU.
Source consulted 2026-09-15:
https://raw.githubusercontent.com/torvalds/linux/master/drivers/net/ethernet/stmicro/stmmac/stmmac_main.c
Restored unprofiled control f83005de... after capture: RAM hashes, gigabit
startup and fresh 64 MiB pattern passed (20260915-poll-decision-restore-*).
Default Ethernet features restored, board remains on control, SD/SPI not
written. The below-one-core objective remains unmet.


## RX batch tail publication experiment

Added a generic Ring receive_detached_batch_single_tail entry point and a
Mars rx-batch-tail-experiment switch (default off, implies rx-batch-experiment).
Both batch APIs share one implementation. The new path preserves each
replacement buffer's preparation and descriptor fields/OWN/cache/barrier
sequence, then writes the inclusive RX tail once to the final reserved slot.
It publishes tickets only afterward. Zero-reservation/empty paths do not
write a tail; malformed first-frame fallback remains the existing single-frame
path. Publication failures still quarantine the ring and require proven reset.

All 108 EQoS model tests pass. Existing batch tests now run both variants,
covering FIFO/pool pressure, malformed prefixes, publication failures before
and after metadata changes, borrowed-buffer retention during reset and the
eight-entry bound. A new wrap test verifies the 3,0,1 descriptor sequence,
one tail versus three, each OWN/cache visibility before that tail and no
extra tail on the following empty receive. Models prove ordering/event count,
not hardware cache coherence or a CPU saving.

The unprofiled target FIT built and passed RAM payload hashes, gigabit startup
and 64 MiB changing-pattern verification. Two 20-second fixed-rate runs gave
909.96/909.92 Mbps with h0/h1 active percentages 97.45/98.56 and 97.46/97.75
(roughly 1.960/1.952 aggregate cores). These do not show a material CPU gain
over recent control runs. No default promotion or below-one-core claim.
Under active RX, cancelling/restarting virtio-net advanced generation 1 to 2;
post-restart 64 MiB verification passed. Final received/acquired/released were
all 3474078, full=dropped=ready=borrowed=0 and free=128.

FIT SHA-256: 330c89eb6e8af4e14240c09849ef535abbbf28cf648926bcd5d844b8cd8a560b.
Exact ELF: target/mars-reference/20260915-rx-batch-tail.elf. Evidence under
that prefix: tests.log, build2.log, fit.log, ramboot.log, integrity.json,
910/, recovery.log, after-recovery-integrity.json, final-pool.log; detailed
recovery logs in target/mars-acceptance/20260913-gigabit/20260915-rx-batch-tail-recovery/.
The experiment stays opt-in. Further descriptor synchronization batching must
preserve fields-before-OWN and cache-before-tail across wrap and partial
prefixes; this result alone does not justify removing ordering operations.
Restored the unprofiled control f83005de...: RAM hashes, gigabit startup and
fresh 64 MiB pattern passed (20260915-rx-batch-tail-restore-*). Default Ethernet
selection restored; board remains on control; SD/SPI untouched. Goal unmet.


## Batched descriptor visibility experiment; archive without promotion

Extended the prior tail-only prototype with a third publication mode: prepare
all replacement payloads and descriptor fields, synchronize the reserved
prefix, issue a barrier, write all OWN bits, synchronize the prefix again,
issue a barrier, then publish one inclusive tail. Wrapped prefixes split into
two physical spans and never include unprepared descriptors. Ticket publication
and quarantine/reset behavior remained afterward as before.

This required explicit Backend/Memory admission. Pool admission validated each
possible bounded RX span against the cache service before enabling the mode;
individual line admission was not assumed to imply span admission. Runtime
range checks rejected zero/misaligned lengths, payload addresses, cross-ring
ranges, and multi-line TX spans. Default pool construction did not enable it.
111 model tests passed, including all three modes, wrap visibility before OWN
and tail, partial prefixes, publication failures, retained borrowers on reset,
cache services rejecting multi-line ranges, and absent backend admission.

Unprofiled FIT build, RAM hashes, gigabit startup and 64 MiB pattern passed.
Two fixed-rate 20-second RX samples both reached 909.92 Mbps, with h0/h1
97.52/96.85% and 97.45/98.03% active (roughly 1.944/1.955 aggregate cores).
These do not show a material improvement over the recent control/tail-only
samples. Do not claim that fewer synchronization calls proved lower CPU cost.
Load-time cancellation and restart advanced generation 1 to 2; afterward a
fresh 64 MiB pattern passed. Final pool counters: received=3472750,
acquired=released=3472749, free=128, ready=borrowed=full=dropped=0. One received
frame was not acquired across the cancellation sequence; the exact retirement
path was not separately traced. There are no outstanding borrowed/ready slots.

Both tail-only and grouped-sync implementation/tests/feature switches were
archived together as target/mars-reference/20260915-rx-batch-publication-experiments.patch
and removed from the working tree. This supersedes the earlier decision to
retain the tail experiment as an opt-in API. Default driver behavior is restored;
no extra DMA interfaces are retained without a demonstrated benefit.
Evidence: target/mars-reference/20260915-rx-batch-publish-{tests,build,fit,ramboot,recovery}.log,
20260915-rx-batch-publish.elf, 20260915-rx-batch-publish-910/,
20260915-rx-batch-publish-{integrity,after-recovery-integrity}.json,
20260915-rx-batch-publish-final-pool.log and the corresponding recovery directory
under target/mars-acceptance/20260913-gigabit/.
FIT SHA-256: `5b3aa1d1befcc6c34292e19d0a21b3c3bec64cb48a148af3d2bda183523d2052`.

Next investigation should sample actual interrupted instruction locations with
minimal hot-path instrumentation, using the exact ELF. Such samples must expose
bias from delayed interrupts during IRQ-masked critical sections; a PC near
interrupt restoration alone cannot identify the body that delayed the interrupt.
Restored unprofiled control f83005de...; RAM hashes, gigabit startup and
fresh 64 MiB pattern passed (20260915-rx-batch-publish-restore-*). Board remains
on control, default features restored, no SD/SPI writes. Goal remains unmet.

### Periodic PC sampling (2026-09-15)

The independent `pc-sample` diagnostic feature adds a bounded, one-shot timer
capture (`npc 1` through `npc 5`, followed by `npc` after expiry). It is separate
from per-function `network-profile`. Per-hart pinned tasks re-arm local timers;
the sampler only shortens an existing deadline, never postpones a task timer.
The SSIP handler still takes no scheduler lock. Sampling skips missed periods
instead of generating catch-up interrupts. IRQ collection has no allocation,
lock, or printing; freezing waits for writer publication without spinning.
Default images contain neither these buffers nor the timer/trap hooks.

The capture contains interrupted PC, saved x1/RA, entry time and expected time.
`mars-pc-sample.py` requires a complete, non-overflowing dump and the exact ELF,
retains available symbol aliases and hashes both inputs. IRQ-masked work is
underrepresented and its pending interrupt can land immediately after `csrs
sstatus`. RA is not a stack trace. Generic Drop bodies can also be merged under
one representative symbol name; a displayed VSH type does not imply VSH work.
Idle harts sampling in `exec::run` are sleeping/WFI, not busy executors. None of
these percentages are unbiased CPU-cycle shares.

FIT `target/mars-boot-20260915-pc-sample/out/artifacts/vibeos.itb`, SHA-256
`731186c3ca18ccce611e3dac106d06ff3cfae3da3aabc8c27d83d6228d9506cb`, passed RAM
hash validation, gigabit negotiation and 64 MiB changing-pattern verification.
A 3 s capture inside a 15 s RX run gave 947.28 Mbps overall; individual one-second
intervals were 941.7–949.5 Mbps. h0/h1/h2/h3 recorded 1492/1496/1499/1499 samples
with no drops. h0/h1 lateness p99 was 28.75/40.25 us; h0 had one 4.23 ms maximum,
so uniform-period sampling must not be assumed perfect.

On h1, 498/1496 samples (33.3%) landed in `compiler_builtins::mem::memcpy`,
predominantly in its misaligned-source shift/merge loop. On h0, 724/1492 samples
landed in one shared SpinGuard drop body. Disassembly verifies the common PC
`0x4042c9dc` is immediately after interrupt enable. Of those, the saved RA was
`0x4031f310` 498 times (pooled RX publication loop), `0x4031f108` 185 times (TX
block), and `0x4031fac4` 37 times. These identify interrupted critical-section
boundaries, not lock contention duration. The next comparisons should isolate
copy code generation and per-packet publication synchronization; this evidence
does not justify attributing all busy time to the hardware driver.

Evidence: `target/mars-reference/20260915-pc-sample-{tests,parser-tests,build,fit,ramboot,run}.log`,
`20260915-pc-sample-{integrity,analysis}.json`, exact `.elf`, and
`target/mars-acceptance/20260913-gigabit/20260915-pc-sample-rx-*`.

The sampler subsequently gained a host-tested ceiling division for unusual
non-divisible timebases, maintaining the 500 samples/s bound. Mars' 4 MHz period
remains 8000 ticks; the captured ELF predates this source-only arithmetic fix.

#### Copy code-generation comparison: built, not yet measured

A temporary `[profile.release.package.compiler_builtins] opt-level = 3`
configuration produced the unprofiled `20260915-copy-speed` RAM FIT, SHA-256
`01891811943207fbd74ef9a6800ff75f1e22517780b1e7be84561a35c4d69cbe`.
Cargo initially warns that the package is absent from the normal workspace,
then recompiles the build-std compiler_builtins package. The exact ELF confirms
changed memcpy code (0x1d6 bytes, versus 0x17c in the sampled ELF), including a
shorter misaligned steady-state loop. The override is archived at
`target/mars-reference/20260915-copy-speed-profile.txt`; default Cargo and
Ethernet feature selection have been restored.

The FIT's load hashes passed, but boot failed before networking:
`MARS_TRNG_PROBE FAIL ... prepare=Err(Protocol) read=Err(DriverRestarted)` followed
by `pmic_ops: cannot read pmic power register`. No copy-speed throughput or CPU
measurement exists. Its integrity JSON records a connection timeout with zero
bytes submitted, not data corruption. A cold power cycle was requested; the
cause of this boot failure is not established. Do not promote the build override
or claim a CPU improvement from these artifacts. After recovery, complete the
same-rate comparison and restore the known control RAM image.

#### Preserve the boot failure cause

The 2026-09-15 recovery check still received no serial response. Inspection
found that `entropy_instance::prepare` converted every child initialization
error into HAL `Protocol`, so the earlier log does not establish that the
underlying TRNG error was itself a protocol error. Firmware now retains the
first concrete failure and phase (`PrepareDomain`, `Initialize`, `Read`, or
`StopDomain`). The diagnostic boot log prints that retained code, as well as
separate prepare/start outcomes. This adds no MMIO, output-byte logging, retry,
entropy approval, or weakening of existing failure handling. Shutdown preserves
the first cause; an admitted new preparation epoch clears it.

`cargo test -p vibeos-firmware-milkv-mars --no-default-features --features
entropy-device --test entropy_model` passed, including mode failure, domain
reset timeout, read lockup, retained cause through shutdown, and clearing on a
new successful epoch. Log: `20260915-trng-cause-host-tests.log`. The initial host
attempts omitted `--no-default-features` and are separately archived; they failed
because the bare-metal image binary cannot build for the host. No additional
hardware qualification is claimed by these model checks.

Diagnostic FIT: `target/mars-boot-20260915-trng-cause/out/artifacts/vibeos.itb`,
SHA-256 `86e50dbddd3fafd5cbd9271fd91518ad4a4aad46e37acec0bfec3179f6b15dfe`. Build and FIT packaging passed; no RAM boot yet.
The default Ethernet feature mapping is restored.

### Copy code-generation experiment completed after serial recovery

The user confirmed `/dev/tty.usbmodem54340134951`; interrupt/newline then received
`vibe>` and live task output. The temporary cold-boot listener was stopped and
its handle confirmed terminal before another serial owner was started. No
additional power cycle was required. The `trng-cause` control FIT and the
same-source `copy-speed-cause` FIT both subsequently passed RAM hash validation,
TRNG protocol probe, gigabit negotiation and 64 MiB changing-pattern TCP checks.
The earlier TRNG failure was not reproduced; its cause remains unresolved.

`copy-speed-cause` FIT SHA-256:
`e9b9f6f7de2ffa801259e10c1536841a815811d1e5ecf1efca9f43d874deb19b`.
Both images use the same unprofiled network feature set; PC sampling and
network-profile are off. The sole build override for the experiment is
compiler_builtins opt-level 3. Exact ELF checks show memcpy text sizes of 0x17c
(control) and 0x1d6 (experiment), confirming a real code-generation difference.
No build ran concurrently with a benchmark.

Two 20 s, MTU 1500, 910M host-to-board runs per image:

| RAM image | RX Mbps | Aggregate non-WFI cores |
| --- | --- | --- |
| control, run 1 | 909.96 | 1.9177 |
| control, run 2 | 909.96 | 1.8987 |
| copy opt-level 3, run 1 | 909.92 | 1.9464 |
| copy opt-level 3, run 2 | 909.96 | 1.9218 |

This small comparison shows no CPU benefit; it does not establish a general
regression or isolate every cache/layout effect. Do not promote the build
change. The default workspace profile and Ethernet feature mapping are restored.
The board was restored to the `trng-cause` control FIT with successful hash and
1000-full-duplex checks. The observed non-WFI occupancy is not CPU-cycle or power
measurement, and it remains well above the one-core effort target.

Evidence: `target/mars-reference/20260915-{trng-cause,copy-speed-cause}-910/`,
matching `*-integrity.json`, `copy-speed-cause-{build,fit,ramboot}.log`, exact ELFs,
and `20260915-copy-speed-cause-restore-{ramboot.log,integrity.json}`. The next
hardware-backed experiment should target per-frame RX queue publication and its
nested synchronization; optimizing memcpy code generation alone did not remove
the observed overhead.

### RX queue publication batching: tested, archived without promotion

A separate `rx-queue-batch-experiment` changed only publication above the
existing detached hardware batch. One session barrier and one live SEND
invocation covered a batch; the queue transferred available tickets under one
queue lock, cleared accepted source slots in place, and emitted the existing
empty-to-nonempty notification after unlocking. No temporary per-frame stamp
array or new allocation was required. Each ticket still consumed one queue slot.
Pending tickets retained their original batch stamp through queue pressure;
stale/revoked pending tickets were discarded. The 32-wire-frame turn budget
remained bounded. DMA descriptors, cache synchronization, and protocol receive
consumption stayed on the preceding paths. The older per-frame driver-stage
profiler was explicitly incompatible with the experiment instead of emitting
misleading counters.

Host endpoint/receive suites passed 16 tests, including new sparse-batch,
partial-capacity, wraparound, limit-zero, notification, SEND revocation,
new-session rejection and concurrent-producer cases. FIT SHA-256:
`383a331799cc8ed9ca2aeacfd361bb3498fd6bcbad89e9c7d7c078dfd785be15`.
RAM hashes, gigabit boot and 64 MiB changing-pattern checks passed.

Two 20 s RX runs measured 909.96/909.92 Mbps and 1.9474/1.9280 aggregate
non-WFI cores. The preceding same-rate control measured 1.9177/1.8987 cores.
This comparison shows no CPU benefit; it is not proof of a general regression.
Cancelling the network component during RX and restarting generation 1 -> 2
passed, followed by another 64 MiB check. Final pool counters were
received=acquired=released=3,474,002, free=128, ready=borrowed=full=dropped=0.

All queue batching runtime changes, tests and feature declarations were saved
in `target/mars-reference/20260915-rx-queue-batch-experiment.patch` and removed
from the working runtime. Existing PC diagnostics and TRNG failure attribution
were preserved. The board was restored to the `trng-cause` control FIT with
successful load hashes/gigabit boot. Evidence: `20260915-rx-queue-batch-*` under
`target/mars-reference`, plus the recovery directory under
`target/mars-acceptance/20260913-gigabit`.

During review, TX-owned descriptors were reconsidered as a possible reason
for continuous polling. The earlier TX-wait attribution (table above) already
recorded zero TX-only turns in RX workloads, so that hypothesis is not supported
as the next RX remedy. Do not infer a scheduler gain from reducing the lock
count alone, or repeat the TX-wait experiment without new contradictory evidence.

### Same-hart configuration comparison on the current optimized path

The `same-hart` RAM build removes only the existing `network-pipeline` feature
from the preceding unprofiled feature manifest. Driver, stack and application
then execute on logical hart 0; observed h1–h3 non-WFI residency under load was
zero to the displayed precision. This option also changes component construction
order and resulting memory layout. It is a practical configuration comparison,
not an isolated measurement of cross-hart lock traffic. No live arena migration,
clock change, driver change or build concurrent with traffic was performed.

FIT SHA-256 `93d8284b65c3caa250e5ff5a4c92ca0a9426ee5a78e7301dcf16f9bc3155b2d5`.
Build, RAM hashes, 1000-full-duplex boot and 64 MiB changing-pattern verification
passed. Two 20 s fixed-load runs on each configuration:

| Configuration | RX Mbps | Aggregate non-WFI cores | Core-seconds/GiB |
| --- | --- | --- | --- |
| preceding two-hart control, run 1 | 299.98 | 0.8488 | 24.385 |
| preceding two-hart control, run 2 | 299.97 | 0.8185 | 23.515 |
| same hart, run 1 | 299.98 | 0.6442 | 18.501 |
| same hart, run 2 | 299.97 | 0.6620 | 19.019 |

Mean fixed-load cost fell 21.67% in this sequential comparison. However, two
unpaced same-hart runs reached only 694.07/696.49 Mbps at 0.99875/0.99887 cores
(12.403/12.363 core-seconds/GiB). This does not meet the 900 Mbps target and was
not promoted. Final same-hart pool counts were received=acquired=released=
3,457,253, free=128, ready=borrowed=full=dropped=0.

After restoring the exact `trng-cause` two-hart control FIT, a fresh unpaced
20 s RX run reached 949.06 Mbps with h0/h1 at 99.88/99.69% non-WFI occupancy.
Full-run GRO delta counters (rx_frames, merged_segments, aggregates) were:

- same hart, two runs: [2381257, 2122810, 244200], about 9.69 segments/aggregate;
- two-hart control, one run: [1625334, 1343052, 252323], about 6.32 segments/aggregate.

These aggregate averages exclude standalone frames; captures also differ in
throughput and duration. Placement changes both locality and coalescing, so the
fixed-load saving must not be assigned entirely to cross-core synchronization.
The difference motivates separating receive aggregation from placement in the
next controlled experiment. At roughly 695 Mbps, the same-hart path still needs
about 30% more throughput to reach 900 Mbps; lower total residency alone is not
success. Default Ethernet composition and the board are restored to two-hart
control, followed by another changing-pattern integrity check.

Evidence: `target/mars-reference/20260915-same-hart-comparison.json`,
`20260915-same-hart-{control-300,300,full,control-full}/`, `*-gro-{before,after}.log`,
`same-hart-{build,fit,ramboot}.log`, exact ELF and feature manifest, and
`20260915-same-hart-restore-{ramboot.log,integrity.json}`. No runtime source
changes were introduced by this placement comparison.

### Complete the 300 Mbps placement/GRO matrix

To separate aggregation from the preceding placement observation, build the
same unprofiled feature manifests with `bounded-gro` removed, once with and once
without `network-pipeline`. Other network/offload/window features are unchanged.
No runtime source was edited. The no-GRO protocol path passed 33 host tests with
`pooled-rx,native-tcp-segmentation,tcp-large-window`, including backpressure,
connection transitions, checksum policy and revocation. Both RAM FITs passed
load hashes, TRNG protocol probe, 1000-full-duplex boot and 64 MiB changing-pattern
checks before traffic. No build ran during measurement.

Each cell contains two 20 s RX samples; all achieved 299.97–299.98 Mbps:

| Placement | GRO | Aggregate non-WFI cores, runs 1/2 | Mean core-seconds/GiB |
| --- | --- | --- | --- |
| two harts | on | 0.8488 / 0.8185 | 23.950 |
| same hart | on | 0.6441 / 0.6620 | 18.760 |
| two harts | off | 0.8765 / 0.8546 | 24.864 |
| same hart | off | 0.6834 / 0.6826 | 19.620 |

Same-hart cost is 21.67% lower with GRO and 21.09% lower without it. Thus the
fixed-load placement difference persists without GRO and is not explained
primarily by the observed full-load aggregate-size difference. This still does
not isolate lock contention from cache locality, component construction order,
memory layout or scheduling. Samples are sequential, not randomized, and these
300 Mbps percentages must not be extrapolated to 900 Mbps. The same-hart full
GRO result remains about 695 Mbps, below the target.

The next bounded placement experiment should co-locate the protocol stack and
TCP services while retaining the driver on the PLIC dispatch hart, targeting
the shared frontend boundary rather than moving every network task to one core.
It must preserve arena affinity and verify cancellation/restart placement before
promotion; merely changing initial placement is not complete lifecycle support.

No-GRO FIT SHA-256:
- two harts: `8522e68287024c39d2c3f51c91b4544abc38d57428fca817b3fbe371a8ff0bb9`;
- same hart: `c2010013193f8b7723997c5b3997bc614aa561fa2aa6b520cab0a534a68f7fe0`.

Same-hart final RX pool: received=acquired=released=1,075,996, free=128,
ready=borrowed=full=dropped=0. Default composition and the board were restored to
the `trng-cause` two-hart GRO control FIT, with successful hash/gigabit checks and
a subsequent changing-pattern verification. Evidence is in
`target/mars-reference/20260915-gro-placement-matrix.json`, the preceding
`same-hart-{control-300,300}` directories, `no-gro-{two-hart,same-hart}-300/`,
matching build/FIT/RAM/integrity logs and exact ELFs, plus
`20260915-gro-placement-restore-{ramboot.log,integrity.json}`.

### TCP frontend / stack co-location experiment (2026-09-15)

The earlier four-cell placement/GRO matrix could not attribute the co-location
saving to frontend handoff specifically. This experiment kept the driver on
logical hart 0 and constructed iperf3, tcp-probe, and net-stack fresh arenas on
logical hart 1. `nplace` inspected actual scheduler queue ownership. No existing
raw arena was migrated. All other experimental network features matched the
unprofiled `trng-cause` control, including GRO and MTU 1500.

To avoid silent migration after a console restart, the opt-in prototype recorded
network component home harts and dispatched pointer-free, generation/task-bound
control requests via one bounded mailbox per component to SYSTEM-owned pinned
workers. Workers rechecked lifecycle identity on the destination hart. No
lifecycle lock was held while awaiting another hart. Four standalone mailbox
state tests passed. This was experimental code, not a qualified general-purpose
lifecycle API: monitor interaction and interrupted worker handling were not
fully tested. The experiment is archived and removed from active source at
`target/mars-reference/20260915-frontend-affinity-experiment.patch` (applicability
checked after removal).

Initial FIT SHA-256:
`5fa9d81e50d7c3070d6d92c80aae2d9d03fd9675e3fc477eb4c3334851837778`.
RAM load hashes, gigabit link, actual component placement, and a 64 MiB changing
pattern TCP verification passed. Two 20-second RX runs at each load gave:

| Placement / load | Received Mbps | Total non-WFI cores | Core-seconds/GiB |
| --- | ---: | ---: | ---: |
| frontend + stack hart 1, 300M run 1 | 299.97 | 0.8040 | 23.104 |
| frontend + stack hart 1, 300M run 2 | 299.98 | 0.7986 | 22.943 |
| frontend + stack hart 1, unpaced run 1 | 888.22 | 1.9538 | 18.958 |
| frontend + stack hart 1, unpaced run 2 | 888.84 | 1.9525 | 18.931 |

For context, the earlier same-day two-hart control measured 0.8488/0.8185 cores
at 300M and 949.06 Mbps / 1.9957 cores unpaced. These are earlier sequential
controls, not a randomized or immediately paired comparison. At fixed load the
small apparent saving does not explain the earlier ~22% all-network co-location
saving; at full load the experiment is slower and uses more core-seconds per GiB.
There is no evidence to promote this placement toward the >900 Mbps / <1 core
objective. Non-WFI residency still includes MMIO stalls and interrupt work.

Evidence: `target/mars-reference/20260915-frontend-affinity-comparison.json`,
`20260915-frontend-affinity-{300,full}/`, matching ELF/build/FIT/RAM-boot logs,
`20260915-frontend-affinity-placement.log`, and `*-integrity.json`.

### Persistent network control-table allocation ownership (2026-09-15)

The subsequent cancellation/restart acceptance exposed a separate correctness
problem. iperf3 and tcp-probe each restarted from generation 1 to 2 and stayed on
hart 1. net-stack cancellation completed, but restart hit the existing
`close_empty_domain` assertion with `ArenaBusy { live_bytes: 384,
live_allocations: 2 }`. The remote worker faulted and the waiting console request
did not complete. The full recovery script failed; post-recovery integrity was
not run. See `20260915-frontend-affinity-recovery.log` and its per-command folder.

Inspection found that `config::CONTROL` and `LISTENER_INTERFACES` are persistent
static vectors, but both registration methods reserve/grow them in the caller's
allocation domain. The caller is the reclaimable net-stack task. Publishing
these allocations into static storage violates that task's no-escape contract,
independently of CPU placement. The allocation-domain regression test observed
four non-SYSTEM allocations covering initial allocation and growth before the
fix; with the fix all four use SYSTEM/untracked storage. Both functions now
enter a SYSTEM owner scope for their persistent metadata and restore the caller
on return. The arena-empty assertion and raw reclamation rules are unchanged.
The fixed FIT subsequently passed cancellation/restart of all three services
from generation 1 to 2 on hart 1 and a post-restart 64 MiB data verification.
The unchanged arena-empty assertion no longer failed. This first fixed replay
performed the cancellation sequence before a throughput load; a loaded replay
on the original-placement image is recorded separately below.

`components/netstack/tests/config_allocation.rs` uses a host allocator audit of
real registration calls. It does not claim to exercise target raw reclamation.
The test was red before the fix and green afterward. The seven netstack tests
passed under both default static-address and DHCP/pooled-RX/native-segmentation/
GRO/large-window feature compositions. Logs:
`20260915-config-allocation-{before,after,dhcp}.log`.

A second RAM FIT retains the experimental placement solely to replay the failed
recovery test with the metadata fix. Its SHA-256 is
`22f0ac273d79b4bf4db01de8ac13255475c10ae43cf8d3deadfeb384cdc207e7`.
Serial prompt probes initially returned zero bytes after the requested power
cycles. After the user checked the connections, the serial prompt returned and
the fixed FIT was loaded with verified hashes and a gigabit link. Evidence:
`20260915-frontend-affinity-config-{ramboot,recovery}.log`, the matching recovery
folder, and `20260915-frontend-affinity-config-recovery-integrity.json`.

Active source restores the original placement and keeps only the persistent
metadata fix from this experiment. No SD/SPI writes or saved U-Boot environment
changes occurred. The full >900 Mbps / <1 core objective remains open.

The original-placement image with only the metadata fix has SHA-256
`160ebbe055260612a0320f15c353d2373eec154e87f01152ebe72b779773120b`.
Its RAM hashes, gigabit link, and initial 64 MiB verification passed. Two
20-second unpaced RX runs measured 949.17/949.06 Mbps, still near two non-WFI
cores. This supports retaining the correctness fix, not a CPU-efficiency claim.
Exact results are in `20260915-config-owner-full/summary.json` and the updated
frontend-affinity comparison JSON. The corrective patch is archived at
`target/mars-reference/20260915-config-owner-fix.patch` and retained in source.

After those two full-speed RX runs, the original-placement fixed image also
passed net-stack cancellation and generation 1 -> 2 restart, followed by another
64 MiB changing-pattern verification (board time 1212 ms). This covers recovery
after traffic, in addition to the earlier fixed idle co-location replay.
Evidence: `20260915-config-owner-loaded-recovery.log`, its per-command folder,
and `20260915-config-owner-loaded-recovery-integrity.json`.
The original console restart still constructs a fresh arena on its caller hart;
this test does not establish affinity preservation for the default API. The
same fixed FIT is reloaded afterward before further performance measurements.

Final board state: the original-placement `config-owner` FIT above was reloaded,
its RAM hashes and 1000/full link verified, and a final 64 MiB data test passed
(board time 1151 ms). Logs: `20260915-config-owner-final-ramboot.log` and
`20260915-config-owner-final-integrity.json`. The board is not left on the slower
co-location prototype or the console-restarted placement.

### Attribute bulk memcpy calls instead of timer delivery PCs (2026-09-16)

A default-off `copy-profile` image links `--wrap=memcpy`. The assembly entry
passes the original caller RA to a bounded per-hart recorder, then calls the
original compiler_builtins memcpy. Exact ELF disassembly verifies the wrapper's
sampled call and unselected tail-call both reach `memcpy`, which tail-calls the
original mangled implementation. No packet bytes are inspected. Calls below
256 bytes, inline copies, memmove, and reentrant calls while a hart writer is
busy are not sampled. Every 127th eligible admitted call records caller RA,
source/destination modulo 8, a power-of-two size bin, bytes, elapsed timer ticks,
and maximum duration. There is one 1–5 second window per boot and a 512-entry
bounded table per hart. Freeze first prevents new writers and then checks that
admitted writers have completed, without spinning. Copies admitted before
expiry may finish just beyond it. Dumping is deferred until after the window.

The host recorder tests cover capture bounds/single use, a copy finishing across
freeze, reentrancy, and full-table handling. Parser tests reject missing/corrupt
samples, inconsistent counts, and duplicate entries. All six tests pass. The
post-capture source also marks the sample token non-Send; this type-only guard
was added after the captured ELF was built. The feature and its linker option
remain off for normal images. No smoltcp/vendor changes were made for collection.

Diagnostic FIT SHA-256:
`7365ef326d7becad4be5f9c2fc7bbce27cafb8d644097effcdb217ef52a0743e`.
A 64 MiB pattern test passed. Unarmed RX measured 948.65 Mbps. During a separate
20-second RX run, the 3-second window was armed about 5.00–5.10 seconds after
starting iperf. Overall throughput was 948.69 Mbps; fully interior 6–7 and 7–8
second host intervals were 949.05 and 949.23 Mbps. The 5–6 second interval was
942.25 Mbps, so arming/transition overhead is not claimed to be zero. The host
command timestamps bracket the board start approximately, not exactly at an
iperf interval boundary. The data do not show a large throughput collapse from
the profiler. They do not prove an unchanged CPU distribution.

Hart 0 admitted 352,932 eligible calls and stored 2,779 samples; hart 1 admitted
332,274 and stored 2,617. No table overflow occurred. Harts 2/3 had no eligible
calls. Important sampled callers (weighted elapsed time / sampled bytes):

| Hart / caller | Samples | Sampled bytes | ns/byte |
| --- | ---: | ---: | ---: |
| h0 `TcpListener::try_recv` | 113 | 2,670,168 | 1.022 |
| h1 VecDeque byte extend (network frontend path) | 146 | 3,171,987 | 1.532 |
| h1 TCP `Socket::process`, main receive write | 234 | 2,860,855 | 1.453 |
| h1 GRO append, following payloads | 1,716 | 2,505,360 | 1.576 |
| h1 GRO append, materializing first frame | 197 | 298,258 | 1.379 |

The h0 application copies were source/destination modulo 8 = 0/0. The h1
frontend source was often 1 or 5 while its destination was 0. TCP receive copies
were source 6 / destination 1 or 5. GRO 1460-byte append samples split between
6/2 (1.830 ns/byte) and 6/6 (1.281 ns/byte). This exposes an alignment hypothesis,
not an isolated proof that alignment alone caused the timing difference: cache
state, lengths, and surrounding work remain confounders. The frontend generic
symbol can serve multiple VecDeque users; attribution to receive is based on
its call sites and this one-direction traffic, not a captured call stack.

The recorder also exposed fixed-size metadata/message movement:
- h0 `network::poll_rx_batch`: 1,184 samples of 256 bytes, the returned ticket
  batch representation, not a payload copy.
- h0 `dwmac_net::driver_task`: multiple callers copy a fixed 1470 bytes; the
  disassembly includes an immediate `li a2, 0x5be`. These require follow-up
  tracing through large owned-frame/async-state moves before treating them as
  actual RX payload copies.
- h1 `dispatch_ip<PacketTxToken>` has several fixed 1500-byte memcpy callers.
  `PacketTxToken::consume` currently drops the existing pool reservation for
  non-segmented traffic and constructs/sends a full owned `Packet`; the native
  transmit queue and driver pending enum retain the large frame variant. Small
  ACK transport is a concrete suspect for representation-copy overhead, but
  copied-size records alone do not establish the wire packet length.

These results identify actual copying sites that the earlier IRQ delivery PC
histogram could not resolve. Do not multiply the selected times into exact CPU
shares: selection is deterministic, not every copy is intercepted, and timer
reads include interrupt time. Next implementation work should address the
application receive handoff or remove large by-value wire-frame moves from the
native pooled path, preserving capacity, ordering, generation checks, and fault
recovery. Merely changing memcpy optimization level already failed its earlier
A/B and is not re-proposed as a new fix.

Artifacts retain the 20260915 job prefix because the run crossed local midnight:
`target/mars-reference/20260915-copy-profile-{analysis.json,wrapper-disassembly.txt,build.log,fit.log,ramboot.log,integrity.json}`,
`20260915-copy-profile-unarmed/`, `20260915-copy-profile-capture/`, and exact
`20260915-copy-profile.elf`. Parser: `scripts/mars-copy-profile.py`.
The board was restored to the unwrapped original-placement `config-owner` FIT
(SHA-256 `160ebbe055260612a0320f15c353d2373eec154e87f01152ebe72b779773120b`),
RAM hashes and gigabit link passed, and final 64 MiB verification passed (1162 ms
board time). Restore logs use `20260915-copy-profile-restore-*`. No runtime
performance change is promoted from this diagnostic turn; >900 Mbps with <1
core remains unachieved.

### 2026-09-16: ordinary wire-frame pool experiment — rejected

A default-off `pooled-wire-frames` experiment serialized ordinary native TX
frames directly into the existing segment pool and sent generation-checked
small tickets through the ordered queue. It removed the large owned-frame
variant from that path, retained bounded capacity and retry ordering, and used
an explicit ordinary-frame kind. DMA still copied into its private buffers;
this was not zero-copy DMA. Raw endpoints were unchanged.

Core pool/queue tests and protocol integration tests passed, including mixed
ordinary/segmented order, backpressure, stale tickets, serializer failure,
revocation, actual TCP data delivery, and legacy feature compatibility. The
experimental FIT SHA-256 was
`279cee9ba81a3099097e90b6eddfb1c9cee397d9bd71fcfe3a3099290d0e93b1`.
Initial 64 MiB verification passed. Under RX load, driver cancellation and
restart advanced generation 1 to 2; subsequent 64 MiB verification passed
(1142 ms board time).

| Configuration | RX Mbps, two 20 s runs | Total active-core proxy |
| --- | --- | --- |
| Fresh control, paced 300M | 300.00 / 299.98 | 0.8142 / 0.8152 |
| Pooled wire, paced 300M | 299.98 / 299.98 | 0.8282 / 0.8319 |
| Prior control, unpaced | 949.17 / 949.06 | 1.9958 / 1.9953 |
| Pooled wire, unpaced | 948.69 / 949.10 | 1.9950 / 1.9953 |

Experimental TX reached 945.83 / 946.94 Mbps at 1.8780 / 1.8947 active-core
proxy. There was no paired TX control in this run, so this is not a TX gain
claim. Non-WFI residency includes interrupt and MMIO time and is not an
instruction-cycle attribution. At matched RX throughput the experiment did
not reduce CPU occupancy. Added pool synchronization is a possible cost, but
was not isolated. No new copy-profiler capture established how much copying
actually disappeared. Large owned-frame movement therefore remains a measured
copy site, not a demonstrated explanation for the RX CPU limit.

The runtime experiment was removed and archived in
`target/mars-reference/20260916-pooled-wire-experiment.patch` (reapplication
check passed). Prior configuration-ownership fixes and default-off diagnostic
instrumentation are preserved. Evidence is under
`target/mars-reference/20260916-pooled-wire-*`, including comparison JSON,
exact ELF, build/test logs, integrity results, and residency directories.
Recovery serial logs are under
`target/mars-acceptance/20260913-gigabit/20260916-pooled-wire-recovery/`.
The >900 Mbps / <1 active core target remains unmet.

After the experiment, the board was restored in RAM to the original-placement
`config-owner` FIT, SHA-256
`160ebbe055260612a0320f15c353d2373eec154e87f01152ebe72b779773120b`.
FIT component hashes and 1000 Mbps full-duplex initialization passed; final
64 MiB integrity verification passed (1136 ms board time). Restore evidence
uses `20260916-pooled-wire-restore-*`. No SD/SPI persistent writes were made.

### 2026-09-16: empty TCP receive-ring origin experiment — not promoted

The copy profiler observed receive-buffer/front-end copy addresses with persistent
non-word offsets. An isolated default-off smoltcp `tcp-rebase-empty-rx` experiment
cleared the receive ring's origin before placing payload only when BOTH the
allocated ring and the out-of-order assembler were empty. It did not clear
storage bytes or change sequence numbers, advertised capacity, MSS, or GRO.
Rebasing merely because the allocated ring is empty is incorrect: outstanding
out-of-order bytes can still be relative to its old origin.

194 TCP tests passed with `std,medium-ip,medium-ethernet,proto-ipv4,socket-tcp,
socket-tcp-reno,tcp-rebase-empty-rx`. The new test covers 1–7 byte consumed prefixes,
rebasing an empty stream, and holes received while a prefix is still unread,
followed by prefix drain, another out-of-order segment and gap filling. It checks
both the resulting bytes and the required storage origin. An initial test run
without `medium-ip` selected zero TCP tests and was not used as validation. A
first test fixture also exceeded the previously advertised window after draining;
the corrected fixture leaves sufficient advertised space and all tests pass.

Experimental FIT SHA-256:
`7601102d0348775e14f593cf0b593b2017d112f68db60ef3e9a7981b60591e1c`.
64 MiB and 512 MiB changing-pattern integrity checks passed (1178 / 9292 ms board
time). Measurements used MTU 1500, two 20-second RX runs per configuration:

| Configuration | Received Mbps | Total active-core proxy |
| --- | --- | --- |
| Control before, paced 300M | 299.97 / 299.97 | 0.9068 / 0.9011 |
| Experiment, paced 300M | 299.97 / 299.95 | 0.9014 / 0.8641 |
| Control restored, paced 300M | 299.97 / 299.97 | 0.9019 / 0.8923 |
| Experiment, unpaced | 948.61 / 948.46 | 1.9951 / 1.9951 |

One experimental paced run decreased occupancy; the other matched control. This
small sample does not prove a reproducible efficiency improvement. The full-rate
CPU limit remains, and no copy-profile recapture measured how often rebasing
occurred or changed actual copy alignment. These data do not disprove all alignment
optimizations; they do not justify promoting this particular change. This turn's
control also differed from earlier 0.81-core controls, so those older runs were
not used as the paced A/B baseline. Non-WFI residency remains a proxy, not CPU
instruction cycles.

The experiment was removed from the worktree, including the smoltcp submodule;
existing correctness fixes and diagnostics remain. Reapplicable patches are
`target/mars-reference/20260916-rx-rebase-{smoltcp,integration}.patch` (both apply
checks passed). Exact ELF, build/test logs, measurement summaries and comparison
JSON use `20260916-rx-rebase-*`. No upstream commit/push was made for this rejected
experiment. The board now runs the stable original-placement `config-owner` RAM
FIT (`160ebbe055260612a0320f15c353d2373eec154e87f01152ebe72b779773120b`);
component hashes, gigabit initialization, and restored 64 MiB integrity passed
(1174 ms board time). SD and SPI were not written.

Remaining work should address the shared receive handoff itself or acquire
stronger synchronization attribution. The frontend still copies TCP storage into
its SYSTEM-owned bounded byte queue and then into application storage. Removing
that ownership boundary by exposing task-arena pointers would violate recovery
requirements; a replacement must preserve bounded capacity, authority and session
checks, and safe lifetime across netstack cancellation. The >900 Mbps / <1-core
objective remains open.

### 2026-09-16: identify frontend contention before redesigning the handoff

Added default-off `network-profile` listener lock identities. The net-api exposes
only the stable Arc-owned lock address; the kernel prints ID/port/address at
listener construction, outside the data path. Boot identity lines are combined
with the existing post-window dump for parsing. No locking algorithm, queue
capacity, lifetime or notification behavior changed. Firmware compilation and
64 MiB integrity passed (1177 ms board time).

Diagnostic FIT SHA-256:
`215c2bac5ae6d5d77a1658dffa66ef0e183c27ea5009a6f8995aada40e1a6f2c`.
A 20 s RX run armed a 5 s profile after a 5 s host delay. Total received rate was
946.49 Mbps. Full interior one-second intervals at roughly 6–10 s were
949.2, 949.3, 942.7 and 949.3 Mbps; before/after also varied around 942–949 Mbps.
There was no gross throughput collapse while armed, but this does not prove
identical instruction/cache costs with and without instrumentation.

The profile window was [359808540, 379808540) at 4 MHz. All bucket/hart/lock
wait totals reconciled. Measured contended wait over those five seconds:

| Lock | Hart | Wait seconds | Contended acquisitions |
| --- | --- | ---: | ---: |
| TCP data listener 2, port 5201 | 1 | 0.242937 | 9113 |
| TCP data listener 2, port 5201 | 0 | 0.060856 | 4703 |
| RX_META | 1 | 0.065635 | 97474 |
| RX_META | 0 | 0.055868 | 93590 |
| packet-driver-control | 1 | 0.048210 | 6118 |

Total recorded waits across all locks/harts were 0.530498 seconds (0.1061
core-equivalent over this window). The frontend data lock accounted for 0.303793
seconds (0.0608 core-equivalent). `RX_META` at 0x405fb480 and `SCHED` at 0x40604128
were resolved against the exact captured ELF. Dynamic unnamed locks remain
unresolved; no nearby-symbol attribution is assumed for them.

Exclusive measured stage times included 7,089,621 frontend ticks and 7,126,738
PacketQueue ticks, versus 1,216,845 and 340,520 contended wait ticks respectively.
These broader execution costs warrant follow-up. PacketQueue is NOT pure queue
synchronization: its scope includes GRO, RX loan lifecycle, TX reservation and
flush. Its sampled child stages cannot simply be multiplied into exact cost
shares. Low recorded contention also does not exclude uncontended lock overhead
or cacheline migration. The data argue against attributing the missing roughly
one core simply to spinning on the frontend lock; they do not prove which
execution sub-operation dominates.

Inbound high-water was 64, with 301 full attempts in buckets 0,1,31,43; outbound
high-water was 2 with no full attempts. After traffic, RX pool counts matched:
received=acquired=released=1,666,985; free=128, ready=borrowed=0, full=dropped=0.
Endpoint backpressure counters and DMA-pool counters refer to distinct layers.
No claim of zero hardware loss is inferred from these pool counts.

Artifacts: exact `target/mars-reference/20260916-frontend-lock.elf`, matching
build/FIT/RAM logs, symbols and `20260916-frontend-lock-summary.json`. Raw boot,
arm, dump, named combined log, iperf JSON and parser output are under
`target/mars-acceptance/20260913-gigabit/20260916-frontend-lock-*`.
The diagnostic identity feature is retained off by default. The board was
restored to the original-placement config-owner RAM FIT
`160ebbe055260612a0320f15c353d2373eec154e87f01152ebe72b779773120b`;
hashes, gigabit link and final 64 MiB verification passed (1144 ms board time).
SD/SPI were not written. The >900 Mbps / <1-core goal remains unachieved.

### 2026-09-16: split frontend phases and reject intrusive measurement

Added diagnostic frontend_status, frontend_rx, frontend_tx and frontend_close
scopes around initial validation/state publication, bounded RX transfer, bounded
TX transfer and close handling. These retain all existing authority checks,
queue operations and limits. Without network-profile, scopes are no-ops. The
parser accepts both prior stage schemas and the new 20-stage schema, checks
sampling metadata, and reconciles timeline/hart/lock totals. Five parser tests
cover old/new schemas, 127-call sampling, truncated arrays, inconsistent totals
and invalid sampling declarations.

The first full-count phase build was too intrusive. Its FIT was
`bf62b255a94262cfad0653d5a522cbf8fda576b58e58582c0c5fae19f27727ab`.
During the 5 s armed window within a 20 s RX run, throughput fell from roughly
949 Mbps to 875 Mbps, then recovered after expiry. Inbound full attempts reached
88,505, spanning every bucket. The resulting phase proportions must NOT be used
as normal-load CPU attribution. Full-count data and exact ELF remain under the
`20260916-frontend-phase-*` prefix; 64 MiB integrity passed (1124 ms board time).

The retained version samples all eight detailed child stages every 127 calls
per hart/stage. The interval is coprime with the six-listener loop, avoiding the
obvious fixed-subset alias of a 64-call period; deterministic selection can still
be biased. A 64-period intermediate build was not run on hardware. Old 64-period
captures remain parseable. No sampled ticks may be multiplied into exact timeline
totals: unsampled child work remains in the parent stage.

Sampled FIT SHA-256:
`33ef570e61217f862913dff3b78b0981ba3db6cb5e82815b53b169f314ac6c1c`.
A fresh 20 s RX run again armed a five-second window after a five-second host
delay. Total received rate was 947.07 Mbps. Fully interior one-second intervals
were 949.4, 946.4, 948.8 and 949.3 Mbps. The gross throughput collapse disappeared;
this does not prove zero instrumentation overhead or unchanged cache behavior.
Inbound full attempts were 517 across four buckets, versus 88,505 in the intrusive
run; outbound high-water was 2 with no full attempts.

Each frontend child collected 1,298 calls on hart 1 during the window:

| Sampled child | Exclusive timer ticks | Contended wait ticks |
| --- | ---: | ---: |
| frontend_status | 5,188 | 2,406 |
| frontend_rx | 31,226 | 3,047 |
| frontend_tx | 2,599 | 0 |
| frontend_close | 3,655 | 2,045 |

Among these selected calls, RX transfer accounted for substantially more work
than state checking, empty TX or close handling. The RX scope includes empty
iterations, device revalidation, socket lookup/recv and frontend queue copying;
this is not a memcpy-only measurement. The result supports prioritizing the
receive handoff over another idle-listener-skip optimization. It does not yet
quantify the benefit of replacing that handoff or isolate each operation inside
it. No production performance improvement is claimed from diagnostic changes.

Window data, named lock mapping, iperf intervals and analysis are under
`target/mars-acceptance/20260913-gigabit/20260916-frontend-sampled-*`; exact ELF,
build/FIT/RAM logs and parser tests are under `target/mars-reference/` with the
same prefix. Sampled-image 64 MiB integrity passed (1125 ms board time).
The board was restored to stable config-owner RAM FIT
`160ebbe055260612a0320f15c353d2373eec154e87f01152ebe72b779773120b`;
hashes, gigabit initialization and final 64 MiB verification passed (1156 ms).
No SD/SPI writes were made. The >900 Mbps / <1-core target remains open.

### 2026-09-16: TCP receive-buffer exchange primitive (integration pending)

Implemented opt-in smoltcp `tcp-buffer-exchange` and
`Socket::exchange_receive_buffer(replacement, max_bytes)`. This transfers the
entire received ring by value, preserving its wrap position, instead of copying
its payload. The socket receives an empty ring of identical capacity; successful
consumption advances remote_seq_no by precisely the transferred byte count.
The operation does not allocate, dereference a foreign task pointer, or change
advertised capacity. Its ordinary Rust storage lifetime is retained.

Exchange is rejected without consuming bytes if there is no readable data,
the data exceeds the caller budget, the replacement is occupied or differently
sized, or the assembler has any outstanding out-of-order bytes. The caller gets
the original replacement back and may use the existing copied receive path.
The out-of-order guard is essential even when a subsequent ordinary read drains
all currently contiguous data.

Four new tests cover wrapped ring contents and pointer-preserving reuse, atomic
rejection/budget/capacity rules, out-of-order data followed by gap filling, and
FIN/ACK/window equivalence with recv_slice. Full selected TCP suites passed:
197 tests without segmentation; 201 with tcp-segmentation. A no-default-feature
`medium-ip,proto-ipv4,socket-tcp,tcp-buffer-exchange` library check also passed,
without std/alloc features. A first fixture incorrectly expected a synthetic
SynSent socket with manually queued data to reject reads; the existing recv
semantics permit buffered data via may_recv. That fixture was corrected to test
zero-budget refusal rather than changing unrelated TCP behavior.

Evidence: `target/mars-reference/20260916-buffer-exchange-{tests.log,tso-tests.log,nostd.log,smoltcp.patch}`.
The patch remains uncommitted in the smoltcp submodule and is disabled by default.
It is NOT yet connected to VibeOS frontends, and no throughput/CPU improvement
or physical qualification is claimed. Board runtime remains the previously
verified config-owner FIT; this turn did not load firmware or write SD/SPI.

The next required integration cannot simply move the existing socket Vec into
the frontend: socket allocations currently belong to the netstack arena, while
the capability frontend outlives that arena. Allocating those Vecs in SYSTEM
alone is insufficient if task fault teardown abandons them without running
Drop. A stable pool must retain ownership of backing storage and issue bounded,
generation-checked exclusive leases. Socket-held leases must be retired only
after the owning task incarnation is stopped; published frontend data must
remain independently valid or be explicitly invalidated before storage reuse.
Application/connection generations and existing byte capacity limits still
apply. At every instant a slot must have one writer/owner, with no mutation of
published data. Pool exhaustion and any assembler hole must preserve the copied
fallback and normal TCP backpressure. Those lifetime/recovery obligations remain
unimplemented and must be tested before activating this primitive on Mars.

### 2026-09-16: stable receive-storage prototype (not wired into firmware)

Added default-off net-api `receive-buffer-exchange` modules for bounded ownership
metadata and permanent backing storage. They depend on neither smoltcp nor board
code. Ownership distinguishes Free, Socket, Pending and Published slots. Tickets
include pool identity, slot and non-wrapping generation; producer identity includes
both AllocationDomain and TaskRecoveryKey. Pending and Published bytes jointly
reserve the existing frontend byte budget, and preparation retains the existing
32 KiB per-call bound. Rollback restores exclusive socket ownership. Published
ranges support partial reads across ring wrap and release only after consumption
or explicit frontend discard.

`Storage::new_static` allocates backing memory and metadata in SYSTEM once and
retains them permanently. It must eventually be called at assembly, not at each
socket restart. Writer address lookup returns a raw address without constructing
any payload reference that could alias a live socket mutable borrow. Unsafe
preparation requires all writer references to have ended and the specified range
to contain received bytes for that connection. Published reads copy directly into
application output under the metadata lock; they do not create an intermediate
byte queue or let payload references escape. A published slot cannot be remapped
for writing or retired with its former producer. Pending/socket slots can be
retired only after the exact task is permanently quiescent; capability revocation
alone is insufficient.

Tests passed: nine ownership/storage unit tests, ten existing frontend/event
regressions, and one allocator audit. They cover wrong pool, stale slot reuse,
wrong connection/task/arena, generation exhaustion, byte budget including pending
transfers, rollback, wrapped partial reads, publication surviving producer stop,
and exact-owner unpublished-transfer retirement. The allocator audit observed
exactly three SYSTEM allocations for a two-buffer pool, restored the calling
allocation domain, and observed zero allocations during 100 transfer/reuse cycles.
Host System owns the test bytes; this audits allocation provenance, not actual
raw-arena reclamation. Log:
`target/mars-reference/20260916-receive-storage-tests.log`.

This is an unfinished opt-in prototype, not a deployed optimization. The existing
TcpListener still uses its byte queue, socket construction still uses its current
buffers, and no firmware feature enables these new modules. Hard-fault recovery
of an abandoned metadata lock is deliberately NOT implemented: the current lock
must not be force-released merely from a ticket, and a fault during application
copy needs exact consumer provenance plus quiescence. Frontend queue publication
must also be serialized with connection checks and Pending->Published transfer.
Those adapters, fault tests, and actual smoltcp buffer-exchange binding remain
required before hardware A/B. No claimed throughput/CPU improvement, SD/SPI write,
or RAM reload occurred in this turn; the board retains the verified config-owner
image. The >900 Mbps / <1-core objective remains open.

### 2026-09-16: release receive metadata lock during application copy

The unfinished stable-storage prototype now uses an explicit Reading state.
`Storage::read` acquires a generation-checked read lease under the metadata lock,
releases that lock, copies the pinned immutable range to application output, and
commits consumption under the lock. Other slots remain usable during the copy;
the active slot rejects another read, discard or writer mapping. Published byte
budget includes active reads. No payload reference escapes the operation.

Read leases carry an independent non-wrapping generation as well as buffer ticket,
connection and exact consumer domain/task identity. This rejects a delayed read
completion even when the underlying buffer slot has not been reused. The trusted
platform adapter must supply the actual consumer identity; it is not client input.
An ordinary Rust unwind cancels the lease via Drop without consuming bytes. If a
hard fault skips Drop, a supervisor that has permanently quiesced that exact
consumer may return its Reading state to Published, preserving uncommitted data.
A producer's retirement cannot release another task's read. Socket/Pending
retirement retains the prior exact-owner rules.

The existing unsafe quiescence boundary is still required: all references and
possible later guard drops belonging to the retired task must be dead, including
remote-hart references. No barrier is inferred from revocation or a ticket. This
change removes payload copying from the lock but does not yet implement recovery
from a hard fault inside metadata mutation or a held metadata lock. It must not
be presented as complete hard-fault integration.

Validation passed: 13 ownership/storage tests, 10 existing frontend/event tests,
and the allocator audit (100 transfers, no operation-time allocations). New tests
cover active-read pinning, same-arena/different-task and different-arena rejection,
read-generation exhaustion, delayed completion after replacement, normal unwind,
and a forgotten read guard followed by exact-owner retirement and intact data
readback. The forgotten-guard test models skipped Drop with no remaining payload
references; it is not a physical trap or cross-hart acknowledgement test. Log:
`target/mars-reference/20260916-receive-read-lease-tests.log`.

The modules remain opt-in and unbound to the actual TcpListener/smoltcp path.
No hardware performance improvement is claimed; no RAM reload or SD/SPI write
occurred. Remaining integration includes metadata-fault handling, atomic frontend
publication, socket buffer binding, then real cancellation and throughput/CPU A/B.
The >900 Mbps / <1-core goal remains open.

### 2026-09-16: connect stable storage to actual smoltcp buffer exchange

Added opt-in net-protocol `receive-buffer-exchange`, connecting the smoltcp
primitive to the net-api stable pool through `receive_exchange::Binding`.
Construction reserves one writer and supplies its permanent backing to a new
socket. Exchange admits only a nonempty entire readable ring within the existing
turn/byte budget, reserves a spare, and asks smoltcp to exchange storage. A refused
exchange drops the unused spare borrow and releases exactly that writer. Success
records the new socket buffer, verifies the outgoing pointer/range against its
pool slot, ends the outgoing mutable borrow and returns a Pending transfer.
There is no payload copy in this exchange helper.

This is an explicitly unsafe integration boundary: the socket must own the
binding's current buffer, the trusted producer identity must be correct, and
producer/publication operations for that listener must be serialized. The helper
does not silently recover a post-exchange invariant/preparation error; the caller
must abort the stream and perform quiescent cleanup. It does not automatically
release buffers on Binding drop, since a separately owned socket may still hold
their references. Storage now provides exact-writer release for unused spares,
with an explicit requirement that all their references have ended.

Three real ARP/TCP integration cases each deliver 300,007 changing payload bytes:
- three-slot pool, mixed exchange/copied reads, delayed partial application reads
  and byte-budget backpressure;
- one-slot pool with no spare, using the copied fallback throughout;
- deliberately delayed middle TCP payload segments, exercising assembler-hole
  refusal, returned spares and eventual in-order delivery.
Each verifies unchanged recv_queue on refused exchange, complete byte equality,
zero remaining published bytes and exactly one final socket writer to retire
after dropping the socket set. Thus unused spares are not left reserved. The
first versions of the hole fixture did not hit the intended path; the final
fixture filters TCP packets with actual payload, uses small non-Nagle sends and
asserts that a real hole refusal occurred. Mere handshake/ACK reordering is not
accepted as coverage.

Validation: 27 default-feature stack integration tests; with pooled-rx,
bounded-gro, native-tcp-segmentation and tcp-large-window, four protocol unit plus
42 integration tests passed. Storage/API regression passed 14 unit, ten frontend
and one allocator-audit test. Logs:
`target/mars-reference/20260916-receive-exchange-{integration-tests,combined-tests,storage-tests}.log`.

The tests use a real protocol peer but a standalone test frontend queue. The
production TcpListener queue, SharedIpv4TcpStack construction/relisten and kernel
supervisor are not yet wired to this binding. Atomic queue publication with
connection validation and metadata hard-fault recovery remain required. No
firmware features enable this code, no Mars RAM image was loaded this turn and
no throughput/CPU gain is claimed. Existing hardware state remains config-owner;
SD/SPI were not written. The >900 Mbps / <1-core objective stays open.

### 2026-09-16: validate the mixed TcpListener receive queue

The opt-in listener now has an ordered queue of copied runs and exchanged pool
ranges. A single byte budget covers both forms, copied runs coalesce, and chunk
metadata reserves space at construction. Publication validates the current
connection generation, pending pool ticket and capacity while holding the
listener lock; notifications run after dropping that lock. The regular receive
API obtains actual executor task provenance for exchange-enabled listeners;
host fixtures use the explicit trusted-consumer entry. Default listeners keep
the original copied path.

Added frontend tests for 100 alternating copied/exchanged cycles with wrapped
pool ranges and partial reads, exact byte capacity, rejected wrong-owner/pool/
connection and duplicate publications, reset/relisten generation changes,
unadmitted pending transfer preservation, and reentrant reads from publication
notifications. A host call without current executor provenance must not consume
an exchanged range. These tests exercise the actual listener, not a surrogate
queue.

The real smoltcp TCP fixture now also feeds this listener. It publishes exchanged
ranges, copies fallback data into the same ordered queue, and consumes through
try_recv_for. Both normal traffic and deliberately delayed middle payloads
reconstruct 300,007 bytes exactly under delayed reads and capacity backpressure.
The original standalone/no-spare fixtures remain as separate coverage. Combined
pooled-rx, bounded-gro, native-tcp-segmentation and tcp-large-window regression
passed four protocol unit and 43 integration tests; see
`target/mars-reference/20260916-exchange-listener-combined.log`.
Frontend and default-feature regression logs are
`20260916-exchange-frontend-provenance.log` and
`20260916-exchange-listener-default.log` under the same directory.

This remains disabled in the firmware: SharedIpv4TcpStack socket assembly and
supervisor retirement are not connected yet. Publication is serialized for normal
execution but does not recover a hard fault between pool publication and queue
insertion. The outer listener lock still spans the application payload copy,
and neither that boundary nor the pool metadata lock has a completed hard-fault
protocol. Passing these tests therefore does not establish safe production
restart or a CPU reduction. Hardware remains the restored config-owner baseline
(~948.6–948.7 Mbps RX, ~1.995 non-WFI cores); no new RAM image or SD/SPI writes
were performed in this implementation turn. The >900 Mbps / <1-core goal remains
open.

### 2026-09-16: bind exchange storage in SharedIpv4TcpStack

Added opt-in `enable_receive_exchange` on the real shared protocol stack. It
attaches an image-selected frontend's permanent pool before connection activity,
prepares buffers before replacing sockets, and retains bindings by SocketHandle.
Exclusive ports have both an active and a pending socket; both are bound, so
promotion preserves each socket's receive-buffer identity. Failed preparation
releases unused writers after ending their buffer references. Repeated binding
and a substituted frontend instance are rejected.

`drive_tcp_frontend` now attempts exchange within its existing receive budget,
then uses the same ordered frontend copied path for any fallback. All original
socket options are applied through the shared passive-socket constructor.
This API is unsafe at the assembly boundary: the stack must remain exclusively
owned by the specified producer, and no pool retirement may race any live socket
reference. It is not called by production netstack/firmware yet.

A new actual SharedIpv4TcpStack integration test transfers 600,007 changing bytes
in each direction with delayed application reads and bounded transmit storage.
It asserts pooled publication really occurred. It then opens a second client
while the original peer is closing, sends data through the pending socket,
closes/drains the old frontend and verifies that the promoted connection uses
exchange and delivers only its own bytes under a new generation. Packet authority
revocation still rejects driving. After dropping the entire stack, exactly two
socket writers retire; there are no remaining published bytes. The test also
forces failure after the first prepared buffer, retries successfully, and checks
that no spare leaked and no same-ID frontend substitution is accepted.

Combined pooled-rx/bounded-gro/native-tcp-segmentation/tcp-large-window regression:
four unit and 44 integration tests passed. Net API exchange/event regression:
14 ownership/storage, ten existing frontend, five exchange frontend and one
allocation test passed. Default API/protocol regression: six frontend and 24
protocol integration tests passed. Logs under target/mars-reference:
`20260916-exchange-shared-stack-{combined,api,default,rollback}.log`.

Still required before firmware use: task/supervisor assembly, permanent pool
lifetime across restarts, publication and metadata hard-fault recovery, and
removing the listener guard around payload copy where safe. This turn changes
no board image and claims no hardware CPU gain. The current ~949 Mbps/~1.995
non-WFI-core baseline and >900 Mbps/<1-core objective remain unchanged.

### 2026-09-16: normal exchange-stack destruction and rebuild

SharedIpv4TcpStack now explicitly destroys its SocketSet before releasing its
exchange bindings' current writers. Cleanup addresses exact tickets, not all
slots with the producer task identity; it cannot release another stack's live
writer or a range already published to an application. Invalid writer metadata
is left unavailable rather than freeing an unverified slot. This Drop path only
covers ordinary destruction and unwinding that reaches Drop, not skipped Drop
or abandoned locks after a hard fault.

Added a Pending-only discard transition and used it when normal frontend
publication rejects an exchanged transfer. It refuses published data and live
socket writers and validates the exact owner/ticket. The replacement receive
buffer remains in the socket. Post-exchange internal invariant failures still
require the separately documented abort/quiescence path.

A 100-cycle lifecycle fixture repeatedly binds active/pending sockets against
one permanent three-slot pool. It alternates retaining an unrelated live writer
with the same task identity and publishing bytes before stack destruction. The
unrelated writer remains valid; published bytes remain readable; subsequent
construction reuses the two released slots. Exact-owner retirement after each
cycle must find zero remaining writers (the test does not silently clean up
leaks). Existing actual TCP promotion coverage now requires ordinary Drop to
release both socket writers. These are host lifetime tests; they do not emulate
physical task traps or cross-hart quiescence.

Validation: combined protocol features passed four unit plus 45 integration
tests. Exchange/event API passed 14 ownership/storage, ten existing frontend,
six exchange frontend and one allocation tests. Defaults passed six API frontend
and 24 protocol integration tests. Logs:
`target/mars-reference/20260916-exchange-lifecycle-{api,combined,default}.log`.

Inspection also identified a required assembly ordering change: InterfaceTask
currently constructs a replacement stack before dropping its old stack on an
epoch change. A permanent pool cannot bind both full generations simultaneously;
when exchange assembly is enabled, the old socket references must be retired
before reserving the replacement writers. Production assembly and hard-fault
metadata/publication recovery remain unfinished. No firmware load or hardware
performance improvement is claimed in this turn; the <1-core effort continues.

### 2026-09-16: retire the previous interface stack before rebuilding

InterfaceTask now clears its old stack and observed session metadata immediately
after a successful new packet-session bind, before replacement construction.
This ends old socket references and releases normal exchange writers before a
new generation can reserve permanent pool slots. A busy/offline bind keeps the
old instance for retry without polling it; a construction error after successful
binding leaves no stale stack or observed epoch. Carrier loss uses the same
local cleanup helper while retaining its existing link-down publication.

Added a real InterfaceTask::poll lifecycle test with an exchange-bound old stack.
It covers bind-busy retention, invalid-MAC replacement failure, and successful
replacement; pool admission checks prove that the two old socket writers remain
owned during the retry case and are free after either completed-bind case. The
replacement still uses normal production assembly (copied sockets): this test
does not claim that pool-backed replacement assembly is enabled. Test interface
IDs 40–42 avoid the configuration tests' global entries and absent-net2 assertion.

Default netstack regression passed two unit, four command and one allocation
audit tests. Exchange-enabled static and DHCP/combined configurations passed
three unit, four command and one allocation audit tests. Logs:
`target/mars-reference/20260916-exchange-epoch-{rebuild,default,dhcp-final}.log`.
The new netstack receive-buffer-exchange feature forwards the protocol feature
for validation; no firmware selects it and no production assembly call was
added. Hard-fault recovery and final owner-aware image assembly remain required.
No hardware performance measurement or RAM reload occurred in this turn.

### 2026-09-16: fail closed after a rejected receive exchange

Review found that a rejected frontend publication discarded the already-consumed
TCP range but only returned an error. A caller that retried drive_tcp_frontend
could otherwise continue the same incomplete byte stream. Exchange failures now
mark the listener failed, abort active and pending sockets, publish Reset and
refuse subsequent drives. The listening service does not automatically rearm a
failed exchange listener; rebuilding the stack is required. Cleanup errors also
enter this state before returning. Ordinary no-spare/budget refusal (None from
exchange) continues to use the unchanged copied fallback.

A real TCP test receives four bytes, then uses the existing reentrant network
notification to fill frontend capacity after its drive snapshot and before
exchange publication. It verifies rejection, zero remaining pending pool bytes,
Reset with no queued bytes, repeated drive refusal and no auto-relisten across
ten further network polls. Normal destruction releases both writers without
supervisor sweeping. This deliberately injected concurrent admission case
exercises the actual error path rather than calling the failure helper directly.
The test uses an opt-in protocol activity-events feature forwarding net-api's
existing event feature.

Logs under target/mars-reference:
`20260916-exchange-{rejection-test,fail-closed-combined,fail-closed-default}.log`.
This closes a normal-return stream-integrity hole; it does not implement
hard-fault lock recovery or atomic queue publication. Firmware remains unchanged
and there is no new throughput/CPU result. The >900 Mbps / <1-core goal is open.

### 2026-09-16: admit and publish one exact pool range under one guard

The frontend queue previously read a Pending length under one pool guard and
published under another. A cancel/reprepare between those observations could
make the queued length differ from the range actually published. Storage now
provides publish_bounded: validate the pending ticket/owner/connection, check the
current range against remaining frontend capacity, publish, and return that
exact length in one metadata critical section. Queue publication uses this
operation, removing one pool-lock acquisition from each exchanged chunk.

A regression replaces a pending three-byte range with a nine-byte range under
the same writer ticket. Admission against the stale three-byte limit must refuse
without consuming the pending range; nine-byte admission returns the actual
length and the complete replacement payload remains readable. Existing mixed
frontend and actual TCP/backpressure/refusal tests pass. This test covers stale
observations deterministically; it is not a physical concurrency stress test.

Validation logs: target/mars-reference/
`20260916-exchange-atomic-admission-api.log` (14 ownership/storage, ten legacy
frontend, seven exchange frontend, one allocation tests), and
`20260916-exchange-atomic-admission-tcp.log` (four unit, 46 combined integration
tests). Diff whitespace check passed. Atomicity here means normal lock-based
serialization, not hard-fault durability: the pool-publication/queue-insertion
fault window and abandoned lock recovery remain open. No firmware deployment or
measured CPU improvement occurred; the hardware target remains unmet.

### 2026-09-16: reclaim unread exchange chunks on frontend destruction

The mixed receive queue now discards its published pool chunks during ordinary
Drop. Previously the VecDeque metadata was freed while unread published slots
remained occupied in the permanent pool. Destruction validates each ticket and
connection independently, allowing a stale entry to be skipped without leaking
later valid entries. It does not retire producer owners, unadmitted pending
transfers, reused slots, or ranges pinned by a read lease. Failed validation
never authorizes reuse. Abandoned-lock/skipped-Drop fault recovery is separate.

New tests drop a frontend containing copied and exchanged runs plus an unrelated
Pending transfer, then prove exactly the published slots are reusable and the
Pending bytes remain intact. Another test retires the first queue ticket and
reuses its slot before frontend destruction, verifying both new writers survive
and the later valid published chunk is reclaimed.

Validation: API exchange/event suite passed 14 ownership/storage, ten legacy
frontend, nine exchange frontend and one allocation tests. Combined protocol
suite passed four unit and 46 integration tests; whitespace check passed. Logs:
`target/mars-reference/20260916-exchange-frontend-drop-{api,tcp}.log`.
This repairs normal lifecycle leakage; no hardware image changed, and no new
CPU/throughput improvement is claimed. Production assembly and hard-fault
recovery are still outstanding for the exchange optimization.

### 2026-09-16: independent exchange pools for shared service ports

Added TcpListener::new_shared_with_receive_storage, retaining existing explicit
port-group validation while attaching one independently budgeted permanent pool
to each frontend. Both exclusive and shared constructors use the same private
pool-attachment implementation. This removes a construction gap for iperf's
same-port control/data listeners; it does not yet select them in firmware.

A real SharedIpv4TcpStack test binds two exchange-enabled listeners to the same
port group and sends two distinct 300,007-byte streams simultaneously, with
different delayed-read schedules. It requires pool publication on both sides,
exact stream equality without assuming which SYN selects which socket, bounded
frontend queues, rejection of a substituted sibling frontend, and zero writer
leases remaining after normal stack drop. The initial fixture compilation had
a u64/usize modulo mismatch; after correcting it, the transfer test passed.

Logs: target/mars-reference/20260916-exchange-shared-port-{fixed,api,combined}.log.
This is protocol/assembly preparation, not an iperf service performance result.
Hardware remains unchanged; hard-fault recovery and owner-aware production
assembly remain necessary before testing CPU savings on Mars.

### 2026-09-16: RISC-V validation and capability-preserving pool assembly

Checked the exchange/GRO/pool/segmentation/DHCP/event configuration on the real
riscv64imac-unknown-none-elf no_std target. The first root-directory invocation
missed the firmware build-std configuration and failed to locate core; rerunning
from firmware with its existing .cargo configuration passed. This is cargo check,
not a linked/deployed image or hardware test.

Assembly inspection found that netstack holds Revocable<TcpListener>, whose API
intentionally cannot expose an Arc or an escaping resource borrow. Added
`enable_receive_exchange_capability`: it validates inside try_with, retains the
capability, and revalidates it when matching a frontend for subsequent drives.
The existing Arc-based entry remains for direct trusted image assembly. Both
entries share socket installation and lifetime requirements; neither weakens
Revocable's API or extracts its private Arc.

The simultaneous shared-port TCP fixture now installs both pools through actual
capabilities. After exact concurrent stream verification, it revokes one root,
then proves that even an externally retained Arc cannot drive that binding while
the sibling remains usable. Four unit and 47 combined integration tests passed;
the changed code also passed the RISC-V no_std check. Logs:
`target/mars-reference/20260916-exchange-capability-{combined,riscv-check}.log`.

This removes the capability-shape obstacle to netstack assembly. Actual task
identity selection, supervisor hard-fault recovery and image enablement remain
unfinished. No new hardware CPU result or RAM deployment occurred.

### 2026-09-16: resolve producer identity from the actual task poll

Added current_task_allocation_identity in core, returning task ID and registered
domain from one validated current-running observation. Unlike reading the heap
owner, this is unchanged by temporary SYSTEM allocation scopes. It is only
provenance, not capability authority or a stopped-task/reclamation proof.

Receive ownership now separates current_producer (scheduler identity; requires a
tracked arena) from the existing lighter current_reader scope provenance.
The frontend uses the reader helper without adding a scheduler lock per read.
A new capability assembly entry resolves the current producer instead of taking
an image-supplied task ID. Its unsafe full-stack lifetime/quiescence contract
remains; production netstack does not invoke it yet.

An actual executor test verifies the task/domain pair during polling, inside a
temporary SYSTEM owner scope, after yielding, and its absence outside a task.
The guarded detached-task test also checks that producer identity is unavailable
there. The positive test uses an owner-accounted untracked task to isolate the
scheduler observation; it does not validate full reclaimable arena teardown.
RISC-V no_std check passed. API suite passed 14 ownership/storage, ten existing
frontend, nine exchange frontend and one allocation tests; combined protocol
passed four unit and 47 integration tests. Logs under target/mars-reference:
`20260916-exchange-task-identity-{core,detached,api,tcp,riscv}.log`.
Hard-fault recovery and production image selection are still unfinished. No
hardware throughput/CPU measurement was made this turn.

### 2026-09-16: commit complete pool metadata banks

Storage metadata mutations now operate on a snapshot and initialize the inactive
bank before a Release store selects it. Readers Acquire the selected bank. The
inactive banks use MaybeUninit<Ownership>, so an interrupted write may contain
invalid enum bytes without constructing/reading a Rust Ownership value from
those bytes. Only the fully committed bank is exposed; no mutable dereference
to committed ownership is available. Payload bytes remain in their original
permanent buffers and are not copied by this transaction.

This prevents a partially updated ownership enum/table from becoming the state
that a future abandoned-lock recovery would expose. It does not itself recover
the lock, prove a task stopped, or make pool and frontend queue commits atomic.
Each mutation now copies the small bounded metadata snapshot, so its CPU cost
must be measured along with the saved payload copy before retaining the full
optimization. Firmware remains disabled for this feature.

The new test interrupts a candidate update before commit, verifies the prior
writer remains valid, fills the inactive bank with arbitrary invalid bytes, and
then verifies the committed bank and subsequent reservations remain correct.
The initial mechanical mutation-wrapper edit had nested-argument and test std
import errors, corrected before validation. API suite passed 15 unit, ten legacy
frontend, nine exchange frontend and one zero-allocation audit tests; combined
TCP passed four unit and 47 integration tests. RISC-V no_std check and diff
whitespace check passed. Logs under target/mars-reference:
`20260916-exchange-metadata-banks-{fixed,tcp,riscv}.log`.
No hard-fault hardware result or CPU reduction is claimed in this turn.

### 2026-09-16: exact-task recovery of an abandoned pool metadata guard

Pool metadata now uses the existing recoverable SpinLock acquisition path and
exposes unsafe recover_metadata_lock. It authenticates the exact acquisition
domain and globally unique task key through core's existing lock-generation
protocol. Recovery exposes the last complete metadata bank. False does not
prove quiescence or validate a free lock, and this API does not retire payloads
or repair a frontend queue. Cross-hart users must first observe the stopped
hart's Release acknowledgement with Acquire; no such coordinator is wired yet.

A host test publishes data and reserves another writer, acquires the lock under
an exact task/domain context, corrupts only the inactive bank, and forgets the
guard. Wrong-task and wrong-domain recovery attempts fail; exact recovery
succeeds once, the published payload is intact and the writer remains valid.
There are no remaining guard/payload references in this fixture. This models
skipped Drop and invalid inactive bytes, not a physical trap or SMP stop proof.

Validation logs: target/mars-reference/
`20260916-exchange-lock-recovery-{api,tcp,riscv}.log`. API passed 16 unit, ten
legacy frontend, nine exchange frontend and one allocation test; combined TCP
passed four unit and 47 integration tests; RISC-V no_std check passed. The new
recoverable acquisition has extra provenance bookkeeping, whose real cost is
not measured yet. Queue joint recovery and supervisor/image integration remain
unfinished, and no hardware CPU gain is claimed.

### 2026-09-16: first RAM-only receive-exchange CPU experiment

Composed the opt-in experiment into the actual netstack task and iperf control /
data frontends. Image policy allocates one permanent 3 x 256 KiB pool per shared
listener (IDs 1/2, port 5201), and task startup binds its capability with the
scheduler-derived producer identity. Rebuild clears old frontend state before
reserving new writers. Ordinary independent TCP probe listeners remain copied.
Added `nrxexchange` cumulative exchanged/copied frontend bytes; two relaxed
counter updates occur per nonempty drive in the experiment. This bookkeeping is
included in the results, not claimed free.

FIT SHA256: 7e4112b6a005a5784b88a6ce391196148e028e57fbecd14b39e0c5c1a6d49056.
Exact ELF: target/mars-reference/20260916-rx-exchange.elf.
Boot/load: target/mars-reference/20260916-rx-exchange-ramboot.log and
mars-acceptance/20260913-gigabit/20260916-rx-exchange-{load,boot}.log under target.
Both FIT component hashes were verified by U-Boot before RAM boot; 1000/full link
and RXEX_POOL assembly lines were observed. No SD/SPI flashing or saveenv.
DHCP/event/combined netstack tests passed three unit, four command and one
allocation audit tests. Final build and image checker passed.

Two 20-second unpaced RX runs: 948.5376 / 947.8985 Mbps, non-WFI 1.982650 /
1.982211 cores. Cumulative bytes after these runs: 4,334,912,526 exchanged and
406,477,568 copied, about 91.427% exchanged. Thus the small CPU result is not
simply a completely unused path. Two 300 Mbps runs: 299.9676 / 299.9526 Mbps,
0.887032 / 0.871866 cores. Then the exact config-owner baseline was restored in
RAM (SHA256 160ebbe055260612a0320f15c353d2373eec154e87f01152ebe72b779773120b)
and the same paced test repeated: 0.900726 / 0.906545 cores. This small sample's
mean difference is about 2.67%; it does not establish a durable gain across
conditions. Full-rate baseline from the earlier same-link check was about
1.995 cores, so the <1-core objective is plainly unmet.

Evidence directories under target/mars-reference:
20260916-rx-exchange-{rx,paced,control-paced}/summary.json;
20260916-rx-exchange-counters.log, -control-ramboot.log and
-control-integrity.json. The restored baseline gets the independent 64 MiB
integrity check. Since those probes stay copied, it is NOT hardware byte-for-byte
qualification of the new exchange path. Host real-TCP tests cover its byte
ordering, but hard-fault/queue joint recovery and physical integrity qualification
remain incomplete. Board ends on the baseline; ethernet feature defaults were
restored by packaging. The experiment remains default-off.

Conclusion for the next experiment: removing most frontend payload copies alone
has not materially reduced the full-rate two-core residency. Further work must
measure where time remains (including pool bookkeeping and sustained ready work)
rather than assume that completing more exchange machinery will reach one core.

### 2026-09-16: remove empty per-packet service traversal candidate

Re-read the existing full-rate poll-decision evidence before changing waiting:
99.68% of stack turns processed ingress; empty retries were 0.19%, and the prior
protocol-event comparison showed no CPU improvement. These data do not support
another idle-grace adjustment as the primary RX optimization.

Found that poll_network supplies an empty application callback but still calls
service_listeners after each ingress result and once after ingress processing.
That traversal constructs listener handles and resolves each mutable socket,
including bounds/type validation whose possible panic is observable even when
the callback ignores its arguments. Added a default-off skip-empty-service
feature: a const generic removes those traversals for empty network-only calls;
real synchronous service_echo continues with SERVICE=true. The feature is
forwarded through netstack/kernel/Mars as skip-empty-service-experiment.

Validation: four unit/39 combined TCP integration tests and 24 default tests
passed, including echo and capability frontend behavior. Full Mars build and
image checker passed. Candidate adds only this experiment to config-owner's
network feature map; it does not enable receive-buffer exchange. FIT SHA256:
ea851197f93a3449388ebce782839998670e538cf970ad9430f356f34e3e430d.
ELF: target/mars-reference/20260916-skip-empty-service.elf.
The exact poll_network symbol size is 17,438 bytes versus 18,366 in the prior
config-owner ELF. Address-bounded objdump outputs are archived as
20260916-skip-empty-service[-control]-disassembly.txt. This proves a generated
code difference, not a CPU reduction or an attribution of all changed bytes to
one source statement. Initial symbol-name disassembly lookup failed; the saved
complete outputs use verified nm address/size bounds instead.

Build/test/FIT logs use target/mars-reference/20260916-skip-empty-service-*;
feature map: skip-empty-service-features.json. Packaging restored the default
ethernet flags. No board reload occurred this turn; it remains on config-owner.
Next action is a RAM-only full-rate and paced CPU comparison of this candidate,
with integrity and baseline restoration. The >900 Mbps / <1-core goal is open.

### 2026-09-16: skip-empty-service RAM experiment, no demonstrated CPU gain

Loaded ea851197f93a3449388ebce782839998670e538cf970ad9430f356f34e3e430d
via RAM TFTP with both U-Boot component hashes checked. Candidate 64 MiB patterned
TCP verification passed (1131 ms board time). Two 20-second full RX runs:
948.6720 / 948.5980 Mbps, 1.994461 / 1.994898 non-WFI cores. Two paced 300 Mbps
runs: 299.9826 / 299.9826 Mbps, 0.926773 / 0.914425 cores. Full-rate results are
essentially the previous ~1.995-core baseline; paced results are above the prior
0.900726 / 0.906545 control sample, not an improvement. A fresh post-candidate
control was attempted but not completed, so do not claim a definitive causal
regression percentage. The experiment remains default-off and is not adopted as
a CPU optimization.

Restoration loaded and hash-verified the exact config-owner baseline FIT
160ebbe055260612a0320f15c353d2373eec154e87f01152ebe72b779773120b, but boot
failed before shell: MARS_TRNG_PROBE prepare=Err(Protocol), start=Err(Protocol),
read=Err(DriverRestarted), cause=Some(Initialize(Mode)), followed by
"pmic_ops: cannot read pmic power register". A further 15-second serial read
returned no bytes. The restore helper terminated with failure; it is not live or
waiting. Physical power-cycle requested. Board is NOT recorded as recovered.
No SD/SPI flashing/saveenv was issued. The entropy gate was not bypassed.

Evidence under target/mars-reference:
20260916-skip-empty-service-{ramboot,integrity}.log/json (separate log/json files),
20260916-skip-empty-service-{rx,paced}/summary.json,
20260916-skip-empty-service-control-{reboot,ramboot,stall}.log.
Next hardware action after power-cycle: capture boot, restore baseline in RAM,
complete control/integrity checks. CPU work should return to measured dominant
packet/frontend costs rather than treating smaller generated code as success.

### 2026-09-16: serial recovery remains blocked after wiring confirmation

After the user confirmed wiring, a 20-second tty read and a separate 12-second
cu read at 115200 both received zero bytes, including after a carriage return.
No other serial test process was observed. en13 reports active 1000baseT full
duplex at 192.168.77.1/24; two pings to 192.168.77.10 timed out. Physical link
does not establish that U-Boot or VibeOS is running. Evidence:
20260916-wiring-confirmed-serial.log and 20260916-wiring-confirmed-cu.log.
Requested an adapter-side TX/RX loopback with the board TX/RX disconnected to
separate adapter transport from board output. No loopback result yet.

Retained TRNG mode-register observations now have host validation: 10 driver
protocol tests and the firmware entropy lifecycle model passed. Initial host
commands failed because they included the image binary or omitted the required
entropy-device feature; the successful firmware command used
--no-default-features --features entropy-device --test entropy_model.
Logs: 20260916-trng-driver-recheck.log and
20260916-entropy-model-noimage-recheck.log. This does not validate the new boot
diagnostic on hardware. No new CPU measurement or successful baseline restore
is claimed; no SD/SPI write or saveenv was performed.

The retained mode observation and boot log also passed the RISC-V firmware
compile check with the ethernet and trng-probe features:
`cargo check --config firmware/.cargo/config.toml -p vibeos-firmware-milkv-mars
--features ethernet,trng-probe`. Log: 20260916-trng-mode-riscv-check.log.
This checks the boot-only diagnostic call path omitted by host model tests;
it is not an image-link, hardware recovery, or entropy qualification result.
