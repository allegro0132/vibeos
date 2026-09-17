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

### 2026-09-16: serial and known network baseline recovered

After the operator re-confirmed the working port 54340134951, a cu-endpoint
probe received shell prompts and background logger output. It explicitly
asserted DTR/RTS, but modem bits were 0x6 both before and after: this observation
does not prove that the control lines caused recovery. Leading bytes were
garbled; subsequent commands and reboot output were readable. The old tty
command helper then worked too. The initially running image reported no modern
network transport; its identity was not established.

Software reboot reached U-Boot and was intercepted. RAM-only restoration of
the exact config-owner FIT 160ebbe055260612a0320f15c353d2373eec154e87f01152ebe72b779773120b
passed both component hash checks, boot admission, four-hart online, the
unqualified TRNG protocol probe, and 1000 Mbps full-duplex link. No SD/SPI write
or saveenv. The earlier hardware recovery blocker is now cleared.

64 MiB TCP pattern validation passed with all bytes confirmed (1153 ms board
time). Two 20-second host-to-board iperf runs reported 948.2227 / 948.7863 Mbps
in iperf end.sum_received and 1.993819 / 1.995365 aggregate non-WFI cores.
These reproduce the previous baseline; they do not demonstrate a CPU reduction
or sub-one-core completion. Evidence: 20260916-cu-dtr-rts-check.log,
20260916-restored-{quiet,net,reboot}.log,
20260916-restored-baseline-{ramboot.log,integrity.json,rx/summary.json} under
target/mars-reference, plus restored-baseline boot/load logs under
target/mars-acceptance/20260913-gigabit. Board remains on this known baseline.

### 2026-09-16: same-image RX rate curve after recovery

Kept the restored config-owner FIT, network adapter, MTU and task placement
unchanged. Ran two 20-second RX tests at each of 900M, 600M and 300M, following
the two unpaced runs above. This is a sequential baseline characterization,
not a randomized optimization A/B or an attribution to one code path.

| Offered rate | iperf end.sum_received Mbps | Aggregate non-WFI cores |
| --- | --- | --- |
| Unpaced | 948.2227 / 948.7863 | 1.993819 / 1.995365 |
| 900M | 899.9928 / 899.9478 | 1.939014 / 1.874073 |
| 600M | 599.9652 / 599.9652 | 1.440770 / 1.343564 |
| 300M | 299.9826 / 299.9826 | 0.841968 / 0.827190 |

Pre-run idle samples were 0.205–0.224 aggregate cores. They are not subtracted:
the objective concerns total cost, and idle/background behavior need not add
linearly to traffic cost. In particular harts 2/3 show background activity
while idle but nearly none during sustained traffic. No IRQ, MMIO or lock time
is excluded from the non-WFI proxy. Near 900 Mbps still consumes about 1.9
cores; full-link saturation alone does not explain the unmet CPU objective.
The 600M runs vary by about 0.097 core, so small cross-session differences
must not be promoted as demonstrated optimization gains. This does not erase
earlier measurements, but strengthens the need for interleaved controls.

The JSON sender=true field also appears in receiver/sum_received records;
the measurement script explicitly selects end.sum_received. The previous
recovery entry's description as sender summaries was corrected accordingly.
Neither this field nor iperf's reported remote CPU=0 is a CPU measurement.

Evidence: target/mars-reference/20260916-baseline-{900m,600m,300m}/summary.json
with raw iperf and before/after NIDLE logs, and
20260916-baseline-rate-curve.json. No code or firmware configuration changed
for this rate curve. Board remains on the working baseline; sub-one-core
performance and full hardware qualification remain unachieved.

### 2026-09-16: sample RX metadata acquisition and protected work separately

Added default-off rx-metadata-profile to Mars assembly. Four hot RX_META paths
use the same existing recoverable guard through an inline closure: driver ring
metadata access (kind 0), batch length publication (1), loan acquisition (2),
and loan return (3). Per logical hart/kind, sample one in 127 calls; count all
calls but read the timer only for selected operations. Report cumulative
calls/samples/acquire_ticks/held_ticks/max_held_ticks from nrpool outside traffic.
No ownership transitions, capability checks, DMA operations or reset rules
were removed. No global SpinLock changes. Normal images have no counters/timer
reads from this diagnostic.

Acquisition time starts before lock() and therefore includes IRQ masking,
contended wait and recoverable owner bookkeeping. Held time ends before unlock;
it excludes guard release/IRQ restoration. The timer is 4 MHz (0.25 us), and
the sampling reads perturb short sections. These are inclusive durations,
not contention-only measurements or unbiased/exclusive CPU shares. Maxima are
cumulative boot maxima; do not subtract them or treat them as complete tails.

Diagnostic FIT: 12803efb7f9378fd851da44f4c432c9066e86c32c933a75f6fbd6344092ad7c1.
Full build/image check and enabled/disabled RISC-V checks passed. All 107 EQoS
driver tests passed. RAM component hashes and 1000 Mbps link passed; 64 MiB
patterned TCP passed (1109 ms). A 20-second RX capture reported 948.8686 Mbps
and 1.989464 non-WFI cores, not a demonstrated performance improvement.

| Hart / kind | Calls in counter interval | Samples | Mean acquisition us | Mean held us |
| --- | ---: | ---: | ---: | ---: |
| 0 / ring metadata | 2196978 | 17299 | 0.5760 | 0.7585 |
| 0 / batch publication | 732326 | 5767 | 0.5859 | 0.8520 |
| 1 / loan acquisition | 1624887 | 12794 | 0.5868 | 0.6721 |
| 1 / loan return | 1624887 | 12794 | 0.5597 | 0.4845 |

Sampled held maxima since boot were 2.25 / 1.75 / 1.50 / 0.75 us respectively.
This capture does not reveal long RX_META critical sections; it does establish
frequent short serialized operations. About 2.22 packets were admitted per
publication batch in the interval. The observed ring metadata call count is
exactly three per publication. Batching can amortize those operations, but the
prior queue-publication experiment did not prove a CPU gain; these results do
not justify simply increasing a batch limit or removing ownership checks.

Evidence: target/mars-reference/20260916-rx-metadata-{check,disabled-check,
build,driver-tests,fit,ramboot,capture}.log; exact ELF and feature map; capture/
contains raw pool and NIDLE before/after logs, iperf JSON and analysis.json.
Restored exact config-owner FIT in RAM; both hashes and gigabit initialization
passed, then 64 MiB verification passed (1142 ms). Restore evidence uses
20260916-rx-metadata-restore-*; raw boot/load logs are under
target/mars-acceptance/20260913-gigabit. No persistent writes. Board remains on
the unprofiled baseline. The sub-one-core objective is still open.

### 2026-09-16: bounded consumer admission primitive, not yet a runtime experiment

Reviewed descriptor synchronization, OWN reads, RX readiness probing and TX
reaping. No barrier was removed: the ordering contracts do not justify treating
adjacent synchronization calls as interchangeable. Consumer admission is a
separate potential source of repeated work after the hardware batches arrive.

Added ReceiveEndpoint::try_receive_batch, capped at the HAL batch size (8),
with a caller-specified smaller limit. A caller can hold one existing live
receive capability invocation around it. Each frame still leaves the queue
and becomes an owner-tracked DMA loan before the next dequeue; there is no
array of prefetched raw Ready tickets outside queue retirement or borrower
recovery. Queue locks and HAL loan acquisition remain per frame. This primitive
alone therefore does not amortize those locks or change existing callers.

On a late session/device error, admitted loans drop normally, the rejected
ticket follows existing single-frame discard rules, and the unvisited tail
stays queued. Revocation blocks new invocation; already admitted loans retain
their original lifetime/owner until release or proven stopped-owner recovery.
The existing single-frame dequeue/acquire fault window is not claimed fixed.

Nine receive tests passed, including four new tests for limit-zero/full-cap,
FIFO storage identity, queued-tail retirement versus live loans, late session
failure cleanup, invalid owner, revocation, exact-owner recovery and duplicate
ticket device rejection without double release. RISC-V core check passed.
Logs: target/mars-reference/20260916-rx-consumer-batch-{final-tests,riscv}.log.
No protocol caller, firmware feature or hardware image selects the new method
yet. Next step is a default-off adapter integration with bounded retained loans,
ingress budget/revocation/drop tests, then same-rate interleaved hardware
controls. There is no new performance measurement or improvement claim here.

### 2026-09-16: consumer batch adapter integration and paired RAM artifacts

Added default-off rx-consumer-batch to protocol/netstack/kernel, selected in
Mars by rx-consumer-batch-experiment. PacketReceive performs one existing live
authority invocation around the bounded endpoint admission. PacketDevice keeps
at most eight admitted loans, preserving FIFO across refills and GRO lookahead.
Admission charges the existing wire-frame budget; retained loans already
charged at admission are not charged a second time. A failed batch conservatively
charges its requested limit because the endpoint error does not report how many
prefix loans were consumed/released. Queue/HAL ownership checks remain per frame.

Cached loans keep the adapter runnable even if the endpoint queue is empty.
Receive-time authority failure clears cached loans; normal adapter destruction
also drops them. End-of-GRO revalidation still prevents a revoked collection
from publishing a token. Admitted immutable loans retain the existing cleanup
and exact-owner recovery contract. No raw DMA tickets are prefetched separately.

Four protocol unit tests and 41 combined pooled/GRO/native-TCP integration tests
passed. Two new adapter tests exercise FIFO across batch refills, queued-empty
runnability, normal destruction with cached loans and receive revocation without
dequeueing the unvisited tail. Existing wire-budget, GRO revocation-during-
collection and actual TCP changing-payload tests also pass. Default protocol
regression passed 24 integration tests; netstack rx-consumer-batch tests passed.
Both feature-on and feature-off full Mars builds/image checks passed.

Built paired artifacts from the same working runtime source, rather than using
the older config-owner ELF as the sole performance control:
- Experiment target/mars-boot-20260916-rx-consumer/out/artifacts/vibeos.itb:
  fd74a303c2833c5d253729d1703d711b6ea465edebc1e72d99dc9c0d60b5220c.
- Control target/mars-boot-20260916-rx-consumer-control/out/artifacts/vibeos.itb:
  17fb3a5fd2459ac6d2aa30a873266b2adfddb3e5a122e893144b54ed9bd73d6a.

Feature maps, exact ELFs, build/FIT and host test logs use the
20260916-rx-consumer[-control] prefix under target/mars-reference. Default
ethernet feature selection was restored after packaging. These images have
NOT been loaded or performance-tested yet. Board remains on the previously
validated config-owner baseline. Next action is RAM-only integrity and
interleaved same-rate control/experiment measurements before any promotion.

### 2026-09-16: consumer batching A/B/A — no demonstrated CPU gain

Rechecked both FIT SHA256 values above, then RAM-loaded control, experiment,
control in that order. Each load passed U-Boot component hash verification,
gigabit link initialization and a 64 MiB changing-pattern TCP check (1125,
1178, 1175 ms board time respectively). No SD/SPI write or saveenv was issued.

| Image / rate | Receiver Mbps, two 20 s runs | Aggregate non-WFI cores |
| --- | --- | --- |
| Control before, 910M | 909.9157 / 909.9612 | 1.927288 / 1.938279 |
| Consumer batch, 910M | 909.9157 / 909.9612 | 1.945316 / 1.943267 |
| Consumer batch, unpaced | 947.9235 / 948.6278 | 1.993414 / 1.995531 |
| Control after, 910M | 909.9157 / 909.9157 | 1.932381 / 1.946091 |

The candidate overlaps the post-control range and does not beat the preceding
control. This short sequential A/B/A demonstrates no CPU reduction; it is not
a confidence interval or proof of a general regression. The experiment only
amortized receive capability invocation; per-frame queue/HAL locks and loan
ownership operations remained. Do not infer that all batching designs fail,
or attribute this result solely to one atomic/array operation without evidence.

Archived and removed the consumer-batch runtime API, adapter fields/methods,
feature forwarding and its dedicated tests. Patch:
target/mars-reference/20260916-rx-consumer-experiment.patch. Reverse application
and clean reapplication checks passed. Other diagnostics and prior work were
preserved. Existing receive tests and pooled/GRO/native protocol tests passed
after removal. Board remains on the feature-off paired control FIT
17fb3a5fd2459ac6d2aa30a873266b2adfddb3e5a122e893144b54ed9bd73d6a.

Evidence: target/mars-reference/20260916-rx-consumer-comparison.log and
20260916-rx-consumer-results.json; control1/candidate/control2 integrity files,
paced residency directories, candidate-full directory, RAM helpers and logs.
Raw boot/load/network evidence is under target/mars-acceptance/20260913-gigabit
with the same phase prefixes. Host post-removal tests use
20260916-rx-consumer-removed-{core,protocol}-tests.log. There is no performance
optimization promoted from this experiment; the <1-core objective remains open.

### 2026-09-16: independent sink and multi-flow CPU cross-check

Used the unchanged paired-control FIT 17fb3a5fd2459ac6d2aa30a873266b2adfddb3e5a122e893144b54ed9bd73d6a
to compare independent VBENCH02 mode-0 sinks on ports 5300–5303 with iperf3.
Mode 0 counts bytes without the per-byte pattern validation of mode 2; the
earlier integrity-test runtime is therefore not a comparable throughput result.
The independent client first calibrated at 32108.70 Mbps single-flow and
10001.17 Mbps four-flow on host loopback (128 MiB per flow).

Each board run transferred a fixed aggregate 2 GiB: 2 GiB for one flow or
512 MiB per flow for four. The barrier action captured NIDLE only after every
flow received application-ready R and before sending G. Post-capture followed
byte-count confirmation/close; it includes that small completion overhead.
This avoids counting application readiness as low-CPU payload execution.
Later port-5300 setup waits measured 9.14–9.85 seconds and were excluded.
No CPU/clock/firmware/MTU setting was changed.

| Independent sink | Receiver Mbps | Aggregate non-WFI cores |
| --- | ---: | ---: |
| Single flow, first | 945.2367 | 1.980249 |
| Four flows, first | 943.8200 | 1.974080 |
| Single flow, second | 946.5163 | 1.983403 |
| Four flows, second | 944.0515 | 1.977047 |

All 8 GiB were confirmed by board byte counts; this benchmark does not validate
payload patterns. A subsequent same-image two-round iperf control reached
948.34 / 948.37 Mbps at approximately 1.994 cores. Rates have different timing
boundaries, so the few-Mbps gap is not an isolated service-performance effect.
Replacing iperf control/parser/service state did not remove near-two-core RX
cost; the shared TCP capability/frontend/stack/driver path remains the target.
Four flows did not materially improve throughput or total CPU. This does not
separate every common-path cost or prove that the services have zero overhead.

Evidence: target/mars-reference/20260916-independent-rx-loopback.json;
run-independent-rx-residency.py; 20260916-independent-rx-run.log;
20260916-independent-rx/{summary.json,*flow-*.json,*-before.log,*-after.log};
20260916-independent-rx-iperf-control/summary.json and raw iperf/NIDLE logs.
Board remains on the same functional control image. No code optimization,
persistent write, sub-one-core result or full qualification is claimed.

### 2026-09-16: hardware cycle/retired-instruction availability and first RX sample

Added default-off kernel/Mars counter-probe and ncounters. Each command spawns
one short pinned task per online hart, allocating task/result storage under
SYSTEM and restoring that scope before awaiting. Tasks read time/cycle/instret/
time and report the observed hart; no recurring task or per-packet counters.
Cycle/instret availability has separate bits, so unavailable is not valid zero.

The diagnostic trap hook resumes only S-mode illegal-instruction exceptions at
the exact two static CSR probe sites. It sets saved a0/a1 to unavailable and
advances four bytes. Other exceptions/PCs retain the original trap policy;
ordinary IRQs return before reading extra CSRs. The host predicate test covers
both sites, unrelated exceptions/PCs, interrupts, user mode, alignment, null
and overflow. It does not execute the machine trap-return path. Full RISC-V
build/image check and feature-disabled check passed. Exact ELF disassembly
confirms fixed-width rdcycle/rdinstret followed by ret and separate site labels.

Local SDK sbi_hart.c enables MCOUNTEREN and leaves cycle/instret uninhibited,
but this was not treated as proof of the SPI binary. RAM FIT
03d80009469f8c01dfe2dbfcb52b4e064292a0d5eaec35b8f3b5954a015ca33e
passed load hashes and gigabit boot; all four actual harts reported available=3.
Unsupported-counter recovery was therefore NOT exercised on this hardware.

One 10-second idle interval and one 20-second RX interval produced these
counter deltas, normalized by each hart's own rdtime bracket midpoint:

| Workload / hart | Cycles per wall second | Instret/cycle | Non-WFI % |
| --- | ---: | ---: | ---: |
| Idle / 0 | 112838182 | 0.5399 | 10.511 |
| Idle / 1 | 61290544 | 0.5304 | 5.985 |
| Idle / 2 | 25656653 | 0.4198 | 2.501 |
| Idle / 3 | 26225458 | 0.4280 | 2.560 |
| RX / 0 | 984104596 | 0.7258 | 99.372 |
| RX / 1 | 977638893 | 0.8435 | 99.134 |
| RX / 2 | 117397 | 0.4459 | 0.011 |
| RX / 3 | 112409 | 0.4563 | 0.011 |

RX receiver throughput was 948.3915 Mbps. Cycle rates track busy residency,
rather than an invariant wall-clock rate on all harts; these observations are
consistent with counter/clock gating during WFI on this setup. Counter and
WFI snapshots have slightly different boundaries and include command/probe
overhead. They independently support the near-two-core load and do not by
themselves distinguish cache stalls, barriers, branches or execution width.
Do not call 1-IPC a stall percentage or claim an instruction-level attribution.

Diagnostic 64 MiB TCP pattern verification passed (1188 ms). Restored the
feature-off paired control FIT 17fb3a5fd2459ac6d2aa30a873266b2adfddb3e5a122e893144b54ed9bd73d6a;
load hashes, gigabit boot and 64 MiB verification passed (1154 ms). No SD/SPI
write or saveenv. Board remains on this control.

Evidence uses target/mars-reference/20260916-counter-probe-* (host tests,
checks, build/FIT, exact ELF, address-bounded instructions, sample1, integrity,
restore logs). The capture directory contains raw ncounters/NIDLE brackets,
iperf JSON and analysis.json. The earlier symbol-name disassembly was truncated
at alias labels; counter-probe-instructions.txt is the complete verified range.
This adds a diagnostic capability, not a CPU optimization; the target is open.

### 2026-09-16: compact short-frame queue A/B/A (not adopted)

Serial at /dev/tty.usbmodem54340134951 was revalidated with a prompt,
background output and a command response. Software reboot and RAM FIT loading
also worked; no additional cable/power intervention was required.

Tested a complete default-off inline-wire-frames path, not merely a standalone
message type. Native frames up to 128 bytes carried immutable stamped inline
bytes through the ordered transmit endpoint, protocol pending retry and driver
pending state. Larger ordinary frames used the existing bounded, recoverable
segment pool with a distinct request kind. TSO remained in the same queue.
Compile-time bounds limited InlineFrame to 160 bytes and Transmit to 168 bytes.
Legacy Packet/raw endpoints were unchanged. Admission still reserved before
serialization and cancelled unused reservations; this experiment did NOT remove
RX-side eager TX reservations or their capability/lock costs.

Tests covered bounds before serialization, session mismatch, owned bytes,
FIFO/backpressure, pending inline retry blocking successors, revocation both
before token serialization and while pending, large-frame fallback, stale pool
generations, invalid lengths and interrupted serialization. Core suites passed
4 inline + 8 existing pool + 2 transmit + 3 fallback tests. Protocol combined
suite passed 4 unit + 41 integration tests. Disabled-feature regression passed
4 unit + 39 protocol integration and 8 pool + 2 transmit tests. Mars RISC-V
build and image checks passed.

Candidate FIT SHA256:
bde84b43542922a063f792a4a8e6941cabed5f3a6b4d20ef07932dc3a8a18cf6.
Control was the previously verified feature-off FIT
17fb3a5fd2459ac6d2aa30a873266b2adfddb3e5a122e893144b54ed9bd73d6a.
Every RAM load checked kernel/DTB hashes and gigabit link initialization.
MTU 1500 RX runs were 20 seconds, two per phase; CPU is summed non-WFI
residency without idle subtraction, not a per-function execution profile.

| Phase | RX Mbps (two runs) | Active-core equivalents (two runs) |
| --- | --- | --- |
| Control before, 910M paced | 909.916 / 909.961 | 1.94113 / 1.94734 |
| Inline candidate, 910M paced | 909.961 / 909.961 | 1.91506 / 1.94167 |
| Inline candidate, unlimited | 948.452 / 948.558 | 1.99376 / 1.99434 |
| Control after, 910M paced | 909.916 / 909.915 | 1.93902 / 1.93350 |

Candidate 64 MiB patterned TCP verification passed in 1109 ms; restored control
passed in 1166 ms. These are integrity checks, not throughput measurements.
The paced ranges overlap and the unlimited candidate still occupies nearly two
cores. This does not establish a repeatable CPU benefit and cannot attribute
the remaining cost to ACK representation. The complete experiment was removed
from active source, including its preliminary standalone type. Its patch is
archived at target/mars-reference/20260916-inline-wire-experiment.patch;
reverse application and clean reapplication checks passed. Prior counter and
RX metadata diagnostics and unrelated work were preserved. No SD/SPI writes
or saveenv; the board remains on control.

Evidence: target/mars-reference/20260916-inline-* contains build/FIT logs,
exact candidate ELF, enabled/disabled tests, integrity JSON, raw residency and
iperf captures, and inline-wire-comparison.json. RAM boot component hash logs
are under target/mars-acceptance/20260913-gigabit/20260916-inline-*.
The >900 Mbps throughput threshold remains demonstrated; the <1-core effort
objective remains unmet. Any next optimization must measure a distinct cost,
such as eager TX reservation frequency/cost, rather than reusing this negative
result as proof of a dominant bottleneck.

### 2026-09-16: native TX lease cost sampled before optimization

The preceding compact-frame A/B/A was progress (new hardware evidence), but
provided no repeatable efficiency gain. Added default-off tx-lease-profile and
ntxlease to measure the distinct eager-admission hypothesis before redesigning
it. Three per-hart counters cover pooled reserve (including capability invoke
and authority clone), Reservation cancellation (capability invoke/pool cancel),
and publish. They count calls and sample elapsed timer ticks every 127 calls,
with no allocation, reset, locks or printing in the sampler. Scopes are !Send
and synchronous. Cancellation scope does not include the later implicit drop
of Reservation fields. Counts include failure paths; fault-abandoned scopes
need not have completed samples. Snapshots are non-transactional and maxima
are boot-wide. Feature-off code has no hooks or counter module.

Enabled protocol tests passed 4 unit + 39 integration cases; disabled tests
passed the same suite. RISC-V build/image verification passed. Diagnostic FIT:
a567070cd0b8c1cf7e9f70a62583f29a4b243abe39a253b6b8eb01bdaf388f82.
RAM load checked kernel/DTB hashes and 1000 Mbps initialization. Captured one
10-second idle interval and one 20-second MTU 1500 RX interval, with raw
ntxlease and NIDLE brackets plus iperf JSON.

RX receiver throughput was 949.029 Mbps, summed non-WFI residency 1.98758
cores. Only logical hart 1 performed these lease operations:

| RX operation | Calls | Samples | Mean sampled elapsed us | Projected elapsed seconds |
| --- | ---: | ---: | ---: | ---: |
| Reserve | 494117 | 3891 | 0.896106 | 0.442781 |
| Cancel | 494118 | 3890 | 1.033290 | 0.510567 |
| Publish pooled request | 0 | 0 | n/a | 0 |

The ordinary ACK path uses the frame queue, so zero pooled publish calls does
not imply zero ACK transmission. Reserve/cancel differ by one because brackets
are not atomic. Idle recorded 10110 calls each, with mean sampled reserve
0.909375 us and cancel 1.071875 us; idle residency was 0.21908 cores.

Scaling the RX means by calls gives about 0.95335 elapsed seconds over the
roughly 20-second workload (~0.048 core). This is a sampling estimate, not an
exclusive-cycle total, a guaranteed saving, or an upper bound: it includes
interrupt/lock delay, excludes some destruction/instrumentation costs, and may
miss sampling correlations or cache effects. Nevertheless these measurements
do not support prioritizing eager TX lease removal as an explanation for the
roughly one-core gap. No admission or ownership semantics were changed.

Evidence: target/mars-reference/20260916-tx-lease-* includes tests, build/FIT,
exact ELF, boot logs and integrity reports. The capture directory has raw
before/after counters, CPU brackets, iperf JSON, host timing and analysis.json;
analyze-tx-lease.py validates sample declarations, nonnegative deltas and sample
count consistency. This is diagnostic evidence, not a CPU optimization.

Diagnostic 64 MiB pattern verification passed (1147 ms). Restored control FIT
17fb3a5fd2459ac6d2aa30a873266b2adfddb3e5a122e893144b54ed9bd73d6a;
component hashes, gigabit boot and restored 64 MiB verification passed (1114 ms).
Board remains on this feature-off control. No SD/SPI writes or saveenv. The
sampler remains default-off for future diagnostics; <1-core goal remains open.

### 2026-09-16: MSS diagnostic exposed an iperf setup recovery defect

Attempted a constant-300-Mbps MSS sweep to distinguish packet-rate costs from
byte-transfer costs. Added an explicit --mss option to mars-residency-bench.py,
recorded as requested_mss separately from observed sizes. On this macOS host,
iperf3 -M 1460 fails with "unable to set TCP/SCTP MSS: Invalid argument" before
creating its data stream. Thus target/mars-reference/20260916-mss-sweep contains
NO valid MSS performance comparison. An existing Linux container could not
connect to the board; its connection timed out and no matching traffic was seen
on en13 during that attempt. The temporary capture was stopped and verified
absent. A subsequent native 64 MiB TCP verification passed (1155 ms). No host
MTU change, container install, or prepared board MSS source edit was performed.
The later capture includes that native integrity traffic and must not be
misrepresented as container traffic.

The failed native -M connection exposed a real service problem: a subsequent
ordinary iperf run timed out after 50 seconds, while the independent TCP service
remained usable. AcceptData checked only data accept; it never read an abandoned
control connection, and setup phases had no deadline. This can permanently
occupy the single supported iperf session after a client-side setup failure.

Fixed components/iperf3-server: AcceptData and DataCookie now observe control
EOF/termination/unexpected input. AcceptData accepts first so cleanup can reset
an already-arrived data stream too. ControlCookie, Parameters, AcceptData and
DataCookie share a 10-second deadline starting at control acceptance. The idle
listener has no setup deadline; running-test timing/payload work are unchanged.
Existing task error handling resets both held tokens and creates a fresh server.
Tests cover EOF and CLIENT_TERMINATE during both stream setup phases, reset of
both connections and acceptance of the next client, each silent setup phase at
the deadline boundary, and unlimited idle acceptance. Both default and
event-driven suites passed 8 tests; RISC-V build/image verification passed.

RAM FIT SHA256:
523347fa705950ba8a5aaab74d433f4c98b8d3d7a5c12b461071d642f73242a1.
Component hashes and gigabit link initialization passed. Twice reproduced the
same expected native -M failure on the fixed firmware and immediately followed
it with an ordinary 5-second iperf run: 945.443 and 946.229 Mbps. A connection
sending only a partial control cookie was reset after 10.007 seconds; the next
ordinary test delivered 946.205 Mbps. The harness asserts the expected client
error, successful following byte counts and bounded silent-connection reset.
These are service-recovery tests, not a new CPU efficiency claim.

Evidence: target/mars-reference/20260916-iperf-setup-* contains tests, exact ELF,
build/FIT/load logs, raw recovery client JSON, recovery summary and integrity.
The 64 MiB patterned TCP verification passed (1128 ms). The abandoned MSS
sweep and container connectivity evidence remain under 20260916-mss-* and
20260916-linux-mss; no packet-vs-byte cost conclusion can be drawn from them.

Post-fix MTU 1500, 1000baseT full-duplex tests (20 seconds each, alternating
RX/TX) gave:

| Run | Receiver Mbps | Summed non-WFI core equivalents |
| --- | ---: | ---: |
| RX 1 | 948.862 | 1.99529 |
| TX 1 | 946.416 | 1.91371 |
| RX 2 | 949.006 | 1.99548 |
| TX 2 | 897.549 | 1.82842 |

The low TX run is preserved: its first second was ~7.2 Mbps, second ~913.2,
third ~943.0, and subsequent intervals ~947 Mbps. Do not remove that startup
interval or reinterpret the lower CPU as efficiency. No packet capture yet
attributes this startup stall to TCP, host, DMA or scheduling.

A requested TX repeat did NOT run: the initial quiet command timed out with
zero serial bytes. Follow-up tty and cu probes at 115200 both produced zero
bytes, no other process held the serial port, and three ICMP probes timed out.
en13 remained active at MTU 1500, 1000baseT full duplex; the USB UART device
still existed and modem bits were 0x6. These observations do not prove a cable
fault or a kernel root cause. A software reboot/capture was started and physical
RESET requested. Last loaded firmware is the above setup-fix RAM FIT, but it
cannot currently be described as responsive or stability-qualified. The single
low TX run, later loss of responsiveness and <1-core target remain unresolved.
No SD/SPI write, saveenv, or smoltcp MSS edit occurred in this turn.

### 2026-09-16: preserve serial diagnostics throughout performance tests

The previous reset capture was polled to completion: exit 0, 180-second window,
0 captured bytes. A fresh five-second serial probe also returned zero bytes
with no other reader. No physical RESET acknowledgement has arrived. The UART
has been released; no capture process is being described as still live.

Source review found an evidence-loss path in mars-residency-bench.py: it blocked
in subprocess.run throughout iperf and called tcflush(TCIFLUSH) before the next
serial command. Unsolicited panic/fault messages could therefore be discarded.
This does NOT establish that any panic actually occurred in the previous run.

The benchmark now uses a single serial reader while polling its exact iperf
child, during idle measurements, and between tests. Raw bytes are flushed to
serial-full.log; command preamble bytes are preserved before starting the reply
boundary instead of being discarded. A 16 MiB limit bounds capture size. Client
stdout/stderr are written directly to files, retaining partial output on timeout.
Every workload exit kills/reaps its own child if still running. Summary errors
include the exception type/message; UART attributes and descriptor are restored
and released on failure. No concurrent serial-reader thread is introduced.

Four host PTY tests passed: pre-command fault preservation without treating its
prompt as a fresh reply; asynchronous diagnostic retention while a client fails;
timeout retention of partial outputs plus child reaping; and idle diagnostics.
Python compilation and diff checks passed. Evidence is
 target/mars-reference/20260916-residency-capture-tests-final.log.
These tests qualify the collector behavior only, not board stability or CPU
performance. A fresh physical capture after RESET is still required to locate
the TX startup stall and subsequent loss of response. The goal remains open.

Recovery blocking audit: on the third consecutive goal turn with the same
unresponsive-board condition, a fresh five-second serial probe again captured
zero bytes with no competing reader. Three fresh ICMP probes received no replies;
en13 remained active at MTU 1500 / 1000baseT full duplex. Both probe processes
completed and released their resources. Evidence is
 target/mars-reference/20260916-blocked-audit3-serial.log plus the tool output.
The prior turn completed the remaining collector repair and host tests. Further
hardware attribution and optimization validation now require physical RESET or
another external recovery; no response has acknowledged that action. The goal
is blocked, not complete. Resume with boot capture, verify the actual image,
and reproduce the TX startup stall with continuous serial/packet evidence
before making further performance changes.

### 2026-09-16: user RESET restored service; repeat with preserved serial output

After the user's ready reply, serial returned a usable vibe prompt (preceded by
uninterpreted buffered bytes). Software reboot worked. Reloaded setup-fix FIT
523347fa705950ba8a5aaab74d433f4c98b8d3d7a5c12b461071d642f73242a1
into RAM; verified both component hashes and 1000 Mbps initialization. This
restores test access, not proof of the previous unresponsive condition's cause.

Using the repaired continuous serial collector, two 20-second TX runs delivered
946.391 / 947.355 Mbps, with non-WFI residency 1.90640 / 1.91007 cores. A bounded
128-byte-snaplen host capture recorded 250000 packets and reported zero kernel
capture drops. The first TX data stream prefix spans 2.756659 seconds with
226911 board data packets; the parser reported no retransmission/zero-window
flags and a maximum host-observed inter-data gap of 1.45793 ms. These are
Wireshark heuristics at a host capture point, not proof of exact wire timing or
absence of loss outside that prefix. The prior 897.549 Mbps startup-stall sample
remains valid evidence and is not superseded by these normal repeats.

No panic/fatal/fault/stopped/timeout text was found in the TX continuous log.
A subsequent 30-second serial observation retained a valid NIDLE response and
the next benchmark could issue commands normally. Two 20-second RX runs then
delivered 948.47 / 947.85 Mbps; exact values and residency are recorded in
 target/mars-reference/20260916-ready-resume-summary.json.
Final 64 MiB patterned TCP verification passed (1129 ms). The additional host
serial polling can extend the CPU bracket by up to approximately 100 ms after
client completion; small differences from earlier residency runs are not an
optimization result. RX remains close to two core equivalents.

Artifacts: 20260916-ready-resume-* RAM/reboot logs; 20260916-ready-tx/ contains
raw pcap, tcpdump completion/drops, parser output, bounded prefix summary, iperf
JSON and serial-full.log; 20260916-ready-rx/ contains the RX measurements and
continuous serial log. The packet-capture supervisor and benchmark processes
completed normally and the serial port is released. Board remains on the
setup-fix RAM image; no SD/SPI writes or saveenv. The goal is active again.
The earlier loss of responsiveness and TX startup stall are not reproduced or
root-caused; <1-core efficiency and long stability qualification remain open.

### 2026-09-16: controlled packetization comparison at fixed byte rate

Completed the previously blocked MSS experiment using board SYN advertisement,
not macOS -M. Baseline and restored image were the setup-fix FIT
523347fa705950ba8a5aaab74d433f4c98b8d3d7a5c12b461071d642f73242a1.
A diagnostic-only build changed the SYN MSS expression to min(calculated,536)
and nothing about interface MTU, receive capacity, payload copying, scheduling
or GRO limits. Its FIT SHA256 was
1cb41fd4cbf65a7c6a92f7a9aa5f4fea5f279fda9e23730dfeffab70056673e6.
The one-line source change was undone immediately after compilation; the full
TCP source SHA256 matches its pre-experiment value, preserving prior submodule
work. All RAM loads checked component hashes and gigabit initialization.
This is a diagnostic artifact, not a production configuration or SD image.

Each phase used two 20-second host-to-board tests paced at 300 Mbps, the same
continuous serial collector, with no idle subtraction. Interface MTU remained
1500. iperf reported MSS 1460 / 536 / 1460 across the three phases. The small-MSS
host capture contains both SYN pairs: host advertises 1460 and board 536. Among
captured host data packets, 239943 had 536-byte payload, 970 had 288 bytes, and
all remaining payloads were smaller; none exceeded 536. The capture stopped at
250000 packets and reported zero kernel drops. These are host capture facts,
not a full-run loss qualification.

| Phase | RX Mbps (two runs) | Non-WFI core equivalents (two runs) |
| --- | --- | --- |
| Normal MSS before | 299.983 / 299.983 | 0.86048 / 0.85072 |
| MSS 536 diagnostic | 299.983 / 299.983 | 1.21597 / 1.22829 |
| Normal MSS restored | ~299.98 / ~299.97 | mean 0.86082 |

GRO counter deltas bracket both tests and include idle/control traffic:

| Phase | RX frames | Merged segments | Aggregates |
| --- | ---: | ---: | ---: |
| Normal before | 1030012 | 929024 | 99112 |
| MSS 536 | 2804201 | 2577283 | 211125 |
| Normal restored | 1030010 | 928608 | 99260 |

At unchanged byte rate, small MSS raises frame count about 2.72x and aggregate
count about 2.13x; CPU rises from about 0.86 to 1.22 cores. Both active harts
increase (driver/application hart and protocol hart). This reproducible response
supports measuring packet and aggregation/handoff-frequency costs together.
It is NOT a pure cycles-per-packet model: MSS also changes ACK behavior, GRO
sizes, copying granularity/cache behavior, and application delivery frequency.
It does not isolate a driver bottleneck or justify claiming copies are irrelevant.
Do not extrapolate this one operating point into a promised full-rate CPU saving.

Small-MSS 64 MiB pattern verification passed (1261 ms), as did restored normal
MSS (1118 ms). Board remains responsive on the setup-fix normal-MSS RAM image;
no SD/SPI writes or saveenv. Temporary source edits are gone. The staged mss536
FIT and archived ELF are explicitly diagnostic, and must not be used for SD
release packaging. Rebuild the normal source for any new release artifact.

Evidence: target/mars-reference/20260916-mss2-* contains A/B/A raw iperf and CPU
brackets, serial-full.log, GRO snapshots, packet-length/SYN extraction, pcap,
exact-source restoration hash, integrity JSON and mss2-analysis.json. Diagnostic
build/FIT/ELF/RAM logs use 20260916-mss536-*. This adds causal packetization
comparison evidence, not an optimization; <1-core and stability goals remain open.


## 2026-09-16 RX producer batch publication: incomplete A/B/A

User-specified UART recovered and showed a demo command set (net info reported
virtio-net offline). A software reboot identified Milk-V Mars 4 GiB. Loaded the
known setup-fix baseline into RAM, validating FIT/kernel/DTB hashes and the
1000-full link before measurement. No SD/SPI writes or saveenv.

The candidate batches producer CONTROL/capability/queue operations with a
32-frame budget. This is distinct from the earlier consumer prefetch experiment;
it actually amortizes queue locking. Both paths already wake on empty-to-nonempty,
so the experiment is not elimination of an unconditional per-frame wake.
Feature-enabled tests passed (9 channel, 7 RX endpoint); default tests also passed.
The experimental ethernet feature expansion is restored to the ordinary profile
in the worktree; rx-publish-batch remains opt-in. Candidate FIT SHA256:
064198a638257ab9564182bdab656ef8d8e13eb427e1a7609d78da92045f355c.

All traffic runs below are host-to-board, MTU1500, two 20-second runs, same
continuous serial collector. CPU is summed non-WFI core equivalents without idle
subtraction, not exclusive driver CPU.

| Phase | RX Mbps | Core equivalents |
| --- | --- | --- |
| Baseline, paced 910M | 909.961 / 909.961 | 1.94598 / 1.95598 |
| Batch candidate, paced 910M | 909.961 / 909.961 | 1.93821 / 1.90202 |
| Batch candidate, unpaced | 948.884 / 948.724 | 1.99414 / 1.99150 |

Candidate 64 MiB pattern verification passed (1167 ms board time). Paced sample
means differ by about 1.6%, but candidate variation is substantial and the
restored-baseline leg failed before traffic. This is insufficient evidence of a
repeatable saving. Full-rate candidate still consumes nearly two cores; it does
not meet the <1-core effort target.

Restored baseline FIT 523347fa705950ba8a5aaab74d433f4c98b8d3d7a5c12b461071d642f73242a1
passed hashes, four-hart admission, network initialization and 1000-full link.
The next collector timed out on quiet with zero bytes in serial-full.log and no
iperf started. A follow-up CR probe also received zero bytes and two ICMP probes
failed. Failure origin is unknown; no panic was captured. It occurred after
restoring baseline, not while running the candidate. Do not call this a completed
A/B/A or stability qualification. Current responsiveness needs recovery before
further performance changes are justified.

Evidence: target/mars-reference/20260916-rx-publish-{baseline4,candidate4,restore4}*
and target/mars-acceptance/20260913-gigabit/20260916-rx-publish-*-{load,boot}.log.
User-port identification and restart logs: 20260916-user-port-recheck4-*.log.


### Recovery follow-up: no demonstrated RX publication gain

After the user restored the board, UART again showed the demo image. Rebooted
to U-Boot and RAM-loaded the exact setup-fix baseline (523347fa...); component
hashes and 1000-full link passed. Two new 20-second 910M RX runs measured
909.961 / 909.961 Mbps with 1.89913 / 1.89425 non-WFI core equivalents.
64 MiB changing-pattern verification passed (1131 ms board time).

The restored baseline is at least as efficient as the candidate's 1.93821 /
1.90202 samples. Thus the small earlier paced reduction is not demonstrated
as a repeatable batch-publication benefit. The recovery required a power cycle,
so this is a recovery-separated control comparison, not an uninterrupted A/B/A.
Candidate full-rate results remain nearly two cores. Keep the experiment opt-in;
do not promote it into the normal ethernet profile or report it as a CPU win.
No SD/SPI writes. Evidence: target/mars-reference/20260916-recovered5-* and
20260916-recovered5-baseline910/; exact RAM load/boot logs are under
 target/mars-acceptance/20260913-gigabit/20260916-recovered5-*.

The recovered baseline then completed sequential 60-second RX and TX runs:
- 01-rx: 946.270 Mbps, 1.98988 non-WFI core equivalents.
- 01-tx: 946.678 Mbps, 1.91584 non-WFI core equivalents.
Post-traffic n idle snapshots (nidle command) completed in both directions;
the continuous collector completed successfully. This did not reproduce the
loss of responsiveness during these limited runs, but does not explain the
earlier failure or constitute the one-hour mixed-load qualification. Evidence:
20260916-recovered5-sustained/{summary.json,serial-full.log,*-iperf.json}.


### 2026-09-16 GRO wire-boundary diagnostic

Re-reading full-rate evidence (99.68% ingress-active stack turns, 0.19% empty
retries) does not support changing idle grace as the next primary experiment.
Captured a fresh setup-fix baseline RX run: 948.915 Mbps,
1.98773 non-WFI core equivalents over 20 seconds. The bounded capture stopped
at its 60-second wall timeout, with 185086 captured packets, 187409 received by
filter and zero kernel drops. It is a prefix, not a complete-run capture.

Tshark extraction selects host-to-board TCP data. The dominant stream has
175406 packets over 2.164 seconds; 175402 payloads are 1460 bytes, four are
shorter (including the 37-byte iperf cookie). Only four have PSH. Adjacent ACK,
window, TCP header length and options never change, and sequence numbers have
no gap/overlap. 9651 adjacent IP ID transitions (~5.5%) fail the current GRO
same-or-increment-by-one rule. PSH and short packets therefore are not frequent
enough in this prefix to explain very small aggregation groups. The IP ID
condition can terminate some groups; this does not quantify its actual CPU cost.

Host capture cannot observe board queue gaps, actual GRO termination reasons,
interleaved traffic seen by the board, or exact arrival timing after offload.
Do not report a simulated GRO speedup or relax validation from these counts.
The next useful measurement is board-side termination reasons (input unavailable,
PSH/short, segment budget, incompatible headers including IP ID), paired with
actual group sizes. This distinguishes changes to batching from protocol policy.
Linux reference inspected: https://raw.githubusercontent.com/torvalds/linux/master/net/ipv4/tcp_offload.c
(tcp_gro_receive compares flags, ACK, options, sequence and network flush state;
master is a moving reference, not a pinned release dependency).

Evidence: target/mars-reference/20260916-gro-boundary.pcap, .tsv,
20260916-gro-boundary-analysis.json, analyze-gro-boundary.py and
20260916-gro-boundary-rx/ (continuous serial, iperf and CPU brackets).
No firmware change, SD/SPI write or demonstrated optimization in this diagnostic.


### 2026-09-16 default-off GRO end-reason instrumentation (not yet run)

Added gro-end-profile through protocol/netstack/kernel/Mars. Protocol-local
non-atomic cumulative counters record one exclusive reason per attempted group:
first_rejected, psh, short, receive_none, next_ineligible, headers, ipid, budget,
original_invalid. A second histogram counts attempted group sizes 0..16, with
zero reserved for rejected first frames. Both pooled and copied adapters record
attempts before final authority validation, so these are not delivered-group
counts. receive_none includes empty input, revocation and acquisition failure;
it must not be interpreted alone as DMA starvation. Header/capacity mismatch
has precedence over IP ID when both fail. No eligibility or merge policy changes.

The live stack publishes approximate atomic snapshots once per second. ngrodetail
prints the reasons and histogram outside traffic. Per-counter snapshots can be
inconsistent during publication; compare quiescent snapshots and check totals.
No per-packet clocks, printing or diagnostic atomics. Default builds omit fields,
updates and command. Diagnostic build changes code layout and has overhead;
its throughput is not directly an uninstrumented optimization result.

Feature-enabled protocol suite: 5 unit + 39 integration tests passed, including
reason classification, count conservation and rejected-packet preservation.
RISC-V build/image checks passed. FIT:
 target/mars-boot-20260916-gro-end/out/artifacts/vibeos.itb
SHA256 73cab4e1e8e7cff265924ab205a9737c0de67571a78e816258881fb1abb04eef.
Packaging restored the ordinary ethernet profile. No commit/push or SD/SPI writes.

Before loading, reboot received zero serial bytes for 15 seconds on the existing
setup-fix baseline; network probes also failed. Diagnostic FIT has NOT been
loaded and has no hardware results. User asked to restore power. Continue with
ramboot-gro-end.py after a confirmed U-Boot prompt, take ngrodetail/ngro snapshots
before and after bounded RX runs, validate size/reason conservation, then restore
setup-fix via ramboot-gro-end-restore.py and verify data integrity.

Build/tests/feature map/ELF/FIT helper evidence: target/mars-reference/20260916-gro-end-*
and gro-end-features.json, ramboot-gro-end*.py.


### GRO end-profile hardware result

RAM-loaded diagnostic FIT 73cab4e1... after confirmed U-Boot; hashes and gigabit
link passed. Each phase used one 20-second RX run with pre/post ngrodetail,
including the runner's idle interval and control traffic in counter deltas.
Both phase deltas have equal reason totals and size-histogram totals.

| Rate | Mbps | Non-WFI cores | Mean eligible group size | receive_none | IP ID | 16-packet budget |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Full | 948.886 | 1.98762 | 6.221 | 66.669% | 29.965% | 3.277% |
| 300M | 299.983 | 0.87104 | 9.730 | 33.566% | 20.822% | 34.736% |

Percentages use all attempted groups; means exclude size-zero rejected first
frames. Full-rate PSH ends were 0.083%, versus 10.854% at paced 300M. These
rates have different sender pacing/burst behavior. Diagnostic overhead/layout
and one sample per rate limit comparisons; there is no optimization claim.

IMPORTANT: source review shows receive_pooled/receive_packet also return None
when ingress_remaining (per-interface poll budget) reaches zero. Therefore
receive_none includes a software budget boundary, empty endpoint, unsupported
transport, authority failure and rejected loan. It does NOT prove producer
starvation or justify sleeping the consumer. Next split those reasons at the
actual receive method before experimenting with scheduling or coalescing delay.
Current data do not support simply raising the 16-packet GRO group limit.

Diagnostic 64 MiB pattern passed (1137 ms). Restored original setup-fix baseline
523347fa... with verified hashes/1000-full link; fresh pattern passed (1119 ms).
Board is responsive on the baseline. No SD/SPI writes. Evidence:
20260916-gro-end-{full,300}*/summary.json and before/after logs,
analyze-gro-end.py, 20260916-gro-end-analysis.json, integrity JSONs and
20260916-gro-end[-restore]-ramboot.log under target/mars-reference.


### GRO detail v2: distinguish receive-none causes (pending RAM run)

Extended the same default-off gro-end-profile with five receive-none subreasons:
ingress_budget, empty_endpoint, authority, rejected, unsupported. The adapter
sets the last failure at its actual return site; only a failed successor read
inside an eligible GRO attempt increments the subreason. First-frame failures
and unrelated empty device polls do not inflate this histogram. The original
nine reasons and 17 group sizes remain at their original offsets; five new
counters follow them. ngrodetail prints GRO_DETAIL version=2 and GRO_NONE.
The sum of GRO_NONE must equal the receive_none main count in quiescent deltas.
No receive or budget policy change, no extra timer reads or hot-path atomics.

A new integration fixture places 33 frames in a real pooled endpoint and closes
the first group with PSH. The first 32-frame poll stops within a group while a
packet remains queued, recording only ingress_budget. The next poll drains that
packet and records empty_endpoint. It verifies all loans release and count
conservation. Feature-enabled suite: 5 unit + 40 integration tests pass; default
diagnostic-off regression also passes. RISC-V build/image checks pass.

FIT target/mars-boot-20260916-gro-none/out/artifacts/vibeos.itb:
b0d41e1f4059d6f0b12c7a12a143a8d271ce07b982f5c28e3db30027af4cc826.
Exact ELF, tests, build, feature map and helpers are in target/mars-reference
with gro-none prefixes. Packaging restored the ordinary ethernet profile.
This v2 image has NOT been loaded. Before RAM loading, reboot on baseline
returned zero serial bytes for 15 seconds; two network probes failed. An earlier
40-second serial capture contains only 299 bytes of partial background output,
not a successful command response. Do not infer from those bytes that the
board stayed responsive. No panic/root cause established. No SD/SPI writes.

After recovery use ramboot-gro-none.py at a confirmed U-Boot prompt, take
ngrodetail snapshots around bounded RX traffic and verify both conservation
relations. Then restore via ramboot-gro-none-restore.py and test integrity.


### GRO detail v2 hardware result: endpoint-empty dominates full-rate None

After recovery, RAM-loaded b0d41e1f...; hashes, v2 command and 1000-full link
verified. One 20-second full RX and one paced 300M run, each bracketed by
ngrodetail snapshots. Both deltas satisfy reason-total == size-total and
receive_none == sum(GRO_NONE). Counters include idle/control traffic, published
approximately once per second. Results are diagnostic, not an optimization.

| Phase | Mbps | Non-WFI cores | Mean eligible group | Ingress-budget None | Empty-endpoint None |
| --- | ---: | ---: | ---: | ---: | ---: |
| Full | 949.007 | 1.98870 | 5.735 | 105 | 185086 |
| 300M | 299.983 | 0.84588 | 10.011 | 4774 | 10437 |

Authority/rejected/unsupported None counts were zero in both phases. At full
rate, 99.943% of receive_none endings are endpoint-empty; only 0.057% are the
per-poll ingress budget. Across ALL attempted groups, None is 65.346%, IP ID
34.312%, 16-frame group budget 0.332%, PSH 0.00494%. This does not support raising
the protocol poll budget to eliminate full-rate early GRO termination. It
locates the immediate end condition at the driver-to-protocol endpoint, not a
proved root cause: producer publication timing, application/driver sharing a
hart, scheduling and wire arrival remain possible contributors. Nor do counts
establish that removing boundaries would save enough CPU to meet the goal.
V1/V2 group means differ; do not treat instrumented runs as identical timing.

Diagnostic pattern verification passed (64 MiB, 1156 ms board time). Restored
setup-fix baseline 523347fa... via RAM with hashes/link verified. No SD/SPI writes.
Evidence: target/mars-reference/20260916-gro-none-{full,300} directories and
before/after logs, analyze-gro-none.py, 20260916-gro-none-analysis.json,
20260916-gro-none[-restore]-ramboot.log and integrity JSONs. Next investigate
producer/consumer work cadence before choosing a batching delay; do not replace
these measurements with more blind ring or budget tuning.


### Current RX cadence diagnostic prepared; serial confirmation hardened

Reviewed existing notification/placement evidence: channels already wake only
empty-to-nonempty, inline waiter storage had no measured benefit, stack/application
co-location reduced throughput, and older driver-stage figures predate the
current batch HAL. Prepared a combined diagnostic from existing gro-end-profile,
rx-batch-profile, driver-stage-profile (includes TX-wait) and executor-profile.
This adds no new production policy or presumed optimization. It can compare
hardware batch histograms, software GRO groups, sampled driver phases and task
poll times in the same run; profiling overhead and nested scopes must not be
summed as independent CPU shares.

RISC-V build/image checks passed. FIT target/mars-boot-20260916-rx-cadence/out/artifacts/vibeos.itb
SHA256 0c24b5174c2bf1c73149ffdd03c6fd187ac688407b54e3bc2d7f28ba4e7badc0.
Exact ELF, feature map, build/FIT logs and RAM helpers are archived with
rx-cadence prefixes in target/mars-reference. Ordinary ethernet profile restored.
No SD/SPI writes; this diagnostic has NOT been loaded.

Found a host-tool weakness: legacy serial-run.py may return on a buffered vibe
prompt without establishing that the new command completed (including reboot).
Added scripts/mars-serial-command.py: preserves but excludes drained pre-command
bytes from reply matching; requires an explicit command-specific regex; supports
bounded U-Boot interruption; restores the original termios state on every exit.
Three PTY tests pass: stale expected marker + unrelated prompt do not succeed,
reboot waits for chunked U-Boot response and sends the autoboot interrupt, and
timeout retains asynchronous fault output. New rx-cadence RAM helpers use this
path and semantic network/load/boot markers, with existing hash checks retained.
This fixes confirmation logic, not a demonstrated cause of board network loss.

Using the strict tool, reboot still timed out after 15 seconds with zero bytes;
one ICMP probe also failed. Earlier partial background bytes did not confirm
interactive health. Actual current image cannot be re-queried. User recovery is
needed before loading the already-built diagnostic. Latest evidence:
20260916-rx-cadence-reboot.log, -build-echo.log and 20260916-serial-command-tests.log.


### User-reported possible test-induced hang: controlled responsiveness run

Prioritized stability investigation after the user reported that tests may hang
the board. Recovery produced a fresh echo and the demo command set, so rebooted
to U-Boot and selected the same known setup-fix baseline (523347fa...), not a new
profiling build. First U-Boot ARP attempt failed while serial remained responsive;
a retry reached 192.168.77.1. This is a separate boot-network symptom, not evidence
of a kernel hang. The strict helper initially stopped on that negative response;
RAM helpers now recognize positive OR negative ping completion and preserve the
existing one-retry policy, still requiring positive success before TFTP.

After verified baseline RAM load, a single process continuously collected UART
and bracketed each phase with complete NIDLE_END responses:
- 60 seconds idle before traffic: response normal.
- 20 seconds RX: 949.171 Mbps, response normal.
- 60 seconds post-RX idle: response normal.
- 20 seconds TX: 946.269 Mbps, response normal.
- 60 seconds post-TX idle: response normal.
All phases completed within 220.39 seconds. This is a short reproducibility
probe, not throughput/CPU optimization or one-hour stability qualification.

Then closed the serial descriptor for 60 seconds. Network probes at 30 and 60
seconds both succeeded. Reopening via the strict tool and requesting nidle
returned all four hart rows and NIDLE_END. Thus neither this traffic sequence nor
this single close/reopen interval reproduced the reported hang. Earlier repeated
UART/network silence remains unexplained; this run does not disprove the user's
observation or establish long-term reliability. No crash cause is claimed.

Board remains on responsive baseline, no SD/SPI writes. Combined rx-cadence
profiling image is still staged and untested. Evidence:
target/mars-reference/20260916-hang-triage/{summary.json,serial-full.log,rx.json,tx.json,closed-serial.json,reopened-nidle.log},
20260916-hang-baseline2-ramboot.log; raw boot/load/network responses in
 target/mars-acceptance/20260913-gigabit/20260916-hang-baseline2-*.
The exact orchestration is target/mars-reference/hang-triage.py.

### Later loss of responsiveness and host sleep hypothesis

The responsive-board statement above describes only the end of the short run.
The next extended run failed on its initial `quiet` command, before any traffic
phase started (phases=[]). Last successful NIDLE_END log was at 23:20:17.669;
the new empty UART log opened at 23:21:31.712, about 74 seconds later. Its
10-second command timeout and subsequent ping failures do not establish whether
the board, USB path, host power state or command triggered the loss.
Evidence: target/mars-reference/20260916-hang-extended/.

The user suggested Mac sleep. The inspected pmset log contained no full-system
sleep/wake transition around 23:19–23:22, and the 23:22 assertion snapshot showed
idle system sleep prevented. This does not exclude USB/power issues. Subsequent
hardware commands use `caffeinate -i -s` scoped to their child process; a short
probe under that assertion still timed out. Preventing future sleep cannot
recover an already unresponsive endpoint. No new reboot loop was attempted.

### Atomic IPv4 ID experiment (default off; hardware comparison pending)

Full-rate GRO end profiling attributed 34.31% of attempted group boundaries to
IP ID discontinuity; 65.35% ended on receive-none, almost entirely empty endpoint.
This motivates removing an unnecessary ID constraint, not increasing poll or
ring budgets. RFC 6864 section 4.1 requires receivers to ignore the ID of atomic
IPv4 datagrams (DF=1, MF=0, offset=0):
https://www.rfc-editor.org/rfc/rfc6864.html#section-4.1

`gro-atomic-id` is propagated through protocol, netstack, kernel and Mars firmware.
It only bypasses the same-or-next ID comparison after the existing strict atomic
IPv4 eligibility test. Flow, sequence, ACK, window, options, flags, length and
checksum checks remain; both first frames and successors reject non-atomic
packets. The synthetic packet retains the first ID and is consumed locally by
TCP, not used as a forwarding/GSO template. This is not a claim that Linux GRO
ignores arbitrary IDs in its forwarding/segmentation paths.

Host tests with the feature enabled and disabled cover payload/checksum
preservation, repeated/wrapping/arbitrary IDs, non-DF/MF/fragment-offset/reserved
flags, and diagnostic reason/histogram conservation. Commands:

```
cargo test --offline --locked -p vibeos-net-protocol --features 'gro-atomic-id,gro-end-profile,pooled-rx,native-tcp-segmentation'
cargo test --offline --locked -p vibeos-net-protocol --features 'gro-end-profile,pooled-rx,native-tcp-segmentation'
```

Each passed 6 unit and 40 integration tests. Logs:
target/mars-reference/20260916-gro-atomic{,-off}-tests.log.
The candidate uses the optimized setup-fix baseline feature set plus only
`gro-atomic-id`, excluding GRO diagnostic counters. Build configuration is
archived in target/mars-reference/gro-atomic-features.json. No default activation,
CPU saving, increased group size, or hardware correctness is claimed until
paired baseline/candidate runs and independent payload validation complete.

Atomic-ID candidate build and ELF/image checks passed. RAM-only FIT:
`target/mars-boot-20260916-gro-atomic/out/artifacts/vibeos.itb`, SHA-256
`2835183e57cff1dc3f425b8e8604f135685cc9d96d5218273a8e69fdac4f1030`.
Exact ELF: target/mars-reference/20260916-gro-atomic.elf.
Ordinary firmware feature selection was restored after packaging.

The user subsequently confirmed immediate UART recovery after board power-cycle.
This strengthens the board-side hang hypothesis and takes priority over the
unconfirmed host-sleep explanation. Echo and old SD/demo network status were
verified, then setup-fix baseline 523347fa... was RAM-loaded with component hashes
verified. A controlled run uses continuous UART and ten-second NIDLE_END checks,
180 seconds idle, 10 seconds RX, 180 seconds post-RX idle. No `quiet` command,
stack restart or new performance feature is introduced in this run. The host
power assertion snapshot confirms caffeinate was active. Periodic UART commands
and demo output may change timing; a passing run cannot disprove intermittent
hangs. Evidence is target/mars-reference/20260916-hang-guarded/ and
20260916-hang-confirm-ramboot.log. Result recorded below when complete.

Controlled run FAILED before any iperf traffic: last complete four-hart NIDLE_END
at elapsed 151.541 s; next scheduled command received no response and timed out
at 171.656 s. Two ICMP requests then received no replies. Raw UART ends after the
last complete prompt; no panic text. Thus sustained benchmark traffic, `quiet`,
and the new atomic-ID feature are not necessary for this reproduction. Network
services and demo tasks were running, so this is not a network-disabled idle
control. Full Mac system sleep was prevented during the run; USB transport or
board hardware failure cannot be distinguished solely from this observation.
Treat as a reproducible board-path liveness failure, not as a proven lock bug.

A separate default-off `lock-stall-probe` instruments failed spinlock acquisition
only. It samples the timer every 4096 failed attempts (and at first contention),
and after two seconds reports once per acquisition through SBI legacy console,
without allocator, scheduler or TTY locks. It never force-unlocks or panics.
Reports carry physical hart, lock address, elapsed timer ticks and recoverable
lock state/owner/task-key snapshots; fast-lock ownership is unknown and printed
as zero with recoverable=0. Independent atomic fields are not a transactional
owner record. Concurrent reports may interleave; SBI firmware itself may still
block. No report does NOT exclude a lock problem, MMIO stall, interrupt storm or
firmware/hardware failure. The diagnostic changes timing and must not be used as
a CPU-performance result. Build uses baseline features plus this probe only.

Lock-stall diagnostic passed two detector unit tests, seven sync integration
tests with the feature on and seven with it off, plus the existing sync unit
test. Target release build and ELF/image checks passed. FIT SHA-256:
`64727a4a0252ac6d5e40dff5d6d536ce25bea1799db2ffa5827397e4f33315ee`,
path `target/mars-boot-20260916-lock-stall/out/artifacts/vibeos.itb`.
Exact ELF and demangled symbols are archived as
`target/mars-reference/20260916-lock-stall.{elf}` and
`target/mars-reference/20260916-lock-stall-symbols.txt` for lock-address lookup.
Ordinary firmware feature selection restored; diagnostic not yet loaded.
Board remains unresponsive after controlled reproduction; user power recovery
requested only after this reviewable diagnostic image was ready. No SD/SPI writes.

### Lock-stall image live idle observation

After user power recovery, the first echo marker timed out but its raw log was
NOT empty: the old SD shell reported `unknown command: xecho` (a stale leading
input byte), then continued logger output. This was not classified as a hang.
A subsequent reboot entered U-Boot normally. RAM load of diagnostic FIT
64727a4a... verified both component hashes and reached ready/1000-full markers.

Ten-minute idle-only run completed in 602.889 seconds with 60 periodic four-hart
NIDLE_END checks and no LOCK_STALL/panic output. No iperf, quiet, protocol restart
or performance candidate was used. Both the failed baseline and this diagnostic
boot used physical hart 1, four online harts and a 4 MHz timebase. This does not
prove a fix or exclude deadlock: added failed-acquisition instrumentation and
image layout can change race timing. Diagnostic stays active for further cause
capture; no performance conclusion follows from it.

Evidence: target/mars-reference/20260916-lock-stall-idle/{summary.json,serial-full.log,host-power-assertions.txt},
20260916-lock-stall-ramboot.log, 20260916-hang-diag-ready.log,
and raw boot/load/network logs under mars-acceptance/20260913-gigabit/20260916-lock-stall-*.
The subsequent passive phase keeps UART capture open but sends no commands for
180 seconds, bracketed by nidle and nrxirq. Before that phase, RX_IRQ counters
were [12,622380,0,622364,3] (interrupts,arms,busy_rechecks,timers,tx_wakes): the
network IRQ top half was not firing continuously during the successful run.

The diagnostic's passive phase passed (180.110 s): IRQ delta was
[4,174528,0,174524,0], with complete NIDLE_END afterwards. Then closed the serial
FD for 180 seconds under caffeinate, sent one ICMP request every ten seconds,
and reopened serial: all 19 ICMP requests and the final NIDLE_END succeeded.
No lock stall was captured. Evidence:
20260916-lock-stall-passive/ and 20260916-lock-stall-closed/ under mars-reference.
These observations do not identify the original hang cause or establish that
closing serial is harmless under all timing conditions. A subsequent four-minute
idle control uses the exact earlier baseline 523347fa..., not a rebuilt image,
to assess whether instrumentation/layout perturbs the reproduction.

### Exact old-image idle control reproduced loss again (September 17)

Reloaded old baseline 523347fa... with verified hashes, no iperf or `quiet`.
Last complete NIDLE_END returned at 150.744 s; the next command timed out and
15 seconds of additional raw capture produced no diagnostic. Final error was
recorded at 185.905 s (includes that extra capture, NOT the failure onset).
Two ICMP requests failed. Raw UART includes logger readings 55–57 and guest
heartbeat 19 after the last successful nidle, then stops. No panic.
Evidence: target/mars-reference/20260917-hang-control/ and
20260917-hang-control-ramboot.log.

Together with the earlier 151.541 s failure this strengthens the reproducible
old-image symptom, but does not establish an exact 152-second timer or a
seventeenth-command bug. Terminal history deduplicates successive identical
commands and has a 64-entry bound, not a 16-entry rollover. Current diagnostic
and older archived baseline also differ in build/source history, not solely the
probe feature; no causal assertion about the lock probe is made. Prepare a fresh
same-source, same-feature-set control differing from the successful diagnostic
only by absence of lock-stall-probe. Keep GRO atomic-ID and profiling experiments
off. Board is currently unresponsive; no new performance experiment is loaded.

Same-source control built and image checks passed; FIT is
`target/mars-boot-20260917-lock-control/out/artifacts/vibeos.itb`, SHA-256
`ce40f34edc4cdc48ce899b27abb017cba8b6292baa3aa89f57db77c557e17180`.
Exact ELF archived as target/mars-reference/20260917-lock-control.elf.
Its payload length equals the old baseline (4210936 bytes), but 1881627 bytes
differ; equal size is not source/binary equivalence. Comparison ranges archived
in 20260917-lock-control-binary-diff.json. This is a control, not a hang fix.
Ordinary firmware feature selection restored. User power recovery requested;
new control not loaded and root cause remains unidentified. No SD/SPI writes.

### Serial adapter recovery changes the interpretation

The user reported that board power cycling did not restore serial, but unplugging
and reconnecting the serial adapter did. Therefore prior UART/ICMP loss proves
loss of observed responsiveness, not by itself a halted CPU or spinlock deadlock.
The shared host/USB path remains a candidate. After that reconnect, an explicit
echo succeeded. The interrupted capture process was checked and was no longer
running; no competing serial reader was found.

Added a current-boot RAM prefix journal and the physical shell command `bootlog`.
It records early UART messages, ordinary formatted console output (formatting
only once), and kernel SBI panic text before attempting the hardware write.
Prompt redraws/input echoes are excluded. Writers reserve bounded spans without
locks or allocation; readers stop at an unpublished span rather than waiting.
The first 32 KiB are retained, with an explicit truncation flag; later output
cannot overwrite boot history. Dumping bypasses recording so repeated reads do
not duplicate the journal. Readout includes entry/current timer ticks and Hz,
allowing elapsed-time comparison across reconnects. It is RAM-only and reset by
actual reboot/power loss; no SD/SPI persistence is claimed. This is diagnostic
observability, not a demonstrated hang fix.

Three host tests cover concurrent fragments, bounded/truncated/NUL prefixes,
repeatable reads, and an interrupted writer with later published fragments.
Log: target/mars-reference/20260917-bootlog-tests.log.

Bootlog target release build and image checks passed. FIT SHA-256:
`f8be52ec4e9b3bf6ee32d1be56c6fb233a355eab17bb4e7e4153e3195a06429d`,
path target/mars-boot-20260917-bootlog/out/artifacts/vibeos.itb.
RAM load verified both hashes and ready/1000Mbps; ordinary build feature
selection restored afterwards. No SD/SPI update was made.

Live `bootlog` reads through two separately opened serial connections passed:
entry_ticks=412768029 in both; now_ticks advanced from 472215335 to 529066271
at 4 MHz. First/second snapshots contained 1963/2160 bytes, neither truncated;
second retained the first prefix. Both included entry, page tables, four harts,
GMAC/PHY setup and 1000Mbps link. No dump markers occurred inside the retained
body, proving readback did not recursively fill the journal in this test.
This verifies close/reopen, not a physical USB unplug experiment. A short
uninterpreted garbage prefix appeared on the first serial capture outside the
clean retained boot body; do not interpret those bytes as a new kernel failure.
Evidence: 20260917-bootlog-read{1,2}.log, -validation.json, -ramboot.log,
-build.log and -package.log under target/mars-reference/.

Usage on this RAM-loaded image: `bootlog`. Compare entry_ticks and elapsed
(now_ticks-entry_ticks)/hz across reconnects. The journal is a bounded prefix,
not a persistent crash recorder; once full it preserves boot history and marks
truncation. Kernel boot begins after SPL/OpenSBI/U-Boot, so their output is only
available in external serial captures. The original liveness failure remains
unexplained; this change improves evidence and is not a hang fix.

Post-implementation liveness check passed for another 180.245 seconds: all 18
10-second windows contained UART output and all 18 independent ICMP probes
succeeded. Final bootlog retained entry_ticks=412768029, confirming the same
recorded boot as the earlier reads. Host en13 reported MTU 1500 and 1000baseT
full-duplex. Evidence: target/mars-reference/20260917-bootlog-liveness/.
The macOS kernel USB/serial/CDC log query for the earlier failure interval
2026-09-17 00:06–00:08 returned no entries under the queried/default log level.
Absence of such entries does not rule out a host/adapter fault. Raw query result:
20260917-loss-host-usb.log. No cause or fix is established by this passing run.
If loss recurs, preserve board power while reconnecting only the serial adapter,
then compare retained bootlog entry/current ticks before considering a board
reset; resetting first destroys the RAM evidence needed for that distinction.

### Host serial line-setting evidence

The bootlog image completed a short RX/idle/TX/idle liveness sequence: RX10s
946.745 Mbps, idle60s, TX10s 943.971 Mbps, idle60s; all NIDLE_END checks returned
and bootlog remained readable. This is neither CPU optimization evidence nor a
long-duration qualification. Evidence: 20260917-bootlog-load/.

An independent host issue is now observed. After the last serial FD closes,
a new open reports 9600 baud with HUPCL, although Mars uses 115200. Even explicitly
setting raw115200/HUPCL=0 and closing WITHOUT restoring saved termios did not
persist those settings on next open. Thus blaming only the helper's restore
logic is insufficient: reopen/driver defaults also matter. A pre-command raw
capture contained 133 bytes of binary-looking prefix; retained bootlog after it
was intact. Keep raw prefixes as evidence rather than silently flushing them.

A bounded 180-second keeper held a cu FD open at115200/HUPCL=0 and did not read or
write. With it active, a second FD reported115200/HUPCL=0. First read retained
previous buffered garbage (38 non-ASCII bytes); the next 21036-byte capture had
zero non-ASCII or NUL bytes. Both reported the same entry_ticks=412768029.
This supports retaining a serial session across commands to avoid baud/default
transitions. It establishes a transport configuration/confounding issue, NOT
that it caused every earlier loss of UART AND network responsiveness; continuous
capture had also failed on the old baseline. No kernel hang fix is claimed.
Evidence: 20260917-serial-{line-settings,held-settings,held-validation}.json and
20260917-serial-held-bootlog{,2}.log in target/mars-reference/.

### One-connection serial diagnostic sessions

`scripts/mars-serial-command.py` now exposes `SerialSession` and `--sequence`
(JSON command/expect steps and passive collect_seconds steps). It configures
115200/no-HUPCL once, retains one FD and raw capture between commands, and
restores saved settings only at session end. Existing single-command callers
remain compatible. Stale buffered bytes are retained in the raw log but cannot
satisfy a new command marker. Capture, response and sequence duration are bounded;
invalid sequences are rejected before opening the port. Use one reader/owner.

Five host tests passed, including same-FD commands/passive diagnostics, stale
markers, timeout capture and upfront sequence validation. On macOS, the kernel
can set PENDIN when restoring canonical mode with buffered input; the test checks
the exact restoration argument and masks only that kernel-maintained readback
flag. Evidence: 20260917-serial-session-tests-final2.log.

Live sequence: bootlog, three 60-second passive captures each followed by nidle,
then bootlog. All commands completed on one connection. Both bootlog responses
were ASCII, retained entry_ticks=412768029, and advanced 182.3184915 seconds;
bytes grew from24406 to28183 with the original prefix intact, no truncation and
no recursive dump markers. Passive captures received1143/1148/1145 bytes and
all three NIDLE_END markers arrived. Two concurrent ICMP probes also succeeded.
Evidence under target/mars-reference/: 20260917-session-liveness-{steps.json,
raw.log,results.jsonl,validation.json,ping.log}. This validates the diagnostic
transport workflow; it does not establish a cause or cure for previous failures.

### Bootlog baseline residency and load-exit check (2026-09-17)

With the f8be52ec bootlog RAM image, one continuously open serial session ran
idle10s, RX20s, idle30s, RX20s, TX20s, idle30s. RX measured949.092/949.003Mbps
with total resident occupancy1.98969/1.99583 cores; TX947.097Mbps with1.91501
cores. Idle totals were0.20813 initially,0.21853 after RX and0.22265 after TX.
No idle subtraction is applied to loaded occupancy. Host en13 remained MTU1500,
1000baseT full-duplex. All NIDLE_END replies and final bootlog completed.

Both bootlog snapshots retained entry_ticks=412768029, with133.60850625 seconds
between snapshots. During this run the bounded journal reached32768 bytes and
correctly reported truncated=true; this preserves the boot prefix and does not
indicate a fault. These short tests establish that the logging baseline still
reaches gigabit throughput and remains near two active cores; they neither meet
the one-core effort target nor explain previous intermittent loss of liveness.
Evidence: target/mars-reference/20260917-bootlog-residency/, with the exact helper
in target/mars-reference/20260917-bootlog-residency.py.

### Atomic-ID experiment with boot logging: paired hardware result

Rebuilt the same optimized bootlog baseline plus only gro-atomic-id. Build and
ELF/image checks passed; ordinary ethernet feature selection was restored after
packaging. Candidate FIT74b48b31172e07b30067d9d770d4bd5d0bc92f2b05adb14a5d703731a8c21d81
is target/mars-boot-20260917-bootlog-atomic/out/artifacts/vibeos.itb. The exact ELF
and feature map are archived under target/mars-reference/20260917-bootlog-atomic.elf
and bootlog-atomic-features.json. RAM boot verified component hashes and1Gbps.

The same idle/RX/idle/RX/TX/idle sequence measured candidate RX948.999/949.098Mbps
at1.99004/1.98674 resident cores, versus baseline949.092/949.003Mbps at
1.98969/1.99583 cores. Candidate TX946.189Mbps used1.89165 cores, versus
947.097Mbps at1.91501 for baseline; this isolated TX difference is not an RX
optimization result. All liveness queries completed. Independent64MiB TCP
application byte verification passed (67108864 bytes confirmed, not a throughput
benchmark). These short tests show no material full-rate RX residency improvement;
they do not measure actual candidate GRO group sizes or prove that an individual
pipeline stage consumes fewer cycles. Keep the feature default-off.

Evidence: 20260917-bootlog-atomic-{build.log,package.log,residency/,integrity.json,
comparison.json,ramboot/} in target/mars-reference/. After testing, the exact
f8be52ec bootlog baseline was RAM-restored; both image hashes, readiness,1Gbps
and bootlog readback passed (20260917-bootlog-atomic-restore/). No SD/SPI writes.

Restored baseline RX repeats measured 948.695Mbps at1.98576 cores, 948.855Mbps at1.99056 cores. These overlap candidate occupancy and confirm no observed benefit in this
comparison. Evidence: 20260917-bootlog-atomic-restored-residency/.

### RX cadence attribution with bootlog (2026-09-17)

Built and RAM-booted the optimized baseline plus rx-batch-profile,
driver-stage-profile (includes tx-wait-profile), executor-profile and GRO end
profiling. No atomic-ID or publish-batch experiment. Build/image checks passed;
FIT35daf15411c27270cd29a6e9f70c0b70bd32e9495dbc60dc2c9105c713971896.
Exact image: target/mars-boot-20260917-bootlog-cadence/out/artifacts/vibeos.itb;
ELF and feature map: target/mars-reference/20260917-bootlog-cadence.elf and
bootlog-cadence-features.json. Ordinary build features restored after packaging.

One serial session collected counters before/after20s full RX and20s300Mbps RX.
Full RX948.358Mbps occupied1.99391 resident cores;300Mbps299.968Mbps occupied
0.95005. These are instrumented results, not a performance improvement; do not
compare300Mbps occupancy directly with earlier differently instrumented images.

Full-rate successful receive batches averaged2.365 frames (300Mbps:2.268).
The RX_BATCH_HIST excludes descriptor-not-ready and pool-full early returns;
its zero bucket MUST NOT be interpreted as the fraction of all empty polls.
Within5003 sampled driver turns, RX acquired27350 frames, published27340,
encountered10 queue-full events and4993 empty receive calls. Sampling is every64
turns, potentially biased by workload periodicity. RX hardware callback time
was397174 of562315 RX-phase timer ticks (70.63%); at300Mbps134633/194819 (69.11%).
These are nested elapsed scopes including waits/preemption, not exclusive CPU
cycles, and must not be scaled into total CPU usage or added to task timings.

GRO averaged5.768 eligible frames per group at full rate, with182206 receive-none
boundaries:182010 empty endpoint and196 ingress budget. IP-ID boundaries96954.
At300Mbps the mean was8.060 and receive-none31441:28193 endpoint,3248 budget.
This repeats software queue exhaustion without showing pervasive sampled queue
backpressure. It does not prove the physical DMA engine is starved.

Full-rate task elapsed scopes: net-stack18.984s/112766 polls, virtio-net11.431s/
320128 polls, iperf3-server4.800s/178961 polls. These include interrupts/waits;
task/counter snapshots are sequential, with slightly different time windows.
No exclusive per-core attribution follows. The next narrower measurement target
is receive_batch's descriptor/DMA and metadata handling: the successful batches
are small and its sampled scope dominates driver RX, while removing only the
GRO ID boundary did not improve residency in the preceding paired experiment.

Source inspection found receive_detached_batch still writes the RX tail for
every rearmed descriptor; this is a candidate fixed cost to examine against
controller ordering requirements, not evidence that batching it is safe or
beneficial. No new DMA ordering change was made in this diagnostic run.

Evidence: target/mars-reference/20260917-bootlog-cadence-measure/ (raw snapshots,
iperf, residency, attribution.json), helper20260917-bootlog-cadence-measure.py,
analyzer20260917-cadence-analyze.py, build/package logs and ramboot directory.
Both workload phases and final bootlog read completed; no loss of liveness was
observed in this short run. The prior intermittent issue remains unexplained.

After collection, exact f8be52ec bootlog baseline RAM restore passed component
hash validation, readiness,1000Mbps link and bootlog readback. Evidence:
target/mars-reference/20260917-bootlog-cadence-restore/. No SD/SPI writes.

### RX tail notification batching experiment (2026-09-17)

Linux v6.12 stmmac_rx_refill publishes OWN in its replenishment loop and writes
the RX tail once after the loop (including partial allocation):
https://github.com/torvalds/linux/blob/v6.12/drivers/net/ethernet/stmicro/stmmac/stmmac_main.c#L4459-L4516
This supports testing notification amortization separately from descriptor
visibility. Linux's dirty_rx address convention is not copied into VibeOS:
the experiment retains exactly the last tail address emitted by the existing
scalar path, including wraparound. Controller/model evidence and live testing
are still required; Linux source alone is not proof of this driver's correctness.

Added default-off eqos-net feature rx-tail-batch, selected by Mars feature
rx-tail-batch-experiment. In receive_detached_batch, all successful replacements
retain existing per-descriptor payload maintenance, fields, OWN publication,
descriptor visibility and barriers. Only intermediate RX tail notifications are
suppressed; one write advertises the last replenished descriptor before ticket
publication. Empty/fully pool-blocked batches emit no notification. Malformed
first-frame handling continues using the existing scalar path; publication
failure still faults/quarantines as before. No other RX/TX path is changed.

Host driver tests passed both with and without the feature (108 tests each).
New event assertions cover partial and ring-wrapping batches, final tail address,
OWN/cache/barrier ordering before final notification, no notification when empty,
and no advertising the unprepared second slot under pool pressure. Existing
fault/reset/borrow-preservation tests also passed. The model cannot validate
hardware cache or DMA behavior. Logs: target/mars-reference/20260917-rx-tail-batch-
tests-final.log and20260917-rx-tail-batch-off-tests.log.

Candidate build and ELF/image checks passed. RAM FIT SHA-256:
b069176f533db670bd6187407b9b105b7f9458fc1f6b665896fb93bc5ad7d4ad,
target/mars-boot-20260917-bootlog-tail/out/artifacts/vibeos.itb.
Exact ELF: target/mars-reference/20260917-bootlog-tail.elf; feature map:
bootlog-tail-features.json. Live RAM boot verified kernel/DTB hashes, readiness,
1000Mbps link and bootlog readback. Build configuration was restored after
packaging. Full-rate20s RX repeats measured948.577/948.229Mbps, approximately
1.99338/1.98446 resident cores. TX945.802Mbps occupied1.91679 cores. Idle gaps
and final bootlog queries completed without observed liveness loss. Full-rate
occupancy alone does not establish small cost changes under a saturated load;
matched910Mbps tests follow. Evidence: 20260917-bootlog-tail-residency/.

Matched910Mbps RX comparison:
- 910: 909.916Mbps, 1.94546 resident cores.
- 910: 909.961Mbps, 1.92402 resident cores.
- restored-910: 909.961Mbps, 1.94621 resident cores.
- restored-910: 909.961Mbps, 1.94253 resident cores.

Candidate and restored baseline remain near1.94 cores; the small varying
difference does not establish a repeatable CPU benefit. Independent64MiB byte
verification passed. Keep rx-tail-batch default-off; no one-core result or
long-duration DMA qualification is claimed. The exact f8be52ec bootlog baseline
is restored in RAM, with component hashes/readiness/link/bootlog verified.
Evidence: 20260917-bootlog-tail-{910/,restored-910/,comparison.json,integrity.json,
restore/}. No SD/SPI writes.

### Receive callback stage sampling (2026-09-17)

Added default-off Mars rx-callback-profile, sampling one in127 batch callbacks.
Five consecutive elapsed scopes: readiness probe; engine detached-batch operation;
frame validation; accepted-ticket metadata registration; final counter snapshot.
A Drop recorder captures sampled empty/full/error returns too, with outcome and
accepted-frame counts. No printing occurs in the hot path. nrpool emits cumulative
RX_CALLBACK counters before taking the metadata lock. Timers/counter overhead,
interrupts and waits are included; these are not exclusive CPU cycles. Relaxed
snapshots can be transiently inconsistent if read during traffic; use deltas and
validate completed snapshots. Existing rx-metadata-profile was enabled alongside
it to observe descriptor metadata guards and stack-side borrow/release costs.

Optimized baseline plus only these two diagnostic features built and passed
image checks. FIT ab3f68304121b9ddf6febd5d65b17db5c1a52828790b902168a1c9a26958fe85,
target/mars-boot-20260917-bootlog-callback/out/artifacts/vibeos.itb. Exact ELF and
features: target/mars-reference/20260917-bootlog-callback.elf and
bootlog-callback-features.json. No rx-tail-batch experiment. Normal feature
selection restored after packaging. RAM boot checked both component hashes,
readiness,1Gbps link and bootlog readback.

Full20s RX948.332Mbps,1.98790 resident cores;910Mbps run909.961Mbps,1.88808
cores. These are instrumented measurements, not an optimization comparison.
Full callback deltas:926021 calls,7292 samples,6135 successful,1157 empty,
zero sampled full/errors,13378 sampled accepted frames. At910Mbps:891794 calls,
7022 samples,5854 successful,1168 empty,zero sampled full/errors. Both checked
sample outcome conservation and one-in127 sampling count within rounding.
Zero sampled failures does not prove zero unsampled failures.

Elapsed phase shares were remarkably similar across these two runs:

| scope | full |910Mbps |
|---|---:|---:|
| readiness probe |6.81% |6.87% |
| detached-batch operation |69.70% |69.67% |
| frame validation |9.03% |9.05% |
| ticket metadata registration |9.19% |9.15% |
| finish/snapshot |5.27% |5.27% |

Descriptor-operation metadata guards (kind0) averaged0.551us acquisition and
0.739us held at full load; kind1 registration0.557us/0.853us. Stack-side loan
acquire0.594us/0.671us, release0.573us/0.496us. At910Mbps these means remained
similar. Acquisition time includes the uncontended lock path and measurement
cost, not only contention. Kind0 calls2207271 were exactly3x registration calls
735757 during the full interval. Nested sampled lock times must not be added to
callback scope time or subtracted as exact exclusive attribution.

This narrows the next measurement target to ring receive_detached_batch's
metadata lookup/preparation/publication, descriptor snapshots, DMA synchronization
and rearming. It does not establish that cache operations, MMIO or locks dominate
that inner scope. Prior tail batching failed to show a repeatable residency gain.
Evidence: target/mars-reference/20260917-bootlog-callback-measure/ including
attribution.json, raw logs, iperf and residency. Helper20260917-callback-measure.py
and analyzer20260917-callback-analyze.py. Both phases and final bootlog completed;
no loss of liveness was observed in this short run.

Exact f8be52ec bootlog baseline RAM restoration completed with hashes, readiness,
1Gbps and bootlog verified. Restore evidence:20260917-bootlog-callback-restore/.
No SD/SPI writes; rx-callback-profile remains default-off.

### Inner RX ring phase sampler (2026-09-17)

Added default-off eqos-net rx-stage-profile, exposed by Mars rx-ring-profile.
Ring receive_detached_batch samples one in131 invocations using the existing
platform monotonic timer through its controller/backend. Seven consecutive
elapsed scopes: metadata lookup; descriptor snapshot/validation; received-payload
DMA synchronization; replacement preparation; descriptor rearm plus tail; ticket
publication; finish. All normal Result returns, including early empty/error exits,
finalize their current phase. A malformed first descriptor retains its existing
scalar fallback, whose elapsed cost stays in the descriptor phase. Panics or
nonlocal fault unwinds are not guaranteed to finalize this diagnostic record.

No descriptor/cache/OWN/tail ordering changes. Diagnostic clock reads are compiled
out without the feature; models default to a zero clock. nrpool emits cumulative
RX_RING_STAGE counters outside the metadata lock. Interpret deltas outside traffic
and check sample/outcome conservation; relaxed snapshots are not transactional.
Times include sampling overhead, waits and interrupts, not exclusive CPU cycles.

Driver suite passed with profiling (109 tests) and without (108 tests). A new
unit test checks seven stage allocations, timer wrap, success/empty/error outcome
accounting and each early-exit stage. Existing integration tests exercise ring
error, quarantine, wrap and DMA ordering with profiling enabled. Logs:
20260917-rx-ring-profile-tests-final.log and-rx-ring-profile-off-tests.log under
target/mars-reference/. Models establish software behavior only, not hardware DMA.

Inner sampler target build/image checks passed. FIT SHA-256
be43b121f6fd3ab7208d0ba664bdd16424b9d76968e06e88e41b17b141aa5233,
target/mars-boot-20260917-bootlog-ring/out/artifacts/vibeos.itb. Exact ELF and
feature map:target/mars-reference/20260917-bootlog-ring.elf and
bootlog-ring-features.json. Only rx-ring-profile was added to the optimized
baseline (no outer/metadata samplers or tail experiment), and ordinary build
features were restored after packaging. RAM boot hashes/link/readiness passed.

Full RX948.237Mbps occupied1.99254 resident cores;910Mbps909.961Mbps occupied
1.89405. These instrumented occupancy values are not optimization comparisons.
Full ring deltas:700455 calls,5347 samples,12758 sampled frames, all sampled
returns nonempty successes. At910Mbps:672241 calls,5131 samples,12241 frames,
all sampled returns nonempty successes. Outcome conservation and one-in131
sample count within rounding passed. Empty readiness probes occur above this
function, so this does not establish an absence of empty driver polling.

| phase | full share |910Mbps share | full mean us/sample |
|---|---:|---:|---:|
| metadata lookup |12.84% |12.82% |1.021 |
| descriptor reads/validation |13.04% |13.04% |1.037 |
| payload DMA sync |9.26% |9.27% |0.736 |
| replacement preparation |17.03% |16.99% |1.354 |
| rearm and tail |24.65% |24.69% |1.960 |
| metadata ticket publication |11.55% |11.64% |0.918 |
| finish |11.63% |11.55% |0.925 |

Means include timer/control overhead and return-value construction/movement,
not solely the named operation. In particular finish includes forming the Result
and diagnostic closure boundary; it must not be called a measured hardware cost.
Systematic sampling can be biased, and these numbers must not be extrapolated
into exact exclusive core occupancy. Both rates sampled about2.386 frames/batch.

The three metadata scopes sum to41.42% at full rate; rearm is the largest single
scope but not a majority. Combined with the negative tail experiment, this does
not support continuing to treat tail MMIO or payload sync as the dominant source
of the entire near-two-core pipeline cost. Next work should target protocol-stack
and task-handoff common paths as well as any amortization of descriptor metadata,
with paired tests rather than assuming another small cache change will save a
core. No CPU reduction or full physical stability qualification is claimed.

Evidence:target/mars-reference/20260917-bootlog-ring-measure/ (raw counters,
iperf/residency,attribution.json), helpers20260917-ring-measure.py and
20260917-ring-analyze.py, build/package/ramboot artifacts. Final bootlog was
readable; no liveness loss was observed during the short measurement sequence.

All-features driver suite (tail experiment plus sampler) also passed109 tests,
20260917-rx-ring-profile-all-tests.log. Exact f8be52ec baseline RAM restoration
passed hashes, readiness,1Gbps and bootlog readback; evidence
20260917-bootlog-ring-restore/. No SD/SPI writes. Diagnostics remain default-off.

### Refreshed common-path timeline (2026-09-17)

Built the optimized bootlog baseline plus existing network-profile only, without
new ring/callback samplers or tail/atomic-ID experiments. Image checks passed;
FIT0492dfcc69db6271cc739d883cd82e3bad2298f7cc705fb5ef1e7762e6479f91,
target/mars-boot-20260917-bootlog-stack-profile/out/artifacts/vibeos.itb.
Exact ELF and feature map:target/mars-reference/20260917-bootlog-stack-profile.elf
and bootlog-stack-profile-features.json. Ordinary features restored after
packaging. RAM boot verified hashes/readiness/1Gbps and bootlog readback.

One serial session ran20s RX, armed the existing5s profiler at host elapsed
5.013s, then dumped after traffic and expiry. Aggregate throughput948.028Mbps;
fully interior one-second intervals6..9s were949.22,949.09,948.86Mbps (the9..10s
interval949.55Mbps is also near the end boundary). No gross throughput collapse
was observed. This is not proof that diagnostic overhead/cache effects are zero.
The parser reconciled bucket/hart/lock totals and the127-call child-stage schema.

Five-second window parent-exclusive elapsed scopes plus separately classified
contended waits (sum across harts, not independent core measurements):
- Frontend:1.80317s work +0.29987s contended wait.
- Packet receive entry:1.78170s +0.07658s.
- Driver remainder:1.51041s +0.02081s.
- RX callback:1.33968s +0.04786s.
- Protocol-poll remainder:1.24067s +0.00072s.
- Executor remainder:0.84026s +0.00937s.
- Application remainder:0.47832s +0.00011s.

Frontend is cross-core: hart0/application-side0.75292s, hart1/network-side
1.35013s. Packet receive entry and protocol remainder are on hart1. Unselected
child work remains in parents: sampled rx_loan/rx_gro/tx_reserve/tx_flush and
frontend sub-stages MUST NOT be multiplied and added into these totals. These
scopes include instrumentation and interrupts, not hardware instruction cycles.
Selected rx_loan3476 calls averaged1.654us including classified waits;
rx_gro3613 calls averaged2.530us. Frontend RX selected1308 calls consumed0.008707s
including waits, exceeding other sampled frontend children; it includes socket
operations/authority checks and queue copying, not solely payload memcpy.

Stack decisions:13814 runnable hints,15 empty retries,10 wait attempts;13811
turns processed ingress and13809 made frontend progress. This does not support
idle spinning as the dominant hart1 cost in this window. Inbound high water64
with368 full retry attempts in3 of50 buckets; outbound high water1,zero full.
Queue fullness is not a count of packet drops. Application had8511 empty retries,
but their count alone cannot establish dominant CPU consumption.

This reconfirms frontend receive transfer and packet receive construction as
common-path targets. Existing negative results for empty-service skipping,
one-copy removal, ordinary TX pooling and consumer queue batching remain relevant;
do not re-propose those unchanged as new fixes. Any bulk loan or handoff change
must preserve generation/revocation checks, borrower fault cleanup and bounded
backpressure; it must reduce actual acquire/release or data movement work, not
merely batch queue dequeue while retaining all per-frame work.

Evidence:target/mars-reference/20260917-bootlog-stack-profile-measure/ contains
raw profile, parsed analysis, iperf intervals, residency and before/after bootlog.
Helper:20260917-stack-profile-measure.py. No liveness loss during this short run.

Exact f8be52ec bootlog baseline RAM restoration passed hashes, readiness,1Gbps
and bootlog; evidence20260917-bootlog-stack-profile-restore/. No SD/SPI writes.

### GRO follower bulk release experiment (2026-09-17)

Previous consumer batching still acquired/released metadata per frame. Added a
separate default-off gro-batch-release path that actually shares one metadata
guard across cleanup of merged GRO followers. Acquisition/dequeue policy is
unchanged: every dequeued frame immediately becomes an exact-owner tracked
loan. Raw ready tickets are never prefetched into a new untracked batch.

HAL rx-batch-release adds optional unsafe bulk cleanup to Loan and a bounded
ReleaseBatch holder. Only consumed followers are retained, for the synchronous
GRO group (at most15 followers with16-segment limit). The first frame and failed
merge/lookahead retain their existing lifetime. No await or public slice escapes
the cleanup holder. Matching bulk callbacks consume each unique Borrow once;
mixed/scalar providers fall back to existing per-loan Drop. Overflow returns the
loan for normal cleanup. Hard-fault recovery still sees all outstanding borrowed
slots under the original owner/incarnation; ordinary capability revocation is
not treated as proof of owner death. The batch callback must not panic and must
leave no unconsumed Borrow. Its metadata-only implementation takes no ENGINE
borrow. Without the HAL feature, Loan's representation remains unchanged.

Mars bulk cleanup holds RX_META once and releases validated Borrow records;
release counters count successful releases. Additional under-lock integer
counters report bulk calls/frames through nrpool after dropping RX_META, so no
console/metadata lock inversion is introduced. Scalar acquisition/cleanup remain
available. This defers some buffer availability by one GRO group, which requires
hardware pool/backpressure validation; it is not automatically a performance win.

HAL tests3 passed, including matching/mixed/scalar callback cleanup, bounded
capacity, empty group and ordinary unwind. Protocol enabled tests5 unit+40
integration passed, including real TCP data, merged-only bulk release (two
followers under one callback), original/lookahead pinning and revocation cleanup.
Disabled protocol tests and5 core receive tests passed, preserving existing
queue retirement and exact-incarnation recovery. Logs under target/mars-reference/
20260917-batch-release-{hal-tests,protocol-tests,protocol-off-tests,core-tests}.log.

Candidate build/image checks passed. FIT SHA-256
09c7e300303cf952ae2f73473526984dc92acab4f137bc0d53240c7007c9fed7,
target/mars-boot-20260917-bootlog-release/out/artifacts/vibeos.itb; exact ELF
20260917-bootlog-release.elf and feature map bootlog-release-features.json.
Normal ethernet configuration restored after packaging. RAM boot verified both
component hashes, readiness,1Gbps and bootlog. No SD/SPI writes.

Live bulk cleanup operated as intended: full20s RX delivered948.661Mbps at
1.98928 resident cores. Bulk counters advanced217541 calls/1390041 frames
(6.390 followers/call), eliminating1172500 individual cleanup-guard acquisitions
relative to releasing those same followers separately. Received/acquired/released
all1624665 afterward; free128,ready0,borrowed0,full0,dropped0.

Two910Mbps runs measured909.961/909.915Mbps at1.94010/1.94454 cores. Their bulk
calls/frames were191415/1350887 and190294/1351314, respectively. These directly
verify the intended reduction in cleanup operations, not CPU saving. Other loan,
queue, protocol and scheduling work remains; deferring cleanup also changes batch
and cache timing. Independent64MiB application byte verification passed, with
67108864 bytes confirmed (not used as a throughput benchmark).

Evidence:target/mars-reference/20260917-bootlog-release-measure/ (raw pool counts,
release-deltas.json, throughput and residency),20260917-bootlog-release-integrity.json.
The exact original f8be52ec bootlog baseline was RAM-restored with component hash,
readiness,1Gbps and bootlog validation (20260917-bootlog-release-restore/).
No SD/SPI writes. Matched restored-baseline910Mbps measurements follow.

Restored baseline matched RX: 909.961Mbps/1.92465 cores, 909.916Mbps/1.93435 cores.
Candidate1.94010/1.94454 cores did not improve these controls. Keep the feature
default-off; fewer cleanup guards is demonstrated, a CPU benefit is not.
Restored evidence:20260917-bootlog-release-restored-910/. No one-core or
long-duration stability claim.

### Drain-to-interrupt experiment (2026-09-17)

Existing driver_turn returns historical immediate_work OR TX ownership sampled
before RX service. Therefore even a turn ending with RX empty can yield back to
an immediately runnable driver, and a completed ACK can retain a stale busy hint.
Added default-off rx-progress-park for interrupt-capable devices only. It reports
remaining private TX/RX/coalescer/prefetched work, retaining immediate service for
these items. If the earlier TX sample was busy and no private work remains, it
rechecks/reclaims TX ownership under CONTROL and updates cached tx_inflight and
deadline consistently. It otherwise attempts the existing interrupt wait path.

No delay constant, DMA interrupt mask policy, ring size or poll budget changed.
The existing wait captures/registers TX and RX events before rechecking outbound
and hardware RX ownership/arming, and retains its timer for bounded revalidation.
Hardware work arriving after driver_turn is caught by that recheck. A wait that
returns synchronously MUST still yield before the next turn; otherwise continuous
arrivals could form an unbounded poll without an await suspension. The experiment
adds that explicit yield on the wait branch. TX DMA still busy never parks.
Fallback devices without RX interrupt operations retain the original policy.

Added StampedBatch::has_pending for both sparse-ticket and publish-batch layouts.
Tests cover empty, sparse, last-pop and exhaustion; core receive tests passed6
without and8 with rx-publish-batch, including existing ownership/revocation tests.
These host tests do not prove real interrupt transition behavior or performance.
The experiment's network-profile worked hint now reflects pending work rather
than historical progress; do not compare that field's meaning across builds.

Candidate build/image checks passed. FIT SHA-256
14e8ec370b7078b224229a28aee0d1538a078bbb0e336a8b88ae5d72cda01f69,
target/mars-boot-20260917-bootlog-park/out/artifacts/vibeos.itb. Exact ELF and
features:20260917-bootlog-park.elf and bootlog-park-features.json. RAM hashes,
readiness/link and bootlog passed; ordinary build features restored after package.

Live results: RX948.619Mbps/1.98838 resident cores; TX945.286Mbps/1.89248 cores;
910Mbps RX909.961/909.916Mbps at1.94275/1.93100 cores. Full RX IRQ deltas:
157 interrupts,116092 arm attempts,115797 busy rechecks (99.746%),175 timer
returns,106641 TX wakes. At910Mbps,96.080%/96.116% of arm attempts found busy.
Counts include the short snapshot edges, and TX wake branches and arm branches
are different paths; do not add their percentages or infer exact sleep duration.
The intended wait path is being attempted but overwhelmingly finds current work,
so changing progress classification alone does not produce a useful idle window.

Full RX pool afterward:received=acquired=released=1624494,full=dropped=0,
free128,ready=borrowed=0. Independent64MiB byte verification passed. Final
bootlog remained readable; no liveness loss in this short run. Exact f8be52ec
baseline RAM restore passed hashes/readiness/1Gbps/bootlog. No SD/SPI writes.
Evidence:20260917-bootlog-park-{measure/,integrity.json,restore/} under
target/mars-reference/. irq-deltas.json records counters; helpers preserve raw
serial and network output. Matched restored-baseline910Mbps repeats follow.

Restored controls: 909.961Mbps/1.91393 resident cores, 909.961Mbps/1.92029 resident cores.
The candidate did not reduce occupancy. Removed this experimental scheduler
branch, feature wiring and helper/test from active source; archived exact patch
in target/mars-reference/20260917-progress-park-experiment.patch. Reapplication
check passed against current source. Existing unrelated changes were preserved.
Board remains on f8be52ec bootlog baseline; matched data are under
20260917-bootlog-park-restored-910/. No low-core or full stability claim.

### 2026-09-17: active-load driver and protocol restart with continuous UART

The bootlog baseline FIT (`f8be52ec4e9b3bf6ee32d1be56c6fb233a355eab17bb4e7e4153e3195a06429d`)
was exercised with one continuously open serial descriptor per recovery test.
After four seconds of host-to-board TCP traffic, the operator path cancelled
and restarted `virtio-net`, then separately `net-stack`. Both advanced generation
1 -> 2. The interrupted clients exited with errors without forced termination;
those interrupted transfers are not counted as successful data tests.
Host interval counters before cancellation show approximately 949 Mbps traffic.

Each restart was followed by a fresh ten-second TCP connection and a separate
64 MiB changing-pattern verification. Both integrity tests passed. The driver
restart's fresh receive result was 947.514 Mbps. The subsequent protocol restart's
result was only 678.876 Mbps: recovery restored functionality but did not preserve
the original performance. The console restart factory creates its fresh arena
on the caller hart, whereas initial network-pipeline setup explicitly constructs
the protocol task on hart 1. Thus these results do not establish placement
preservation, and no CPU-efficiency comparison is made from this changed state.
Preserving the component's intended placement across operator restart remains a
concrete recovery issue; it must preserve allocation-domain ownership rather than
migrate an already constructed reclaimable arena.

Both final RX pool snapshots had free=128, ready=0, borrowed=0, full=0 and
dropped=0. After protocol restart, received exceeded acquired by 72; all acquired
loans were released. Unacquired tickets during cancellation are not evidence of
application delivery, and the pool snapshot alone is not a packet-loss audit.
The same boot entry timestamp and advancing current timestamps were retained
throughout both tests. No memory-domain assertion or serial silence was observed
in these bounded runs; historical hangs and physical USB reconnect behavior
remain unproven.

Evidence: `target/mars-reference/20260917-bootlog-active-{driver,stack}-recovery/`
contains continuous UART, interrupted/fresh client results, integrity results,
bootlog snapshots and reproduction scripts. The parsed summary is
`20260917-bootlog-active-recovery-summary.json`. The exact baseline FIT was then
reloaded to RAM with verified component hashes and gigabit link, recorded under
`20260917-bootlog-recovery-restore/`. No SD, SPI or saved boot environment writes
were made. The >900 Mbps / <1 core objective remains open.

### 2026-09-17: preserve home hart for shell restart

The shell now awaits `World::restart_component_on_home`. Each component records
its initial logical hart. A SYSTEM-owned pinned worker performs the audited
restart factory on that hart, creating the new arena there; no existing arena
is migrated. The requester releases its owner scope before awaiting completion,
and no lifecycle lock crosses an await. The worker rechecks registry membership
and the captured generation under the lifecycle lock, so a delayed request
cannot replace a newer incarnation. Running components remain rejected.

This change applies to the legacy shell `restart` entry. The synchronous
`restart_component` and `vtop` control entry still use their caller's placement;
they are not covered by this fix or these tests. Automatic network-stack
supervision already runs on the designated pipeline hart. Full lifecycle-wide
placement preservation remains separate work.

Built and RAM-loaded FIT SHA-256:
`918fdf3be9a1fe04eb62dba8d68d74a9628cd0d03a187da15f1af82713d600b6`.
Two active-RX cancellations and shell restarts advanced protocol generation
1 -> 2 and 2 -> 3. The fresh ten-second receive tests after those restarts
measured 946.217 and 948.480 Mbps, respectively, versus the prior caller-hart
replay's 678.876 Mbps. Each restart passed an independent 64 MiB pattern check.
Each final pool had 128 free buffers, zero ready/borrowed, zero full/dropped,
and acquired equalled released. Both attempts to restart a still-running stack
were rejected. No memory-domain assertion or UART loss appeared in these runs.

Between the two restarts, two twenty-second unpaced receive tests measured
948.304/948.666 Mbps with total non-WFI residency of 1.98665/1.98953 cores.
These results establish restoration of >900 Mbps after shell restart, not a
reduction in steady-state CPU cost. Residency includes MMIO stalls and interrupt
work; it is not an exclusive cycle profile. The <1 core effort target is unmet.

Artifacts in `target/mars-reference/`:
`20260917-bootlog-home-restart-{build2,package}.log`,
`20260917-bootlog-home-restart-load/`,
`20260917-bootlog-home-stack-recovery{,2}/`, and
`20260917-bootlog-home-restart-rx/summary.json`.
Reproduction scripts are `test-bootlog-home-stack-recovery{,2}.py`.
The repaired image remains running in RAM at protocol generation 3. No SD/SPI
writes or persistent U-Boot environment changes occurred. Physical cold-boot,
long-duration stability, concurrent operator races and other control entries
are not established by these bounded tests.

### 2026-09-17: isolate receive queue dequeue from loan admission

Source review corrects a possible attribution error: `Revocable::try_with`
checks its node's atomic alive flag; it does not acquire a capability lock.
The archived rx-consumer-batch experiment invoked `try_receive` repeatedly,
so it did not combine queue lock operations. Popping a batch of raw tickets
before recording borrower ownership would create an additional fault-recovery
window and is not introduced by this diagnostic.

Default-off `rx-queue-profile` samples one in 127 ReceiveEndpoint calls per
logical hart. It measures the complete `Endpoint::try_recv` operation separately
from the complete admission call, classifying success/empty/rejected outcomes.
The queue duration includes lock acquisition, dequeue, unlock and any sender
notification; it is not pure lock contention. The remainder includes owner and
stamp validation, HAL acquisition, Result movement and sampling boundaries.
Per-hart cumulative snapshots are printed by `nrpool` outside traffic. Normal
images contain no counters/timer reads from this feature.

Diagnostic FIT SHA-256:
`bf01b77a88d898b2f0e2b905c29b6c5b7deef6081709d3ed3f8de4826d7b1866`.
With the home-hart shell-restart correction retained, twenty-second RX runs
measured 947.666 Mbps unpaced and 909.916 Mbps at 910M pacing. Non-WFI residency
was 1.98352 and 1.90203 cores, respectively; these instrumented numbers are not
an efficiency improvement claim.

The full-rate interval counted 1,908,205 admission calls and 15,025 samples:
12,836 successes and 2,189 empty results. Successful samples averaged 0.64769 us
in queue dequeue and 1.41892 us in the remainder (queue 31.3407% of admission).
At 910M, 1,731,256 calls yielded 13,632 samples, including 12,344 successes and
1,288 empty results. Success averages were 0.64483/1.41875 us (queue 31.2481%).
Neither interval sampled a rejection. Empty-result queue durations averaged
0.54842/0.55842 us, with remainder 0.81042/0.80823 us. Sample-count deltas match
the exact one-in-127 cadence; queue duration never exceeds its enclosing total.
The 4 MHz timer and nested measurement overhead limit short-duration precision,
and systematic sampling may alias traffic cadence. These nested durations must
not be added to older profile scopes or extrapolated as exclusive core use.
The observations do not establish queue locking as the dominant CPU bottleneck;
the admission remainder is larger and warrants further decomposition.

The existing five receive-contract tests passed with the feature enabled and
disabled. Physical outputs, raw serial, pool state and parsed attribution are in
`target/mars-reference/20260917-bootlog-queue-measure/`; the analyzer is
`20260917-queue-analyze.py`. Build/package and load evidence uses the
`20260917-bootlog-queue-*` prefix. The no-sampling home-restart FIT is restored
after this measurement; no SD/SPI or persistent environment writes are made.

### 2026-09-17: start extended RX recovery/stability coverage

No new hot-path optimization is promoted from the queue admission review.
Existing metadata samples already cover much of its remaining duration, and
source inspection did not identify an ownership check that can safely be
removed. A longer network-only run is used to investigate accumulated resource
loss or UART disappearance beyond the previous short tests.

The initial `iperf3 -t 3600` request was rejected during parameter exchange:
`components/iperf3-server` explicitly bounds `MAX_TEST_SECONDS` to 60. The host
reported a broken control pipe, with no data connection/traffic intervals, and
UART recorded `iperf3 reset while reading parameters`. This is an unsupported
test duration, not evidence of a board hang. Raw output is preserved under
`target/mars-reference/20260917-network-soak/`; its summary is failed and must
not be counted as a one-hour stress result.

The replacement runner, `target/mars-reference/20260917-network-soak-rounds.py`,
uses 60 consecutive 60-second single-flow RX sessions, one continuously open
UART descriptor, per-round non-WFI residency and pool snapshots, and recorded
connection gaps. Each complete round must exceed 900 Mbps; a client error,
serial timeout or short transfer terminates the run with retained evidence.
A final independent 64 MiB pattern check is required. Host en13 was verified at
MTU 1500, 1000baseT full-duplex. The image provenance remains the no-sampling
home-restart FIT, with the current boot entry matching its verified RAM reload.

The run is in progress when this entry is written. Only a terminal
`20260917-network-soak-rounds/summary.json` with `passed=true` establishes this
bounded run's success. `live.json` is progress only. Even success does not prove
a single TCP connection survived an hour, concurrent storage/WASM, cold boots,
or the <1 core effort target.

The running soak now has an independent read-only verifier:
`python3 scripts/mars-soak-audit.py target/mars-reference/20260917-network-soak-rounds`.
It compares each summary row with raw receiver JSON, four-hart NIDLE snapshots
and pool output, verifies CPU sampling covers the transfer and that counters
remain continuous between rounds, and requires all 60 rounds plus final boot
continuity, complete 64 MiB verification and a fully returned pool before
reporting `passed`. An unfinished run is `collecting`; terminal failure is not
masked by earlier good rounds. The audit does not open UART or affect traffic.
Five host tests cover partial-run status, raw/CPU mismatches, failed termination,
incomplete terminal success, integrity/loan failure and reused CPU snapshots.
Initial live evidence through round 4 was consistent (948.730–949.100 Mbps,
1.99494–1.99594 cores, all buffers returned). This is partial evidence only;
the runner session remains live and must be checked to completion.


### 2026-09-17: compact borrower metadata prepared while soak continues

Read-only disassembly of the exact home-restart ELF shows `acquire_rx_loan`
occupies 0x202 bytes, uses a 160-byte stack frame, and calls memcpy for a
72-byte successful result. Its slot addressing has a 48-byte stride and the
u128-bearing state uses a two-word discriminant. Evidence is saved in
`target/mars-reference/20260917-acquire-rx-loan.asm`. This identifies generated
operations, not their exclusive CPU cost; the memcpy is not removed here.

Added default-off driver feature `rx-compact-owner`, exposed by Mars as
`rx-compact-owner-experiment`. The Borrowed variant stores the existing HAL
Owner (two u64 fields) instead of the packed u128 key. Public ticket/borrow APIs,
full owner/incarnation comparisons, release/reset and recovery rules remain the
same. This reduces the measured 64-bit host Slot layout from 48 to 40 bytes;
for 256 slots the nominal slot-array reduction is 2048 bytes. The existing
RISC-V ELF establishes the old stride; the candidate's actual RISC-V layout and
code generation still need a target build and inspection.

A new recovery test uses identities sharing only the high or low 64-bit half,
verifies zero-incarnation/nonmatching keys do not reclaim them, recovers one
exact identity, rejects its stale release and frees the surviving loans. Both
feature-on and feature-off metadata tests passed. All EQoS host tests with the
feature enabled passed (110 tests). Logs:
`20260917-compact-owner-host-{on,off,all}.log` under `target/mars-reference`.
The soak audit gained a positive complete-evidence test, bringing its host
suite to six passing tests.

Only brief host tests ran while the network soak continued; no target firmware
build, reset or competing traffic was launched. This remains an unmeasured
candidate, not a retained performance optimization. The candidate feature
manifest is `bootlog-compact-owner-features.json`; the ordinary ethernet feature
line has not been changed. Wait for the live soak session to finish before
building/loading a candidate and interleaving its 910 Mbps/full-rate controls.

### 2026-09-17: completed RX soak, CPU target still unmet

The unchanged home-restart FIT (`918fdf3be9a1fe04eb62dba8d68d74a9628cd0d03a187da15f1af82713d600b6`)
completed all 60 sequential 60-second RX connections. The runner exited 0;
`scripts/mars-soak-audit.py` independently reports `passed` for the raw records
in `target/mars-reference/20260917-network-soak-rounds/audit-final.json`.
Mean receiver throughput was 948.756 Mbps (range 944.498–949.202 Mbps), with
mean four-hart non-WFI residency 1.996112 cores. No idle-baseline subtraction
was applied. This establishes the throughput target for this RX test, not the
sub-one-core goal.

Every per-round pool snapshot was quiescent. The final snapshot, after a
separate complete 64 MiB pattern verification, showed received/acquired/released
all 292481912, free 128, ready/borrowed/full/dropped zero. These are software
pool counts, not complete MAC/DMA error counters. The pattern check covers its
own transfer, not all iperf payload. Serial commands remained responsive.
Boot entry ticks remained 42520122, with time advancing from 1257001921 to
15703114522 ticks at 4 MHz; per-hart counters also remained continuous. The
retained boot prefix reached 32 KiB and reported truncation as designed; the
host-side continuous serial capture remains available.

This is accumulated one-hour traffic across separate connections with measured
short gaps, not one uninterrupted TCP connection, simultaneous storage/WASM
qualification, or a cold-boot campaign. It did not reproduce the historic
serial loss and does not establish its root cause. The test process has ended;
subsequent diagnostic builds and RAM loads are separate from these results.

### 2026-09-17: batch publication, admission and GRO release experiment

Default-off `rx-admission-batch` adds a bounded eight-frame admission path:
one receive capability check per refill, one queue transaction, and one Mars
RX metadata lock to acquire the matching loans. GRO consumes the prefetched
FIFO without reacquiring queue/metadata locks for every follower. `nrxbat`
exports once-per-second admission-size totals; GRO ending reasons remain
available via `ngrodetail`. Queued tickets remain in place until ownership is
recorded, closing the untracked-Ready-buffer window of naive batch dequeue.
Fault cleanup may recover the admission lock only after the exact owner domain
is permanently quiescent. The lock order is queue then RX metadata; the backend
callback must not allocate, await, borrow ENGINE, or reenter runtime queues.
Wrong-session entries and failed acquisitions retain per-frame rejection.
Remaining prefetched loans are released on revocation and on device drop.

This version still constructs an individual Loan for every frame and retains
the separate driver/protocol tasks and their cross-hart boundary. It is not a
fused NAPI-like execution context and should not be described as that completed
architecture. The combined candidate also enables the existing batch publication
and GRO batch-release features; fixed ring size, MTU and interrupt policy remain
the same as the comparison image. GRO ending-profile diagnostics are enabled
only in the candidate, so small differences cannot establish a performance win.

Validation: eight core receive-contract tests; 32 protocol tests with batch
admission; 41 protocol tests with admission + batch release + GRO diagnostics +
native TCP segmentation. These include order/budget/session rejection, duplicate
identifiers retaining live loans, exact-incarnation fault reclamation, actual
bulk callback selection, capability revocation and real TCP payload paths.
RISC-V target compilation and FIT hash-verified RAM loading succeeded.

| Image | Full RX Mbps (two 20s runs, mean) | Resident cores | 910M offered Mbps | Resident cores |
| --- | ---: | ---: | ---: | ---: |
| Batch candidate | 948.963 | 1.98774 | 909.961 | 1.92895 |
| Restored baseline | 948.541 | 1.99041 | 909.916 | 1.92349 |

Candidate FIT: `80b5f95e428bb81ce0bfbf6cac28cfa9336d3215989fa2fa9312155241b141b6`.
Baseline FIT: `918fdf3be9a1fe04eb62dba8d68d74a9628cd0d03a187da15f1af82713d600b6`.
Both completed a separate 64 MiB pattern verification; final pools had all 128
buffers free and no outstanding loans. Candidate nonempty admission batches
averaged 4.72, 4.73, 5.19 and 5.75 frames. Eligible GRO attempt groups averaged
7.68, 7.67, 7.79 and 8.18 segments; this histogram includes singleton attempts
and is not interchangeable with the merged-only aggregate counter. Candidate
final release counters reported 733225 batch calls covering 5603045 followers.
Counter snapshots are approximate once-per-second totals outside CPU windows.
Some saved GRO_NONE response snippets end mid-line; continuous raw serial was
retained, and the numbers above use the complete GRO_SIZE/admission arrays.

Evidence: `target/mars-reference/20260917-rx-admission-{measure,control}/`,
`20260917-rx-admission-comparison.json`, and the associated build/test logs.
The stable baseline was restored and is currently running. No SD/SPI writes.
These short controls show no convincing CPU reduction and do not justify
promoting the feature. Hardware restart/fault-injection acceptance of the new
admission-lock recovery path has not been performed. Next structural work must
address per-frame ownership-object construction and the remaining task/queue
handoff, rather than merely increasing the batch limit or changing hart affinity.

### 2026-09-17: exclusive driver service context

`DriverWork` now owns the pending TX/RX work, link polling state, TX deadline
and the sole `DriverSession`. The bounded synchronous service turn receives
this context rather than separate task locals. The session is the last field,
so pending software ownership drops before device shutdown. The async task
still owns and schedules the context; every turn retains the existing MMIO,
DMA and control capability checks. No second Engine, protocol-side DMA access,
owner-domain switching or task co-location has been introduced.

This is preparation for a combined receive/protocol execution path, not that
path's implementation or evidence of a CPU improvement. A future shared pump
must also specify exclusive invocation, IRQ dispatch, capability revocation,
task cancellation and exact-domain fault recovery before replacing the task
boundary. Merely calling this function from the protocol task would not meet
those requirements.

The same batch experiment features compiled for Mars and were loaded by
hash-verified TFTP into RAM. FIT SHA-256:
`3000f3ed08ffb8a7311d6dc381abb8301a3f2ed7310cfba10668dbf4b458e112`.
One 20-second full RX smoke test measured 948.894 Mbps and 1.98664 resident
cores across all four harts. Separate 64 MiB pattern verification passed;
final pool counters were received/acquired/released = 1671010, free = 128,
ready/borrowed/full/dropped = 0. This is functional smoke coverage only;
it does not test faults during a pending batch or establish a performance gain.

Evidence: `target/mars-reference/20260917-rx-context-smoke/`, especially
`summary.json`, `integrity.json`, `pool-final.log` and `serial-full.log`;
build/package logs are `20260917-bootlog-rx-context-{build,package}.log`.
After the smoke test, baseline FIT `918fdf3b…600b6` was restored and reached
1 Gbps link readiness; evidence is `20260917-rx-context-control-restore/`.
No SD or SPI contents were changed.

### 2026-09-17: consumed-loan cleanup representation (rejected)

Tested storing only Borrow cleanup credentials and scalar callback slots in
`ReleaseBatch`, instead of retaining complete Loans and constructing a second
Borrow array on Drop. Common-provider bulk cleanup and mixed-provider FIFO
scalar fallback were preserved. This changes metadata movement within GRO;
it does not remove individual admission objects or the driver/protocol handoff.

Three HAL ownership tests, six protocol unit tests and 41 protocol integration
tests passed. An added mixed-provider test checks that a scalar-only first
entry cannot accidentally select a later entry's bulk callback, and that each
entry retains its own scalar release operation. It remains after reverting
the experiment and passes with the original implementation.

Two 20-second runs per load, candidate followed by matching feature/control
image (both include DriverWork, batch admission/publication, batch release and
GRO diagnostics):

| Implementation | Full RX Mbps | Resident cores | 910M RX Mbps | Resident cores |
| --- | ---: | ---: | ---: | ---: |
| Cleanup credentials only | 948.781 | 1.99344 | 909.938 | 1.94397 |
| Original Loan holder | 948.983 | 1.99102 | 909.938 | 1.94349 |

No CPU benefit: the source change was reverted, with the patch archived at
`target/mars-reference/20260917-rx-cleanup-experiment.patch`. Candidate FIT:
`2603c9a50860539d37a6f560d4ab55c35fcce8ff53306473e362d8228dbd7035`;
control FIT: `3000f3ed…58e112` (full hash in the previous section).
Both passed a separate 64 MiB pattern check. All 128 buffers were free with
ready/borrowed/full/dropped zero; received/acquired/released matched (candidate
6420425, control 6421059). This rules out promoting this representation as a
measured CPU optimization; it does not quantify all ownership-management cost.

Evidence: `20260917-rx-cleanup-{measure,control}/` and
`20260917-rx-cleanup-comparison.json` under `target/mars-reference/`.

### 2026-09-17: synchronous controller/protocol service prototype

Default-off Mars `network-inline-rx` puts the stack on the dispatch hart and
calls a bounded controller service before and after each protocol batch. RX
publication, loan admission, GRO and protocol execution can now proceed in one
stack task poll. Ticket queues and individual Loans remain; this does not yet
eliminate all per-frame objects or queue transactions. The driver lifecycle
task retains its own CSpace, task domain and restart template, with a 1 ms
bounded fallback for TX progress and normal stack retirement.

One permanent recoverable gate owns DriverWork and the sole Engine. The stack
supplies control invocation authority and must match the active allocation
incarnation; it never receives the driver's capabilities or changes allocation
domain. Service removal/shutdown holds the same gate. Pending data is fixed
storage or permanent pool tickets; the task-arena TX coalescer combination is
explicitly rejected. A faulting synchronous caller is recorded in the gate.
Exact-domain fault recovery first recovers pool/control guards, then excludes
all service invocations and retires the Engine through firmware hard recovery.
This fault branch has not yet been physically injected and is not qualified.

The RX top half additionally signals the permanent inbound notification without
publishing a ticket. Protocol idle completion masks/acknowledges, arms and
rechecks OWN on the dispatch hart. The stack retains its register-listener then
repeat-work-check protocol, and a 1 ms fallback remains. A new host test covers
notification before/after waiter registration, empty queue after a hint and no
stale wake for a newly created waiter. Nine core receive tests and seven existing
netstack tests passed; these do not model the complete hardware service gate.

Mars build and hash-verified RAM loading passed. FIT:
`a5d6a39bf99931215c00e9a4f49604a733a8e0427dd434cf0f9815a116826111`.
The initial 20-second RX run measured **636.711 Mbps / 0.99574 resident cores**,
with the work concentrated on hart 0. Thus this prototype does not meet the
throughput requirement and is not a replacement for the 949 Mbps baseline.
The test service also remains on hart 0; the result alone cannot isolate its
contribution from controller/protocol work. Separate 64 MiB verification passed
and all 128 buffers returned; initial received/acquired/released = 1136321.

Lifecycle checks under traffic passed for both independent components:
- Stack cancellation/restart: generation 1 -> 2, nine retired capabilities;
  old connection reset, fresh 10-second iperf and 64 MiB integrity passed.
- Driver cancellation/restart: generation 1 -> 2, five retired capabilities,
  device epoch 1 -> 2, 1 Gbps link restored; fresh iperf and integrity passed.
Final received=2759512, acquired=released=2759452, free=128,
ready/borrowed/full/dropped=0. The 60 received-but-not-acquired frames span
session retirement; no outstanding loans remain. These are cancellation tests,
not hard-fault recovery, latency or long-duration stability qualification.

Evidence under `target/mars-reference/`: `20260917-inline-rx-smoke/`,
`20260917-inline-rx-{stack,driver}-recovery/`, associated scripts and build/test
logs. The experiment stays default-off. Next investigation must separate the
test-service CPU work and reduce remaining synchronous path cost while retaining
the >900 Mbps requirement; simply reporting one busy core is insufficient.
Stable FIT `918fdf3b…600b6` was restored with component hashes and link readiness
verified in `20260917-inline-rx-baseline-restore/`. No SD or SPI writes.

### 2026-09-17: isolate test-service CPU from synchronous RX

Default-off `network-service-peer` selects inline RX and creates iperf3 and
tcp-probe components on logical hart 1, leaving synchronous driver/GRO/protocol
work on dispatch hart 0. Each component's owner/arena is created on its home
hart; existing tracked tasks are not migrated. World publication precedes
remote initialization, and boot waits for component publication before installing
the supervisor. Ordinary restart retains the recorded home hart. Remote service
restart/fault recovery has not been physically tested in this configuration.

FIT `209d87c2a9c462745b77682fa0f38ce8a5676d884a1040115d15d181cd4ded12`
built and passed hash-verified RAM loading. Two 20-second full RX runs measured
756.264/756.468 Mbps and 1.25824/1.25656 resident cores. Hart 0 occupied
99.53/99.42%, hart 1 occupied 26.25/26.20%; other harts were nearly idle.
The test service contributed to the prior 637 Mbps ceiling, but moving it off
the RX hart still leaves that hart saturated below 900 Mbps.

The immediately restored same-hart inline control reproduced 636.711 Mbps.
Its NIDLE interval was 21.118 seconds around a 20.002-second transfer; reported
0.95600 residency is diluted by this extra idle edge and must not be presented
as a reduction from the preceding 0.99574 measurement. Active core time was
20.189 seconds. At the matched 600 Mbps offer, separated services measured
599.995 Mbps / 1.17379 cores (20.086-second CPU window); same-hart control
599.965 Mbps / 0.95077 cores (20.176-second window). Thus separation increased
the throughput ceiling but did not reduce total CPU cost in this comparison.

Both images passed independent 64 MiB verification and ended with all 128
buffers free, ready/borrowed/full/dropped zero, and matching receive/acquire/
release counts (peer 3666633, control 2166327). No claim of full system or
long-duration qualification follows from these short tests.

GRO/admission deltas reveal a useful next target. At full rate, peer admission
averaged 7.998 frames; eligible GRO attempts averaged 10.659/10.664 segments.
Sizes 3, 13 and 16 dominated almost equally (first run 39193/39180/39247);
IP-ID endings, ingress-budget endings and max-group endings each accounted for
about one third. At 600 Mbps, peer/control eligible GRO means were 10.146/10.219
and nonempty admission means 7.430/7.494. These approximate counter snapshots
include singletons and are not merged-only aggregate means. The fixed 3/13/16
pattern justifies testing existing atomic-IP-ID handling in this new execution
context, while retaining earlier negative results for the separate-task path.
It does not by itself prove that eliminating IP-ID endings will meet 900 Mbps.

Evidence: `target/mars-reference/20260917-inline-peer-{measure,control}/`,
`20260917-inline-peer-comparison.json`, archived FIT/ELF and feature maps,
build logs and RAM load scripts. The configuration remains default-off.
Stable baseline `918fdf3b…600b6` was restored with hashes/readiness/link checked
in `20260917-inline-peer-baseline-restore/`; no SD/SPI writes.

### 2026-09-17: atomic IP ID in the synchronous RX context

Added only the existing `gro-atomic-id` feature to the inline-RX/peer-service
experiment. No GRO size/budget, ring, interrupt or clock parameter changed.
Existing tests still exclude fragmentation and validate sequence/header policy,
payload and synthetic checksums. Six protocol unit tests and 41 integration
tests passed. Mars build and hash-verified RAM loading passed; candidate FIT:
`262c9a3979df4b0ad7b6f5d312ecce79d665392f8465d87dd1fd8eb4c4f1dfa6`.

Two 20-second full RX runs measured 786.065 and 782.625 Mbps, occupying
1.26724 and 1.26289 resident cores. The immediately restored strict-ID peer
control (`209d87c2…4ded12`) reproduced 756.338 Mbps / 1.25945 cores. Mean full
throughput improved about 3.7%, but remains below 900 Mbps. At a 600 Mbps offer,
candidate/control measured 599.965/599.995 Mbps and 1.14161/1.14434 cores;
that small occupancy difference does not establish a meaningful load reduction.

GRO counters confirm the intended mechanism: full-rate eligible attempted groups
averaged 15.992/15.987 segments, versus control 10.658. Candidate IP-ID endings
were zero; almost all full-rate groups reached 16 segments. At 600 Mbps the
means were 12.976 versus 10.259. Increasing actual aggregation by roughly 50%
at full rate produced only about 4% throughput improvement, so removing this
cutoff is useful but cannot account for the remaining synchronous-path cost.
These histogram means include singleton eligible attempts, and counter snapshots
are approximate rather than exact CPU-window packet counts.

Both images passed separate 64 MiB integrity checks. Final pools were all 128
free, ready/borrowed/full/dropped zero; receive/acquire/release matched at
3762504 for the candidate and 2371289 for the control. No new hard-fault or
long-duration acceptance is claimed. All experimental features remain default-off.

Evidence under `target/mars-reference/`: `20260917-inline-atomic-{measure,control}/`,
`20260917-inline-atomic-comparison.json`, build/test/package logs, feature map,
ELF and RAM-load scripts. Next attribution should separate synchronous device
service from protocol work before changing remaining per-frame operations.
Stable FIT `918fdf3b…600b6` was restored with hashes and link readiness checked
in `20260917-inline-atomic-baseline-restore/`. No SD/SPI contents changed.

### 2026-09-17: attribute inline work and coordinate one RX budget

Added a nested Driver profile scope around synchronous service. Previously its
policy/gate remainder would have been charged to the enclosing stack task. RX,
TX and completion children retain their own parent-exclusive scopes; the scope
compiles out without network-profile. Five parser regressions passed.

The first 5-second capture found an actual scheduling imbalance: each protocol
turn consumed at most 32 original frames, but both its before/after service
calls admitted RX, and the lifecycle fallback also added RX work. Queue high
water was 64, with 13948 full retry attempts across all 50 buckets. Stack turns
still processed ingress; this was not evidence of mostly idle stack spinning.
Capture FIT: `6d7892a77749908fedd2266e4649dc5836559b211b2928fdddeb4be1d0e3fdf4`.

The default-off inline path now requests RX only before protocol processing.
Its final service call drains TX/completions, and the bound driver's 1 ms
fallback also services TX only. Idle fallback still arms/rechecks RX interrupts.
Before a stack binds, the driver retains its normal RX behavior. All legacy
driver turns still request their original receive budget. Seven existing
netstack tests passed after extending the platform service contract.

Unprofiled candidate FIT:
`c795b40078a215e01b2fcc69405267ec73ae93e780473d6360482a8d7bd66017`.
Two full RX runs: 796.442/796.030 Mbps, 1.27904/1.28151 resident cores.
Immediately restored prior atomic-ID control: 785.349 Mbps, 1.26746 cores.
At 600 Mbps, candidate/control occupancy was 1.11923/1.11705 cores. This is
about a 1.4% full-throughput gain, not a verified reduction at the matched
offered load. Both passed 64 MiB verification and had all 128 buffers free;
receive/acquire/release matched at 3803208 and 2420973 respectively.

Matched diagnostic capture after the change used FIT
`7b77f437786e513c691e98382c169cd5c99c73eeb7bc5e64bc998450cb89ff5f`:
inbound high water fell to 32 and full retry attempts to zero. Outbound high
water was 3 with zero full attempts. No empty stack retries were recorded.
Thus the scheduling imbalance is resolved, even though its performance impact
is small. Instrumentation materially perturbs this CPU-limited path: interior
active-capture intervals were about 698 Mbps before and 694 Mbps after, versus
roughly 760–767 Mbps outside the active window in those diagnostic images.
Do not use the diagnostic throughput as an optimization A/B result.

Post-change hart-0 elapsed scopes over the 5-second capture, including each
scope's separately classified waits: packet receive entry 1.37467 s, frontend
1.18120 s, protocol-poll remainder 0.90990 s, RX callback 0.53407 s, driver
remainder 0.48552 s. These scopes include instrumentation/interrupts and are
not exclusive instruction cycles. Selected child samples must not be scaled
and added to their parents. Receive entry and frontend delivery remain useful
targets; the removed queue retries do not explain the remaining gap to 900 Mbps.

Traffic-time stack cancellation/restart also passed on the post-change
diagnostic image: generation 1 -> 2, nine capabilities retired; fresh iperf and
64 MiB verification succeeded, final receive/acquire/release 2233584, free128,
ready/borrowed/full/dropped zero. This does not qualify hard-fault recovery.

Evidence under `target/mars-reference/`: `20260917-inline-profile-measure/`,
`20260917-budget-profile-measure/` (raw profile plus reconciled analysis),
`20260917-inline-budget-{measure,control,stack-recovery}/`, archived feature
maps, ELFs, build and host-test logs. The inline configuration stays default-off.
The ordinary image/ethernet/trng-probe configuration passed release cargo check
with experiments disabled (`20260917-inline-budget-default-check.log`). Stable
FIT `918fdf3b…600b6` was restored with hashes and link readiness verified in
`20260917-inline-budget-baseline-restore/`; no SD/SPI writes.

### 2026-09-17: refill admission batches in place

The protocol device now refills its empty LoanBatch through receive authority
instead of returning and assigning the large batch through nested result
wrappers. The old return-by-value API remains available. A nonempty destination
is rejected before dequeue; owner validation, per-frame session rejection and
firmware ownership tracking remain in the admission path. Queue tickets remain
present until firmware records the admitted owner. This removes metadata
movement, not packet payload copies or per-frame loan tracking.

In archived release ELFs, PacketDevice::receive_pooled shrank from 6586 to
5550 bytes, its stack frame from 4336 to 2464 bytes, and static memcpy call sites
from 20 to 17. The removed sites used 592-byte lengths. These are static sites,
not evidence that every refill previously executed three such copies.

Unprofiled candidate FIT:
`ac41d8f7a79bfec9475be817cad39c0562e387e28541ec142ede312faab95161`.
Two 20-second full RX runs measured 807.157/808.830 Mbps at 1.28495/1.28444
resident cores. Adjacent prior inline-budget control (`c795b400…66017`) measured
797.697 Mbps at 1.28175 cores. At matched 600 Mbps, candidate/control measured
1.08647/1.12486 cores, about 3.4% lower occupancy in this short comparison.
The roughly 1.3% full-rate throughput gain remains far short of 900 Mbps;
the protocol hart is still about 99.7% busy. Occupancy sums all four harts'
non-WFI time and does not subtract idle baseline work.

Both images passed 64 MiB pattern verification. Candidate/control final pools
had 128 free buffers, zero ready/borrowed/full/dropped, and matching
receive/acquire/release counts of 3843437/2442064. On the candidate, cancellation
during traffic and net-stack restart advanced generation 1 to 2 and retired
nine capabilities. Fresh iperf and 64 MiB verification passed; final pool counts
matched at 1019882 with all 128 free. This checks ordinary cancellation/restart,
not injected hard-fault recovery or long-duration acceptance.

Host checks: 12 core receive tests, six protocol unit tests and 41 protocol
integration tests passed, including destination reuse/rejection, stale sessions
and exact-owner recovery with loans in both popped and refilled storage. Mars
release build passed. Experimental configurations remain default-off.

Evidence under `target/mars-reference/`: `20260917-inplace-rx-comparison.json`,
`20260917-inplace-rx-{measure,control,stack-recovery}/`, before/after assembly,
feature map, archived ELF, build and host-test logs. Stable FIT
`918fdf3b…600b6` was restored; component hashes and gigabit link readiness were
verified in `20260917-inplace-rx-baseline-restore/`. No SD/SPI writes.

### 2026-09-17: one frontend transaction for state and RX delivery

Added default-off `frontend-rx-batch` through firmware/kernel/netstack/protocol.
The ordinary copied frontend publishes transport state and drains its bounded
socket receive work under one frontend metadata guard. Wrapped socket fragments
share that guard; application notification occurs only after the batch commits
and unlocks. Existing four-chunk and 32 KiB per-chunk limits, receive capacity,
connection generations, per-chunk device authority checks and socket-owned
storage remain intact. TX and close reconciliation remain separate. The
receive-buffer-exchange configuration retains its existing path.

The net-api transaction borrows queue metadata synchronously; it neither lends
socket storage to applications nor changes driver ownership. Tests cover queue
wrap, capacity exhaustion, a callback error after committed bytes, reset/reuse,
and a reentrant wake callback reading the whole batch after unlock. API checks
passed 16 unit, 12 frontend, nine exchange frontend and one allocation test.
Candidate protocol checks passed six unit and 41 integration tests; combined
exchange fallback checks passed five unit and 40 integration tests. Mars build
and the ordinary image/ethernet/trng-probe release check passed.

Candidate FIT:
`85b761c8a0d482090b40908b8c41a6ebc8cbc2855bbc82595c010b473fd9e9ee`.
Two 20-second full RX tests measured 875.148/876.581 Mbps with
1.27374/1.27484 total non-WFI cores. At 599.935 Mbps occupancy was 1.04307 cores.
The adjacent in-place-admission control measured 809.769 Mbps at 1.28796 cores.
Its first 600 Mbps attempt failed with repeated link down/up and a broken
iperf control connection; it is excluded. A separate paced retry completed at
599.995 Mbps and 1.11845 cores. Thus this short comparison shows about 8.2%
more full-rate throughput and 6.7% lower occupancy at matched 600 Mbps.
These are 20-second samples, not an endurance or variance qualification.
Main protocol hart remains about 99.6–99.8% busy at full rate; neither 900 Mbps
nor sub-core occupancy is proved for this configuration.

Candidate 64 MiB integrity verification passed; receive/acquire/release matched
at 4075989, free128, ready/borrowed/full/dropped zero. Traffic-time net-stack
cancellation/restart advanced generation 1 to 2, retired nine capabilities,
then fresh iperf and another 64 MiB verification passed. Final pool counts
matched at 5174642, all 128 free. Hard-fault and endurance qualification remain
outstanding.

The adjacent control RAM load verified both component hashes for FIT
`ac41d8f7…5161`, then stopped before shell at MARS_TRNG_PROBE FAIL,
prepare/start=Err(Protocol), read=Err(DriverRestarted), cause=Initialize(Mode),
followed by `pmic_ops: cannot read pmic power register`. The loader exited with
failure. After a user power cycle, the old SD firmware responded; the same
control FIT then loaded with hashes and gigabit readiness verified. This was a
boot-probe failure before network initialization, not evidence of a frontend
transaction hang. The successful paced control also passed 64 MiB verification;
final receive/acquire/release matched at 2935469, free128, other counts zero.
No SD/SPI writes or entropy-gate bypass occurred.

Evidence: `target/mars-reference/20260917-frontend-batch-{measure,stack-recovery,control-load,control-cold-load,control,control-paced-retry}/`,
comparison JSON retaining the failed control attempt, archived ELF, feature map,
worktree patch and build/test/check logs. The transaction remains opt-in pending
longer qualification.
Stable FIT `918fdf3b…600b6` was subsequently restored with component hashes and
gigabit readiness verified in `20260917-frontend-batch-baseline-restore/`.

### 2026-09-17: close snapshot experiment rejected after adjacent comparison

Tested capturing the close request with the existing frontend drive snapshot,
removing the separate end-of-drive metadata lock. A new deterministic event
test covered a close arriving after the snapshot but before wait registration,
and preservation of a later reset when clearing a captured graceful close.
The send-drain barrier and listener reconciliation remained unchanged. Host
checks passed (API 16+13+9+1, protocol 6+41, exchange fallback 5+40), as did the
Mars build and ordinary release check.

Candidate FIT `a6defe7a666984f2c63fbacd5ec44ab61b8c1665c0dcc0cbff5ece006372b84d`
measured 877.414/876.469 Mbps at 1.26831/1.27031 cores, versus adjacent RX-batch
control `85b761c8…9e9ee` at 874.290 Mbps and 1.26552 cores. At 600 Mbps,
candidate/control occupancy was 1.07587/1.09006 cores. Less than 0.4% full-rate
throughput difference and about 1.3% paced occupancy difference do not establish
a material, repeatable benefit given prior short-run variation. Both images
passed 64 MiB integrity checks; candidate pool counts matched at 4080195 with
free128 and no ready/borrowed/full/dropped buffers.

The close snapshot API, feature and test were reverted to the exact saved
pre-experiment sources; the useful frontend RX transaction remains. The
experiment is reproducible from `20260917-frontend-close-only.patch` and the
archived feature map/ELF/FIT. Raw tests and comparison JSON are under
`target/mars-reference/20260917-frontend-close-{measure,control}/`. This rules
out adopting this particular extra fast path on current evidence; it does not
prove all remaining frontend synchronization is negligible.

### 2026-09-17: resample the retained frontend RX transaction

After reverting the close snapshot, built the retained RX transaction with
network-profile. Diagnostic FIT:
`a066185564cb9f06471e3535ac54314a349229247996540128112f1632d3f259`.
A complete five-second capture reconciled all bucket/hart totals through
scripts/mars-network-profile.py. Main-hart parent-exclusive elapsed scopes,
including their separately classified waits: packet receive entry 1.42755 s,
protocol poll remainder 0.98454 s, frontend remainder 0.95312 s, RX callback
0.60342 s, and driver remainder 0.51782 s. Frontend contended wait on hart 0
was 0.000235 s (hart 1: 0.000090 s), compared with 0.28215/0.06974 s in the
earlier inline-budget capture. The workload progresses faster in this capture,
so raw absolute times are not a matched-work CPU comparison.

Inbound high water was 32 with zero full retries; outbound high water was 3,
also zero full retries. Stack recorded 10480 ingress turns, 20974 aggregate
ingress objects and no empty retries. Selected GRO samples numbered 2806;
they are not a count of all input packets and must not be scaled and added to
the enclosing packet scope. The remaining large receive-entry and protocol
scopes motivate examining GRO payload materialization and subsequent buffer
delivery, rather than another small metadata-lock shortcut. This capture does
not separately prove the cost of copying versus parsing/ownership checks.

Instrumentation perturbs throughput: active-capture intervals were about
783–787 Mbps, versus about 839–857 Mbps outside the window in this diagnostic
image. Do not substitute these numbers for unprofiled A/B results. Timer-based
elapsed scopes include instrumentation and interrupts; they are not instruction
cycles. Evidence: `20260917-frontend-profile-measure/` contains raw serial,
iperf, profile, reconciled analysis and compact attribution JSON.

Stable FIT `918fdf3b…600b6` was restored with hashes and gigabit link verified
in `20260917-frontend-close-baseline-restore/`. No SD/SPI writes. The retained
unprofiled RX transaction remains approximately 875 Mbps / 1.27 cores and has
not reached the requested performance target.

### 2026-09-17: TCP receive storage groundwork for scatter GRO

The current RxToken contract supplies a contiguous slice. Removing GRO's
materialization without changing the consumer would either expose incomplete
payloads or bypass ordinary receive validation. Started the necessary TCP
storage abstraction in the existing smoltcp submodule, preserving its previous
buffer-exchange changes. New internal `tcp-scatter-receive` support borrows up
to 16 payload slices for one invocation, clips their logical range using the
same TCP window/sequence logic, and writes fragments directly into the socket
ring. It allocates no aggregate buffer and retains no fragment reference in
the socket after the call. SYN reset replies use the logical payload length,
not the deliberately empty payload field of header-only metadata.

Both contiguous and scattered storage instantiate one TCP state machine; this
does not duplicate sequence, ACK, retransmission or assembler policy. With the
feature enabled, the existing TCP send fixture splits payloads (including an
empty fragment) so the established golden tests exercise this new path. New
differential coverage checks all 49 split points of a 48-byte payload, six
sequence displacements and two sequence bases (including signed wrap), with
window clipping, ring wrap and later filling of out-of-order gaps. Separate
coverage clips every range across 16 fragments into a wrapped, capacity-limited
ring, and rejects excessive fragment counts, excessive lengths and ambiguous
contiguous-plus-scattered input before socket mutation.

Results: 195 TCP tests passed with scatter enabled; 193 passed with contiguous
storage. The combined smoltcp configuration (scatter, buffer exchange and TCP
segmentation) passed 388 tests. Existing VibeOS protocol checks passed six unit
and 41 integration tests. IPv6 no_std checking, scatter-enabled RISC-V no_std
release checking and the ordinary Mars release check passed. Earlier zero-test output was a test-filter/configuration
mistake (TCP unit tests require medium-ip), not counted as verification.

This is internal groundwork, NOT a wired GRO optimization: no firmware feature
enables it, no device token/Interface path supplies fragments yet, and no new
image was loaded or performance gain measured. Next work must connect a
validated segmented receive representation through ordinary Ethernet/IP
admission, preserve checksum policy and exceptional-packet fallback, retain
all DMA loans until synchronous TCP consumption completes, then repeat
integrity, recovery and unprofiled performance comparisons. The active goal
remains unfulfilled.

Evidence under `target/mars-reference/`: `20260917-scatter-tcp-only.patch`
(relative to the preserved pre-existing smoltcp edits), saved original files,
TCP contiguous/scatter logs, full smoltcp tests, protocol regressions and checks.
No SD/SPI or board changes were made during this step.

### 2026-09-17: borrowed GRO ingress wired through Interface and DMA loans

The previous storage groundwork is now connected by opt-in `gro-scatter`
(VibeOS) / `tcp-gro-receive` (smoltcp). An RxToken can synchronously supply
the original Ethernet frames, including the first frame, as borrowed slices.
The checked `TcpGro` representation validates every frame and the complete
group before socket mutation: checksum policy, addresses/ports, sequential
sequence numbers, ACK/window/options, flags, lengths and bounded group size.
It accepts at most 16 frames / 32 KiB. Ordinary Ethernet/IPv4 admission and
the existing TCP state machine remain shared with contiguous reception.
Ineligible frames use the existing single-frame path. Invalid externally
supplied groups are dropped atomically. Builds with raw sockets materialize
a complete bounded packet and use ordinary raw delivery; their bytes and
checksums are covered by an actual raw-socket test.

PacketDevice retains all follower DMA loans through synchronous consumption,
then releases them in a batch on the next receive (or individually on device
destruction). Revocation after collection releases followers, lookahead and
the remaining admission batch. No fragment reference survives in the TCP
socket. TCP copies accepted ranges directly from the retained fragments into
its receive ring, avoiding the intermediate GRO payload buffer; frontend
delivery still copies. There is no new unchecked lifetime extension, domain
switch or bypass of capability checks.

Validation: smoltcp ingress/TCP configuration passed 390 tests; raw-socket
configuration passed 384; the broader IPv4/IPv6, fragmentation, multicast,
UDP, DHCP, raw, segmentation and buffer-exchange configuration passed 527.
The initial broader test command omitted `multicast` and failed to compile
existing IPv6 multicast tests; that failed invocation is preserved separately
and is not counted as passing. VibeOS protocol passed 6 unit + 42 integration
tests with scatter, 6 + 41 with legacy GRO, and 6 + 49 with scatter plus buffer
exchange. Both candidate and same-source contiguous control firmware built
and packaged successfully. Existing build warnings remain.

Candidate FIT SHA256:
`dafb5f55d56534b25286fbe157ed2dcf10d57d2b7122cb55e8a10c37722b6eea`.
Same-source contiguous control:
`4b61686f344e1f3c5fbe089f25c118592d030573cd081b922af5ed06672109e1`.
All other experimental firmware features match. The source archive
`20260917-gro-scatter-source.zip` records root HEAD
`1315c16b0b36d26b78034ca332dfdb2e345bc20e`, submodule HEAD, complete dirty
submodule sources including new files, and checksums. Archive SHA256:
`0ff3bbc416820f07ceea8a7e941653fec6c7ef05a8ae9e9a4d14682fae055cdb`.

Following physical recovery, the candidate was loaded into RAM with image
hashes, initialization and gigabit link verified. The earlier silent-board
load attempt failed at its first command, before any reboot or transfer; it
did not run this candidate. No SD/SPI changes were made. Benchmarks ran with
no concurrent compilation, MTU 1500, identical clients and 20-second windows.

| Image | Full-rate TCP RX, Mbps | Total non-WFI cores |
| --- | --- | --- |
| Contiguous, round 1 | 874.363 | 1.26487 |
| Contiguous, round 2 | 874.777 | 1.26199 |
| Scatter, round 1 | 913.742 | 1.29129 |
| Scatter, round 2 | 913.462 | 1.28424 |

Mean throughput improved 4.463%; CPU time per received gigabit improved
2.429%. Total full-rate occupancy is slightly higher because more traffic
is processed. These measurements do not establish lower CPU at equal load.
Full-rate scatter aggregates averaged 15.990 / 15.988 original segments,
with over 99.8% of multi-frame groups reaching 16 segments. In this workload,
poor aggregate fill does not explain the remaining cost. Counters describe
attempted adapter aggregates and are approximate, not an instruction profile.

At equal 600 Mbps load, three 20-second samples were:

| Image | Total non-WFI cores, each sample | Mean |
| --- | --- | --- |
| Contiguous | 1.01243, 1.03401, 1.06103 | 1.03582 |
| Scatter | 1.04197, 1.01623, 1.03350 | 1.03057 |

The ranges overlap and the mean difference is only 0.51%. This does not
establish a repeatable equal-load CPU reduction. The first paced comparison
alone actually favored contiguous GRO, which is why it was repeated. All
repeat runs passed another 64 MiB integrity precheck and finished with the
entire pool free. The useful demonstrated result of this experiment is the
full-rate throughput increase, not the requested substantial CPU reduction.
Before another optimization, resample the remaining receive-entry, protocol
and frontend scopes on this wired implementation. Do not infer that copying
dominates the remaining cost from the fact that one copy was removed.

Both images passed 64 MiB application-visible pattern verification before
performance testing. Candidate cancellation under active traffic retired the
old grants and advanced the stack generation 1 -> 2; the interrupted client
exited without forced termination. A fresh TCP test and another 64 MiB check
passed. At the recovery checkpoint all 5,350,347 received/acquired loans were
released; free=128, ready=borrowed=full=dropped=0. This is cooperative component
cancellation/restart evidence, not injected hard-fault qualification.

Raw evidence under `target/mars-reference/`: `20260917-gro-{scatter,contiguous}-measure/`,
`20260917-gro-scatter-stack-recovery/`, corresponding load/build/package/test
logs, feature maps and ELF/FIT files. `20260917-gro-scatter-comparison.json`
records matched-run metrics and aggregate sizes. The new path stays default
off; the effort target of total occupancy below one core is still unmet.
`20260917-gro-{scatter,contiguous}-paced-repeat/` and
`20260917-gro-scatter-paced-comparison.json` retain the additional equal-load
samples and their summary. These short runs do not qualify the new path for
the earlier one-hour stability or full board acceptance requirements.

Finally restored stable FIT
`918fdf3be9a1fe04eb62dba8d68d74a9628cd0d03a187da15f1af82713d600b6`
through RAM boot, checking component hashes, network initialization and
1000 Mbps link. Evidence: `20260917-gro-scatter-baseline-restore/`. SD/SPI
contents remain unchanged.

### 2026-09-17: profile wired scatter and batch TCP ring writes

Resampled the wired scatter implementation before further changes. Diagnostic
FIT `f9581436d1786f9df70620b0cdd48d195c3cb9913a83eae2b71f77aa0c6e7096`
completed a reconciled five-second capture. On hart 0, parent-exclusive
elapsed scopes (including separately classified waits) were protocol poll
1.40004 s, frontend 1.00132 s, packet receive entry 0.89178 s, RX callback
0.61944 s and driver remainder 0.54193 s. Protocol/frontend/packet contended
waits were only 0.000341 / 0.000334 / 0.000157 s. Inbound high water was 32,
outbound 3, with no full retries. There were 10844 ingress turns and 21705
post-GRO ingress objects, no empty stack retries. These timer scopes include
interrupts and instrumentation, and sampled children must not be extrapolated
and added to parents.

Compared with the earlier contiguous diagnostic capture, packet entry is
smaller and protocol processing larger. Work volume and instrumentation differ;
this alone cannot assign the difference specifically to validation or copying.
The new scatter representation performs per-fragment ring writes inside the
protocol scope. Inspection of the actual unprofiled ELF found an out-of-line
`write_unallocated` invocation for every fragment; its two ring lookups each
execute `remu` and each calls memcpy, including a zero-length second copy on
the usual non-wrapping path.

Changed only the internal scattered payload writer to traverse the at most two
contiguous destination ring regions for the whole accepted logical range,
copying the source fragments into each region. No ring publication, sequence,
assembler, checksum, capability, or DMA lifetime policy changes. The accepted
range is clipped to the available window before writing. It remains a copy
into socket-owned storage, not zero-copy delivery.

A new differential test compares the complete resulting ring contents against
the contiguous writer across zero/small/large capacities, read positions,
allocated lengths, offsets including beyond the free window, clipped source
ranges, empty fragments and ring wrap. Together with existing exhaustive
fragment-range, TCP sequence/window and ingress tests, the broad configuration
passed 528 tests. The first test compile required an explicit `usize` literal
in its capacity matrix; that fixture typing issue was fixed before the pass.
Generated candidate code has one `remu` in the destination-region loop and
one memcpy site in the fragment-copy loop; it no longer calls the per-fragment
ring writer. These are static code observations, not measured cycle savings.

Candidate FIT:
`114e3f368c5e0642ce22e52b94f71d0b4f744f75ad5bbec48a3b6898312e8448`.
Control is the preceding scatter FIT `dafb5f55…b6eea`, with identical firmware
features and the original fragment writer. Source delta and code evidence:
`20260917-scatter-write-only.patch`, `20260917-scatter-write-before.rs`, and
`20260917-scatter-write-{before-caller,before-ring,after}.asm` under
`target/mars-reference/`. Raw profile, reconciled totals and attribution are
in `20260917-scatter-profile-measure/`.

Adjacent unprofiled A/B results, MTU 1500, each sample 20 seconds, with no
concurrent builds:

| Writer | Full-rate Mbps | Total non-WFI cores | 600 Mbps total cores (three runs) |
| --- | --- | --- | --- |
| Original per-fragment | 914.659, 913.027 | 1.29002, 1.28669 | 0.99067, 1.09050, 0.98913 |
| Batched ring regions | 931.259, 930.930 | 1.28602, 1.28770 | 0.98366, 0.98682, 1.08623 |

Mean full-rate throughput improved 1.888%, with 1.967% less total CPU time
per received gigabit. The batch writer is retained within the still-default-off
scatter path. Equal-load mean CPU differed by only 0.443%, with heavily
overlapping ranges; substantial equal-load CPU reduction remains unproven.
The high-occupancy batch run had 12.82 segments per aggregate, versus 13.48
in the other two paced runs. This correlation is not a causal attribution;
it motivates paced profiling of wakeups, empty retries and batch termination
before changing scheduling or batching policy.

Both images passed their 64 MiB pattern check and ended all five tests with
free=128, ready=borrowed=full=dropped=0. This change does not alter ownership
or component recovery; the earlier scatter cancellation test remains relevant
but was not repeated for this writer. No new long-duration qualification is
claimed. Results and all samples, including the high-CPU paced runs, are in
`20260917-scatter-write{,-control}-measure/` and
`20260917-scatter-write-comparison.json`. The source delta, prior source archive
hash and changed file hash are recorded by `20260917-scatter-write-manifest.json`.

Stable FIT `918fdf3b…600b6` was restored with component hashes, successful
initialization and 1000 Mbps link verified in
`20260917-scatter-write-baseline-restore/`. No SD/SPI writes. The active
below-one-core effort target remains unmet at full rate.

### 2026-09-17: paced scatter profile and independent-service cross-check

Built the retained batched ring writer with network-profile. Diagnostic FIT
`8fd02fc0157216d9f81af124e7866dc235c58ba8dcc66f1698aa5fa31994c7cd`
passed RAM boot/hash/link checks. Captured a ten-second profile beginning five
seconds into a 30-second 600 Mbps RX workload, without concurrent compilation.
The complete dump passed bucket/hart and lock-total reconciliation. Raw files,
analysis and explicit interval metadata: `20260917-scatter-paced-profile-measure/`
under `target/mars-reference/`.

Hart-0 parent-exclusive elapsed seconds, including separately measured waits:
protocol 2.16288, frontend 1.62992, packet receive entry 1.47773, driver remainder
1.13170, RX callbacks 0.99006, stack remainder 0.57639 and executor 0.38536.
Protocol/frontend/packet waits were 0.000790 / 0.002942 / 0.000393 seconds.
Inbound/outbound high water remained 32/3 with zero full retries.
Of 25507 stack turns, 19840 reported ingress (38603 post-GRO objects), so
22.217% of turns had no ingress. No-ingress does not imply no useful work:
ACK/TX, timers and frontend progress still need service. Recorded decisions
were 20768 runnable-work hints, 3293 idle rechecks and 1445 wait attempts.
Application-side decisions included 21313 idle rechecks and 31072 wait attempts;
these are counts, not elapsed-time attribution.

The separate whole-workload IRQ snapshots span approximately 30 seconds, not
the ten-second profile: 4954 interrupts, 76046 arm attempts and 22962 busy
rechecks. The legacy timers/tx-wakes counters did not advance; they do not
measure the inline lifecycle task's one-millisecond fallback. Do not infer
zero timer wakeups from these counters or correlate their totals with individual
profile buckets. The 30-second WFI proxy was about 1.067 total cores and includes
the active instrumentation window, so it is not an unprofiled comparison.

The capture establishes extra empty checking at paced load, but protocol and
frontend work remain substantial and neither queue saturation nor contended
locking explains most time. Earlier receive-side TX-only attribution found no
such turns; this new capture does not separately classify TX-only ownership and
does not justify changing completion/interrupt policy. Before modifying shared
reception again, cross-check the current unprofiled image through the independent
TCP sink so the iperf3 service is not silently treated as the network itself.

On unprofiled FIT `114e3f36…e8448`, independent single-flow sink tests measured
867.193 / 867.626 Mbps, four flows 759.914 Mbps. The initial CPU brackets also
included roughly ten seconds of service admission before the explicit GO;
those diluted CPU averages are invalid for comparison, retained with
`20260917-scatter-independent-measure/exclusion.json`, and are not used below.
Revised capture waits until every V2 connection has received R, records NIDLE,
then releases all host senders through one barrier. It records NIDLE again at
confirmed completion and rejects an interval more than one second longer than
the actual data phase. It sends 2 GiB total with no post-test sleep inside the
CPU bracket. The gated results were 867.326 Mbps / 1.65219 cores for one flow
and 761.683 Mbps / 1.63067 cores for four flows. Application hart 1 consumed
65.736% / 63.365%, versus approximately 28.8% during the recent iperf workload.
Counts are verified by the board, but this throughput mode is not a byte-pattern
integrity test. The separate preceding 64 MiB pattern check passed.

Thus the independent service is not a faster reference implementation here;
its different scheduling and four-listener scan add substantial application
work. Source inspection found it still uses the short polling grace after each
progress event, whereas the iperf service already uses activity notifications.
Added opt-in `event-driven` to tcp-probe, propagated through the existing
`application-event-poll` experiment. It acquires notification-only handles via
RECV authority, prepares epochs before a second complete idle check, and waits
on all four events with the existing one-millisecond deadline/revocation
fallback. All data operations keep their capability checks and bounds; busy
turns still yield. No per-turn Vec allocation or new worker task is introduced.
An unsupported notification backend retains ordinary polling.

Event configuration passed six component tests, including a new task-level
check of exactly two complete idle scans before parking and authority rejection
after notification. Original polling configuration passed five tests. Candidate
build/package passed; FIT
`36ada02371db45a3faaf2d6dc2ec40d2d417781925e9671e20dd3ce0b7e536dd`.
Unmodified sources are archived in `20260917-probe-events-original/`.

The candidate passed the same admission-gated 2 GiB total-byte tests:

| Independent TCP sink | Polling Mbps / total cores | Events Mbps / total cores |
| --- | --- | --- |
| One flow | 867.326 / 1.65219 | 936.416 / 1.34159 |
| Four flows | 761.683 / 1.63067 | 809.512 / 1.31381 |

Total CPU occupancy fell 18.80% / 19.43%, while throughput rose 7.97% / 6.28%.
Application hart 1 fell to 34.259% / 31.735%. These are different workloads
at their respective maximum rates; CPU time per received gigabit fell about
24.79% / 24.19%. The change is retained as part of the default-off application
event experiment. It improves the independent service's polling behavior, not
the driver's per-packet execution cost. Four-flow throughput remains below
single-flow throughput and is not a completed scaling qualification.

The unchanged iperf service measured 931.429 Mbps / 1.29122 cores, and
599.995 Mbps / 1.01244 cores at fixed rate. This is consistent with the earlier
iperf result; no additional common-path CPU improvement is claimed. Another
64 MiB byte-pattern verification passed. After these tests, received/acquired/
released all matched at 5,613,260, with free128 and ready/borrowed/full/dropped0.
The independent throughput tests themselves only validate byte counts.

Evidence: `20260917-{scatter-independent,probe-events}-gated-measure/`,
`20260917-probe-events-iperf-measure/`, `20260917-probe-events-comparison.json`,
`20260917-probe-events-only.patch` and source manifest under
`target/mars-reference/`. Both throughput and CPU are bracketed after readiness;
the earlier ungated CPU results remain explicitly excluded.

Idle cancellation/restart of the event-waiting tcp-probe also passed: restarting
a running component was rejected, cancellation completed, generation advanced
1 -> 2 with fresh grants, and a new 64 MiB verified transfer succeeded. All
5,659,233 loans were released and the pool was entirely free afterward. Evidence:
`20260917-probe-events-recovery/`. This verifies normal supervised cancellation,
not a forced fault or a long-duration stability run. No one-core completion
claim is made; the iperf common-path occupancy remains about 1.29 cores.

Stable `918fdf3b…600b6` was RAM-restored with hashes, initialization and gigabit
link verified in `20260917-probe-events-baseline-restore/`. SD/SPI contents
remain unchanged. Normal firmware feature selection is restored; this service
change is enabled only by the opt-in application event configuration.

### 2026-09-17: incremental checked GRO handoff groundwork

The current adapter parses each candidate to choose a compatible group, then
Interface validates that complete group again. Removing checks based on an
untyped “already checked” flag would weaken the boundary. Added
`TcpGroBuilder` in smoltcp to validate an immutable borrowed prefix incrementally,
with captured checksum policy, transactional append, bounded byte/segment counts,
and explicit incompatible/ineligible/capacity/finished rejection reasons. A
rejected frame never mutates the accepted prefix. PSH/short segments terminate
the prefix, sequence arithmetic wraps as TCP requires, and a singleton is not
returned as an aggregate. Existing `TcpGro::new` now uses that common validator;
the first frame is no longer parsed twice inside that constructor.

Added `RxToken::consume_gro_checked` with a compatible default for existing
single-frame/group tokens. An override can hand off `TcpGroRx::Group` built
while selecting its frames. Group fields remain private and are constructible
only through validation. Interface checks that the group's recorded IPv4 and
TCP checksum verification each cover its own current policy, then uses the
existing MAC/IP admission and TCP dispatch. Weaker policy is rejected rather
than silently accepted. Original immutable bytes remain borrowed through the
callback; raw-socket builds retain their complete-packet materialization.
Ordinary non-GRO receive behavior and existing token implementations remain
compatible. No unchecked lifetime extension or kernel/driver dependency was
introduced.

Tests cover failed append followed by retry, sequence wrap, the exact 32 KiB
boundary, 16/17 segments, short/PSH termination, the four checksum-policy
combinations, and an overridden checked token through real Interface admission.
A compile-fail example verifies original storage cannot be mutated while its
validation remains live. Broader smoltcp configuration passed 532 tests; direct
non-raw GRO configuration passed 395;
ordinary non-GRO configuration passed 376. Doc tests passed five regular and
one compile-fail test. VibeOS protocol passed six unit and 42 integration tests,
and the Mars RISC-V no_std release check with scatter/front-end/admission
features passed. Initial checked-token fixture failures came from counting
background multicast/ARP output as TCP resets; the fixture now seeds the peer
neighbor and checks actual TCP RST output, including negative admission cases.

This is checked-handoff groundwork, not completed removal of cross-layer
duplicate parsing. VibeOS PacketDevice still constructs its old group and uses
the compatible default checked entry. Next integration must store pending DMA
loans in stable bounded slots so the builder can borrow them while choosing a
prefix, return a checked token directly, preserve rejected lookahead/order and
batch cleanup, and revalidate capabilities before delivery. It must preserve
ordinary short/ineligible traffic and all revoke/restart semantics. Do not
replace this with unsafe lifetime extension or a caller-forgeable validation
claim. Hardware integrity, performance and recovery comparisons are required
after that wiring; no new throughput/CPU result is claimed here.

Evidence under `target/mars-reference/`: `20260917-gro-builder-original/`,
`20260917-gro-checked-only.patch`, source manifest and the corresponding
ingress/direct/legacy/protocol/doc test and firmware-check logs. No image was
loaded and no SD/SPI/board changes were made in this step.

### 2026-09-17: checked GRO interface hardware regression and paired control

After the requested power cycle, the serial prompt responded on
`/dev/cu.usbmodem54340134951`. Built the current checked-interface groundwork
with the same feature list as the preceding probe-events experiment. RAM FIT
SHA-256: `7e282ca49da7d75595cddb536d90cf57b7ec53ea930d8ff620ed081f6f104c80`.
U-Boot verified kernel and DTB hashes; the board initialized and negotiated
1000 Mbps. Host en13 used MTU 1500 and gigabit full duplex. Normal Cargo feature
selection was restored after packaging. This still uses PacketDevice's legacy
selection and the default checked-token adapter, not the proposed device-side
single-validation handoff.

Repeated the prior probe-events FIT (`36ada023…6dd`) in this same session as
control. Each image received an independent 64 MiB pattern verification, two
20-second full-rate iperf RX runs, and three 20-second 600 Mbps runs. UART was
captured continuously by one reader. CPU below is summed non-WFI residency of
all four harts, with no idle subtraction; these are not instruction-cycle
measurements. No builds ran during measurements.

| Image | Full RX Mbps | Full resident cores | 600 Mbps resident cores |
| --- | --- | --- | --- |
| Checked interface | 925.891, 927.646 | 1.29288, 1.29085 | 1.03061, 1.07364, 1.05976 |
| Prior control | 933.776, 931.758 | 1.29287, 1.29255 | 1.04929, 0.99281, 1.07159 |

The checked image averaged 926.768 Mbps versus 932.767 Mbps (-0.643%), at
1.29187 versus 1.29271 cores. CPU per delivered bit was 0.582% higher. Paced
sample ranges overlap; their averages were 1.05467 and 1.03790 cores. This small
sequential experiment does not establish a statistically significant regression,
but provides no evidence of a CPU improvement. Do not advertise the groundwork
as an optimization or enable it as a production performance change on this
basis. The next implementation remains direct device-side checked grouping,
with preserved rejected lookahead, capabilities and bounded loan lifetimes.

Checked-image full-rate GRO groups averaged 15.946 and 15.998 segments; the
16-segment shares were 98.856% and 99.955%. Paced averages were 13.193, 12.855
and 12.892 segments. Thus aggregation was active; this is not evidence that
turning on GRO alone can remove the remaining CPU cost. At measurement end,
all 6,310,223 checked-image and 6,330,734 control loans were released, with
free=128, ready=borrowed=full=dropped=0 in both runs.

Also cancelled net-stack during an active TCP transfer. Restart while running
was correctly refused; cooperative cancellation permitted generation 1 -> 2,
retired nine old capabilities and installed fresh grants. The interrupted
client exited without forced termination. A new 10-second flow reached
930.669 Mbps, and another independent 64 MiB content verification passed.
All 7,474,629 acquired loans were released, with the entire pool free afterward.
This is cooperative restart coverage, not forced-fault recovery or one-hour
qualification. The one-core full-rate objective remains unmet.

Evidence under `target/mars-reference/`: `20260917-gro-checked-measure/`,
`20260917-gro-checked-control-measure/`, `20260917-gro-checked-stack-recovery/`,
`20260917-gro-checked-hardware-comparison.json`, build/package logs, load logs,
and `20260917-gro-checked-hardware-source.zip` with its source manifest. The
source archive includes the untracked smoltcp GRO and scatter source files.

Stable FIT `918fdf3b…600b6` was RAM-restored after both runs, with hashes,
network initialization and gigabit link verified in
`20260917-gro-checked-baseline-restore/`. No SD or SPI contents were changed.
