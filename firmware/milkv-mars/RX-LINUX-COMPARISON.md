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
