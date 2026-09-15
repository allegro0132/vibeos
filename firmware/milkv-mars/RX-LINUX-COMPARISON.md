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
