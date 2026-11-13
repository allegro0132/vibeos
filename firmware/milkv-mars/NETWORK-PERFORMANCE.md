# Mars network performance experiments

The 2026-09-13 experiments use a 4 GiB Mars, SPI firmware loading a FIT into
RAM, and a direct Mac Ethernet test network. The PHY reports 1000 Mbps full
duplex. All results below are single TCP streams with MTU 1500 / MSS 1460.
They are throughput measurements, not complete Mars hardware qualification.

## Changes

- A bounded cooperative polling grace follows actual progress in the device,
  protocol and stream service loops. Each empty poll yields to the executor;
  grace expires after 1 ms or 64 attempts. Idle services retain their sleep.
- JH7110 cache maintenance batches isolated cache-line flushes between full
  barriers. CPU reclaim of read-only TX payloads validates the DMA region and
  orders completion without flushing unchanged payload data. RX and descriptor
  ownership still require cache synchronization.
- The Mars Ethernet service composition enables 256 KiB TCP buffers instead of
  the default 32 KiB. Its netstack memory quota is 8 MiB; this is an upper bound,
  not a reservation. The allocator rounds charged sizes including metadata,
  so a 2 MiB quota was experimentally insufficient. Other compositions retain
  their default TCP window and memory quota.
- Packet processing and stream frontends are compiled for speed. Capability
  checks, bounded work, and DMA ownership checks remain enabled.

The cache changes follow the ownership rules used by
[RISC-V DMA synchronization](https://raw.githubusercontent.com/torvalds/linux/master/arch/riscv/mm/dma-noncoherent.c)
and the batched maintenance sequence in
[SiFive ccache](https://raw.githubusercontent.com/torvalds/linux/master/drivers/cache/sifive_ccache.c).

## Reproduction and evidence

Build a fresh output directory:

```sh
sh scripts/build-mars-sd.sh --ethernet --trng-probe --work-dir target/mars-network-candidate
```

After booting and observing the runtime DHCP address, run:

```sh
python3 scripts/mars-network-bench.py --address "$MARS_IP" \
  --output target/mars-network-measurement --seconds 60 --rounds 3
```

Use the address assigned to VibeOS, which can differ from U-Boot's address.
The script records raw iperf3 JSON and fails incomplete tests. Report throughput
from the receiver. Retransmit fields are peer-reported and may be absent or
unsupported; they are not independent evidence that no packets were lost.

The pre-optimization SD baseline measured about 93 Mbps in each direction.
The large-window candidate measured 263.66 Mbps host-to-board and 258.98 Mbps
board-to-host over separate 60-second tests. Its netstack used 2,105,216 bytes
with no quota denials. Raw results, FIT/source provenance and incremental
experiments are retained under `target/mars-acceptance/20260913-gigabit/`;
the generated image manifests record component versions and hashes.

The subsequent frontend speed-optimization candidate measured 275.20 Mbps
host-to-board and 273.14 Mbps board-to-host over separate 60-second tests
(`frontend-sustained/`). Its FIT SHA-256 is
`caa89d4c6f4751432d05d49d3b0eb3d6931ee328c9733e09dc225a1085215c11`.
After the tests, every component remained running, executor fault count was
zero, and netstack memory remained 2,105,216 bytes with zero quota denials.
This candidate was tested from RAM; the installed SD boot payload was unchanged.

Removing the frontend's 32 KiB temporary buffer and using smoltcp's synchronous
buffer callbacks measured 303.10 Mbps host-to-board and 297.80 Mbps board-to-host
over separate 60-second tests (`direct-sustained/`). Per-call/chunk limits and
authority revalidation remain enforced. The frontend commits only bytes accepted
by the destination queue; borrowed transport slices never escape the call.
The candidate FIT SHA-256 is
`ba3dc05921198cb60a715c16c0b03c718d4e457b84d04387dd65565b25efea02`.
Host tests transfer 600,007 patterned bytes in each direction through small,
odd-sized frontend queues, check wrap/backpressure and revoke network authority.
Both default and large TCP window configurations pass, as do the QEMU and Duo
DHCP/iperf3 composition build checks. The post-benchmark component fault and
quota-denial counts remain zero.

## Execution timing and two-core experiment

The optional core/kernel `executor-profile` feature adds cumulative task-poll
and executor-turn elapsed ticks to `ps`. A host-clock test checks that time
outside executor turns is excluded. Counters include interrupts and are
approximate snapshots, not hardware CPU-cycle attribution. With unchanged
task identities, differences between snapshots showed the single-core driver
using 40–45% of elapsed time, TCP stack 40–41%, iperf service 6–8%, and the
executor residual about 3% (`exec-profile-analysis.json`).

The experimental kernel `network-pipeline` feature constructs the initial
TCP-stack arena on admitted logical hart 1, retaining the driver and stream
service on logical hart 0. A SYSTEM bootstrap publishes the component before
boot installs its supervisor; no existing reclaimable arena moves between
harts. Single-hart machines fall back to the original placement. The automatic
supervisor stays on hart 1 so fault recovery constructs fresh arenas there.
Manual shell restarts still use the caller's hart and need affinity handling
before this placement is considered complete.

The Mars Ethernet experimental composition currently enables both features.
The first two-core measurements were 450.47 Mbps host-to-board and 500.77 Mbps
board-to-host over separate 15-second tests (`pipeline-forward.json` and
`pipeline-reverse.json`). The FIT SHA-256 is
`d94dafd4460e29e994e0585d60507439ea638000083b485a3721740288d5257b`.
Task timing now shows the TCP-stack hart at approximately 85–87% elapsed
occupancy. This includes possible lock waits; measuring control/queue waiting
separately is needed before attributing all of that time to protocol computation.
Separate 60-second tests then measured 455.68 Mbps host-to-board and 504.82 Mbps
board-to-host (`pipeline-sustained/`). The post-test snapshot showed all service
components running, zero faults/cancellations, and one expected exit from the
completed SYSTEM initialization task. QEMU and Duo default DHCP/iperf3 builds
still pass; their placement feature remains disabled.

## Control-lock scope experiment

Releasing the control lock after every TX and RX packet measured 493.43 /
366.47 Mbps over 15 seconds, a substantial reverse regression. That TX change
was rejected. Keeping the original TX batch and releasing only between RX
frames measured 491.36 / 529.77 Mbps over 15 seconds, then 494.07 / 530.15 Mbps
over separate 60-second tests (`rx-lock-sustained/`). The remaining RX change
keeps descriptor consumption, session stamping, endpoint publication and rearm
inside one critical section. The per-turn packet limit is unchanged.

The retained candidate FIT SHA-256 is
`8320371ffc2506f8f152e1a998f30ec6105a03ed1556d10344de987df01050ed`.
The rejected candidate, source patch and timing analysis remain archived under
`packet-lock-*`; it must not replace the retained image.

A separate reverse run captured only test-peer TCP port 5201 headers, with
128-byte snapshots and a ten-second capture limit. tcpdump reported zero kernel
capture drops. Wireshark 4.4.5 analyzed approximately 8.6 seconds of the data
connection (486,003 packets) without retransmission, zero-window or window-full
flags. The host advertised a median receive window of 2,571,904 bytes.
These are capture-interval heuristics, not whole-run loss qualification. ACK
timing at this receiver-side capture point is not the board's full software RTT.
See `rx-lock-tcp-analysis.json` and `rx-lock-capture.log` for the raw analysis.

The approximately 900 Mbps target remains open. Network diagnostic timing is
still enabled in these experimental payloads. Three cold boots, link recovery,
and one hour of concurrent network/storage/WASM testing remain separate
acceptance requirements. TRNG protocol probing does not qualify entropy and
these images do not enable SSH.

## Driver and platform speed compilation

Compiling `vibeos-eqos-net`, `vibeos-platform-jh7110` and the Mars firmware at
release opt-level 3 instead of z measured 575.53 Mbps host-to-board and
640.17 Mbps board-to-host in separate 60-second single-stream tests. The previous
RX-lock baseline measured 494.07 / 530.15 Mbps. DMA PBL and AXI limits remain at
the baseline values; runtime AXI readback was `0x0002000e`. The candidate also
contains the new AXI readback guard/diagnostic from the preceding experiments.
No ownership checks, cache barriers, or capability checks were removed.

FIT size grows from 3,830,624 to 4,080,480 bytes. Candidate FIT SHA-256:
`2513d2dad5e4b6e1a0c7c0bc14f197bd4b75fa1f07b4762963d49f6d3bc3c3a4`.
SD image SHA-256:
`9d181894eb8cdf22612527e32da19c183ea24fb87666fbb2ef0c6034761461bf`.
Artifacts are under `target/mars-boot-20260913-gigabit-driver-speed/out/`.

The EQoS/JH7110 release host tests passed 71 checks and the real-board selftest
passed 395 checks. Before fault-injection selftests, every component remained
running with zero faults/cancellations and one expected bootstrap exit. Netstack
live memory was 2,105,216 bytes with no quota denials. Logs and throughput JSON
are under `target/mars-acceptance/20260913-gigabit/driver-speed-*`.

The board runs this candidate from RAM; SD contents remain unchanged. These
measurements do not establish long-duration stability, SSH entropy qualification,
or attainment of the 900 Mbps objective.

## Rejected whole-kernel speed experiment

Adding opt-level 3 for the entire kernel increased FIT size to 4,825,952 bytes
and measured 491.40 / 596.08 Mbps in separate 60-second tests, below the retained
driver-speed candidate's 575.53 / 640.17 Mbps. The kernel-only override was
removed. Candidate FIT SHA-256:
`876c202f308c115b5b493f1cf0fed2d45468dc40eae1599eb54ad77b43a3c82e`.

QEMU/Duo DHCP/iperf3 build checks passed. QEMU four-hart DTB boot and 390
selftests passed. On Mars, the selftest reported 391 passed / 4 failed in the
ready-task cancellation test: the freshly spawned task was polled and faulted
before cancellation took effect. This observation is not yet classified as a
test timing assumption or an executor defect; it remains an investigation item.
No faults occurred during the throughput test before the deliberate selftests.
The previous driver-speed FIT was selected for recovery. Logs and source patch
are retained under `target/mars-acceptance/20260913-gigabit/kernel-speed-*`.

## Multi-hart cancellation test precondition

The ready-task test now pins its probe to the caller's logical hart and cancels
it before yielding. An ordinary untracked task is stealable, so the previous
test could legally lose its “never polled” precondition before cancellation.
No executor cancellation behavior or cancellation assertions were weakened.
A deterministic host test dispatches a remote hart between spawn/cancel: the
ordinary task is polled once, whereas the pinned task remains unpolled and
terminates as Cancelled. All 106 executor host tests passed.

The retained driver-speed configuration plus this test correction booted on
Mars and passed three consecutive selftests, each 395 passed / 0 failed.
FIT SHA-256 `58794ec49faf5ecc876af84deae2034038412173e57a8bacfe7980f750933352`.
Artifacts: `target/mars-boot-20260913-gigabit-cancel-ready/out/`; evidence:
`target/mars-acceptance/20260913-gigabit/cancel-ready-*` and
`target/mars-reference/20260913-cancel-ready-runtime.log`. This validates the
ready-state test setup; it is not a general proof of all concurrent cancellation
interleavings or complete Mars hardware qualification.

## Rejected pressure-only TX reap experiment

Moving per-frame TX reclaim to ring-pressure only (while retaining the driver
batch's before/after reclaim) measured 565.48 / 637.14 Mbps over separate
60-second runs. This did not improve on driver-speed's 575.53 / 640.17 Mbps.
The ring change was reverted, preserving earlier per-frame completion/error
observation. No DMA ownership checks or publication barriers were removed by
the experiment. The 41 EQoS model tests and 6 firmware engine tests passed;
pressure reclaim and completion-error admission were exercised. During real
traffic all tasks remained running, with zero faults/cancellations and no
quota denials. These tests do not prove physical error recovery for this
experimental policy, which was not retained.

FIT SHA-256 `17f62f6e150cc6f811f2f100f092be7f7ccda865a93edfca2a0a5f95b0ddbb63`.
Source patch and results are under
`target/mars-acceptance/20260913-gigabit/tx-batch-*`.

## TX checksum insertion experiment

The EQoS hardware reports TXCOE; the opt-in `tx-checksum-experiment` composition
uses Full CIC for ordinary complete IPv4/TCP/UDP and software fallback for
unsupported packet formats or hardware. DMA was already active before this
experiment. RX checksum verification remains in software. The default Ethernet
composition keeps TX software checksums until a faster implementation is
qualified.

FIT SHA-256 `50f6f370635c114cf0af89e5250d3a68a06cbfe4aeb52c7ebf70257c8822c710`
booted successfully after a physical power cycle. All 364,377 captured
board-origin TCP packets have verified Good IPv4 and TCP checksums; maximum IP
length is 1500, snaplen retains complete packets, and tcpdump reports zero
kernel drops. This does not qualify UDP, recovery, or long-term stability.
Separate uncaptured 60-second tests measured **496.81 / 492.01 Mbps**
(host-to-board / board-to-host). Task health reported zero faults/cancellations;
software reboot returned to U-Boot. This is functional offload evidence but
not a performance improvement. The experiment adds a full scratch copy and
repeated packet preparation, which are candidates for removal before retesting.

Evidence: `target/mars-acceptance/20260913-gigabit/tx-checksum-*`. The board was
then RAM-booted into the retained `cancel-ready` software-checksum baseline for
a same-session comparison; SD and SPI contents remain unchanged.

The same-session software-checksum baseline measured **541.99 / 628.96 Mbps**
over separate 60-second single-stream runs, versus the experiment's
496.81 / 492.01 Mbps. Both runs used the same board, host, MTU and direct link;
no capture ran during these measurements. Baseline task health also reported
zero faults/cancellations. The experiment therefore remains opt-in and the
board remains on the `cancel-ready` baseline. This pair is a regression signal,
not a statistical estimate; it does not establish which added operation caused
the loss. Raw baseline results: `tx-checksum-ab-baseline-60s/summary.json`.

## Borrowed TX request follow-up

The follow-up binds validated header offsets to an immutable packet borrow,
parses once, and submits ordinary zero-checksum IPv4/TCP/UDP without an extra
packet copy. Software/nonzero-field fallback retains a separate scratch path.
DMA payload copy, cache synchronization, OWN publication, completion and queue
limits remain unchanged. The request cannot be paired with different bytes.

49 EQoS model tests, 6 packet-engine tests, driver-boundary checks and the Mars
SD/FIT build passed. FIT SHA-256:
`9e9fb7248d9738a6febf31cefdc309ad206ab41d3678cf1720815706425ab13e`.
The RAM-booted image established DHCP and a 1000 Mbps full-duplex link. All
448,319 captured board-origin IPv4/TCP packets have Good checksums, with maximum
IP length 1500 and zero capture kernel drops. Captured 15-second reverse
throughput was 633.17 Mbps; do not compare this directly to uncaptured 60-second
measurements. Evidence prefix is `tx-borrow-*` in the gigabit directory. The
default Ethernet composition still leaves TX offload disabled.

Uncaptured separate 60-second tests measured **534.50 / 632.39 Mbps**, restoring
most of the earlier copy regression but not materially improving the
same-session software-checksum baseline (541.99 / 628.96 Mbps). Task health
before fault injection reported zero faults/cancellations. The physical system
selftest passed **395 / 0** on this image. The remaining throughput gap cannot
be attributed solely to software TX checksum calculation. RX verification,
cache maintenance and service scheduling remain candidates for profiling.
This image stays experimental and does not constitute full Mars qualification.

Post-selftest 5-second smoke tests completed both directions (562.15 / 636.36
Mbps). These confirm fresh connections after deliberate selftest faults, not
physical cable recovery or long-duration stability. The board remains RAM-booted
on the borrowed TX experiment; SD is unchanged.

## RX hardware status diagnostic

The opt-in diagnostic enables MAC IPC after RXCOE admission and readback, while
keeping the stack's RX software checksum checks. It adds a same-frame metadata
receive path with word-1 validity and OWN gating. Default receive does not read
that extra word. 53 EQoS tests, 6 firmware tests, boundary checks and the full
SD/FIT build pass. Physical selftest passed 395 / 0.

Ten-second TCP smoke throughput was 566.35 / 626.90 Mbps. This diagnostic is
not a speed optimization yet. Normal traffic yielded over 513,000 IPv4 status
observations with zero reported checksum errors. Twelve injected UDP packets
cover valid, bad IP, bad UDP and absent IPv4 UDP checksums; full outgoing
capture verified those values. Six additional IPv4 observations were returned,
but no checksum-error status. MAC versus descriptor-level dropping of bad
frames is not yet isolated; software RX verification stays enabled.

FIT SHA-256 `8eeb07c17b2c54c80f262e61e3721816b585e884bac661c9365254044769e512`.
Details and evidence are in `LINUX-NETWORK-COMPARISON.md` and the
`rx-status-*` / `rx-checksum-injected*` artifacts. SD/SPI are unchanged; the
board runs this diagnostic from RAM. Neither experiment is enabled by default.

## RX error-path qualification

Paced valid/bad-IP/bad-UDP/zero-UDP probes with default MAC error dropping
produced no rejected DMA descriptors. Enabling diagnostic error forwarding
then produced exactly six checksum-error observations, without descriptor
error summary. This explains the previous zero-error counter and establishes
that RX offload must inspect word-1 checksum flags separately.

The firmware now drops such errors before delivering frames; its new model
test proves both IP and UDP cases plus subsequent good reception. This last
change is host-tested only (7 engine tests; 56 EQoS tests). No new throughput
claim is made in this phase and software RX verification remains enabled.
The controller's default pre-DMA error dropping is restored after diagnostics.
Details, FIT hashes and packet evidence are in `LINUX-NETWORK-COMPARISON.md`.

## RX verification enabled for the IPv4 experiment

The opt-in complete IPv4 + ARP profile now uses admitted matching TCP/UDP
hardware metadata and software verification for unverified/unsupported IPv4
formats. Other EtherTypes and fragments are not admitted by this experimental
profile; the default Ethernet composition is unchanged. Error observations are
dropped before delivery even without descriptor ES.

FIT `414e8d843e399dd46d0841dc5e8b58380bbba119ccc1fdfef7529e3a328623d7`
booted and passed DHCP. Fifteen probes exercised six hardware verifications,
three IP-options software fallbacks and six bad-checksum drops. No bad-group
ICMP response was captured. The experiment measured **520.69 / 630.76 Mbps**
in separate 60-second single-TCP tests, and passed physical selftest **395 / 0**.
This is functional RX offload evidence, not a demonstrated speed improvement.
Source now also repairs TX-offloaded ICMP inner IPv4 headers; that last change
is host-tested only (61 EQoS tests, 8 engine tests for RX integration).

Artifacts are `rx-verify-*` under the gigabit evidence directory. The board
runs this experimental FIT from RAM, with diagnostic error forwarding and
explicit software rejection enabled. SD and default build flags are unchanged.

## Executor profiling control and ICMP repair verification

The `no-exec-profile` experiment removes only the kernel executor-profile
feature while retaining driver profiling and the same TX/RX/error-forwarding
experiments. FIT SHA-256:
`a967acc59d165de03544ccc4863d58c9854b1461a4db687e84e3f20c9cdf4142`.
The payload contains no EXEC_PROFILE marker but retains MARS_NET_PROFILE.
This image also incorporates the ICMP quoted-header repair. All eight captured
ICMP responses have valid outer IPv4, quoted inner IPv4 and ICMP checksums.
No response to either bad-checksum probe group was captured; hardware/software/
drop counts again reached [8,3,6] from [2,0,0].

A next candidate is RX rearm cache maintenance: the concrete pool copy_rx only
reads the DMA source, yet arm_rx flushes the entire buffer again. Any optimized
reuse path must prove initial full preparation, no CPU writes or writable
aliases, safe handling of speculative clean lines, completion barriers, and
normal post-DMA invalidation before each later CPU read. Default backends must
retain conservative synchronization. No cache barrier has been removed yet.

### Patterned payload integrity

`sudo python3 scripts/mars-dma-integrity.py --address <observed-board-ip>
--output <new-summary.json> --count 4096` sends bounded IPv4 ICMP echo traffic.
It changes every payload using a sequence-seeded SHAKE-256 stream and alternates
1 through 1472 payload bytes, including cache-line boundaries and maximum MTU.
Each reply must match the complete payload and pass the ICMP checksum. Three
consecutive timeouts or one corruption ends the test; output records partial
progress. It exercises stack + RX + TX together and cannot attribute an error
to DMA alone. A pass is not a sustained-load or multi-core coherence proof.

The first probe of the preceding recycle image timed out because smoltcp was
built without `auto-icmp-echo-reply`; ordinary ping also timed out while UART
and receive counters continued. The shared protocol composition now enables
echo replies. A host stack test checks short, boundary and MTU payloads plus
rejection of invalid ICMP checksums. Rebuild the image before using this test.

The ICMP-enabled RX-recycle image (`a0dd38903173c20a26541cccea2fc6981256c27c8460ec4a3287a1291025255b`) passed the
4096-packet patterned test in 12.67 seconds with no timeout, corruption or
unrelated response. Driver software verification increased by exactly 4096.
Results: `target/mars-acceptance/20260913-gigabit/rx-integrity-4096.json`.
The original timeout evidence remains preserved separately; it is not counted
as a successful test or a demonstrated DMA failure.

The same image measured 559.84 / 634.46 Mbps in one uncaptured 60-second
TCP pair. A separate concurrent TCP + 8192-pattern test did **not** pass:
8186 payloads matched exactly, six requests timed out and no corruption was
observed. RX software verification increased by 8186 during that test,
consistent with missing requests before verification; this does not establish
whether the host/link, hardware FIFO/ring, or a software queue lost them.
TCP completed both directions (560.09 / 626.85 Mbps under this mixed workload).
Kernel selftest passed 395/0. Keep recycle opt-in until the loss path and
repeat A/B comparison are resolved. See `rx-integrity-concurrent-*` evidence.

### Larger-ring burst experiment

`dma-ring128-experiment` selects 128 slots instead of 32 for both directions
of the existing EQoS layout. Static DMA storage grows from 102400 to 409600
bytes. It does not alter protocol endpoint queue capacities or service poll
budgets; HAL queue size reports actual hardware ring capacity. Initialization
logs `MARS_NET_RING` so the loaded image's selection is observable. Default
remains 32 pending the controlled hardware comparison. Test with the same
TX/RX checksum and read-only recycle flags as the diagnostics baseline.

The ELF verifier now admits exactly the two composed ring sizes (32/128),
reports `eqos_dma.ring_slots`, and still rejects misalignment, truncated slab
reservation, incomplete writable load backing, and addresses outside the
controller's 32-bit DMA region. Its five image-contract tests include malformed
larger-ring images. This updates an explicit layout assumption; it does not
turn a successful image check into physical qualification.

The 128-slot image FIT SHA-256 is
`da2789d2b0b128d032ac21e6d0a6632a66418abeba126adcb8d49f1dfc75791c`.
Boot logs confirm 128 slots / 409600 bytes. Under the same mixed workload,
8191/8192 replies arrived with exact payloads and valid checksums; one
request (sequence 3680) had no captured reply. No capture drops or >2-second
late replies occurred. RX unavailable and MTL overflow stayed clear, unlike
the 32-slot diagnostics run. Software RX verification counted all 8192
requests. This is improvement, not a complete loss-free qualification.

Code inspection found a remaining policy-layer discard: `driver_turn` reads
and rearms DMA before `send_inbound`, then drops the packet on `QueueFull`.
Bounded pending ingress with preserved session stamps is the next candidate;
this observed path has not yet been proven responsible for this exact timeout.

The 128-slot uncaptured 60-second TCP pair measured 578.53 / 624.59 Mbps
(host-to-board / board-to-host). Selftest passed 395/0; the following status
snapshot still had RX unavailable and MTL overflow clear. Keep this as the
comparison baseline for the pending software ingress backpressure fix.

### Bounded ingress backpressure

The kernel packet adapter now retains one stamped ingress frame if the
protocol endpoint is full, and does not consume more DMA RX until it is
delivered or retired. TX remains serviced each driver turn. Retry keeps the
original device/stack stamp, validates the current binding under CONTROL,
and rechecks endpoint authority. Stale frames are retired and counted; a
revoked endpoint terminates the owner without publishing its retained frame.
The retained frame is fixed-size task-local storage, not an unbounded queue.

Host regression covers repeated full-queue retries, exact-once delivery when
space returns, stack rebinding, device reset/detach and revocation on retry.
The 23 core network tests passed. This closes a concrete discard path but
requires physical load comparison before attributing prior ICMP loss to it.

The bounded-ingress fix FIT
`3543b060d27cfe25fc5871302e8f04b965d051ddf53481152dc7b8b8d9c9b6c8`
passed the mixed 8192-pattern test with zero timeout/corruption. Capture
confirmed 8192 requests and 8192 valid replies, max RTT21.40 ms, zero capture
drops. RBU occurred but MTL overflow stayed clear. Selftest passed395/0.

Pure TCP measured536.85/610.64 Mbps, below the previous128-slot578.53/624.59.
The implementation currently moves each fresh frame through the pending slot
before enqueue. The next optimization will attempt direct enqueue first and
retain only on actual backpressure, preserving original stamps and authority
checks. The performance cause is not yet isolated; do not claim this fixes
throughput or that one loss-free bounded test is long-duration qualification.

### Direct ingress before retention

Fresh ingress now attempts direct enqueue under the same session lock and
per-invocation endpoint authority check. Only a full queue writes the pending
slot. Existing pending frames still use exact-stamp retry validation. The
24 core network tests include direct-to-full-to-retry transitions and stale
or revoked fresh submissions.

The RAM image FIT SHA-256 is
`4fdebac4c6dad2a1701f680458dd4ef97c7c57dab54d94e074e9487aebf2c792`.
Mixed-load capture verified all 8192 requests/replies, exact payloads, no
timeouts or bad checksums, max RTT 21.38 ms, and zero capture drops. DMA RBU
and MTL overflow remained clear. Mixed TCP measured 564.41 / 621.68 Mbps.
The shared worktree also contains ongoing universal platform/configuration
changes; retain source snapshots and avoid treating this as isolated proof
of the optimization's throughput contribution.

Direct ingress pure TCP measured 579.60 / 619.89 Mbps in one 60-second pair,
restoring RX throughput relative to the first retained-ingress implementation
(536.85 / 610.64). Selftest passed 395/0. The next candidate is TX descriptor
publication: pinned U-Boot `drivers/net/dwc_eth_qos.c` writes payload fields,
orders them with `mb()`, then writes OWN and flushes the descriptor once. Our
shared publication currently flushes before and after OWN. Any experiment
must preserve payload visibility, OWN-last order, completion proof and tail
ordering; do not infer RX safety from that TX-only reference path.

### Single TX descriptor synchronization experiment

`tx-single-sync-experiment` selects the opt-in Ring publication mode before
DMA starts. TX data synchronization stays unchanged. Descriptor fields are
written before a backend barrier, OWN is written last, and the full isolated
descriptor line is synchronized once before the final barrier and tail MMIO.
RX retains both descriptor synchronizations. A live or quarantined ring
cannot change this mode; default remains conservative.

The reference is pinned SDK `u-boot/drivers/net/dwc_eth_qos.c`, whose TX
path orders fields, OWN and one descriptor flush in that sequence. This is
not permission to remove payload synchronization or weaken the Backend's
cache/order contract. Model coverage checks the complete publication trace,
no overwrite when full, unchanged RX synchronization and configuration only
after proven stop. Eight firmware packet tests also passed. Hardware
throughput and corruption/loss checks remain separate qualification gates.

Hardware evidence for the single-TX-sync image (FIT SHA-256
`c0cf52ad305b010ba618aa41f96d723979f658a3674c92c43d751b80c6b81d4a`)
is under `target/mars-acceptance/20260913-gigabit/20260914-tx-single-*`.
One 60-second TCP pair measured 583.44 / 623.45 Mbps (host-to-board /
board-to-host), less than 1% above the preceding direct-ingress pair;
this does not establish a repeatable throughput improvement.
Mixed-load integrity verified 8192/8192 exact payloads and captured replies,
no timeouts or bad checksums, maximum RTT 21.17 ms. A separate 30-second
reverse-only TCP load covered the entire additional 8192-probe run:
8192/8192 verified, no timeouts or bad checksums, maximum RTT 20.71 ms,
zero capture drops, receiver throughput 635.06 Mbps. These are bounded
integrity results, not long-duration qualification.

Selftest passed 395/0. A subsequent five-second pair fell to 492.69 / 403.22
Mbps; the later reverse load recovered to the above result, so throughput
variability remains unresolved. Serial observation after the pure TCP pair
showed DMA status `0x00000c84` and MTL interrupt `0x00010000`: RX buffer
unavailable and FIFO overflow flags were set, despite remaining clear during
the earlier mixed capture. These are sticky flags, not event counts, and
cannot identify the exact failing packet or interval. The experiment stays
default-off; 900 Mbps and complete Mars qualification remain unachieved.

### Receive directly into owned packet storage

`Packet::receive_with` provides a fixed-size initialized destination to the
firmware receive operation, validates its optional returned length and clears
the unused tail. The DWMAC policy adapter now receives directly into this
packet instead of receiving into a temporary array and copying the complete
frame again. DMA-to-CPU copying and synchronization remain in the firmware;
this is not a zero-copy DMA contract. Session locking, stamp validation,
one-frame bounded retention, and per-invocation authority checks are unchanged.
Host network coverage passes 25 tests, including producer writes beyond the
returned length, no frame, invalid lengths, and prior session/backpressure tests.
Hardware performance remains to be measured for this candidate.

The direct-fill RAM image FIT SHA-256 is
`1d0ddff086567034802d5ff20590b2f43b84685f12d44854ddd22ef99f599bfa`.
A 60-second single-stream pair measured 594.58 / 615.94 Mbps versus
583.44 / 623.45 in the preceding single-TX-sync image. RX improved 1.9%
and TX decreased 1.2%; this pair does not establish an overall speedup.
Mixed-load integrity verified 8192/8192 exact payloads and captured replies,
no timeouts or bad checksums, max RTT 21.28 ms and zero capture drops.
DMA status remained `0x00000c04` and MTL interrupt status zero in the
collected pure/mixed logs, including the state after both pure directions.
This bounded absence of sticky errors does not prove loss-free operation
under every load. Source snapshots and raw evidence use the prefix
`target/mars-acceptance/20260913-gigabit/20260914-rx-fill-*`.
