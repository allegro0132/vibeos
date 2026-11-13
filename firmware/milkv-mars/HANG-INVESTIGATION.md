# Mars hang investigation

## Established symptom and unresolved cause

The loss of both UART command responses and network connectivity has been
reproduced repeatedly. This is a reproduced liveness failure, not merely a
hypothetical hang. Its execution location and root cause have not been captured;
no fix is established. Short passing runs must not be described as disproving
the reproduced failure.

For the latest uninstrumented prefix-candidate boot, retained bootlog entry_ticks
was 42433783. The final successful read was saved at 2026-09-23 20:08:09 +08:00.
The subsequent UART check captured zero bytes; TCP 5300 and 5201 were confirmed
unreachable by 21:59:31 +08:00. These host file modification times bound evidence
availability, not the exact board failure instant. The intervening interval was
not continuously captured. Raw evidence and timestamp qualifications are in
`target/mars-reference/20260923-hang-evidence-timeline.json`.

Observed exclusions are limited:

- Both single- and four-flow transfers can pass before a later idle failure.
- Closing UART is not a deterministic trigger: six TCP checks and a same-boot
  UART reopen passed during one closed-UART interval.
- A same-source lock-probe image passed load and short idle tests without a
  `LOCK_STALL`; this does not exclude a timing-sensitive deadlock or failure
  where SBI output is also unavailable.

## Prepared execution evidence

The default-off `lock-stall-probe` now reports prolonged PLIC dispatch loops and
UART RX draining as `LOOP_STALL`, in addition to contended locks. Reports include
hart, elapsed ticks, iterations, and IRQ; they never log UART input bytes. This
is instrumentation, not a fix. It cannot observe a single nonreturning MMIO
access/callback and its SBI output can also block.

Prepared, not yet loaded:
`target/mars-boot-20260921-bootlog-hangloops-20260923/out/artifacts/vibeos.itb`

SHA-256: `790d48224b9697c58ea007d46239f8192ea4b62212d281bf1aff376a3c465fb3`.
Detector tests, target compilation and image checks passed. Exact source/ELF and
feature manifest accompany the image in `target/mars-reference/`.

## Continuous capture

`scripts/mars-hang-capture.py` preserves raw bytes, per-chunk byte offsets and
wall/monotonic timestamps, independent timestamped ICMP outcomes, and final
file hashes. It writes no UART input and performs no reset. Only one UART reader
may run. The capture has a bounded lifetime (up to one hour); use `caffeinate -is`
on this host. Never start it concurrently with the RAM loader. Simulated PTY
validation preserved binary boot/error bytes exactly and verified lengths,
metadata and hashes. A silent capture records missing output; it does not prove
where the board stopped.

Next hardware run must preserve the entire boot/load/test/long-idle interval,
with at least one hour of passive observation after workload, and retain output
after the first failed liveness check. Short samples alone missed the observed
failure window. Recovering the already inaccessible board is required to load
new instrumentation; resetting discards the current RAM log. Do not describe
repeated timeout probes as execution-location evidence.

The bounded `20260923-hang-continuous-evidence` launch never executed: elevated
access approval timed out twice. A least-privilege attempt then failed at serial
open with EPERM; its zero-byte file is a HOST permission failure, not evidence
of another board hang. No reader remains live from these attempts. Explicit
user guidance to retry access has been requested.

The prepared `target/mars-reference/ramboot-20260923-loop-stall-long.py` extends
the loader with timestamped serial chunks across boot/load/workload and 60
one-minute idle windows. ICMP status is saved after each window, failures do
not abort capture, and final serial timeout retains another minute. It has been
syntax-checked but not executed. `20260923-hang-evidence-manifest.json` hashes
the existing successful/failed observations, separate from this unrun plan.

## Approved capture and loaded diagnostic

After explicit user confirmation, passive capture ran for 180.126 seconds and
retained 3,464 UART bytes, per-chunk timestamps, ICMP results and hashes in
`target/mars-reference/20260923-hang-approved-capture/`. Logger/guest heartbeats
were present while ICMP timed out. A subsequent command returned `unknown
command: bootlog`; therefore continuity with the previously loaded candidate
cannot be established from this running firmware. This observation must not be
misclassified as another simultaneous UART/network hang.

The extended loop diagnostic FIT above has now been successfully RAM-loaded,
with both FIT hashes verified and a gigabit link. Single/four-flow workloads
exited zero. A one-hour idle capture is running in the same serial session;
completion is not yet claimed. Authoritative live process handle: exec session
38279. Output directory: `target/mars-reference/20260923-loop-stall-long-run/`.
`run-info.json` preserves image/script identity and the state when recorded;
`serial-full.log`, `serial-chunks.jsonl`, and `idle-network.jsonl` are live data.
A future continuation must poll that process, not launch another UART reader.

## Completed one-hour run analysis (2026-09-24)

Exec session 38279 returned exit code 0. The 60 ICMP samples from September 23
23:17:22 to September 24 00:16:23 (+08:00), spaced 60.010–60.028 seconds apart,
all succeeded. RTT min/median/max was 0.611/1.578/2.392 ms. Final bootlog returned;
entry_ticks remained 42634746 and its clock advanced 3663.624 seconds since the
first bootlog. No LOCK_STALL, LOOP_STALL, panic or assertion marker was captured.
All 12,841 raw UART bytes are covered by contiguous timestamped chunk records.

Before idle, independent byte-count tests confirmed 2 GiB in each run:
948.115 Mbps single-flow and 785.403 Mbps aggregate four-flow. These were not
pattern-integrity or CPU-cost tests. Port 5300 reuse took 7874.600 ms to become
application-ready, while the fresh ports took 4.926–5.286 ms. This repeated
setup-delay symptom is distinct from total loss of board liveness; no causal
link to the hang has been established.

Conclusion: no observed hang during this diagnostic boot and sampled idle
interval. Earlier reproduced hangs remain unresolved. Sparse ICMP cannot
exclude transient stalls between checks; added instrumentation can affect
scheduling/layout. This is not a one-hour concurrent-workload qualification or
a proof of repair. The final process result does not establish current board
liveness after capture ended. Machine-readable results and immutable-file
hashes: `20260923-loop-stall-long-run/analysis.json` and `final-manifest.json`.
The next discriminating comparison is a longer same-source uninstrumented idle
run with the same continuous capture/host wake settings, rather than changing
network parameters based on this passing diagnostic run.

## Connection-delay explanation and longer control (2026-09-24)

Re-running the existing host regression
`pending_handshake_can_precede_application_admission_during_time_wait` passed:
wire handshake 2 ms, application wait 7800 ms, 9802 ms since the prior-close
observation. smoltcp `CLOSE_DELAY` is 10,000 ms; `ensure_listening` promotes the
pending socket only after the old active socket becomes LISTEN again. The old
socket stays TIME-WAIT until its timer expires. This explains the roughly
7.9-second port-reuse delay without an unbounded wait or held lock. It is not
evidence for the global hang; reducing that timeout would not be a justified
hang fix. Evidence: `20260924-timewait-admission-test.log`.

A fresh bootlog of the diagnostic image returned entry_ticks=42634746 and
now_ticks=26982981333 (same boot, about 112 minutes after entry). This extends
observed endpoint liveness, not continuous monitoring beyond the archived hour.
The diagnostic was then replaced in RAM with the exact previously failing
uninstrumented prefix FIT. Both component hashes and boot/link passed; single
and four-flow clients exited zero. The same continuous timestamped UART capture
and awake-host conditions now cover 120 one-minute idle windows. It is RUNNING,
not yet a passing control. Process: exec session 96496. Evidence directory:
`target/mars-reference/20260924-hang-control-two-hour-run/`. A continuation must
poll this process before opening UART. See `run-info.json` for FIT/script hashes.

## Uninstrumented control reproduced loss (2026-09-24)

Exec session 96496 ended with exit code 1 at the final bootlog timeout, after
retaining another minute of UART capture. Both preceding 2 GiB byte-count
workloads passed (single 949.108 Mbps; four-flow aggregate 786.326 Mbps).
The first ICMP check at 01:10:42 +08:00 succeeded; the next, started at 01:11:42,
timed out after two seconds. All remaining checks failed: 1 success, 119
timeouts through 03:13:40. UART was continuously open throughout load, traffic,
idle and failure retention. Closing/reopening UART is therefore NOT a necessary
trigger for this reproduction.

This bounds the onset of observed network loss to approximately one minute;
it does not identify the CPU stop time. Quiet mode was enabled, so lack of
unsolicited serial bytes during idle is expected. Serial unresponsiveness was
confirmed by the final explicit bootlog command, not sampled at the first
failed ping. All 10,660 UART bytes have contiguous timestamped chunk coverage.
No trap/lock reports were captured, but these probes were disabled, so absence
of such reports carries no evidence against deadlock or interrupt livelock.
Host samples continued at 60.008–62.024 second intervals, including the expected
two-second ping timeouts; this provides no sign of a long capture-process pause.
It does not independently exclude every host/adapter/board hardware failure.

Compared with the probe-enabled run (60/60 ICMP success and final same-boot
serial response), this makes timing or image-layout sensitivity worth isolating.
It does not prove that lock instrumentation repairs the bug or identify a
specific lock. Next isolate lock versus IRQ-loop probes and control memory
layout, retaining continuous capture and an execution-location mechanism that
can still report when the dispatch hart stops. Do not treat TIME-WAIT tuning
as a hang fix. Root cause remains unresolved; all processes in this run are
terminal. Full analysis and file hashes are saved in
`20260924-hang-control-two-hour-run/{analysis.json,final-manifest.json}`.

## Independent cross-hart timer watchdog prepared (2026-09-24)

New default-off `hang-watchdog` records each logical hart's last trap timestamp,
interrupted PC, scause, handler stage and IRQ in independent atomics. Each timer
entry publishes its heartbeat and checks peers BEFORE acquiring timer registry,
heap-owner or scheduler locks. A peer with a previously observed timer heartbeat
older than 30 seconds (three idle heartbeat periods) produces one best-effort
`HART_STALL` via SBI, bypassing normal UART/TTY locks. Healthy peer observations
are rearmed by a new heartbeat. Stages distinguish trap entry, timer, PLIC loop,
IRQ callback, trap return and synchronous exception.

This is not a current-PC dump, not a transactional snapshot, and not recovery.
It cannot diagnose a core that never reached its first timer, nor guarantee any
output if every hart, the bus or SBI console is stuck. It adds timing/layout
perturbation. Timer stalls can be evidence without proving a particular lock.
The new diagnostic deliberately enables this feature WITHOUT lock-stall-probe
to separate the mechanisms. No runtime forced unlock, reset or device masking
was introduced.

Three host tests passed: uninitialized/future/recent samples, report suppression
and recovery rearm, concurrent observers claiming one report. Target release
build/image checks and FIT packaging passed. Exact ELF, symbol map, source and
feature manifest were archived. FIT:
`target/mars-boot-20260921-bootlog-hartwatch-20260924/out/artifacts/vibeos.itb`,
SHA-256 `b619a9f4bea6f4374e7e5a5f81cf4723ad2dd7a64524d337785a88789b4de193`.
Prepared loader `ramboot-20260924-hartwatch.py` retains continuous timestamped
UART and two-hour idle evidence. Not yet loaded or hardware-qualified. Ordinary
firmware feature selection restored. Board was still unresponsive at initial
preload probe; physical recovery requested. Hang root cause remains unresolved.

## Cross-hart diagnostic live run started

After the user's `ready`, `ramboot-20260924-hartwatch.py` loaded the archived
b619a9f4... FIT into RAM, verified both component hashes and reached four-hart
boot admission and gigabit link. Single/four-flow clients exited zero. The
same timestamped UART owner is now collecting 120 one-minute idle windows;
this is RUNNING, not a passing result. Process handle: exec session 12168.
Evidence: `target/mars-reference/20260924-hartwatch-run/`, including image/script
identity in `run-info.json`. Boot entry_ticks=41836890. No second UART reader
may be opened while this process runs. Cross-hart watchdog is enabled; the
older lock/loop probe is disabled. No SD/SPI write occurred.

### ELF layout comparison during capture

Read-only comparison saved in
`target/mars-reference/20260924-hang-layout-comparison.json` confirms the
cross-hart diagnostic and failing uninstrumented control share DMA base
`0x40e80000`, stack bottom `0x41515000`, heap start `0x41614000`, and text,
rodata, data and BSS section start addresses. TIMERS and SCHED also retain
their addresses. Some individual data/BSS objects differ; this is not an
identical-layout experiment. The older lock/loop diagnostic shifts DMA,
stack and heap by 4096 bytes. Thus the live cross-hart comparison removes
that particular page-shift confounder, but cannot eliminate timing or other
layout effects. First six idle ICMP probes succeeded; no HART_STALL, panic
or assertion marker observed at this interim check. The run remains active
and root cause remains unresolved.

### Read-only lock-path review during the live watchdog run

The inspected `timer_tick_at` path removes a due entry under TIMERS, then
releases that guard before invoking its waker. `WaitQueue::wake_all` similarly
takes the waiter vector under its queue lock and invokes wakers afterward.
`ReceiveEndpoint::retire_queued` dequeues before invoking the firmware discard
operation. These observations do not establish an absence of deadlocks in
other paths. In particular, batch receive admission intentionally invokes
firmware acquisition while holding its queue admission guard and still needs
an end-to-end reverse-order audit. SpinLock disables local interrupts before
spinning; a common global-lock blockage can therefore stop all timer observers
before the watchdog's 30-second threshold. No HART_STALL cannot rule this out.
No speculative locking or timing change was made during capture.

## Watchdog positive-control image prepared (2026-09-24)

Separate default-off `hang-watchdog-selftest` forwards through Mars/kernel/core.
On logical hart 1 only, 60 seconds after its first timer entry, it emits
HART_SELFTEST_BEGIN and spins for 45 seconds once, then emits HART_SELFTEST_END
and resumes ordinary timer handling. The injection occurs in the watchdog hook
before registry/scheduler locks. It does not reset or unlock any resource.
Other harts should report target logical hart 1 with stage 2 and timer age at
least 30 seconds. This is a positive control for one stalled hart and SBI
reporting, not a test of the all-hart/global-lock blind spot or a hang fix.
Normal firmware excludes the selftest feature.

Target release build and image checks passed; FIT and dirty source archive
were saved. Ordinary Ethernet feature selection was restored. FIT:
`target/mars-boot-20260921-bootlog-hartwatch-selftest-20260924/out/artifacts/vibeos.itb`
SHA-256 `51b3ac26dc7e7cdaebaa57fe302fbd60e43bbfdfc2a4da50b9dfd75d851bd041`.
Build/package logs: `target/mars-reference/20260924-hartwatch-selftest-{build,package}.log`.
This image has NOT been loaded or hardware-validated. The independent original
watchdog run remains live in session 12168, with 93 successful idle probes at
this checkpoint. The host build ran during that run's idle observation phase;
no board command, firmware replacement, SD or SPI write occurred.

Prepared (syntax checked, NOT executed)
`target/mars-reference/ramboot-20260924-hartwatch-selftest.py`. It pins the FIT
hash before UART use, retains timestamped serial, observes for 150 seconds
with bounded ping probes, and requests a same-boot final bootlog. Its positive
control gate requires exactly one begin/end and one intervening peer report
for logical hart 1 at timer stage 2, report age >=30 seconds, injected delay
>=45 seconds, final serial response, final ping success and no fatal marker.
An END marker proves exit from the injected delay, not a direct measurement
of the target's subsequent timer progress. Do not run while session 12168
owns UART; this is a separate test after the original run is finalized.

### Additional idle-path audit (live capture unchanged)

`wake_with_disposition` releases SCHED and restores its allocation-owner scope
before invoking the ready-notification hook. Thus that inspected call site
does not hold SCHED across the SBI IPI request. `arm_locked` does hold TIMERS
across SBI timer programming; no evidence currently shows that ecall stalled.

One silent fail-stop path remains a diagnostic candidate: on an SBI IPI error,
`ipi::notify_ready` increments the send-failure telemetry in `ring_armed`, then
calls `arch::shutdown(true)` without printing the error. The RISC-V shutdown
fallback waits forever if firmware reset returns. A returning reset could
therefore strand the caller; firmware shutdown could also stop other harts.
This is a code-path observation, NOT evidence that an IPI error occurred in
the reproduced hang. Capture the target/error before this fail-stop in a
subsequent diagnostic build rather than treating it as a root cause or
silently retrying a failed infrastructure operation. Current RAM image and
ongoing capture were not changed during this review.

The working tree now emits `IPI_SEND_FAILED target_logical=...
target_physical=... error=...` through the watchdog SBI writer before that
fail-stop, only with `hang-watchdog` enabled. It preserves the error's Debug
variant and unknown signed value, performs no retry, and does not change
shutdown policy. Four watchdog host tests passed (including target/error
formatting); RISC-V core check passed with `-Zbuild-std=core,alloc`. Logs:
`20260924-hang-watch-ipi-tests.log` and
`20260924-hang-watch-ipi-target-check.log` under `target/mars-reference`.
This diagnostic addition is NOT in either the live watchdog FIT or the
already-packaged selftest FIT and has not been exercised on hardware. It
still depends on functioning SBI console output.

The separate IPI-reporting FIT subsequently built and packaged successfully:
`target/mars-boot-20260921-bootlog-hartwatch-ipi-20260924/out/artifacts/vibeos.itb`,
SHA-256 `eb928240bd9e956848f5fff3cf22821cc2009c5391c3bb714fb008584258fd56`.
Its feature set matches the original watchdog candidate (no selftest), and
dirty sources were archived as
`target/mars-reference/20260921-hartwatch-ipi-20260924-source.zip` with a source
manifest. Build/package logs use `20260924-hartwatch-ipi-*.log` in that folder.
Ordinary Ethernet selection was restored. This FIT remains NOT loaded. The
host build overlapped idle probes 108–109 of session 12168, another host-load
confounder to retain in that run's limitations; no board commands were added.

### Independent watchdog two-hour run finalized

Session 12168 returned exit 0 after 120/120 successful minute ICMP probes and
a final `bootlog` response. Both headers retain entry_ticks=41836890; the
board clock advanced 7264.5691645 seconds between headers. The raw serial
log contains 12816 bytes with complete contiguous coverage in 230 chunk
records and no HART_STALL/panic/assertion marker. Analysis and hashes are
saved in `target/mars-reference/20260924-hartwatch-run/{analysis,final-manifest}.json`.
This is one successful diagnostic boot, not a fix or evidence against the
already reproduced uninstrumented hang. Host selftest and IPI-image builds
overlapped idle observation. Session 12168 is terminal and UART was released
before starting the separate positive-control selftest session 34459.

### Positive-control hardware result

Selftest session 34459 returned exit 0. Exactly one BEGIN, HART_STALL and END
were captured in that order. Observer logical hart 0 reported target 1 at
timer stage 2 with age 120000015 ticks (30.00000375 seconds at 4 MHz).
The target exited its bounded 45-second delay; final bootlog responded from
the same boot and the final ping succeeded. The first ping timed out, followed
by 29 successful probes; do not describe the entire run as loss-free.
Serial chunk coverage and file hashes are archived with analysis in
`target/mars-reference/20260924-hartwatch-selftest-run/`.
This validates one-hart reporting through SBI on the real board, including
the expected target and stage. It does not validate all-hart/global-lock
detection or prove subsequent timer progress on the injected hart directly,
and is not evidence that the real hang used this mechanism. Root cause is
still unresolved. The selftest RAM image remains booted after the test.

### Failure-only follow-up

Split `hang-failure-report` from periodic `hang-watchdog`: the latter includes
the former, but failure-only builds have no trap/timer sampling hooks. This
keeps the IPI error report while reducing normal-path diagnostic perturbation;
it is not a hang fix. Mars/kernel features forward this default-off option.
The release image and four host reporter tests passed. Feature-tree inspection
shows failure-report enabled and watchdog absent; ELF has no watchdog HARTS,
and binary contains IPI_SEND_FAILED but no HART_STALL or HART_SELFTEST marker.

FIT `target/mars-boot-20260921-bootlog-failure-only-20260924/out/artifacts/vibeos.itb`
SHA-256 `b78899d09d191d74868b6781bad1ab309cbeb5121de2377fba48f6d98fc76ec9`.
Sources and manifests use the prefix `20260921-failure-only-20260924-source`;
build/package/feature/symbol evidence uses `20260924-failure-only-*` under
`target/mars-reference`. The ordinary Ethernet feature line was restored.

Started RAM test session 73349 with
`target/mars-reference/ramboot-20260924-failure-only.py`, preserving a single
UART owner and the same single/four-flow workloads before up to 120 minute
idle checks. Unlike the earlier control, three consecutive ping failures
trigger the final bootlog probe immediately (then another 60-second passive
capture if that command times out). This changes observation only after
network failure and must be accounted for in comparisons. It does not reboot
on failure. Run evidence is in `20260924-failure-only-run`; results pending.

Initial workload clients both exited 0 (single stream 948.522 Mbps, four
streams 790.088 Mbps, byte-count diagnostics only). First minute probe passed.
The failure-only ELF retains the failed control's DMA, stack-bottom,
heap-start, TIMERS and SCHED addresses. Comparison saved in
`20260924-failure-only-layout-comparison.json`; this only checks the named
symbols, not identical code layout or timing.

### Fatal-exception reporting gap found during capture

The panic handler already uses `SbiWriter`, bypassing ordinary UART locks.
The unrecognized synchronous-exception branch in `kernel/src/trap.rs`,
however, used `println!` -> `tty::emit` -> UART TX. A synchronous fault inside
an already-held TTY/TX critical section could therefore deadlock while trying
to print its original cause. This is a concrete reporting-path risk, not proof
that the observed hang was a synchronous exception.

Changed those five fatal diagnostics to the existing SBI writer; trap policy,
Wasmtime dispatch and shutdown behavior are unchanged. Mars target check
passed (`20260924-fatal-sbi-check.log`). This fix is working-tree-only, not in
the running failure-only FIT, and has not been fault-injected on hardware.
SBI/firmware or bus failures can still prevent output. The check ran on the
host during the current idle observation, with no additional board command.

QEMU fault-injection validation now covers this gap. Added legacy acceptance
command `mmu guard fault-tty`: its Display implementation stores to the current
hart's reserved guard page while `tty::emit` holds TTY. Added
`guard_page_tty` input/golden and retained raw guard-case logs. The fixed image
passes both ordinary `guard_page` and `guard_page_tty`; raw output reports
cause 15 and the exact injected guard address plus the guard classification.
For a negative control, only fatal printing was temporarily restored to the
old TTY path: the image reached the injection marker but emitted no fatal
report and the same acceptance test failed. The fixed source was restored
byte-for-byte afterward, and the saved fixed ELF passed a repeated tty case.
Red/green ELFs, raw logs, build/test outputs and SHA-256 evidence are archived
under `target/mars-reference/20260924-fatal-console-*`.

This establishes and fixes the TTY-reentry reporting deadlock under deliberate
fault injection. It does NOT establish that Mars' random hang involved that
fault. No Mars reload occurred; session 73349 still runs the earlier image.

Prepared a Mars image containing the validated fatal-SBI fix plus failure-only
IPI reporting, with the same network feature selection. Release build/image
checks and FIT packaging passed. FIT:
`target/mars-boot-20260921-bootlog-fatal-sbi-20260924/out/artifacts/vibeos.itb`,
SHA-256 `1feb716123e8e3d20250fc55d03b20385530d97b6ea5f207cfbc9e4568a97eda`.
Sources/manifests: `target/mars-reference/20260921-fatal-sbi-20260924-source*`;
build/package logs: `20260924-fatal-sbi-*.log`. Ordinary feature selection was
restored. This image has NOT been loaded; the live failure-only run is not
testing this fix. Its observation window overlapped this host build as well.

Archived-source comparison confirms the failed control and live failure-only
image share root/smoltcp commits and unchanged archived source hashes under
components, drivers, platform, vendor and Mars firmware src. The sole added
Ethernet feature is hang-failure-report. Reconstructed diffs (using the pinned
commit for files absent from a dirty-source ZIP) show the active IPI failure
report plus trap/UART/loop instrumentation gated off in this build; core
feature output confirms watchdog and lock-stall-probe absent. Evidence:
`20260924-failure-only-source-comparison.json` and
`20260924-failure-only-control-code.diff`. This strengthens source-level
comparability but does not prove byte-identical normal machine code or timing.

### Prepared longer fatal-console follow-up (not started)

`target/mars-reference/ramboot-20260924-fatal-sbi-long.py` pins the previously
packaged fatal-SBI FIT (SHA-256 `1feb716123e8e3d20250fc55d03b20385530d97b6ea5f207cfbc9e4568a97eda`).
It retains the same two workloads and single UART owner, extends the maximum
idle observation to 480 minute probes, and still probes bootlog immediately
after three consecutive network failures. This longer window addresses the
previous long-idle observation gap; it is not a claim that eight hours proves
the absence of the fault. Script syntax and FIT hash were checked; no hardware
operation was performed. Start only after session 73349 is terminal and its
logs have been finalized. The current failure-only run remains unchanged.

### Failure-only two-hour run finalized

Session 73349 returned exit 0: 120/120 minute ICMP probes passed and the final
bootlog responded with the same entry_ticks=42264856. Board-clock elapsed time
between bootlog headers was 7264.66417125 seconds. All 12839 raw serial bytes
are covered contiguously by 247 chunk records; no IPI_SEND_FAILED, fatal trap,
panic or assertion marker was captured. Analysis and final SHA-256 manifest
are in `target/mars-reference/20260924-failure-only-run/`. This is a successful
failure-only diagnostic boot, not a fix or a disproof of the earlier hang.
The periodic watchdog was disabled and the later fatal-SBI reporting fix was
not present. Host checks/builds overlapped the observation as recorded there.
The process is terminal and has released UART; the prepared fatal-SBI long
run can now use the port.

### Fatal-SBI longer capture started

Session 44535 runs `ramboot-20260924-fatal-sbi-long.py` under caffeinate. The
pinned FIT loaded via U-Boot/TFTP into RAM, image hashes verified, kernel
network initialization and initial bootlog succeeded. Single-flow and
four-flow workload clients both exited 0. The process now observes up to
480 minute ICMP samples with continuous UART ownership and the previously
specified early-failure bootlog probe. Evidence is being written to
`target/mars-reference/20260924-fatal-sbi-long-run/`; results remain pending.
No SD/SPI writes were performed. The prepared
`finalize-fatal-sbi-long-20260924.py` must only run after session 44535 is
terminal, with its actual exit code. Periodic watchdog remains disabled;
this image includes the QEMU-validated fatal-console fix and IPI failure
reporting, but neither mechanism is established as the cause of the real hang.

Additional read-only timer cleanup review during session 44535: Sleep::drop
and the ready poll path disarm the owned-registration ledger before acquiring
TIMERS; unregister_timer returns the removed Waker and callers drop it after
the TIMERS guard is released. The re-poll replacement likewise drops old and
candidate Wakers after leaving TIMERS. Timer insertion can acquire
IRQ_POLL_PROBE while holding TIMERS, but the reviewed probe arm, clear, sample,
record and completion paths do not acquire TIMERS while retaining that probe
guard (arm releases SCHED before acquiring the probe). No reverse lock edge
was identified in this bounded review. This is not proof against other lock
cycles; arm_locked still invokes SBI timer programming under TIMERS, as noted
above. No board command, source behavior change or host build was added.

Additional fatal-log path review during session 44535: SbiWriter appends each
formatted fragment to the RAM boot journal before invoking SBI putchar. The
journal reserves bounded slots atomically and publishes bytes without taking
TTY, UART, heap or scheduler locks; its reader stops at an unpublished slot
rather than waiting. Consequently a writer fault can hide subsequent journal
fragments from bootlog's committed-prefix read, and capacity exhaustion drops
later journal output. Neither condition suppresses the subsequent direct SBI
output in SbiWriter, but SBI itself can still block. The ordinary bootlog dump
allocates and uses TTY, so failure of that command is not an independent
lock-free hart-liveness test. These are capture limitations, not observed
causes of the Mars hang. No runtime code or board state was changed.

Additional read-only entropy admission review during session 44535: this run's
boot.log records MARS_TRNG_PROBE protocol-observed, blocks=2, stopped=true.
The boot diagnostic shuts down the TRNG before the kernel takes ownership.
The Mars discovery table advertises DiagnosticOnly; kernel Endpoint::discover
accepts only FirmwareApproved. virtio_rng::discover returns None on that
rejection, and world.rs only spawns its driver task for admitted resources.
Thus a periodic TRNG read by that runtime driver is not an explanation for
this image's idle path. This does not exclude an earlier boot-time hardware
side effect, shared SEC domain fault, or the separate historical boot-time
TRNG stall. No runtime change or hardware command was made. At this review,
session 44535 had 305 successful minute probes (indices 0–304).

### Fatal-SBI eight-hour capture finalized

Session 44535 completed with exit code 0 after 480/480 successful minute ICMP
probes. The final bootlog responded and matched the original boot entry
(`entry_ticks` 40210248, `timebase_hz` 4000000); the two boot headers were
28871.81270825 seconds apart. Serial capture contains 12852 bytes in 235
contiguous chunks, with no `IPI_SEND_FAILED`, fatal trap, panic, assertion, or
stall marker. The one-flow and four-flow sink workloads completed at 947.1076
Mbps and 789.5694 Mbps respectively. The final SHA-256 manifest and analysis
are in `target/mars-reference/20260924-fatal-sbi-long-run/`.

This is strong evidence that the fatal-SBI image survives this diagnostic
8-hour idle/network run; it does not establish the cause of the earlier Mars
hang or prove a fix. The run used one diagnostic boot, minute ICMP samples,
disabled periodic watchdog, and a bootlog command that allocates and uses TTY.
Payload integrity and continuous TCP qualification were not performed.

### Watchdog follow-up image built

After the completed capture, the current source was rebuilt with
`image,ethernet,hang-watchdog,hang-failure-report` (without
`lock-stall-probe`). The release build finished successfully and
`scripts/mars-check-image.py --ethernet` passed the ELF contract. The resulting
ELF SHA-256 is `f039c89eee2d9ab9738eb99b9160ab30ee5d4f02e6e0486dc104f9990c758ed7`
at `target/riscv64imac-unknown-none-elf/release/vibeos-milkv-mars`. It has not
been loaded on Mars yet, so this is a prepared diagnostic artifact rather than
runtime evidence.

The watchdog ELF was also converted to a raw binary at
`target/mars-reference/20260924-watchdog-image/vibeos.bin` (SHA-256
`f0016e9758a1a9f639b2f9c2752bb27a903b8017236c7490b84fc6e248c564c5`). The FIT
was assembled locally with `dtc` and `fdtput` using the existing FIT source
and computed kernel/DTB SHA-256 values. It is saved as
`target/mars-reference/20260924-watchdog-image/vibeos.itb` with SHA-256
`a8b00c0feed80a05a8a37695072be504b8090dd798371d69c5382d7865c8a656`. This
FIT has not yet been accepted by U-Boot on Mars; hardware loading is required
to validate compatibility with the board's FIT parser.
