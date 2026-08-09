# M5.3 SpinLock contention audit

**Snapshot:** 2026-08-09, `riscv64gc-unknown-none-elf`, four logical scheduler
queues with only the boot hart physically running. This audit is a source and
host-contention boundary; the `-smp 4` physical sample is part of M5.5.

## Decision rule

A lock is an IRQ hot lock when normal device traffic must acquire it before the
top half can acknowledge the source or publish event data. A scheduler hot lock
is acquired on every dispatch, wake, or lifecycle transition. A control lock is
retained when its critical section publishes several fields as one invariant and
does not sit in the device-data portion of an IRQ path.

The first `SpinLock::stats()` sample enables allocation-free counters for later
completed acquisitions, acquisitions that observe a real owner, and fault
recoveries on that exact lock. Keeping them opt-in avoids an atomic RMW on every
production acquisition. `smp queues` samples the
retained scheduler lock; `Heap::lock_stats`, `WaitQueue::lock_stats`, and
`timer_lock_stats` provide the corresponding M5.5 measurement points. A
single-hart sample must report zero physical contention. It is evidence that the
counter was exercised, not evidence of multicore scaling.

The M5.3 replacements are:

- executor fault and ready callbacks: release/acquire atomic function slots;
- PLIC handler lookup: fixed atomic sequence snapshots with a bounded IRQ read;
- UART RX: fixed 255-byte-usable SPSC ring with counted drop-newest overflow;
- virtio block/network IRQ transport: validated MMIO base published atomically
  with the PLIC callback, so acknowledging the device takes no transport lock.

Those changes remove the device-data and handler-lookup locks. They do **not**
make the complete interrupt path lock-free: `WaitQueue::wake_all`, scheduler
wake publication, and the timer registry still use the retained locks below.

## Complete inventory

| Location / family | IRQ or contention exposure | M5.3 decision |
|---|---|---|
| `core::exec::TaskStatus::{joiners, registrations}` | Task completion, cancellation, and fault drain; wakers are invoked/dropped after unlock | Retain: variable-size lifecycle records must detach atomically; not device-data IRQ state |
| `core::exec` former callback slots | Ready notification on every wake; fault callbacks on teardown | **Replace:** typed release/acquire atomic function addresses, installed while the executor is quiescent |
| `core::exec::CURRENT_TASK_STATUS` | Every poll/Drop boundary; globally wrong for physical SMP | Retain only through M5.3; replaced by hart-local storage in M5.4 |
| `core::exec::SCHED` | Every spawn, dispatch, wake, cancel, fault, and status query | Retain as the lifecycle/queue-owner linearization point; instrument now, split `running` per hart in M5.4, measure under `-smp 4` in M5.5 |
| `core::exec::WaitQueue::inner` | IRQ wake and task registration | Retain: short epoch/list detach section, no waker callback while held; explicitly instrumented and not described as lock-free |
| `core::exec::IRQ_POLL_PROBE` | Only the opt-in benchmark probe | Retain: one bounded diagnostic slot, inactive fast path is atomic |
| `core::exec::TIMERS` | Timer IRQ plus sleep registration/removal | Retain: ordered registry and hardware re-arm are one transaction; boot-hart timer affinity through M5.5, explicitly instrumented |
| `core::chan::Endpoint::inner` | Task IPC send/receive/waiter bookkeeping | Retain: bounded typed queue transaction; no hardware IRQ producer |
| `core::heap::Heap` | Allocation/free from multiple tasks | Retain: free lists, arena provenance, quotas, and accounting must commit together; IRQ paths do not allocate; explicitly instrumented |
| `kernel::plic::HANDLER_WRITER` | Registration/unregistration only | Retain on the cold writer side; IRQ dispatch reads atomic snapshots and never takes it |
| `kernel::plic::ENABLE_LOCK` | Source mask/priority changes and rare unhandled-source fail-close | Retain for MMIO read/modify/write serialization; absent from normal claim/dispatch/complete |
| `kernel::uart::TX` | Foreground and background output | Retain: serializes task output bytes; RX IRQ never takes it, and the fatal panic writer deliberately bypasses it |
| `kernel::uart` former `RX` | Every input byte | **Replace:** SPSC byte ring; the sole PLIC producer and sole shell consumer are documented obligations |
| `kernel::virtio_blk::{CONTROL, AUTHORITY, REQUEST}` | Driver task lifecycle, authority, one request slot | Retain: reset/recovery and request ownership are multi-field task transactions; IRQ top half does not take them |
| `kernel::virtio_net::{CONTROL, AUTHORITY}` | Driver task lifecycle and authority | Retain for the same recovery boundary; IRQ top half does not take them |
| virtio block/network former `IRQ_TRANSPORT` | Every device IRQ | **Replace:** MMIO base travels in the atomic PLIC publication |
| `kernel::tty::TTY` | Task-side prompt/background rendering | Retain: multi-field terminal rendering transaction; UART RX IRQ does not take it |
| `kernel::rustc::PROG_OUT` | Every generated console callback clones the active binding | Retain through M5.3: one global program invocation/context prevents physical contention; M5.4 makes that context hart-local; no IRQ access |
| `kernel::dev::MemoryRegion::words` | Invocation admission, exclusive claim, and zeroing | Retain: generated code uses the claimed raw extent directly after admission; no per-load/store lock and no IRQ access |
| `kernel::world::{Component::instance, Space/CSpace, components, WORLD}` | Supervision and capability graph mutation | Retain: authority/lifecycle control plane and fault recovery; never held across async I/O |
| `kernel::store::{active, state, INSTALLED_STORE}` | Durable operation claims, state transitions, installation | Retain: cold control/recovery state; media I/O is awaited after unlock |
| `kernel::durable_cspace::{active, graph, INSTALLED_DURABLE_CSPACE}` | Durable authority recovery/publication | Retain: tombstone/graph transaction and task-stable recovery state |
| `kernel::saved_program::{running_owner, active, live, INSTALLED_SAVED_PROGRAM}` | Saved artifact run/publication/recovery | Retain: control-plane claims and persisted generation state |

## SpinLock correctness boundary

Locks that a cleanup hook may repair opt in with `SpinLock::new_recoverable`.
Those locks publish `(owner, arena, exact task recovery key)` only with a `HELD`
token whose acquisition generation prevents a stale recovery CAS from unlocking
a later guard after an ABA. Locks outside fault recovery retain the lean boolean
CAS path and do not pay to publish unused provenance. Every `SpinGuard` keeps its
acquisition hart locally, is `!Send`, and validates Drop before restoring that
hart's interrupt state.

Both recovery APIs remain unsafe. Tracked `recover_after_fault` rejects untracked
domains and requires an all-hart quiescence/ack boundary for the entire allocation
domain before arena reuse. Conservative untracked faults use
`recover_after_task_fault`, which additionally matches the globally unique,
nonzero `TaskId` key installed outside the fault landing pad; sibling SYSTEM tasks
therefore cannot unlock one another. M5.3 still runs tracked component polls on
the boot hart; M5.4 must preserve these contracts when it introduces hart-local
running state.

## Evidence

- host tests race atomic PLIC publication and the SPSC producer/consumer for
  100,000 iterations without torn records or reordered bytes;
- host `SpinLock` tests cover real thread contention, domain-selective recovery,
  same-domain exact-task separation, stale-generation ABA rejection, and
  cross-hart Drop rejection;
- the API compile-fail test proves a guard cannot satisfy `Send`;
- `smp queues` exercises the target PLIC/UART path, reports the retained
  scheduler sample, and keeps physical-contention claims gated to M5.5.
