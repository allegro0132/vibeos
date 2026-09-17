# Mars RX hardware-counter investigation

The current 60 × 60-second RX soak runs the no-sampling home-restart FIT
`918fdf3be9a1fe04eb62dba8d68d74a9628cd0d03a187da15f1af82713d600b6`.
No PMU configuration, extra CSR reads or firmware replacement is performed
while that run owns the serial connection.

The preserved SPI boot output in
`target/mars-reference/20260917-bootlog-home-restart-load/reboot.log` reports
OpenSBI v1.2 and `Platform PMU Device : ---`. This is not an SBI extension probe
and does not prove that the PMU extension is unavailable. The same boot output
has an unnamed HSM device despite the kernel admitting HSM support. Existing
`ncounters` probes cycle/retired-instruction reads only; its measurements do not
identify cache or memory stalls.

OpenSBI v1.2 documents platform-supplied event/counter mappings, through the
firmware's device tree or platform hooks, as a prerequisite for its PMU support.
Its U74 example is for HiFive Unmatched, not a verified JH7110 configuration.
The example's generic cache-related events combine hardware conditions; in
particular, a data-cache event also counts MMIO. Such a value cannot be reported
as pure cache misses in a descriptor/MMIO-heavy driver. See the
[version-matched OpenSBI PMU documentation](https://raw.githubusercontent.com/riscv-software-src/opensbi/v1.2/docs/pmu_support.md).

The [SiFive U74 manual, revision 21G3.02.00](https://www.scs.stanford.edu/~zyedidia/docs/sifive/sifive-u74.pdf),
sections 3.9.3–3.9.6, describes two programmable counters with 40 implemented
bits and separate microarchitectural and memory-system event classes. It also
describes event combinations and privilege/overflow controls. This is a later
core manual, not proof that every described facility exists or is delegated on
the Mars silicon and installed firmware. Counter count, width, access and event
support must be established on the actual boot chain before measurement.

After the soak, the first probe should use the existing SBI Base extension
query (`probe_extension`, PMU ID 0x504d55). If present, enumerate counter metadata
before configuring anything; retain unsupported/error results rather than
interpreting them as zero. Initial measurements should use bounded start/stop
windows on the driver and stack harts, without overflow interrupts. Preserve
counter widths, event encodings, privilege coverage and exact image identity
with every result. Separate MMIO-inclusive event counts from cache claims, and
do not add overlapping busy/stall counters as if they partition elapsed cycles.

If firmware mapping is missing, changing only the VibeOS FIT DTB after OpenSBI
initialization is not evidence of enabling its PMU. Inspect the matched OpenSBI
source and the DTB it actually receives before preparing a RAM-only paired boot
firmware. No SPI update is needed merely to investigate this path.

This investigation establishes a possible measurement route, not PMU
availability on the board or a CPU optimization. The compact-owner candidate
remains separately default-off and unmeasured on hardware.

Preparation during the live soak: the existing default-off `counter-probe`
command now includes a separate `NCOUNTERS_SBI` line with `pmu_probe_error`,
`pmu_probe_value` and `pmu_probe_supported`. The runtime's raw Base-query helper
preserves both SBI return registers, so a failed query remains distinguishable
from a successful query reporting zero. The existing boolean helper retains
its behavior. This changes no event selectors, start/stop state or CSR permissions.
The original counter output format remains intact. The separate candidate
feature map is `target/mars-reference/bootlog-pmu-probe-features.json`; no target
build or hardware execution of this addition has occurred yet.

The two host architecture tests pass with the raw query seam, including a
supported RFENCE result, a successful absent-extension result and exact query
accounting. Host tests do not establish the installed firmware's PMU support;
the RISC-V build and physical query remain pending until after the soak.

## Physical Base query after the completed soak

The 60-round soak finished and passed independent audit before this build/load.
The diagnostic FIT SHA-256 is
`d8d16baa68a8a55426d13bbcd7180cf71e5f2177bbc94af2d54e3f7817ebee8c`;
its exact ELF is `target/mars-reference/20260917-bootlog-pmu-probe.elf`.
Build/package logs and the verified RAM load are retained under
`20260917-bootlog-pmu-probe-*` in `target/mars-reference`. The ordinary Cargo
ethernet feature line was restored during packaging. No SD or SPI was written.

The physical command in `20260917-bootlog-pmu-probe-counters.serial` returned:

```text
NCOUNTERS_SBI pmu_probe_error=0 pmu_probe_value=1 pmu_probe_supported=true
```

All four harts also returned cycle and retired-instruction availability 3.
This proves the installed firmware exposes the PMU extension; it does not yet
prove programmable-counter count, width, event mapping or access permissions.
The next step is read-only counter enumeration, followed by bounded event
configuration only for counters/events actually supported by this firmware.
No programmable event was configured or started in this probe.

## Physical per-hart counter inventory

The default-off `counter-probe` feature now exposes `npmu`. Each online hart
runs one SYSTEM-owned pinned query task, querying FIDs 0 and 1 only. The command
bounds enumeration at 64 slots, reports truncation explicitly, preserves raw
errors and metadata, and decodes width/CSR only for successful hardware entries.
No lock or allocation-owner scope spans the task join. Host stubs return
not-supported rather than fabricated counter metadata.

The decoder follows the [SBI PMU metadata format](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-pmu.adoc)
and the matching [OpenSBI v1.2 implementation](https://github.com/riscv-software-src/opensbi/blob/v1.2/lib/sbi/sbi_pmu.c).
The RISC-V build and RAM boot succeeded for FIT
`ecbb500e0fa357700b11ee73047dfdcd2933c935cccbf275d3fb5dbe7e39b72f`.
Raw evidence: `target/mars-reference/20260917-bootlog-pmu-inventory.serial`;
validated extraction: the adjacent `.json`. All four harts reported the same:

- 21 index slots, queried without truncation.
- Index 0: CSR 0xc00, width 64; index 2: CSR 0xc02, width 64.
- Indices 3 and 4: CSR 0xc03/0xc04, width 40.
- Index 1: error -3, retained as invalid rather than counted as hardware.
- Indices 5 through 20: 16 firmware counters; CSR/width fields ignored.

Thus the reported total is not 21 usable hardware counters. The next probe can
restrict programmable events to indices 3 and 4, leaving cycle/instret intact.
Metadata alone does not establish that event mappings work or that direct
S-mode reads of those programmable CSRs are permitted. Those checks and a
bounded start/read/stop measurement remain necessary before interpreting stalls.

## Event configuration probe prepared; load interrupted before reboot

`npmuevents` is restricted to the same default-off diagnostic feature. It
checks the verified 40-bit CSR metadata before selecting counter 3 or 4,
configures one generic/cache event without AUTO_START, and immediately requests
stop/reset for a successful selection. It excludes cycles/instret because the
v1.2 implementation can return those fixed counters outside the requested mask.
Unexpected selected indices or cleanup errors stop further probing on that hart.
OpenSBI v1.2 clears the mapping even when stop reports already-stopped (-8);
that raw result is retained, not silently converted to success. Each output row
has attempted_mask (bit 0 = configuration, bit 1 = cleanup) so skipped operations
are distinguishable from their sentinel return fields. No PMU start call is used.

The RISC-V build and FIT packaging succeeded:
`7fdcbef006db709269a1f5340c73de17cbe56e0cb95fbb9733ffdf57a93a8dee`.
The load script failed at its first bootlog query, before reboot/TFTP/bootm.
Therefore this candidate has NOT run on hardware and has no event results.
The last verified running FIT remains the inventory image `ecbb500e...`.

Preserved evidence:
- `20260917-bootlog-pmu-events-load/serial-full.log`: four undecodable bytes,
  followed by a 15-second command timeout.
- `20260917-pmu-inventory-serial-retry.serial`: zero bytes during a separate
  20-second bounded bootlog query.
- Host en13 remained 1000baseT full-duplex; two pings to 192.168.77.10 had no
  replies. The existing DHCP record still maps the board MAC to that address.
  These observations do not distinguish a CPU hang from serial/network failure.

No event configuration or programmable CSR read had been sent when this loss
occurred. Requested serial-USB reconnection while preserving board power, to
compare retained boot output and uptime if communication returns. No automated
power cycle, SPI update or SD write was performed.

### Source inspection during the communication loss

The portable UART driver polls LSR THRE indefinitely in `write_byte`, and TEMT
indefinitely in `drain` (`drivers/uart16550/src/lib.rs`). Kernel byte output holds
the TX SpinLock across that call; formatted console output also holds TTY.
`core/src/sync.rs` disables local interrupts before SpinLock acquisition and
restores them on guard release. Thus a permanently unready UART can prevent
local scheduling/interrupt service and can make other console writers spin.
This is a concrete unbounded-wait path, not evidence that it was reached here.
No live LSR/MCR value or trapped PC was captured. Do not label it as the root
cause without further board evidence, or silently drop formal output records
as a speculative workaround. The original boot journal remains RAM-only and
cannot be retrieved while the console is unresponsive.

## Recovery without a new kernel boot; event probe executed

After the user's reconnect-ready reply, `bootlog` succeeded and both network
pings replied (2.477/1.073 ms). The retained inventory boot entry was still
42631616 ticks, identical to the original inventory load. Current ticks were
68070336367 at 4 MHz, giving 17006.926 seconds since entry. The log still included
the earlier PMU inventory. Raw recovery evidence:
`target/mars-reference/20260917-pmu-user-reconnect.serial`. This supports recovery
of the same kernel instance, not a new kernel boot. It does not prove scheduling
continued throughout the loss or establish the UART unbounded wait as the cause.
The retained prefix also includes link-down/up reports without timestamps.

The event FIT `7fdcbef0...` was subsequently RAM-loaded successfully. A single
serial session covered load, quieting background console output and the event
probe. Evidence is in `20260917-bootlog-pmu-events-reconnected-load/`; events.log
and its validated events.json contain all 80 expected (hart,counter,event) rows.
For every hart and both indices 3/4:

- Events 5, 6, 8 and 9 were accepted at the requested index and then reset;
  cleanup returned already-stopped (-8), as expected without any start call.
- Events 3, 4, 0x10001, 0x10009, 0x10019 and 0x10021 returned not-supported (-2).
- 32 successful configurations/resets and 48 unsupported results; no missing,
  duplicate or unattempted configurations. No counters were started.

The accepted SBI labels are branches, branch misses, frontend and backend
stalls. These are available measurement candidates, not measured bottlenecks.
The kernel FIT DTB contains no riscv,pmu mapping node; it is not necessarily the
DTB OpenSBI consumed. OpenSBI's event translation must still be established
before assigning precise microarchitectural meaning. Next: bounded counter
reads and start/stop measurement, preserving the raw event IDs and mappings.
