# Shared Sv39 integrity map

VibeOS uses one ASID-zero Sv39 address space on every hart. This is not a process
isolation boundary: generated programs still run in S-mode and capability/type
confinement still decides what they can express. Paging exists to enforce kernel
integrity properties that are awkward or impossible to prove in software alone.

The implementation follows the ratified RISC-V privileged architecture's Sv39
three-level translation format. Page-table encodings live in the host-testable
`core/src/mmu.rs`; live storage, activation, and table walking live in
`kernel/src/mmu.rs`.

## M6.1 base map with M6.2--M6.3 permission overrides

| Virtual range | Physical range | Leaf | Permission | Purpose |
|---|---|---:|---|---|
| Selected pages under `0x0c00_0000..0x0c40_0000` | identity | 4 KiB | `rw-` | PLIC priority, boot-visible enable, and the coldboot hart's S-context |
| `0x1000_0000..0x1000_9000` | identity | 4 KiB | `rw-` | UART and eight virtio-mmio windows |
| `__text_start..__text_end` | identity | 4 KiB | `r-x` | linker-delimited kernel text |
| Other ordinary pages in `0x8020_0000..0x8800_0000` | identity | 4 KiB | `rw-` | `.rodata`, data, BSS, page tables, DMA, and heap; M6.4 will remove write where applicable |
| `__code_pool_start..__code_pool_end` | identity | 4 KiB | `rw-` or `--x` | 2 MiB generated-code pool: free/linking or sealed state |
| `__stacks_bottom + n * 256 KiB` | invalid | 4 KiB | `---` | low guard page for logical hart `n`, `0 <= n < 4` |
| guard end through slot end | identity | 4 KiB | `rw-` | 252 KiB usable downward-growing stack for logical hart `n` |

Everything else is invalid, including address zero, the OpenSBI-owned
`0x8000_0000..0x8020_0000` prefix, unused PLIC/device pages, and RAM beyond the
configured 128 MiB QEMU machine. Device pages are never executable. RAM starts
with 4 KiB leaves so the stack, text, code-pool, and later M6.4 read-only changes
never need to split a live superpage. M6.1's original all-RWX RAM statement is
historical: M6.3 leaves no writable-executable RAM leaf. `.rodata` and capability
tables are non-executable but remain writable until M6.4.

## Stack guard contract

Each logical hart retains one fixed 256 KiB linker slot. Its first 4 KiB page is
physically reserved but has an invalid PTE; the remaining 252 KiB is usable stack.
Keeping the 256 KiB stride preserves the secondary-entry address calculation and
the logical-hart-to-slot mapping. Generated-code stack probes use a floor 8 KiB
above the first usable byte, leaving that mapped space for the normal abort path
without making the guard writable.

Any access whose address lands in this guard faults instead of reaching memory.
One page is not complete stack-clash protection: a sufficiently large or corrupted
`sp` adjustment can jump over the guard into another mapped page. The guard also
does not provide a recovery stack. Trap entry saves registers on the current `sp`,
so a bad `sp` may trigger another page fault before the fatal diagnostic executes.
Reliable bad-`sp` diagnosis or recovery would require a separate per-hart emergency
trap stack; preventing skipped-guard accesses would additionally require probing or
a stronger boundary mechanism.

## W^X code-pool contract

Generated instructions occupy first-fit, page-granular runs in one linker-reserved
2 MiB pool. A run never shares a leaf PTE with allocator metadata, generated data,
or another executable. The kernel compilation path first reserves and zeros the
complete run, including page padding, then passes its exact logical word slice to
the relocatable image's in-place linker. `WritableCode` is the only API which
exposes that mutable slice. Sealing consumes it and returns an `ExecutableCode`
which exposes an entry address and sizes but no readable or writable view.

Permission changes are serialized by the page-table lock and use this sequence:

1. Validate every page against the complete expected old permission state.
2. Replace the complete run with invalid PTEs, publish the PTE stores, then execute
   local and synchronous remote `sfence.vma` for the range.
3. Install every target PTE, publish again, and repeat the all-hart TLB shootdown.
4. When sealing, execute local `fence.i` and SBI RFENCE `remote_fence_i` before
   publishing the executable owner.

This break-before-make protocol prevents one hart from retaining a writable
translation while another has begun using the execute-only mapping. The online
physical-hart mask comes from the logical/physical registration table rather than
assuming dense SBI IDs. A mask which cannot fit the standardized one-word SBI
encoding, missing RFENCE support, or a failed live remote fence is fail-stop: after
a partial shootdown there is no safe ordinary task error to return.

Each hart clears and reads back `sstatus.MXR` before it publishes paging enabled.
Consequently an execute-only PTE is not implicitly readable by S-mode. Kernel text
remains explicitly readable (`r-x`); sealed generated code is exactly `--x`.

Dropping `ExecutableCode` removes execute through the same two-shootdown protocol,
zeros every byte, and only then clears the allocation record. Runs carry a monotonic
generation plus their allocation owner and arena. If a tracked task fault uses
`longjmp` and skips Rust `Drop`, the audited reclaimer waits for all-hart quiescence,
finds every run for that exact domain, and applies the same unseal/zero/free path.
The pool remains a fixed global resource separate from component heap-quota bytes;
conservative untracked faults retain the existing leak-on-fault policy.

W^X is code-page integrity inside one shared S-mode address space. It neither
provides per-program address isolation nor proves that the trusted emitter generated
safe instructions. Those claims still depend on the compiler audit, runtime
trampoline, capability interface, differential corpus, and fuzzing.

## Boot and publication contract

1. `_start` disables interrupts, selects the boot stack, and clears `.bss`.
2. The boot hart fills the statically allocated hierarchy and Release-publishes
   it. No heap allocation or large stack temporary is involved.
3. The boot hart clears and reads back `sstatus.MXR`, writes `satp`, performs
   `sfence.vma`, reads the exact root back, and only then begins global kernel
   initialization.
4. SBI HSM enters every secondary with `satp=0`. After acquiring the boot
   release, the secondary clears MXR and writes and reads back the same root before
   installing trap state or publishing ONLINE.
5. Boot waits for all online bits and requires them to equal the paging-enabled
   mask. Each paging-enabled bit was published only after that hart cleared and
   read back MXR; the in-kernel self-test separately requires the two masks to
   match exactly. Multicore boot then probes SBI RFENCE and refuses to continue
   without synchronous remote fence support.
6. Every QEMU case requires both the boot-time Sv39 marker and the W^X/MXR/RFENCE
   marker, so integration cannot silently regress to Bare or all-RWX RAM.

The `mmu` shell command walks the live hardware-format hierarchy and reports the
stack slot, usable, guard, and permission summary. The in-kernel self-test checks
the same identity, permission, leaf-size, and unmapped-hole invariants; its M6.2
checks additionally cover all four invalid guards, the first and last usable
RW-NX pages, the aligned 256 KiB stride and address classifier, and the exact
8 KiB abort reserve. M6.3 checks additionally cover R-X text, both RW-NX pool
endpoints, execute-only compiled pages, the absence of any writable-executable RAM
leaf, zeroed same-address reuse, and return of code-pool pages after sixteen raw
fault/restart cycles. Host tests independently check PTE encodings, exact RFENCE
requests and errors, local fence/MXR behavior, physical-hart mask construction,
and the compiler's no-write-on-error in-place linker.

The `guard_page` integration case is intentionally fatal. It prints hart 0's guard
address and attempts a real store there. The harness inspects the raw serial log
and accepts the boot only when the trap has cause 15 (`store page fault`), `stval`
equals the printed address exactly, and the guard-specific marker names hart 0.

The non-fatal `wx` integration case executes sealed code on both the boot hart and
hart 1, drops it, obtains the same address already cleared to zero, seals different
code there, and observes the new result on hart 1 without a per-run `fence.i`. Its
transition counters also require the expected remote TLB and instruction-cache
fences. Three separate expected-fatal cases exercise the hardware boundary:
`wx_execute_fault` fetches from an RW-NX pool page (cause 12),
`wx_read_fault` loads from sealed execute-only code with MXR clear (cause 13), and
`wx_write_fault` stores to sealed code (cause 15). For each case the raw harness
requires the printed probe address to equal `stval` exactly and requires the
code-pool-specific trap marker.
