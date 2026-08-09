# Shared Sv39 integrity map

VibeOS uses one ASID-zero Sv39 address space on every hart. This is not a process
isolation boundary: generated programs still run in S-mode and capability/type
confinement still decides what they can express. Paging exists to enforce kernel
integrity properties that are awkward or impossible to prove in software alone.

The implementation follows the ratified RISC-V privileged architecture's Sv39
three-level translation format. Page-table encodings live in the host-testable
`core/src/mmu.rs`; live storage, activation, and table walking live in
`kernel/src/mmu.rs`.

## M6.1 base map and M6.2 stack override

| Virtual range | Physical range | Leaf | Permission | Purpose |
|---|---|---:|---|---|
| Selected pages under `0x0c00_0000..0x0c40_0000` | identity | 4 KiB | `rw-` | PLIC priority, boot-visible enable, and the coldboot hart's S-context |
| `0x1000_0000..0x1000_9000` | identity | 4 KiB | `rw-` | UART and eight virtio-mmio windows |
| Ordinary pages in `0x8020_0000..0x8800_0000` | identity | 4 KiB | `rwx` (temporary) | kernel image, tables, DMA, and heap pending M6.3--M6.4 |
| `__stacks_bottom + n * 256 KiB` | invalid | 4 KiB | `---` | low guard page for logical hart `n`, `0 <= n < 4` |
| guard end through slot end | identity | 4 KiB | `rw-` | 252 KiB usable downward-growing stack for logical hart `n` |

Everything else is invalid, including address zero, the OpenSBI-owned
`0x8000_0000..0x8020_0000` prefix, unused PLIC/device pages, and RAM beyond the
configured 128 MiB QEMU machine. Device pages are never executable. RAM starts
with 4 KiB leaves so the M6.2 stack override and later M6.3--M6.4 permission
changes do not split live superpages. M6.1's original all-RWX RAM statement is
therefore no longer the current map: ordinary RAM is still temporarily RWX, but
guards are invalid and every mapped stack page is RW-NX.

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

## Boot and publication contract

1. `_start` disables interrupts, selects the boot stack, and clears `.bss`.
2. The boot hart fills the statically allocated hierarchy and Release-publishes
   it. No heap allocation or large stack temporary is involved.
3. The boot hart writes `satp`, performs `sfence.vma`, reads the exact value back,
   and only then begins global kernel initialization.
4. SBI HSM enters every secondary with `satp=0`. After acquiring the boot
   release, the secondary writes and reads back the same root before installing
   trap state or publishing ONLINE.
5. Boot waits for all online bits and requires them to equal the paging-enabled
   mask. Every QEMU case also requires the boot-time Sv39 marker.

The `mmu` shell command walks the live hardware-format hierarchy and reports the
stack slot, usable, guard, and permission summary. The in-kernel self-test checks
the same identity, permission, leaf-size, and unmapped-hole invariants; its M6.2
checks additionally cover all four invalid guards, the first and last usable
RW-NX pages, the aligned 256 KiB stride and address classifier, and the exact
8 KiB abort reserve. Host tests independently check the bit encodings and reject
invalid leaves.

The `guard_page` integration case is intentionally fatal. It prints hart 0's guard
address and attempts a real store there. The harness inspects the raw serial log
and accepts the boot only when the trap has cause 15 (`store page fault`), `stval`
equals the printed address exactly, and the guard-specific marker names hart 0.
