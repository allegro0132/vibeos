# Shared Sv39 integrity map

VibeOS uses one ASID-zero Sv39 address space on every hart. This is not a process
isolation boundary: generated programs still run in S-mode and capability/type
confinement still decides what they can express. Paging exists to enforce kernel
integrity properties that are awkward or impossible to prove in software alone.

The implementation follows the ratified RISC-V privileged architecture's Sv39
three-level translation format. Page-table encodings live in the host-testable
`core/src/mmu.rs`; live storage, activation, and table walking live in
`kernel/src/mmu.rs`.

## M6.1 map

| Virtual range | Physical range | Leaf | Permission | Purpose |
|---|---|---:|---|---|
| Selected pages under `0x0c00_0000..0x0c40_0000` | identity | 4 KiB | `rw-` | PLIC priority, boot-visible enable, and the coldboot hart's S-context |
| `0x1000_0000..0x1000_9000` | identity | 4 KiB | `rw-` | UART and eight virtio-mmio windows |
| `0x8020_0000..0x8800_0000` | identity | 4 KiB | `rwx` (temporary) | kernel image, tables, DMA, stacks, heap |

Everything else is invalid, including address zero, the OpenSBI-owned
`0x8000_0000..0x8020_0000` prefix, unused PLIC/device pages, and RAM beyond the
configured 128 MiB QEMU machine. Device pages are never executable. RAM starts
with 4 KiB leaves so M6.2--M6.4 can remove or narrow individual pages without
splitting live superpages.

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

The `mmu` shell command walks the live hardware-format hierarchy. The in-kernel
self-test checks the same identity, permission, leaf-size, and unmapped-hole
invariants; host tests independently check the bit encodings and reject invalid
leaves.
