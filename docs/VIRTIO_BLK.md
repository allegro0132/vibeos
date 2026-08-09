# Supervised virtio-blk contract

M4.1 uses one modern virtio-mmio block device on QEMU `virt`. The driver is a
supervised async component, but the transport window and DMA slab are owned by
SYSTEM and survive a component incarnation. This separation is deliberate: a
fault can abandon Rust destructors, while a device may still hold every address
published in its live virtqueue.

## Platform and queue

The platform layer scans the eight QEMU `virt` transports at
`0x1000_1000 + slot * 0x1000`, IRQ `1 + slot`. It accepts only magic
`0x74726976`, modern transport version 2, and block device ID 2. Empty slots,
legacy transports, and other device kinds are ignored.

The driver negotiates `VIRTIO_F_VERSION_1` and optionally
`VIRTIO_BLK_F_FLUSH`/`VIRTIO_BLK_F_RO`. Queue 0 is a bounded split queue of
eight descriptors with one request in flight. A sector request consists of a
16-byte header, one 512-byte bounce buffer, and one device-written status byte;
flush omits the data descriptor. Client pointers are never placed in a
descriptor.

Completion is valid only when the used entry names the current head and covers
the complete device-writable prefix (513 bytes for read data plus status, one
status byte for write/flush), its block status is known, and it belongs to the
current session epoch. Under-reported lengths are reset as protocol errors
because a modern driver cannot consume the trailing status outside `used.len`.
IRQs are hints: the top half acknowledges the MMIO cause and wakes the driver;
protocol validation remains in task context.

## DMA and recovery

The aligned DMA slab is stable kernel storage, outside every reclaimable
component arena. In the current no-IOMMU system, software capability checks do
not constrain the device. The checked descriptor builder is therefore part of
the trusted computing base, and the current virtual-equals-physical conversion
is isolated behind the transport/DMA boundary for M6.

Timeout, driver cancellation, or fault never makes an exposed descriptor
reusable by itself. Recovery follows this order:

1. mask the PLIC source;
2. write device status zero and confirm reset with a bounded poll;
3. acknowledge residual interrupt causes and fail/wake the active request;
4. release the session's DMA claim only after reset confirmation;
5. reinitialize with a fresh epoch, or quarantine the device if reset cannot be
   confirmed.

Client-future cancellation only abandons that waiter; it cannot withdraw a
buffer already published to the device. Capability revocation similarly blocks
all new operational MMIO before the next invocation is published, but is not
claimed to interrupt in-flight DMA. Reset and interrupt quiescence remain
permitted after revocation because they remove device access to stable DMA;
component cancellation and capability revocation remain separate supervisor
operations.

## Evidence

Host tests exercise feature negotiation, split-ring layout and wraparound,
malformed completions, session epochs, queue-full behavior, IRQ enable-word
boundaries, and the reset-before-reuse state machine. The QEMU `block` case uses
a fresh raw drive, reads a host-seeded sector, writes and flushes another sector,
then has the host harness inspect the backing file after shutdown. This final
check prevents an in-memory fake from satisfying the acceptance test.
