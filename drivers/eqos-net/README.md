# EQoS controller foundation

This `no_std` crate provides GMAC4/5 Clause 22 command encoding and basic DMA
descriptor codecs and a serialized ring state machine. It is not yet a complete
packet device: JH7110 DMA memory/cache and platform integration remain outstanding. It depends only on
the shared `vibeos-ethernet` protocol crate; it does not import a BSP or kernel.
The separate Duo DWMAC driver also uses the shared transaction/status code.

`mdio::Port` receives ordered register IO and an actual CSR clock rate. It uses
offsets 0x200/0x204 and EQoS's PA/RDA/CR/GOC fields. Supported clock rates are
20–300 MHz; other rates are rejected. Shared transactions validate Clause 22
addresses, wait for idle before issuing exactly one command, and bound the
completion poll loop. A timed-out write is not retried. Link status is read
twice to clear the BMSR latch; an all-ones final response is not a usable PHY.
Controller/PHY reset and wall-clock timeout policy remain to be integrated.

Descriptor codecs accept a complete 32-bit-addressable single-buffer span and
produce CPU-order words without OWN. The ring implements the following protocol;
its unsafe backend must implement the required hardware/cache operations:

1. Keep a private, validated slot-to-buffer mapping; do not trust RX write-back
   descriptor words as buffer pointers.
2. Map and isolate the real DMA pool; synchronize packet bytes and descriptor
   fields before publishing OWN, then synchronize the descriptor before the
   tail-pointer write.
3. Poll ownership using correctly ordered volatile accesses and the platform's
   cache maintenance. Read completion data only after CPU ownership returns.
4. Configure the MAC consistently with the codec: no checksum/TSO/context
   descriptors, standard frames, RX FCS retained in memory (ACS/CST disabled).
   Successful RX lengths returned by the codec exclude that FCS.
5. Program DSL from descriptor stride and actual AXI width. A 64-byte slot on
   an 8-byte AXI bus needs DSL=6; it is not Duo's word-count encoding.
6. Quarantine DMA memory across failed shutdown/reset. No safe reuse is implied
   by a descriptor codec returning an error.

Host tests check literal wire encodings and adversarial boundaries. The optional
`eqos-model-test` in `firmware/qemu-hal-test` executes these same codecs on RV64
with a register model, then runs normal kernel selftests. Neither layer executes
JH7110 MMIO, DMA, clock/PHY setup or cache operations. Source hashes and pinned
SDK paths are in `boards/milkv-mars/eqos-reference.json`.

`ring::Ring` exclusively borrows a permanent backend and validates four disjoint,
aligned, 32-bit DMA spans. The backend must separately admit those spans against
its real owned pool. Software uses 64-byte descriptor slots and 1536-byte packet
buffers, with one reserved TX slot to keep the exclusive tail unambiguous.
Reaping is FIFO and bounded by the configured count. Receive processes at most
one slot, drops malformed/oversized-for-caller frames without copying, then
rearms that slot. Publication order is packet synchronization, descriptor fields,
descriptor synchronization/barrier, OWN, descriptor synchronization/barrier, tail.

A failed start/stop, TX error or explicit deadline fault quarantines the ring.
Recovery first requires the backend's bounded reset to prove old DMA quiescent;
it initializes empty TX slots and never retransmits the abandoned packet. A
dropped ring cannot free its permanently borrowed pool. The backend's unsafe
contract still requires exclusivity and prohibits reuse while DMA may be active.
This is a memory-lifetime guarantee, not proof that hardware has stopped.

Ten host ring tests cover literal ordering traces, both circular indices,
backpressure, RX copy bounds, private buffer addresses, layout rejection and
failed reset/stop. The RV64 model additionally runs TX completion, RX copy/rearm
and quarantine/reset transitions. Real controller MMIO, DMA visibility and
reset completion remain to be qualified on Mars.

The `controller` module now programs actual GMAC4/5 registers through ordered
MMIO (or a register model). Configuration validates MAC address, CSR/timebase
rates, FIFO geometry, descriptor layout and tail ranges. It uses one DCB RX/TX
queue, store-and-forward, eight-beat bursts without PBLx8, 32-bit DMA with zero
upper descriptor addresses, and no promiscuous mode or unnegotiated pause.
RX FCS retention and disabled checksum/TSO match the descriptor codecs. MAC
speed/duplex are explicit inputs from future PHY negotiation, not assumptions
about an attached link.

Reset disables IRQ/MAC/DMA enables, writes SWR once and waits for completion
using a 100 ms counter deadline rounded up to a tick, plus a finite poll cap
for stalled counters. It then checks disabled channel/MAC readback. Start also
checks enable readback. Stop uses that reset handshake to discard old work;
it does not promise TX delivery or infer quiescence solely from FIFO emptiness.
Hardware qualification must establish that the SoC's reset completion covers
outstanding DMA transactions. Clock-gated/hung MMIO itself cannot be made safe
by a software loop bound, so the platform must prepare live resources first.

`backend::Backend` joins this register engine with a permanently borrowed unsafe
`Memory` provider. The provider must admit the actual dedicated pool before any
DMA addresses are programmed and implement cache/volatile/copy operations. The
register adapter supplies standard RISC-V IO fences, never T-Head instructions.
No JH7110 cache implementation is supplied yet. Host integration tests and the
RV64 ring model run this register engine through successful initialization and
reset-failure recovery; neither emulates the physical interconnect or PHY.
