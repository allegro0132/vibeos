# JH7110 platform services

SDIO1 clock/reset/pad preparation is in `sd.rs`. SiFive composable L2 cache
maintenance is in `cache.rs`; neither module imports a device driver or kernel.

The cache service follows the fixed Mars SDK's JH7110 U-Boot and Linux paths:
write the full physical cache-line address to control offset 0x200 with a 64-bit
store, then execute a full IO/memory barrier. It checks the configuration's
64-byte block size and enabled-way range before becoming usable. Both CPU and
device synchronization use the SDK's clean/invalidate path. Partial cache lines,
empty ranges, arithmetic overflow, firmware-reserved low RAM and addresses
outside the Mars RAM envelope are rejected before issuing a command.

The MMIO constructor accepts only the 0x02010000..0x02014000 control window;
firmware must first admit that resource from the DTB and map/permit S-mode
access. The code emits standard RISC-V `fence iorw, iorw`, not T-Head cache
instructions. No uncached RAM alias is used. The generic cache service supports
full 64-bit RAM addresses, while the EQoS pool separately enforces 32-bit DMA
reachability. Those two address limits must not be confused.

The HAL `DmaCache` contract describes visibility; device ownership is transferred
by descriptor/data protocols. Callers must isolate lines, exclude writes by
other cores while DMA owns them, and maintain one owner. Flushing dirty CPU
data after an unsynchronized device write can destroy that write; this service
does not repair an ownership violation. The pool and ring enforce the intended
serialized path but physical multicore/cache testing remains mandatory.

Source file hashes and registers are recorded in
`boards/milkv-mars/jh7110-cache-reference.json`. Host cache models test geometry,
address width, rejection and exact command/barrier sequence; they execute no
real cache maintenance. The QEMU composition model exercises the actual pool,
controller and cache service with modeled register effects. Clock/PHY setup,
GMAC resource admission and Mars firmware integration remain outstanding.
