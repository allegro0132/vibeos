//! Shared static composition for boards with a 16550 console and PLIC.
use super::{Board, BoardContract};
use vibeos_driver_plic::{Mmio as PlicMmio, Plic};
use vibeos_driver_uart16550::{Mmio as UartMmio, Uart};
use vibeos_hal::devices::{ConsoleOps, EarlyDevices, InterruptControllerOps};

// SAFETY: board descriptions supply mapped device apertures. The kernel
// serializes console TX and PLIC enable updates, and owns boot-hart RX/claims.
static UART: Uart<UartMmio> =
    Uart::new(unsafe { UartMmio::new(Board::INFO.uart) }, Board::INFO.uart);
static PLIC: Plic<PlicMmio> = Plic::new(
    unsafe { PlicMmio::new(Board::INFO.plic) },
    Board::INFO.plic.max_irq,
);

#[no_mangle]
pub static VIBEOS_EARLY_DEVICES: EarlyDevices = EarlyDevices {
    console: ConsoleOps {
        description: Board::INFO.uart,
        capabilities: Board::INFO.console,
        init: || UART.init(),
        write_byte: |byte| UART.write_byte(byte),
        drain: || UART.drain(),
        interrupt: || UART.interrupt(),
        read_byte: || UART.read_byte(),
    },
    interrupts: InterruptControllerOps {
        description: Board::INFO.plic,
        supervisor_context: Board::plic_s_context,
        init_context: |context| PLIC.init_context(context),
        set_enabled: |context, irq, enabled| PLIC.set_enabled(context, irq, enabled),
        claim: |context| PLIC.claim(context),
        complete: |context, irq| PLIC.complete(context, irq),
    },
};
