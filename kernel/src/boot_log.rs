//! Current-boot RAM journal. UART reconnection does not erase it; reboot does.
use core::{fmt::{self, Write}, sync::atomic::{AtomicU64, Ordering}};
const CAPACITY: usize = 32 * 1024;
static LOG: vibeos_core::boot_log::BootLog<CAPACITY> = vibeos_core::boot_log::BootLog::new();
static ENTRY_TICKS: AtomicU64 = AtomicU64::new(0);
pub fn init() { ENTRY_TICKS.store(crate::sbi::time(), Ordering::Relaxed); }
pub fn append(text: &str) { LOG.append(text.as_bytes()); }
/// Format once, recording before the UART operation so a stalled UART cannot
/// hide the fragment it was attempting to output. Prompt/input rendering bypasses this.
pub struct Console;
impl Write for Console {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        append(text);
        crate::uart::Console.write_str(text)
    }
}
pub fn dump() {
    let mut system = crate::heap::enter_owner(crate::heap::OwnerId::SYSTEM);
    {
        let mut bytes = alloc::vec![0;CAPACITY];
        let len = LOG.copy_into(&mut bytes);
        let text = alloc::string::String::from_utf8_lossy(&bytes[..len]);
        // Bypass the journal itself: repeated reads must not fill it with copies.
        crate::tty::emit_unrecorded(format_args!(
            "BOOTLOG_BEGIN entry_ticks={} now_ticks={} hz={} bytes={} capacity={} truncated={} storage=ram\n",
            ENTRY_TICKS.load(Ordering::Relaxed), crate::sbi::time(), crate::exec::timebase_hz(),
            len, CAPACITY, LOG.truncated()));
        crate::tty::emit_unrecorded(format_args!("{}", text));
        crate::tty::emit_unrecorded(format_args!("\nBOOTLOG_END\n"));
    }
    system.restore();
}
