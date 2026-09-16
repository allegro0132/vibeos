//! Diagnostic-only bounded network timeline. Units are elapsed timer ticks,
//! not CPU cycles. Scopes must not cross await points. No sampling-time output,
//! allocation, locks, or reset; one capture window is permitted per boot.
#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Stage { Executor, Driver, Stack, Application, Other, Rx, Tx, Frontend, PacketQueue, Completion, PacketBuild, ProtocolPoll, RxLoan, RxGro, TxReserve, TxFlush, FrontendStatus, FrontendRx, FrontendTx, FrontendClose }
pub const SAMPLE_INTERVAL: usize = 127;
pub const SAMPLED_NAMES: [&str; 8] = ["rx_loan", "rx_gro", "tx_reserve", "tx_flush", "frontend_status", "frontend_rx", "frontend_tx", "frontend_close"];
pub const STAGE_COUNT: usize = 20;
pub const NAMES: [&str; STAGE_COUNT] = ["executor", "driver", "stack", "application", "other", "rx", "tx", "frontend", "packet_queue", "completion", "packet_build", "protocol_poll", "rx_loan", "rx_gro", "tx_reserve", "tx_flush", "frontend_status", "frontend_rx", "frontend_tx", "frontend_close"];

#[cfg(feature = "network-profile")]
mod enabled;
#[cfg(feature = "network-profile")]
pub use enabled::*;

#[cfg(not(feature = "network-profile"))]
pub struct Scope;
#[cfg(not(feature = "network-profile"))]
impl Scope {
    #[inline(always)] pub fn enter(_: Stage) -> Self { Self }
    #[inline(always)] pub fn sampled(_: Stage) -> Self { Self }
    #[inline(always)] pub fn task(_: &str) -> Self { Self }
}
#[cfg(not(feature = "network-profile"))]
#[inline(always)] pub fn queue(_: &str, _: usize, _: bool) {}

#[cfg(not(feature = "network-profile"))]
#[inline(always)]
pub fn poll_decision(_: bool, _: bool) {}
#[cfg(not(feature = "network-profile"))]
#[inline(always)]
pub fn stack_activity(_: usize, _: bool) {}
