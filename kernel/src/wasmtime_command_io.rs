//! Adapter to the existing bounded SSH/vsh command transport.
use alloc::sync::Arc;
use core::task::{Context, Poll};
use vibeos_wasi_command::{CommandIo, GuestIo};
use vibeos_wasi_runtime::{WasiIo, WasiIoError};
pub(super) struct CommandStreams(pub Arc<CommandIo>);
fn errno(error: WasiIoError) -> i32 {
    match error { WasiIoError::Closed => 64, WasiIoError::Denied => 76, WasiIoError::Failed => 29 }
}
impl vibeos_wasmtime_runtime::wasi::Streams for CommandStreams {
    fn read(&mut self, cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<Result<usize, i32>> {
        GuestIo(&self.0).read(cx, bytes).map(|r| r.map_err(errno))
    }
    fn write(&mut self, cx: &mut Context<'_>, fd: u32, bytes: &[u8]) -> Poll<Result<usize, i32>> {
        GuestIo(&self.0).write(cx, fd, bytes).map(|r| r.map_err(errno))
    }
    fn close(&mut self, fd: u32) -> Result<(), i32> {
        match fd { 0 => self.0.stdin.close(), 1 => self.0.stdout.close(), 2 => self.0.stderr.close(), _ => return Err(8) }
        Ok(())
    }
}
impl Drop for CommandStreams {
    fn drop(&mut self) {
        // Unregister/wake pipe waiters without assigning a cancellation reason
        // or terminal status. Those are owned by the command supervisor.
        self.0.stdin.close(); self.0.stdout.close(); self.0.stderr.close();
    }
}
