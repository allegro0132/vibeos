//! Minimal TCP echo application consuming only a listener capability.

#![no_std]

use vibeos_core::cap::Cap;
use vibeos_net_api::{TcpConnectionToken, TcpIoResult};

const ECHO_CHUNK_BYTES: usize = 1024;
const IDLE_POLL_MS: u64 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketError {
    AuthorityRevoked,
    StaleConnection,
    Failed,
}

/// Capability-checking operations supplied by the component adapter.
///
/// The application never receives the [`vibeos_net_api::TcpListener`] object,
/// so READ/WRITE/RECV/INVOKE checks remain attached to individual operations.
pub trait Platform: Sync {
    fn tcp_accept(&self, listener: Cap) -> Result<Option<TcpConnectionToken>, SocketError>;
    fn tcp_recv(
        &self,
        listener: Cap,
        connection: TcpConnectionToken,
        output: &mut [u8],
    ) -> Result<TcpIoResult, SocketError>;
    fn tcp_send(
        &self,
        listener: Cap,
        connection: TcpConnectionToken,
        input: &[u8],
    ) -> Result<TcpIoResult, SocketError>;
    fn tcp_close(&self, listener: Cap, connection: TcpConnectionToken) -> Result<(), SocketError>;
}

type Space = dyn Platform;

pub async fn task(space: &Space, listener: Cap) {
    let mut echo = EchoState::new();
    loop {
        match echo.drive(space, listener) {
            Ok(true) => vibeos_core::exec::yield_now().await,
            Ok(false) => vibeos_core::exec::sleep_ms(IDLE_POLL_MS).await,
            Err(SocketError::AuthorityRevoked | SocketError::Failed) => return,
            Err(SocketError::StaleConnection) => {
                echo = EchoState::new();
                vibeos_core::exec::yield_now().await;
            }
        }
    }
}

struct EchoState {
    connection: Option<TcpConnectionToken>,
    pending: [u8; ECHO_CHUNK_BYTES],
    pending_start: usize,
    pending_end: usize,
}

impl EchoState {
    const fn new() -> Self {
        Self {
            connection: None,
            pending: [0; ECHO_CHUNK_BYTES],
            pending_start: 0,
            pending_end: 0,
        }
    }

    fn drive(&mut self, space: &Space, listener: Cap) -> Result<bool, SocketError> {
        let mut worked = false;
        if self.connection.is_none() {
            self.connection = space.tcp_accept(listener)?;
            worked |= self.connection.is_some();
        }
        let Some(connection) = self.connection else {
            return Ok(worked);
        };

        if self.pending_start != self.pending_end {
            match space.tcp_send(
                listener,
                connection,
                &self.pending[self.pending_start..self.pending_end],
            )? {
                TcpIoResult::Progress(length) => {
                    self.pending_start += length;
                    worked |= length != 0;
                    if self.pending_start == self.pending_end {
                        self.pending_start = 0;
                        self.pending_end = 0;
                    }
                }
                TcpIoResult::WouldBlock => return Ok(worked),
                TcpIoResult::Closed => {
                    self.clear_connection();
                    return Ok(true);
                }
            }
        }

        if self.pending_start == self.pending_end {
            match space.tcp_recv(listener, connection, &mut self.pending)? {
                TcpIoResult::Progress(length) => {
                    self.pending_end = length;
                    worked |= length != 0;
                }
                TcpIoResult::WouldBlock => {}
                TcpIoResult::Closed => {
                    space.tcp_close(listener, connection)?;
                    self.clear_connection();
                    worked = true;
                }
            }
        }
        Ok(worked)
    }

    fn clear_connection(&mut self) {
        self.connection = None;
        self.pending_start = 0;
        self.pending_end = 0;
    }
}
