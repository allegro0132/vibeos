//! Capability-checking adapter for the separately supervised TCP probe.

use vibeos_core::cap::{Cap, Rights};
use vibeos_net_api::{TcpConnectionToken, TcpFrontendError, TcpIoResult, TcpListener};
use vibeos_tcp_probe::{Platform, SocketError};

use crate::world::Space;

struct ProbePlatform {
    space: &'static Space,
}

impl ProbePlatform {
    const fn new(space: &'static Space) -> Self {
        Self { space }
    }

    fn listener(
        &self,
        cap: Cap,
        rights: Rights,
    ) -> Result<vibeos_core::cap::Revocable<TcpListener>, SocketError> {
        self.space
            .0
            .lock()
            .lookup_revocable::<TcpListener>(cap, rights)
            .map_err(|_| SocketError::AuthorityRevoked)
    }
}

impl Platform for ProbePlatform {
    fn tcp_accept(&self, listener: Cap) -> Result<Option<TcpConnectionToken>, SocketError> {
        self.listener(listener, Rights::RECV)?
            .try_with(TcpListener::try_accept)
            .map_err(|_| SocketError::AuthorityRevoked)
    }

    fn tcp_recv(
        &self,
        listener: Cap,
        connection: TcpConnectionToken,
        output: &mut [u8],
    ) -> Result<TcpIoResult, SocketError> {
        self.listener(listener, Rights::READ)?
            .try_with(|listener| listener.try_recv(connection, output))
            .map_err(|_| SocketError::AuthorityRevoked)?
            .map_err(map_frontend_error)
    }

    fn tcp_send(
        &self,
        listener: Cap,
        connection: TcpConnectionToken,
        input: &[u8],
    ) -> Result<TcpIoResult, SocketError> {
        self.listener(listener, Rights::WRITE)?
            .try_with(|listener| listener.try_send(connection, input))
            .map_err(|_| SocketError::AuthorityRevoked)?
            .map_err(map_frontend_error)
    }

    fn tcp_close(&self, listener: Cap, connection: TcpConnectionToken) -> Result<(), SocketError> {
        self.listener(listener, Rights::INVOKE)?
            .try_with(|listener| listener.request_close(connection))
            .map_err(|_| SocketError::AuthorityRevoked)?
            .map_err(map_frontend_error)
    }

    fn tcp_reset(&self, listener: Cap, connection: TcpConnectionToken) -> Result<(), SocketError> {
        self.listener(listener, Rights::INVOKE)?
            .try_with(|listener| listener.request_reset(connection))
            .map_err(|_| SocketError::AuthorityRevoked)?
            .map_err(map_frontend_error)
    }

    fn now_ms(&self) -> u64 {
        let hz = vibeos_core::exec::timebase_hz();
        vibeos_core::arch::time().saturating_mul(1_000) / hz
    }
}

pub async fn task(space: &'static Space, listeners: [Cap; 4]) {
    vibeos_tcp_probe::task(&ProbePlatform::new(space), listeners).await;
}

fn map_frontend_error(error: TcpFrontendError) -> SocketError {
    match error {
        TcpFrontendError::WrongListener | TcpFrontendError::StaleConnection => {
            SocketError::StaleConnection
        }
        _ => SocketError::Failed,
    }
}
