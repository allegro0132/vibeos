//! Actual kernel seed adapter; host fixture cannot qualify a physical source.
#![allow(unexpected_cfgs, unused_imports, dead_code)]
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
static READY: AtomicBool = AtomicBool::new(false);
static FAIL: AtomicBool = AtomicBool::new(false);
mod virtio_rng {
    #[derive(Debug, PartialEq, Eq)]
    pub enum RandomError {
        Offline,
    }
    pub struct RandomSource;
    pub async fn bytes_with() {}
    pub async fn fill_seed(out: &mut [u8; 32]) -> Result<(), RandomError> {
        std::future::poll_fn(|_| {
            if super::READY.load(super::SeqCst) {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        })
        .await;
        assert_eq!(out, &[0; 32]);
        out.fill(42);
        if super::FAIL.load(super::SeqCst) {
            Err(RandomError::Offline)
        } else {
            Ok(())
        }
    }
}
#[path = "../../kernel/src/ssh_entropy.rs"]
mod adapter;
#[test]
fn pending_or_failed_source_never_returns_a_partial_seed() {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    let mut context = Context::from_waker(Waker::noop());
    let mut out = [0xa5; 32];
    let mut request = Box::pin(adapter::fill_seed(&mut out));
    assert!(request.as_mut().poll(&mut context).is_pending());
    drop(request);
    assert_eq!(out, [0; 32]);
    READY.store(true, SeqCst);
    FAIL.store(true, SeqCst);
    let mut request = Box::pin(adapter::fill_seed(&mut out));
    assert_eq!(
        request.as_mut().poll(&mut context),
        Poll::Ready(Err(virtio_rng::RandomError::Offline))
    );
    drop(request);
    assert_eq!(out, [0; 32]);
    FAIL.store(false, SeqCst);
    let mut request = Box::pin(adapter::fill_seed(&mut out));
    assert_eq!(request.as_mut().poll(&mut context), Poll::Ready(Ok(())));
    drop(request);
    assert_eq!(out, [42; 32]);
}
