//! One pending wait per native invocation; notification may precede polling.
use alloc::sync::Arc;
use core::{future::Future, pin::Pin, task::{Context, Poll, Waker}};
use crate::sync::SpinLock;
struct State { generation: u64, next: u64, waiter: Option<(u64, Option<Waker>)> }
pub(super) struct NativeNotify { state: SpinLock<State> }
pub(super) struct Wait { notify: Arc<NativeNotify>, id: u64, observed: u64 }
impl NativeNotify {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self { state: SpinLock::new(State { generation: 0, next: 1, waiter: None }) })
    }
    /// Register BEFORE rechecking the external predicate. A second concurrent
    /// wait is rejected; single-threaded native tasks cannot park twice.
    pub(super) fn listen(self: &Arc<Self>) -> Option<Wait> {
        let mut state = self.state.lock();
        if state.waiter.is_some() { return None; }
        let id = state.next;
        state.next = id.checked_add(1)?;
        state.waiter = Some((id, None));
        Some(Wait { notify: self.clone(), id, observed: state.generation })
    }
    pub(super) fn signal(&self) {
        let waker = {
            let mut state = self.state.lock();
            state.generation = state.generation.checked_add(1).expect("native wake generation exhausted");
            state.waiter.as_mut().and_then(|(_, waker)| waker.take())
        };
        if let Some(waker) = waker { waker.wake(); }
    }
}
impl Future for Wait {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.notify.state.lock();
        assert_eq!(state.waiter.as_ref().map(|(id, _)| *id), Some(self.id));
        if state.generation != self.observed { return Poll::Ready(()); }
        let slot = &mut state.waiter.as_mut().unwrap().1;
        if !slot.as_ref().is_some_and(|old| old.will_wake(cx.waker())) {
            let old = slot.replace(cx.waker().clone());
            drop(state);
            drop(old);
        }
        Poll::Pending
    }
}
impl Drop for Wait {
    fn drop(&mut self) {
        let waiter = {
            let mut state = self.notify.state.lock();
            assert_eq!(state.waiter.as_ref().map(|(id, _)| *id), Some(self.id));
            state.waiter.take()
        };
        drop(waiter); // Waker destructors run outside the registry lock.
    }
}
#[cfg(feature = "native-cxx-probe")]
pub(super) async fn probe() {
    let notify = NativeNotify::new();
    let early = notify.listen().unwrap();
    assert!(notify.listen().is_none());
    notify.signal();
    early.await;
    let cancelled = notify.listen().unwrap();
    drop(cancelled);
    let pending = notify.listen().expect("cancelled registration must be removed");
    let producer = notify.clone();
    let peer = crate::exec::spawn_pinned_on(crate::exec::HartId::BOOT, "native-notify-peer", async move {
        crate::exec::sleep_ms(2).await;
        producer.signal();
    });
    pending.await;
    drop(peer);
    assert!(notify.state.lock().waiter.is_none());
    assert_eq!(Arc::strong_count(&notify), 1);
    crate::println!("NATIVE NOTIFY PASS early=1 parked=1 exclusive=1 cancelled=1 reclaimed=1");
}
