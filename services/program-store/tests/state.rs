use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::thread;

use vibeos_program_store::SavedProgramState;

fn load(state: &AtomicU8) -> SavedProgramState {
    SavedProgramState::from_raw(state.load(Ordering::Acquire))
}

#[test]
fn remote_waiter_cannot_observe_staged_recovery_as_ready() {
    let state = Arc::new(AtomicU8::new(SavedProgramState::Staging as u8));
    let staged = Arc::new(Barrier::new(2));
    let (observed_tx, observed_rx) = mpsc::channel();

    let waiter_state = state.clone();
    let waiter_staged = staged.clone();
    let waiter = thread::spawn(move || {
        let observed = load(&waiter_state);
        assert!(observed.recovery_pending());
        assert!(!observed.client_ready());
        waiter_staged.wait();
        loop {
            let observed = load(&waiter_state);
            if !observed.recovery_pending() {
                observed_tx.send(observed).unwrap();
                return;
            }
            thread::yield_now();
        }
    });

    staged.wait();
    state.store(SavedProgramState::Ready as u8, Ordering::Release);
    assert_eq!(observed_rx.recv().unwrap(), SavedProgramState::Ready);
    waiter.join().unwrap();
}

#[test]
fn remote_waiter_observes_failure_instead_of_staged_authority() {
    let state = Arc::new(AtomicU8::new(SavedProgramState::Staging as u8));
    let staged = Arc::new(Barrier::new(2));

    let waiter_state = state.clone();
    let waiter_staged = staged.clone();
    let waiter = thread::spawn(move || {
        assert_eq!(load(&waiter_state), SavedProgramState::Staging);
        waiter_staged.wait();
        loop {
            let observed = load(&waiter_state);
            if !observed.recovery_pending() {
                return observed;
            }
            thread::yield_now();
        }
    });

    staged.wait();
    state.store(SavedProgramState::FailedClosed as u8, Ordering::Release);
    let observed = waiter.join().unwrap();
    assert_eq!(observed, SavedProgramState::FailedClosed);
    assert!(!observed.client_ready());
}
