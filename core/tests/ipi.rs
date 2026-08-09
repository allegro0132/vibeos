use vibeos_core::arch;
use vibeos_core::arch::{HartStartRequest, HartState};
use vibeos_core::exec::HartId;
use vibeos_core::ipi::{
    self, DoorbellDisposition, OnlineDisposition, OnlineError, REASON_RUNNABLE,
};

static TEST_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn mailbox_coalescing_offline_handoff_stale_and_failure_contract() {
    let _test_state = TEST_STATE.lock().unwrap();
    let hart0 = HartId::BOOT;
    let hart1 = HartId::new(1).unwrap();

    ipi::reset_test_state();
    assert_eq!(
        ipi::mark_online(hart0, usize::MAX),
        Err(OnlineError::InvalidPhysicalHart)
    );
    assert_eq!(
        ipi::mark_online(hart0, 0),
        Ok(OnlineDisposition::OnlineIdle)
    );

    assert_eq!(ipi::publish_runnable(hart0), DoorbellDisposition::Local);
    assert!(!arch::test_software_interrupt_pending(0));
    assert_eq!(arch::test_ipi_attempts(0), 0);
    // Self-IPIs are reserved for explicit acceptance/recovery probes.
    assert_eq!(ipi::retry_pending(hart0), DoorbellDisposition::Sent);
    assert!(arch::test_software_interrupt_pending(0));
    assert_eq!(arch::test_ipi_attempts(0), 1);
    assert_eq!(ipi::publish_runnable(hart0), DoorbellDisposition::Local);
    assert_eq!(arch::test_ipi_attempts(0), 1);

    arch::set_test_hart_id(0);
    assert_eq!(ipi::acknowledge_current(), REASON_RUNNABLE);
    assert!(!arch::test_software_interrupt_pending(0));
    assert_eq!(ipi::stats(hart0).acknowledged, 1);

    // A hardware interrupt with no mailbox reason is harmless and leaves the
    // executor free to check its queues again.
    arch::send_ipi(0).unwrap();
    assert_eq!(ipi::acknowledge_current(), 0);
    assert!(!arch::test_software_interrupt_pending(0));
    assert_eq!(ipi::stats(hart0).stale, 1);

    // M5.2 has only the boot hart online. Logical work for a stopped secondary
    // stays in its mailbox without asking OpenSBI to target an invalid hart.
    assert_eq!(ipi::publish_runnable(hart1), DoorbellDisposition::Offline);
    assert_eq!(ipi::pending_reasons(hart1), REASON_RUNNABLE);
    assert_eq!(arch::test_ipi_attempts(1), 0);

    // Accepting an asynchronous HSM request is not an online acknowledgement:
    // only the target physical hart may complete registration.
    assert_eq!(ipi::prepare_start(hart1, 7), Ok(()));
    assert_eq!(ipi::prepare_start(hart1, 7), Ok(()));
    assert!(!ipi::is_online(hart1));
    assert_eq!(ipi::retry_pending(hart1), DoorbellDisposition::Offline);
    assert_eq!(arch::test_ipi_attempts(7), 0);
    assert_eq!(
        ipi::mark_online(hart1, 7),
        Err(OnlineError::NotCurrentPhysicalHart)
    );
    assert!(!ipi::is_online(hart1));
    assert_eq!(ipi::stats(hart1).physical_hart_id, Some(7));
    assert_eq!(
        ipi::prepare_start(HartId::new(2).unwrap(), 7),
        Err(OnlineError::PhysicalHartAlreadyMapped)
    );
    assert_eq!(
        ipi::prepare_start(hart1, 9),
        Err(OnlineError::LogicalHartRemapped)
    );

    arch::set_test_hart_id(7);
    assert_eq!(ipi::mark_online(hart1, 7), Ok(OnlineDisposition::Pending));
    assert_eq!(
        ipi::mark_online(hart1, 7),
        Ok(OnlineDisposition::AlreadyOnline)
    );
    assert_eq!(arch::test_ipi_attempts(7), 0);
    assert_eq!(ipi::retry_pending(hart1), DoorbellDisposition::Sent);
    assert_eq!(arch::test_ipi_attempts(7), 1);
    assert!(arch::test_software_interrupt_pending(7));
    arch::set_test_hart_id(7);
    assert_eq!(ipi::acknowledge_current(), REASON_RUNNABLE);

    // A failed transport attempt does not roll back or consume the reason.
    // Clearing kick-armed lets the next remote publication retry the same work.
    ipi::reset_test_state();
    assert_eq!(ipi::prepare_start(hart1, 7), Ok(()));
    arch::set_test_hart_id(7);
    assert_eq!(
        ipi::mark_online(hart1, 7),
        Ok(OnlineDisposition::OnlineIdle)
    );
    arch::set_test_hart_id(0);
    arch::set_test_ipi_failure(7, true);
    assert_eq!(
        ipi::publish_runnable(hart1),
        DoorbellDisposition::Failed(arch::IpiError::Failed)
    );
    assert_eq!(ipi::pending_reasons(hart1), REASON_RUNNABLE);
    assert!(!arch::test_software_interrupt_pending(7));
    assert_eq!(ipi::stats(hart1).send_failures, 1);

    arch::set_test_ipi_failure(7, false);
    assert_eq!(ipi::publish_runnable(hart1), DoorbellDisposition::Sent);
    assert_eq!(ipi::pending_reasons(hart1), REASON_RUNNABLE);
    assert!(arch::test_software_interrupt_pending(7));
    arch::set_test_hart_id(7);
    assert_eq!(ipi::acknowledge_current(), REASON_RUNNABLE);
}

#[test]
fn hsm_start_status_and_secondary_registration_are_explicit() {
    let _test_state = TEST_STATE.lock().unwrap();
    let secondary = HartId::new(1).unwrap();
    const PHYSICAL: usize = 7;
    const ENTRY: usize = 0x8020_1000;
    const OPAQUE: usize = 1;

    ipi::reset_test_state();
    assert_eq!(arch::hart_status(0), Ok(HartState::Started));
    assert_eq!(arch::hart_status(PHYSICAL), Ok(HartState::Stopped));
    assert_eq!(arch::test_hart_status_attempts(PHYSICAL), 1);
    assert_eq!(
        arch::hart_status(usize::MAX),
        Err(arch::IpiError::InvalidParam)
    );

    assert_eq!(ipi::prepare_start(secondary, PHYSICAL), Ok(()));
    assert!(!ipi::is_online(secondary));
    arch::set_test_hart_start_error(PHYSICAL, Some(arch::IpiError::InvalidAddress));
    assert_eq!(
        arch::hart_start(PHYSICAL, ENTRY, OPAQUE),
        Err(arch::IpiError::InvalidAddress)
    );
    assert_eq!(arch::hart_status(PHYSICAL), Ok(HartState::Stopped));
    assert_eq!(arch::test_hart_start_attempts(PHYSICAL), 1);
    assert_eq!(
        arch::test_hart_start_request(PHYSICAL),
        Some(HartStartRequest {
            start_addr: ENTRY,
            opaque: OPAQUE,
        })
    );

    arch::set_test_hart_start_error(PHYSICAL, None);
    assert_eq!(arch::hart_start(PHYSICAL, ENTRY, OPAQUE), Ok(()));
    assert_eq!(arch::hart_status(PHYSICAL), Ok(HartState::StartPending));
    assert_eq!(
        arch::hart_start(PHYSICAL, ENTRY, OPAQUE),
        Err(arch::IpiError::AlreadyAvailable)
    );
    assert!(!ipi::is_online(secondary));
    assert_eq!(
        ipi::mark_online(secondary, PHYSICAL),
        Err(OnlineError::NotCurrentPhysicalHart)
    );

    // Firmware eventually enters the target with a0=physical and a1=opaque.
    // Only that execution context can acknowledge VibeOS-local readiness.
    arch::set_test_hart_state(PHYSICAL, HartState::Started);
    arch::set_test_hart_id(PHYSICAL);
    assert_eq!(
        ipi::mark_online(secondary, PHYSICAL),
        Ok(OnlineDisposition::OnlineIdle)
    );
    assert_eq!(ipi::current_logical_hart(), Some(secondary));

    arch::set_test_hart_status_error(PHYSICAL, Some(arch::IpiError::Denied));
    assert_eq!(arch::hart_status(PHYSICAL), Err(arch::IpiError::Denied));
    arch::set_test_hart_status_error(PHYSICAL, None);
    arch::set_test_hart_state(PHYSICAL, HartState::Unknown(99));
    assert_eq!(arch::hart_status(PHYSICAL), Ok(HartState::Unknown(99)));
}

#[test]
fn concurrent_start_preparation_preserves_unique_physical_mapping() {
    let _test_state = TEST_STATE.lock().unwrap();
    let logical1 = HartId::new(1).unwrap();
    let logical2 = HartId::new(2).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));

    ipi::reset_test_state();
    let first_barrier = barrier.clone();
    let first = std::thread::spawn(move || {
        first_barrier.wait();
        ipi::prepare_start(logical1, 7)
    });
    let second_barrier = barrier.clone();
    let second = std::thread::spawn(move || {
        second_barrier.wait();
        ipi::prepare_start(logical2, 7)
    });
    barrier.wait();

    let first = first.join().unwrap();
    let second = second.join().unwrap();
    assert!(
        (first == Ok(()) && second == Err(OnlineError::PhysicalHartAlreadyMapped))
            || (second == Ok(()) && first == Err(OnlineError::PhysicalHartAlreadyMapped))
    );
    assert_eq!(
        [ipi::stats(logical1), ipi::stats(logical2)]
            .into_iter()
            .filter(|stats| stats.physical_hart_id == Some(7))
            .count(),
        1
    );
    assert!(!ipi::is_online(logical1) && !ipi::is_online(logical2));
}
