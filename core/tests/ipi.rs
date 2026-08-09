use vibeos_core::arch;
use vibeos_core::exec::HartId;
use vibeos_core::ipi::{
    self, DoorbellDisposition, OnlineDisposition, OnlineError, REASON_RUNNABLE,
};

#[test]
fn mailbox_coalescing_offline_handoff_stale_and_failure_contract() {
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
    assert_eq!(ipi::mark_online(hart1, 7), Ok(OnlineDisposition::Pending));
    assert_eq!(ipi::stats(hart1).physical_hart_id, Some(7));
    assert_eq!(
        ipi::mark_online(HartId::new(2).unwrap(), 7),
        Err(OnlineError::PhysicalHartAlreadyMapped)
    );
    assert_eq!(
        ipi::mark_online(hart1, 9),
        Err(OnlineError::LogicalHartRemapped)
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
