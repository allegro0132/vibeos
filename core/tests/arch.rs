use vibeos_core::arch;
use vibeos_core::arch::{
    IpiError, LocalSfenceVmaRequest, RemoteFenceIRequest, RemoteSfenceVmaRequest,
};

static TEST_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn rfence_probe_requests_and_errors_are_exact() {
    let _test_state = TEST_STATE.lock().unwrap();
    arch::reset_ipi_test_state();

    assert_eq!(arch::test_probe_attempts(), 0);
    assert_eq!(arch::test_last_probed_extension(), None);
    assert!(arch::probe_extension(arch::RFENCE_EXTENSION_ID));
    assert_eq!(arch::test_probe_attempts(), 1);
    assert_eq!(
        arch::test_last_probed_extension(),
        Some(arch::RFENCE_EXTENSION_ID)
    );
    assert!(!arch::probe_extension(0x1234_5678));
    assert_eq!(arch::test_probe_attempts(), 2);
    assert_eq!(arch::test_last_probed_extension(), Some(0x1234_5678));

    assert_eq!(arch::remote_fence_i(0b1010, 3), Ok(()));
    assert_eq!(arch::test_remote_fence_i_attempts(), 1);
    assert_eq!(
        arch::test_last_remote_fence_i(),
        Some(RemoteFenceIRequest {
            hart_mask: 0b1010,
            hart_mask_base: 3,
        })
    );

    assert_eq!(
        arch::remote_sfence_vma(0b0110, 1, 0x8040_0000, 0x3000),
        Ok(())
    );
    assert_eq!(arch::test_remote_sfence_vma_attempts(), 1);
    assert_eq!(
        arch::test_last_remote_sfence_vma(),
        Some(RemoteSfenceVmaRequest {
            hart_mask: 0b0110,
            hart_mask_base: 1,
            start: 0x8040_0000,
            size: 0x3000,
        })
    );

    arch::set_test_remote_fence_i_error(Some(IpiError::Failed));
    arch::set_test_remote_sfence_vma_error(Some(IpiError::InvalidAddress));
    assert_eq!(arch::remote_fence_i(1, 7), Err(IpiError::Failed));
    assert_eq!(
        arch::remote_sfence_vma(1, 7, 0x8050_0000, 0x1000),
        Err(IpiError::InvalidAddress)
    );
    assert_eq!(arch::test_remote_fence_i_attempts(), 2);
    assert_eq!(arch::test_remote_sfence_vma_attempts(), 2);

    arch::set_test_rfence_supported(false);
    assert!(!arch::probe_extension(arch::RFENCE_EXTENSION_ID));
    assert_eq!(arch::remote_fence_i(1, 0), Err(IpiError::NotSupported));
    assert_eq!(
        arch::remote_sfence_vma(1, 0, 0x8060_0000, 0x1000),
        Err(IpiError::NotSupported)
    );
}

#[test]
fn local_fences_and_mxr_have_deterministic_host_state() {
    let _test_state = TEST_STATE.lock().unwrap();
    arch::reset_ipi_test_state();

    assert_eq!(arch::test_local_sfence_vma_attempts(), 0);
    assert_eq!(arch::test_last_local_sfence_vma(), None);
    arch::local_sfence_vma(0x8070_0000, 0x2000);
    assert_eq!(arch::test_local_sfence_vma_attempts(), 1);
    assert_eq!(
        arch::test_last_local_sfence_vma(),
        Some(LocalSfenceVmaRequest {
            start: 0x8070_0000,
            size: 0x2000,
        })
    );

    assert_eq!(arch::test_local_fence_i_attempts(), 0);
    arch::local_fence_i();
    arch::local_fence_i();
    assert_eq!(arch::test_local_fence_i_attempts(), 2);

    assert!(!arch::mxr_enabled());
    arch::set_test_mxr_enabled(true);
    assert!(arch::mxr_enabled());
    arch::clear_mxr();
    assert!(!arch::mxr_enabled());
}
