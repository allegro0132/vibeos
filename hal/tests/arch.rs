use vibeos_hal::arch::{HartState, IpiError};

#[test]
fn architecture_contracts_preserve_unknown_values() {
    assert_eq!(IpiError::Unknown(-37), IpiError::Unknown(-37));
    assert_ne!(IpiError::Unknown(-37), IpiError::Failed);
    assert_eq!(HartState::Unknown(37), HartState::Unknown(37));
    assert_ne!(HartState::Unknown(37), HartState::Started);
}

#[test]
fn architecture_contracts_are_copy_values() {
    fn assert_copy<T: Copy>() {}

    assert_copy::<IpiError>();
    assert_copy::<HartState>();
}
