use crate::{HartState, IpiError};

pub(crate) const fn ipi_error_from_sbi(error: isize) -> IpiError {
    match error {
        -1 => IpiError::Failed,
        -2 => IpiError::NotSupported,
        -3 => IpiError::InvalidParam,
        -4 => IpiError::Denied,
        -5 => IpiError::InvalidAddress,
        -6 => IpiError::AlreadyAvailable,
        -7 => IpiError::AlreadyStarted,
        -8 => IpiError::AlreadyStopped,
        -9 => IpiError::NoSharedMemory,
        other => IpiError::Unknown(other),
    }
}

pub(crate) const fn hart_state_from_sbi(value: usize) -> HartState {
    match value {
        0 => HartState::Started,
        1 => HartState::Stopped,
        2 => HartState::StartPending,
        3 => HartState::StopPending,
        4 => HartState::Suspended,
        5 => HartState::SuspendPending,
        6 => HartState::ResumePending,
        other => HartState::Unknown(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standardized_sbi_errors_map_exactly_and_preserve_unknown_values() {
        let expected = [
            IpiError::Failed,
            IpiError::NotSupported,
            IpiError::InvalidParam,
            IpiError::Denied,
            IpiError::InvalidAddress,
            IpiError::AlreadyAvailable,
            IpiError::AlreadyStarted,
            IpiError::AlreadyStopped,
            IpiError::NoSharedMemory,
        ];
        for (offset, expected) in expected.into_iter().enumerate() {
            assert_eq!(ipi_error_from_sbi(-1 - offset as isize), expected);
        }
        assert_eq!(ipi_error_from_sbi(-37), IpiError::Unknown(-37));
    }

    #[test]
    fn standardized_hsm_states_map_exactly_and_preserve_unknown_values() {
        let expected = [
            HartState::Started,
            HartState::Stopped,
            HartState::StartPending,
            HartState::StopPending,
            HartState::Suspended,
            HartState::SuspendPending,
            HartState::ResumePending,
        ];
        for (raw, expected) in expected.into_iter().enumerate() {
            assert_eq!(hart_state_from_sbi(raw), expected);
        }
        assert_eq!(hart_state_from_sbi(37), HartState::Unknown(37));
    }
}
