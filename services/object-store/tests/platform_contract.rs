use vibeos_object_store::barrier_after_successful_write;
use vibeos_storage_device::{MutationCertainty, MutationFailure};

#[test]
fn a_barrier_failure_after_a_successful_write_is_always_ambiguous() {
    let before_publication = MutationFailure::not_submitted("driver restarted");
    let promoted = barrier_after_successful_write::<(), _>(Err(before_publication)).unwrap_err();
    assert_eq!(promoted.error(), &"driver restarted");
    assert_eq!(promoted.certainty(), MutationCertainty::Ambiguous);

    let already_ambiguous = MutationFailure::ambiguous("flush timed out");
    let retained = barrier_after_successful_write::<(), _>(Err(already_ambiguous)).unwrap_err();
    assert_eq!(retained.error(), &"flush timed out");
    assert_eq!(retained.certainty(), MutationCertainty::Ambiguous);

    assert_eq!(barrier_after_successful_write::<_, &str>(Ok(7)), Ok(7));
}
