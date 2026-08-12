mod common;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Checkpoint {
    slot: u8,
    generation: u64,
    previous_generation: u64,
    admitted_segments: u64,
    admitted_range_pages: u64,
    exact_bytes_tag: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectionError {
    WrongSlot,
    BrokenChain,
    ConflictingGeneration,
    AllocationAmplification,
}

fn expected_slot(generation: u64) -> Option<u8> {
    generation.checked_sub(1).map(|value| (value & 1) as u8)
}

fn select(
    left: Option<Checkpoint>,
    right: Option<Checkpoint>,
) -> Result<Option<Checkpoint>, SelectionError> {
    for checkpoint in [left, right].into_iter().flatten() {
        if expected_slot(checkpoint.generation) != Some(checkpoint.slot) {
            return Err(SelectionError::WrongSlot);
        }
        if checkpoint.generation == 1 {
            if checkpoint.previous_generation != 0 {
                return Err(SelectionError::BrokenChain);
            }
        } else if checkpoint.previous_generation != checkpoint.generation - 1 {
            return Err(SelectionError::BrokenChain);
        }
        let expected_pages = 16_u64
            .checked_add(
                checkpoint
                    .admitted_segments
                    .checked_mul(1024)
                    .ok_or(SelectionError::AllocationAmplification)?,
            )
            .ok_or(SelectionError::AllocationAmplification)?;
        if checkpoint.admitted_range_pages != expected_pages {
            return Err(SelectionError::AllocationAmplification);
        }
    }

    match (left, right) {
        (None, None) => Ok(None),
        (Some(checkpoint), None) | (None, Some(checkpoint)) => Ok(Some(checkpoint)),
        (Some(left), Some(right)) if left.generation == right.generation => {
            if left == right {
                Ok(Some(left))
            } else {
                Err(SelectionError::ConflictingGeneration)
            }
        }
        (Some(left), Some(right)) => {
            let (older, newer) = if left.generation < right.generation {
                (left, right)
            } else {
                (right, left)
            };
            if newer.generation != older.generation + 1
                || newer.previous_generation != older.generation
            {
                return Err(SelectionError::BrokenChain);
            }
            Ok(Some(newer))
        }
    }
}

fn checkpoint(generation: u64) -> Checkpoint {
    Checkpoint {
        slot: expected_slot(generation).unwrap(),
        generation,
        previous_generation: generation - 1,
        admitted_segments: 3,
        admitted_range_pages: 16 + 3 * 1024,
        exact_bytes_tag: generation,
    }
}

#[test]
fn selects_only_the_highest_consecutive_checkpoint() {
    assert_eq!(select(None, None), Ok(None));
    assert_eq!(select(Some(checkpoint(1)), None), Ok(Some(checkpoint(1))));
    assert_eq!(
        select(Some(checkpoint(1)), Some(checkpoint(2))),
        Ok(Some(checkpoint(2)))
    );
}

#[test]
fn same_generation_must_be_byte_equivalent() {
    let left = checkpoint(2);
    let mut conflict = left;
    conflict.exact_bytes_tag ^= 1;
    assert_eq!(
        select(Some(left), Some(conflict)),
        Err(SelectionError::ConflictingGeneration)
    );
}

#[test]
fn stale_or_nonconsecutive_generation_fails_closed() {
    assert_eq!(
        select(Some(checkpoint(1)), Some(checkpoint(4))),
        Err(SelectionError::BrokenChain)
    );
    let mut broken = checkpoint(3);
    broken.previous_generation = 1;
    assert_eq!(
        select(Some(checkpoint(2)), Some(broken)),
        Err(SelectionError::BrokenChain)
    );
}

#[test]
fn slot_and_allocation_amplification_are_rejected() {
    let mut wrong_slot = checkpoint(2);
    wrong_slot.slot = 0;
    assert_eq!(
        select(Some(wrong_slot), None),
        Err(SelectionError::WrongSlot)
    );

    let mut amplified = checkpoint(2);
    amplified.admitted_range_pages += 1024;
    assert_eq!(
        select(Some(amplified), None),
        Err(SelectionError::AllocationAmplification)
    );
}
