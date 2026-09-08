//! Host-only dynamic instruction counts. Instrumented runs are not benchmarks.
use crate::ir::Op;
use std::{
    cell::RefCell,
    collections::HashMap,
    format,
    mem::{discriminant, Discriminant},
    string::String,
    vec::Vec,
};

std::thread_local! {
    static COUNTS: RefCell<HashMap<Discriminant<Op>, (String, u64)>> = RefCell::default();
}

pub(crate) fn record(op: &Op) {
    COUNTS.with(|counts| {
        let mut counts = counts.borrow_mut();
        let entry = counts.entry(discriminant(op)).or_insert_with(|| {
            let text = format!("{op:?}");
            (String::from(text.split([' ', '{']).next().unwrap()), 0)
        });
        entry.1 += 1;
    });
}

/// Drain this thread's counts, sorted from most to least frequent.
pub fn take() -> Vec<(String, u64)> {
    COUNTS.with(|counts| {
        let mut values: Vec<_> = counts
            .borrow_mut()
            .drain()
            .map(|(_, value)| value)
            .collect();
        values.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        values
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_are_drained_and_thread_local() {
        take();
        record(&Op::Return);
        std::thread::spawn(|| {
            assert!(take().is_empty());
            record(&Op::Return);
            record(&Op::Return);
            assert_eq!(take(), [(String::from("Return"), 2)]);
        })
        .join()
        .unwrap();
        assert_eq!(take(), [(String::from("Return"), 1)]);
        assert!(take().is_empty());
    }
}
