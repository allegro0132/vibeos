use vibeos_core::bench::{summarize, Summary};

#[test]
fn empty_distributions_have_no_summary() {
    assert_eq!(summarize(&mut []), None);
}

#[test]
fn singleton_distributions_use_the_only_sample_everywhere() {
    let mut samples = [u64::MAX];
    assert_eq!(
        summarize(&mut samples),
        Some(Summary {
            count: 1,
            min: u64::MAX,
            p50: u64::MAX,
            p95: u64::MAX,
            max: u64::MAX,
            mean: u64::MAX,
        })
    );
}

#[test]
fn percentiles_are_nearest_rank_and_input_is_sorted() {
    let mut samples = [10, 1, 9, 2, 8, 3, 7, 4, 6, 5];
    let summary = summarize(&mut samples).unwrap();

    assert_eq!(samples, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    assert_eq!(summary.count, 10);
    assert_eq!(summary.min, 1);
    assert_eq!(summary.p50, 5, "ceil(50% * 10) selects rank 5");
    assert_eq!(summary.p95, 10, "ceil(95% * 10) selects rank 10");
    assert_eq!(summary.max, 10);
    assert_eq!(summary.mean, 5, "integer means round down");
}

#[test]
fn exact_nearest_rank_boundaries_are_stable() {
    let mut twenty = [0u64; 20];
    for (index, value) in twenty.iter_mut().enumerate() {
        *value = (index + 1) as u64;
    }
    let summary = summarize(&mut twenty).unwrap();
    assert_eq!(summary.p50, 10);
    assert_eq!(summary.p95, 19);

    let mut twenty_one = [0u64; 21];
    for (index, value) in twenty_one.iter_mut().enumerate() {
        *value = (index + 1) as u64;
    }
    let summary = summarize(&mut twenty_one).unwrap();
    assert_eq!(summary.p50, 11);
    assert_eq!(summary.p95, 20);
}

#[test]
fn mean_accumulation_does_not_overflow_u64() {
    let mut samples = [u64::MAX, u64::MAX, u64::MAX - 3];
    let summary = summarize(&mut samples).unwrap();
    assert_eq!(summary.mean, u64::MAX - 1);
}
