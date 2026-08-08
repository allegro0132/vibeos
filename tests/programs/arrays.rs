// Array indices are `usize` in Rust and `i64` in the subset. Rust infers the
// loop counter as `usize` from the indexing, so a program stays valid in both
// as long as the counter is only used to index and to count -- values that need
// to be `i64` are kept in a separate binding, since the subset has no `as`.
fn main() {
    let mut a: [i64; 8] = [0; 8];
    let mut i = 0;
    let mut v: i64 = 0;
    while i < 8 {
        a[i] = v * v;
        v = v + 1;
        i = i + 1;
    }

    let mut sum: i64 = 0;
    i = 0;
    while i < 8 {
        sum = sum + a[i];
        i = i + 1;
    }
    println!("{}", sum);
    println!("{} {} {}", a[0], a[3], a[7]);

    let mut b: [i64; 4] = [9; 4];
    b[2] = -1;
    println!("{} {} {} {}", b[0], b[1], b[2], b[3]);

    // Reverse in place.
    let mut lo = 0;
    let mut hi = 7;
    while lo < hi {
        let t: i64 = a[lo];
        a[lo] = a[hi];
        a[hi] = t;
        lo = lo + 1;
        hi = hi - 1;
    }
    println!("{} {} {}", a[0], a[3], a[7]);
}
