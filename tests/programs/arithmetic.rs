// Bindings are annotated `i64` because real rustc infers `i32` for a bare
// integer literal, and the VibeOS subset has only `i64`. Without the
// annotation the two languages would be computing in different widths.
fn main() {
    let a: i64 = 7;
    let b: i64 = 3;
    println!("{} {} {} {} {}", a + b, a - b, a * b, a / b, a % b);
    println!("{} {}", 2 + 3 * 4, (2 + 3) * 4);

    let c: i64 = 5;
    println!("{} {}", -c, -(2 + 3));

    let zero: i64 = 0;
    let five: i64 = 5;
    println!("{} {}", !zero, !five);

    let m: i64 = 1_000_000;
    println!("{}", m * m);

    let neg: i64 = -7;
    let two: i64 = 2;
    println!("{} {}", neg / two, neg % two);

    let big: i64 = 9223372036854775807;
    println!("{}", big - 1);

    let min: i64 = -9223372036854775807;
    println!("{}", min + 1);
}
