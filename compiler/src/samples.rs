//! Programs used by the shell, and by the test suites on both sides of the
//! fence. Keeping them here means a host test and a QEMU test compile exactly
//! the same bytes.

pub const HELLO: &str = r#"fn main() {
    println!("Hello, world!");
}
"#;

pub const DEMO: &str = r#"// Compiled to RV64 by VibeOS, in VibeOS.
fn fib(n: i64) -> i64 {
    if n < 2 { n } else { fib(n - 1) + fib(n - 2) }
}

fn gcd(a: i64, b: i64) -> i64 {
    let mut x = a;
    let mut y = b;
    while y != 0 {
        let t = x % y;
        x = y;
        y = t;
    }
    return x;
}

fn main() {
    println!("Hello, world!");
    let mut i = 0;
    while i < 10 {
        print!("fib({}) = {}  ", i, fib(i));
        i = i + 1;
    }
    println!("");
    println!("gcd(1071, 462) = {}", gcd(1071, 462));
    let n = 30;
    if n % 2 == 0 && n > 10 {
        println!("{} is even and greater than ten", n);
    }
}
"#;

/// Exercises every operator and control-flow form the subset has, and prints a
/// checkable value for each. Used as the end-to-end oracle in QEMU.
pub const CONFORMANCE: &str = r#"fn add(a: i64, b: i64) -> i64 { a + b }
fn fact(n: i64) -> i64 { if n <= 1 { 1 } else { n * fact(n - 1) } }

fn classify(n: i64) -> i64 {
    if n < 0 { 0 } else if n == 0 { 1 } else if n < 10 { 2 } else { 3 }
}

fn main() {
    println!("arith {} {} {} {} {}", 7 + 3, 7 - 3, 7 * 3, 7 / 3, 7 % 3);
    println!("prec {} {}", 2 + 3 * 4, (2 + 3) * 4);
    println!("neg {} {}", -5, -(2 + 3));
    println!("cmp {} {} {} {} {} {}", 1 < 2, 2 < 1, 1 <= 1, 1 > 2, 2 >= 2, 1 == 1);
    println!("ne {} {}", 1 != 2, 1 != 1);
    println!("not {} {}", !0, !5);
    println!("and {} {} {}", 1 && 1, 1 && 0, 0 && 1);
    println!("or {} {} {}", 0 || 0, 0 || 1, 1 || 0);
    println!("call {} {}", add(40, 2), fact(10));
    println!("branch {} {} {} {}", classify(-1), classify(0), classify(5), classify(50));
    let mut i = 0;
    let mut sum = 0;
    while i <= 100 { sum = sum + i; i = i + 1; }
    println!("loop {} {}", i, sum);
    println!("tail {}", squared(3));
    if 1 { println!("if-statement runs"); }
    println!("after if-statement");
    println!("shadow {}", shadowed());
    println!("escapes a\tb {{}} done");
}

fn squared(n: i64) -> i64 { n * n }

fn shadowed() -> i64 {
    let x = 1;
    let x = x + 10;
    x
}
"#;
