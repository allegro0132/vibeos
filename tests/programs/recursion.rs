fn fib(n: i64) -> i64 {
    if n < 2 { n } else { fib(n - 1) + fib(n - 2) }
}

fn fact(n: i64) -> i64 {
    if n <= 1 { 1 } else { n * fact(n - 1) }
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

fn ackermann_ish(m: i64, n: i64) -> i64 {
    if m == 0 { n + 1 } else if n == 0 { ackermann_ish(m - 1, 1) } else { ackermann_ish(m - 1, ackermann_ish(m, n - 1)) }
}

fn main() {
    println!("{} {} {}", fib(20), fact(15), gcd(1071, 462));
    println!("{}", ackermann_ish(2, 3));
}
