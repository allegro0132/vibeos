fn classify(n: i64) -> i64 {
    if n < 0 { 0 } else if n == 0 { 1 } else if n < 10 { 2 } else { 3 }
}

fn main() {
    let mut i: i64 = 0;
    let mut sum: i64 = 0;
    while i <= 100 {
        sum = sum + i;
        i = i + 1;
    }
    println!("{} {}", i, sum);
    println!("{} {} {} {}", classify(-1), classify(0), classify(5), classify(50));

    let mut n: i64 = 0;
    while n < 5 {
        if n % 2 == 0 {
            print!("even {} ", n);
        }
        n = n + 1;
    }
    println!("");
}
