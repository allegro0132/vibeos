fn shadowed() -> i64 {
    let x: i64 = 1;
    let x = x + 10;
    x
}

fn params(a: i64, b: i64, c: i64, d: i64, e: i64) -> i64 {
    a * 10000 + b * 1000 + c * 100 + d * 10 + e
}

fn main() {
    println!("{}", shadowed());
    println!("{}", params(1, 2, 3, 4, 5));
    let outer: i64 = 1;
    if outer < 2 {
        let inner = outer + 41;
        println!("{}", inner);
    }
    println!("{}", outer);
    println!("escapes a\tb {{}} done");
}
