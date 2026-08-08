// A comparison is `bool` in Rust and `i64` here, so a comparison is never
// printed directly -- `if c { 1 } else { 0 }` reads the same in both languages.
fn main() {
    println!("{} {} {}", if 1 < 2 { 1 } else { 0 }, if 2 < 1 { 1 } else { 0 }, if 1 <= 1 { 1 } else { 0 });
    println!("{} {} {}", if 1 > 2 { 1 } else { 0 }, if 2 >= 2 { 1 } else { 0 }, if 1 == 1 { 1 } else { 0 });
    println!("{} {}", if 1 != 2 { 1 } else { 0 }, if 1 != 1 { 1 } else { 0 });
    println!("{} {}", if 1 < 2 && 3 < 4 { 1 } else { 0 }, if 1 < 2 && 4 < 3 { 1 } else { 0 });
    println!("{} {}", if 2 < 1 || 4 < 3 { 1 } else { 0 }, if 2 < 1 || 3 < 4 { 1 } else { 0 });

    let a: i64 = 5;
    let b: i64 = 10;
    if a < b && b < 100 {
        println!("in range");
    }
    let x = if a < b { a } else { b };
    println!("{}", x);
}
