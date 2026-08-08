// Comparisons are `bool` in both languages now, so they can be printed
// directly and rustc checks that VibeOS renders them the same way.
fn main() {
    println!("{} {} {}", 1 < 2, 2 < 1, 1 <= 1);
    println!("{} {} {}", 1 > 2, 2 >= 2, 1 == 1);
    println!("{} {}", 1 != 2, 1 != 1);
    println!("{} {} {}", 1 < 2 && 3 < 4, 1 < 2 && 4 < 3, 2 < 1 && 3 < 4);
    println!("{} {} {}", 2 < 1 || 4 < 3, 2 < 1 || 3 < 4, 1 < 2 || 4 < 3);
    println!("{} {} {}", true, false, !true);
    println!("{} {}", true == false, true != false);

    let a: i64 = 5;
    let b: i64 = 10;
    if a < b && b < 100 {
        println!("in range");
    }
    let x = if a < b { a } else { b };
    println!("{}", x);

    let flag: bool = a < b;
    if flag {
        println!("flag holds");
    }
}
