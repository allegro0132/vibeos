use std::io::{Read, Write};
fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("filter") => {
            let mut bytes = Vec::new();
            std::io::stdin().read_to_end(&mut bytes).unwrap();
            bytes.make_ascii_uppercase();
            std::io::stdout().write_all(&bytes).unwrap();
        }
        Some("args") => for arg in &args[2..] { println!("{arg}"); },
        Some("exit") => std::process::exit(7),
        Some("stderr") => { print!("out\n"); eprint!("err\n"); }
        Some("loop") => loop { std::hint::black_box(1); },
        _ => println!("Hello from Rust WASI!"),
    }
}
