use std::hint::black_box;
use std::time::Instant;

use vibeos_blob_format::sha256;

const CHUNK_BYTES: usize = 4096;
const ITERATIONS: usize = 16 * 1024;

fn main() {
    let input = [0xa5; CHUNK_BYTES];
    let started = Instant::now();
    let mut digest = [0u8; 32];
    for _ in 0..ITERATIONS {
        digest = sha256(black_box(&input));
        black_box(digest);
    }
    let elapsed = started.elapsed();
    let bytes = CHUNK_BYTES * ITERATIONS;
    let mib_per_second = bytes as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64();
    println!(
        "hashed {bytes} bytes in {:.6}s: {:.2} MiB/s ({:02x}{:02x}{:02x}{:02x})",
        elapsed.as_secs_f64(),
        mib_per_second,
        digest[0],
        digest[1],
        digest[2],
        digest[3]
    );
}
