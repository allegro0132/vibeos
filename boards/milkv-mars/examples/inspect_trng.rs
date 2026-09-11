//! Inspect the final DTB; no hardware access or entropy quality inference.
fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: inspect_trng FILE.dtb");
    let blob = std::fs::read(path).expect("read DTB");
    match vibeos_bsp_milkv_mars::trng_resources::admit(&blob) {
        Ok(r) => println!("MARS_TRNG_DTB PASS {r:?} entropy_qualified=false"),
        Err(e) => {
            eprintln!("MARS_TRNG_DTB FAIL {e:?}");
            std::process::exit(1);
        }
    }
}
