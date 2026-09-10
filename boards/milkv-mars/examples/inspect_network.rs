//! Read-only topology inspection; no hardware or coherence qualification.
fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: inspect_network FILE.dtb");
    let blob = std::fs::read(path).expect("read DTB");
    match vibeos_bsp_milkv_mars::network_resources::admit(&blob) {
        Ok(r) => println!(
            "MARS_NETWORK_DTB PASS {r:?} phy_address=undiscovered hardware_acceptance=false"
        ),
        Err(e) => {
            eprintln!("MARS_NETWORK_DTB FAIL {e:?}");
            std::process::exit(1);
        }
    }
}
