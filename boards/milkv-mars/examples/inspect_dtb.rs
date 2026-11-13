//! Host-only inspection of a supplied Mars DTB. This never accesses MMIO and
//! cannot qualify SBI availability, clocks, DMA or physical boot behavior.
use vibeos_bsp_milkv_mars as mars;
fn number(s: &str) -> Result<usize, String> {
    let (s, radix) = s.strip_prefix("0x").map_or((s, 10), |s| (s, 16));
    usize::from_str_radix(s, radix).map_err(|e| e.to_string())
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: inspect_dtb FILE DTB_PHYSICAL_ADDRESS BOOT_HART".into());
    }
    let blob = std::fs::read(&args[1]).map_err(|e| e.to_string())?;
    let physical = number(&args[2])?;
    let boot = number(&args[3])?;
    let resources = mars::resources::admit(&blob).map_err(|e| format!("resources: {e:?}"))?;
    let harts = mars::harts::admit(&blob, boot, false).map_err(|e| format!("harts: {e:?}"))?;
    if !harts.is_four_core() {
        return Err("DTB does not admit four application harts".into());
    }
    let memory =
        mars::usable_memory::<32>(&blob, physical).map_err(|e| format!("memory: {e:?}"))?;
    println!("MARS_DTB PASS boot={} harts={:?} timebase={} ram_regions={} sd={:#x} uart_irq={} plic_context={}",
        boot, harts.ids(), harts.timebase_hz, memory.ranges().len(), resources.sd.start,
        mars::UART_IRQ, mars::plic_s_context(boot).unwrap());
    println!("hardware_acceptance=false");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("MARS_DTB FAIL: {error}");
        std::process::exit(1);
    }
}
