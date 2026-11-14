//! MT7988 XFI1 / PCS1 fixed 10GBASE-R, matching U-Boot mtk_eth.c.
//! XFI0 (GMAC2 to the switch) is never reset or reprogrammed here.
use core::ptr::{read_volatile, write_volatile};
use vibeos_runtime_aarch64::bare;
fn write(address: usize, value: u32) {
    unsafe {
        write_volatile(address as *mut u32, value);
    }
}
fn delay(us: u64) {
    let start = bare::counter();
    let ticks = (bare::counter_frequency() * us).div_ceil(1_000_000);
    while bare::counter().wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
}
pub fn initialize() -> bool {
    // Clear only the XFI1 clock gate bits; select the same parents as XFI0.
    // TOPCKGEN CLK_CFG_9/10 CLR, SET and update strobes (clk-mt7988-topckgen).
    let (sbus, xtal) = unsafe {
        (
            (read_volatile(0x1001_b080 as *const u32) >> 24) & 1,
            (read_volatile(0x1001_b0a0 as *const u32) >> 8) & 1,
        )
    };
    write(0x1001_b098, 0x81);
    write(0x1001_b094, sbus);
    write(0x1001_b0a8, 0x81 << 16);
    write(0x1001_b0a4, xtal << 16);
    write(0x1001_b1c4, (1 << 5) | (1 << 11));
    write(0x11f4_0108, 0x02283248);
    write(
        0x11f4_0008,
        unsafe { read_volatile(0x11f4_0008 as *const u32) } | 1 << 31,
    );
    write(0x1001_c0fc, 0x0000a004);
    write(0x1001_c018, 0x88f0a004);
    write(0x1001_c0fc, 0);
    write(0x1001_c018, 0x88f00000);
    write(0x1001_c018, 0x00f00000);
    delay(10_000);
    write(0x10081810, 0x000ffe6c);
    write(0x10081818, 0x07b1ec7b);
    write(0x1008180c, 0xb0000000);
    delay(2);
    write(0x1008180c, 0x90000000);
    delay(2);
    write(0x11f39024, 0x00c9071c);
    write(0x11f32020, 0xaa8585aa);
    write(0x11f32030, 0x0c020707);
    write(0x11f32034, 0x0e050f0f);
    write(0x11f32040, 0x00140032);
    write(0x11f350f0, 0x00c014aa);
    write(0x11f350e0, 0x3777c12b);
    write(0x11f3506c, 0x005f9cff);
    write(0x11f35070, 0x9d9dfafa);
    write(0x11f35074, 0x27273f3f);
    write(0x11f35078, 0xa7883c68);
    write(0x11f3507c, 0x11661166);
    write(0x11f35080, 0x0e000aaf);
    write(0x11f35084, 0x08080d0d);
    write(0x11f35088, 0x02030909);
    write(0x11f350e4, 0x0c0c0000);
    write(0x11f350e8, 0x04040000);
    write(0x11f350ec, 0x0f0f0c06);
    write(0x11f350a8, 0x506e8c8c);
    write(0x11f36004, 0x18190000);
    write(0x11f300f8, 0x01423342);
    write(0x11f300f4, 0x80201f20);
    write(0x11f30030, 0x00050c00);
    write(0x11f30070, 0x02002800);
    delay(2);
    write(0x11f330b0, 0x00000020);
    write(0x11f33028, 0x00008a01);
    write(0x11f3302c, 0x0000a884);
    write(0x11f33024, 0x00083002);
    write(0x11f33010, 0x00022220);
    write(0x11f35064, 0x0f020a01);
    write(0x11f350b4, 0x06100600);
    write(0x11f33048, 0x47684100);
    write(0x11f33050, 0x00000000);
    write(0x11f33054, 0x00000000);
    write(0x11f3306c, 0x00000f00);
    write(0x11f3a060, 0x00040000);
    write(0x11f390d0, 0x00000001);
    write(0x11f30070, 0x0200e800);
    delay(150);
    write(0x11f30070, 0x0200c111);
    delay(2);
    write(0x11f30070, 0x0200c101);
    delay(15);
    write(0x11f30070, 0x0202c111);
    delay(2);
    write(0x11f30070, 0x0202c101);
    delay(100);
    write(0x11f330b0, 0x00000030);
    write(0x11f300f4, 0x80201f00);
    write(0x11f33040, 0x30000000);
    delay(400);
    unsafe {
        read_volatile(0x1008_1810 as *const u32) == 0x000ffe6c
            && read_volatile(0x1008_1818 as *const u32) == 0x07b1ec7b
            && read_volatile(0x1008_180c as *const u32) == 0x90000000
            && read_volatile(0x1001_b090 as *const u32) & 0x80 == 0
            && read_volatile(0x1001_b0a0 as *const u32) & (0x80 << 16) == 0
    }
}
