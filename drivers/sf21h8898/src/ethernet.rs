//! Polled SF21H8898 shared XGMAC DMA channel. Each frame uses a context
//! descriptor and a data descriptor. RX returns the ingress port in word 0.
use crate::Console;
#[cfg(feature = "extended-dma")]
extern crate alloc;
#[cfg(feature = "extended-dma")]
use alloc::vec::Vec;
use core::{arch::asm, fmt::Write, ptr};
// Initial LAN pacing before a proxy protocol is selected.
#[cfg(feature = "extended-dma")]
pub const LAN_TICKS_PER_BYTE: u64 = 13;
// Timed MAC4 submissions include a software scheduling gap between trains.
#[cfg(feature = "local-offload")]
pub const WAN_TICKS_PER_BYTE: u64 = 9;
// MAC4 can issue the next TSO train up to this many wire bytes ahead.
#[cfg(feature = "local-offload")]
const WAN_TSO_CREDIT_BYTES: u64 = 4096;
const DMA: usize = 0x08018000;
const SYS: usize = 0x0ce01800;
const SE: usize = 0x11000000;
const LAN: usize = 5;
const ARENA: usize = 0x24000000;
// map_arena marks one 2 MiB leaf non-cacheable. Above it the CE payload,
// XGMAC packet buffers and proxy heap all use normal cached DRAM.
#[cfg(feature = "extended-dma")]
pub const CACHED_RAM_AFTER_ARENA: usize = ARENA + (1 << 21);
const RX: usize = ARENA;
#[cfg(not(feature = "extended-dma"))]
const TX: usize = ARENA + 0x1000;
#[cfg(feature = "extended-dma")]
const TX: usize = RX + COUNT * 16;
#[cfg(not(feature = "extended-dma"))]
const RX_BUF: usize = ARENA + 0x2000;
// Reserve independent cache lines outside the non-cacheable descriptor arena.
#[cfg(feature = "extended-dma")]
// Keep the expanded packet rings above the CE scratch at 0x24300000.
const RX_BUF: usize = 0x24400000;
#[cfg(feature = "extended-dma")]
pub(crate) fn flush_dma_lines(addr: usize, size: usize) {
    debug_assert_eq!(addr % 64, 0);
    for offset in (0..size).step_by(64) {
        unsafe {
            asm!(".option push", ".option arch,+zicbom", "cbo.flush 0({line})", ".option pop",
                 line = in(reg) (addr + offset), options(nostack));
        }
    }
    fence();
}
// Both TX engines only read these bytes. A clean writes back the containing
// cache lines without invalidating adjacent allocations on another hart.
#[cfg(feature = "extended-dma")]
pub(crate) fn clean_dma_source(bytes: &[u8]) {
    let start = bytes.as_ptr() as usize;
    for addr in (start & !63..start + bytes.len()).step_by(64) {
        unsafe {
            asm!(".option push", ".option arch,+zicbom", "cbo.clean 0({addr})",
                      ".option pop", addr = in(reg) addr, options(nostack));
        }
    }
    fence();
}
// A TLS poll can occupy the CPU for several records while the MAC receives.
#[cfg(feature = "extended-dma")]
const COUNT: usize = 1024;
#[cfg(not(feature = "extended-dma"))]
const COUNT: usize = 32;
const _: () = assert!(COUNT * 16 <= TX - RX);
const BUF: usize = 2048;
const TX_BUF: usize = RX_BUF + COUNT * BUF;
const OWN: u32 = 1 << 31;
const FD_LD: u32 = 3 << 28;

#[repr(align(4096))]
struct Table([usize; 512]);
static mut ROOT: Table = Table([0; 512]);
static mut LOW: Table = Table([0; 512]);

fn read(addr: usize) -> u32 {
    unsafe { ptr::read_volatile(addr as *const u32) }
}
fn write(addr: usize, v: u32) {
    unsafe { ptr::write_volatile(addr as *mut u32, v) }
}
fn fence() {
    unsafe { asm!("fence iorw, iorw", options(nostack)) }
}
fn update(addr: usize, clear: u32, set: u32) {
    write(addr, (read(addr) & !clear) | set);
}
fn wait_clear(addr: usize, mask: u32) -> bool {
    (0..1_000_000).any(|_| read(addr) & mask == 0)
}

// Identity map the low GiB, preserving PMA for devices and normal RAM.
// Only the private DMA arena gets the Svpbmt non-cacheable memory type.
unsafe fn map_arena() {
    let low = ptr::addr_of_mut!(LOW.0) as *mut usize;
    for n in 0..512 {
        let addr = n << 21;
        let flags = if addr == ARENA {
            (1usize << 61) | 0xc7
        } else if addr >= 0x20000000 {
            0xcf
        } else {
            0xc7
        };
        low.add(n).write((addr >> 2) | flags);
    }
    ROOT.0[0] = (low as usize >> 2) | 1;
    activate_dma_map();
}

// Caller must run after the boot hart has published the page tables.
pub unsafe fn activate_dma_map() {
    let satp = (8usize << 60) | (ptr::addr_of!(ROOT) as usize >> 12);
    asm!("sfence.vma","csrw satp, {}","sfence.vma",in(reg)satp);
}

fn descriptor(base: usize, slot: usize, addr: u32, word2: u32, status: u32) {
    let d = base + 16 * slot;
    write(d, addr);
    write(d + 4, 0);
    write(d + 8, word2);
    fence();
    write(d + 12, status);
}
fn arm_rx(slot: usize, address: usize) {
    descriptor(RX, slot + 1, 0, 0, OWN);
    descriptor(RX, slot, address as u32, 0, OWN);
}

#[cfg(feature = "extended-dma")]
mod rx_loan;
pub enum Received<'a> {
    View(&'a [u8]),
    #[cfg(feature = "extended-dma")]
    Loan(vibeos_hal::network_rx::Loan),
}
#[cfg(feature = "extended-dma")]
const LAN_Q0: usize = SE + 0x100000 + LAN * 0x2000;
pub struct Ethernet {
    #[cfg(feature = "local-offload")]
    classify_return: fn([u32; 3], &[u8]) -> bool,
    #[cfg(feature = "extended-dma")]
    original_lan_limits: (u32, u32),
    #[cfg(feature = "extended-dma")]
    buffers: rx_loan::Buffers,
    rx: usize,
    returned_rx: bool,
    tx: usize,
    pub received: u64,
    pub sent: u64,
    #[cfg(feature = "extended-dma")]
    pub tso: [(u64, u64); 2],
    #[cfg(feature = "extended-dma")]
    pub checksum_tx: [u64; 2],
    #[cfg(feature = "extended-dma")]
    lan_next: u64,
    #[cfg(feature = "extended-dma")]
    lan_ticks: u64,
    #[cfg(feature = "local-offload")]
    wan_ticks: u64,
    #[cfg(feature = "local-offload")]
    wan_next: u64,
    #[cfg(feature = "extended-dma")]
    lan_deferred: u64,
    #[cfg(feature = "extended-dma")]
    pub audit_rx: bool,
    #[cfg(feature = "extended-dma")]
    rx_ipc: [bool; 2],
    #[cfg(feature = "extended-dma")]
    verified_rx: [u64; 2],
    #[cfg(feature = "extended-dma")]
    audited: [[u64; 3]; 2],
    #[cfg(feature = "extended-dma")]
    tx_buffers: [Vec<u8>; COUNT / 2],
}
impl Ethernet {
    /// # Safety
    /// Call once on the boot hart with exclusive access to the RV2 DMA arena and MAC.
    pub unsafe fn start(#[cfg(feature = "local-offload")] classify_return: fn([u32; 3], &[u8]) -> bool) -> Result<Self, &'static str> {
        let _ = Console.write_str("mapping DMA arena\r\n");
        unsafe { map_arena() }
        let _ = Console.write_str("enabling Ethernet clocks\r\n");
        update(
            0x0ce0048c,
            0,
            (1 << 2) | (1 << 8) | (1 << 12) | (1 << 13) | (1 << 20),
        );
        // U-Boot uses a different CMNPLL multiplier from the stock kernel.
        // Calculate the divider for the required 250 MHz RGMII reference.
        let pll = read(0x0ce00400);
        let feedback = (pll >> 14) & 0xfff;
        let reference = pll & 0x3f;
        if reference == 0 || feedback == 0 || feedback % (10 * reference) != 0 {
            return Err("unsupported RGMII reference clock");
        }
        let divisor = feedback / (10 * reference);
        update(0x0ce00480, 1 << 27, 0);
        update(0x0ce0049c, 0xff << 24, (divisor - 1) << 24);
        write(0x0ce00500, 1);
        write(0x0ce00500, 0);
        // Release both host and line interface resets before the DMA reset.
        update(SYS + 0x88, 0x180, 0);
        update(SYS + 0x88, 0, 0x180);
        let _ = Console.write_str("resetting DMA\r\n");
        write(DMA + 0x3000, 1);
        if !wait_clear(DMA + 0x3000, 1) {
            return Err("DMA reset timeout");
        }
        let _ = Console.write_str("programming ingress table\r\n");
        // Direct ingress table entries upload each physical port to the CPU.
        update(SE + 0x180008, 1 << 19, 1 << 8);
        write(SE + 0x180040, 0xa0000);
        for port in 0..6 {
            write(SE + 0x18003c, 0x01010000 | port);
            if !wait_clear(SE + 0x18003c, 1 << 31) {
                return Err("ingress table busy");
            }
        }
        update(SE + 0x80038, 0x77000, 0x22000);
        write(SYS + 0xb8, 0x003f003f);
        write(SYS + 0xb4, 0xaa);
        write(DMA + 0x3000, 1 << 12);
        write(DMA + 0x3004, 0x1f1f8001);
        write(DMA + 0x3040, 1);
        write(DMA + 0x3044, 1);
        // All MTL input queues feed the single polled DMA channel.
        write(DMA + 0x1030, 0);
        write(DMA + 0x1034, 0);
        for q in 0..4 {
            write(DMA + 0x1100 + 0x80 * q, 0x7000a);
            write(DMA + 0x1140 + 0x80 * q, 0xf0000);
        }
        let _ = Console.write_str("initializing DMA rings\r\n");
        #[cfg(feature = "extended-dma")]
        flush_dma_lines(RX_BUF, COUNT * BUF);
        for i in (0..COUNT).step_by(2) {
            arm_rx(i, RX_BUF + i / 2 * BUF);
        }
        for i in 0..COUNT {
            descriptor(TX, i, 0, 0, 0);
        }
        write(DMA + 0x3114, TX as u32);
        write(DMA + 0x311c, RX as u32);
        write(DMA + 0x3130, COUNT as u32 - 1);
        write(DMA + 0x3134, (7 << 24) | COUNT as u32 - 1);
        write(DMA + 0x3124, TX as u32);
        write(DMA + 0x312c, (RX + 16 * COUNT) as u32);
        fence();
        write(
            DMA + 0x3104,
            0x100001
                | if cfg!(feature = "extended-dma") {
                    1 << 12
                } else {
                    0
                },
        );
        write(DMA + 0x3108, 0x100001 | (BUF as u32) << 1);
        let _ = Console.write_str("enabling MAC5\r\n");
        // Route RGMII and MAC0 MDIO through the RV2 pinctrl group.
        for off in [
            0x54, 0x5c, 0x60, 0x64, 0x68, 0x6c, 0x70, 0x74, 0x78, 0x7c, 0x80, 0x84, 0x88, 0x8c,
        ] {
            update(0x0ce3c000 + off, 0x1f80, 0x1100);
        }
        update(SYS + 0x88, 1 << 9, 0);
        write(SYS + 0xdc, 1 << 16);
        update(SYS + 0x88, 0, 1 << 9);
        let mac = 0x8000000 + LAN * 0x4000;
        // RV2 NAND DTS requests 1519 ps RX and 2499 ps TX on MAC5.
        // Each enabled delay field encodes (steps - 1), with 49 ps steps.
        update(
            SYS + 5 * 4,
            0x01ff01ff,
            (1 << 24) | (30 << 16) | (1 << 8) | 50,
        );
        write(mac + 8, 1);
        write(mac, 0x60000101);
        write(mac + 4, 0x207);
        update(SYS + 0xd4, 1 << LAN, 0);
        Ok(Self {
            #[cfg(feature = "local-offload")]
            classify_return,
            #[cfg(feature = "extended-dma")]
            original_lan_limits: (read(LAN_Q0) & 0x7ff00, read(LAN_Q0 + 0x18) & 0xfff),
            #[cfg(feature = "extended-dma")]
            buffers: rx_loan::Buffers::new(),
            rx: 0,
            returned_rx: false,
            tx: 0,
            received: 0,
            sent: 0,
            #[cfg(feature = "extended-dma")]
            tso: [(0, 0); 2],
            #[cfg(feature = "extended-dma")]
            checksum_tx: [0; 2],
            #[cfg(feature = "extended-dma")]
            lan_next: 0,
            #[cfg(feature = "extended-dma")]
            lan_ticks: LAN_TICKS_PER_BYTE,
            #[cfg(feature = "local-offload")]
            wan_ticks: 0,
            #[cfg(feature = "local-offload")]
            wan_next: 0,
            #[cfg(feature = "extended-dma")]
            lan_deferred: 0,
            #[cfg(feature = "extended-dma")]
            audit_rx: false,
            #[cfg(feature = "extended-dma")]
            rx_ipc: [false; 2],
            #[cfg(feature = "extended-dma")]
            verified_rx: [0; 2],
            #[cfg(feature = "extended-dma")]
            audited: [[0; 3]; 2],
            #[cfg(feature = "extended-dma")]
            tx_buffers: core::array::from_fn(|_| Vec::new()),
        })
    }
    pub fn receive(&mut self, out: &mut [u8; BUF]) -> Option<(u8, usize)> {
        let result = self.receive_view(|port, bytes, _| {
            out[..bytes.len()].copy_from_slice(bytes);
            (port, bytes.len())
        });
        self.flush_rx();
        result
    }
    pub fn flush_rx(&mut self) {
        if self.returned_rx {
            fence();
            write(DMA + 0x312c, (RX + 16 * self.rx) as u32);
            self.returned_rx = false;
        }
    }
    /// The callback finishes reading before the descriptor returns to DMA.
    pub fn receive_view<R>(&mut self, inspect: impl FnOnce(u8, &[u8], bool) -> R) -> Option<R> {
        self.receive_frame(|port, frame, verified| match frame {
            Received::View(bytes) => inspect(port, bytes, verified),
            #[cfg(feature = "extended-dma")]
            Received::Loan(loan) => inspect(port, loan.as_bytes(), verified),
        })
    }
    #[cfg(feature = "extended-dma")]
    pub fn set_rx_loan(&mut self, on: bool) { self.buffers.enabled = on; }
    #[cfg(feature = "extended-dma")]
    pub fn loan_stats(&self, side: usize) -> (u64, u64) { self.buffers.stats[side] }
    #[cfg(feature = "local-offload")]
    pub fn set_lan_loan(&mut self, enabled: bool) { self.buffers.lan_enabled = enabled; }
    #[cfg(feature = "local-offload")]
    pub fn set_solo_return_loans(&mut self, enabled: bool) { self.buffers.solo_returns = enabled; }
    #[inline]
    fn rx_address(&self, slot: usize) -> usize {
        #[cfg(feature = "extended-dma")]
        { self.buffers.address(slot) }
        #[cfg(not(feature = "extended-dma"))]
        { RX_BUF + slot / 2 * BUF }
    }
    pub fn receive_frame<R>(&mut self, inspect: impl FnOnce(u8, Received<'_>, bool) -> R) -> Option<R> {
        self.receive_inspected(|port, frame, verified, _| inspect(port, frame, verified))
    }
    pub fn receive_inspected<R>(&mut self, inspect: impl FnOnce(u8, Received<'_>, bool, [u32; 3]) -> R) -> Option<R> {
        let slot = self.rx;
        if read(RX + 16 * (slot + 1) + 12) & OWN != 0 {
            return None;
        }
        fence();
        let status = read(RX + 16 * slot + 12);
        let size = (status & 0x3fff) as usize;
        let desc0 = read(RX + 16 * slot);
        let port = (desc0 & 0x3f) as u8;
        let valid = status & (OWN | FD_LD | 1 << 15) == FD_LD && (14..=BUF).contains(&size);
        let result = valid.then(|| {
            #[cfg(feature = "local-offload")]
            let meta = [desc0, read(RX + 16 * (slot + 1)), read(RX + 16 * (slot + 1) + 4)];
            #[cfg(not(feature = "local-offload"))]
            let meta = [0; 3];
            let addr = self.rx_address(slot);
            #[cfg(feature = "extended-dma")]
            flush_dma_lines(addr, size);
            self.received += 1;
            // OWN is clear on both descriptors. A view expires at callback return.
            // A detached loan replaces this address before arm_rx publishes OWN.
            let bytes = unsafe { core::slice::from_raw_parts(addr as *const u8, size) };
            #[cfg(feature = "extended-dma")]
            let verified = self.rx_tcp_verified(slot, port, bytes);
            #[cfg(not(feature = "extended-dma"))]
            let verified = false;
            #[cfg(feature = "local-offload")]
            let translated = (self.classify_return)(meta, bytes);
            #[cfg(all(feature = "extended-dma", not(feature = "local-offload")))]
            let translated = false;
            #[cfg(feature = "extended-dma")]
            let eligible = match port {
                4 => verified || translated,
                #[cfg(feature = "local-offload")]
                5 => self.buffers.lan_enabled && verified,
                _ => false,
            };
            // One worker can consume small translated ACKs straight from DMA.
            // With competing workers, copying small frames costs less.
            #[cfg(feature = "local-offload")]
            let minimum = if port == 4 && translated && self.buffers.solo_returns { 14 } else { 128 };
            #[cfg(all(feature = "extended-dma", not(feature = "local-offload")))]
            let minimum = 128;
            #[cfg(feature = "extended-dma")]
            if self.buffers.enabled && eligible && (minimum..=1514).contains(&size) {
                if let Some(loan) = unsafe { self.buffers.detach(slot, size, usize::from(port - 4)) } {
                    return inspect(port, Received::Loan(loan), verified, meta);
                }
            }
            inspect(port, Received::View(bytes), verified, meta)
        });
        arm_rx(slot, self.rx_address(slot));
        self.rx = (slot + 2) % COUNT;
        self.returned_rx = true;
        result
    }
    pub fn tx_available(&self) -> bool {
        read(TX + 16 * self.tx + 12) & OWN == 0 && read(TX + 16 * (self.tx + 1) + 12) & OWN == 0
    }
    #[cfg(feature = "local-offload")]
    pub fn tx_batch_available(&self, packets: usize) -> bool {
        packets <= COUNT / 2 && (0..packets).all(|n| {
            let slot = (self.tx + 2 * n) % COUNT;
            read(TX + 16 * slot + 12) & OWN == 0 && read(TX + 16 * (slot + 1) + 12) & OWN == 0
        })
    }
    pub fn send(&mut self, port: u8, bytes: &[u8]) -> bool {
        self.send_frame(port, bytes, 0)
    }
    fn send_frame(&mut self, port: u8, bytes: &[u8], cic: u32) -> bool {
        if port >= 6 {
            return false;
        }
        self.submit_frame((7 << 17) | (1 << 16) | (u32::from(port) << 8) | 6, bytes, cic)
    }
    #[cfg(feature = "local-offload")]
    pub fn send_to_pipeline(&mut self, bytes: &[u8]) -> bool {
        // Vendor slow-mode descriptor, IVPORT = host, no forced physical egress.
        self.submit_frame((6 << 8) | 6, bytes, 0)
    }
    fn submit_frame(&mut self, context: u32, bytes: &[u8], cic: u32) -> bool {
        if !(14..=BUF).contains(&bytes.len()) { return false; }
        let i = self.tx;
        if !self.tx_available() {
            return false;
        }
        fence();
        let addr = TX_BUF + i / 2 * BUF;
        let len = bytes.len().max(60);
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), addr as *mut u8, bytes.len());
            ptr::write_bytes((addr + bytes.len()) as *mut u8, 0, len - bytes.len());
        }
        #[cfg(feature = "extended-dma")]
        flush_dma_lines(addr, len);
        descriptor(TX, i + 1, addr as u32, len as u32, OWN | FD_LD | cic | len as u32);
        descriptor(
            TX,
            i,
            context,
            0,
            OWN | (1 << 30) | (1 << 25),
        );
        self.tx = (i + 2) % COUNT;
        fence();
        write(DMA + 0x3124, (TX + self.tx * 16) as u32);
        self.sent += 1;
        true
    }
    #[cfg(feature = "extended-dma")]
    pub fn send_packet(&mut self, port: u8, packet: &mut vibeos_net_protocol::tx_packet::Packet) -> bool {
        let Some(mss) = packet.mss else {
            let checksum = matches!(port, 4 | 5)
                && vibeos_net_protocol::packet_accel::tcp_checksum_field(packet).is_some();
            let sent = self.send_frame(port, packet, if checksum { 3 << 16 } else { 0 });
            if sent && checksum { self.checksum_tx[usize::from(port - 4)] += 1; }
            return sent;
        };
        self.send_tso(port, packet, mss, (1 << 16) | (u32::from(port) << 8) | 6)
    }
    #[cfg(feature = "local-offload")]
    pub fn pipeline_tso(&mut self, packet: &mut vibeos_net_protocol::tx_packet::Packet, mss: u16) -> bool {
        self.send_tso(4, packet, mss, (6 << 8) | 6)
    }
    #[cfg(feature = "extended-dma")]
    fn send_tso(&mut self, port: u8, packet: &mut vibeos_net_protocol::tx_packet::Packet, mss: u16, context: u32) -> bool {
        use vibeos_net_protocol::packet_accel::{tso_headers, MAX_BYTES};
        // Each validated aggregate fits one 16 KiB slot. Buffer 1 supplies
        // Ethernet/IP/TCP headers, buffer 2 the contiguous payload (14-bit B2L).
        let (header, tcp) = tso_headers(packet).expect("invalid stack GSO headers");
        assert!(matches!(port, 4 | 5) && packet.len() <= MAX_BYTES && mss != 0);
        let payload = packet.len() - header;
        let segments = payload.div_ceil(usize::from(mss));
        // The driver paces aggregate submissions. Ordinary ACKs use the
        // single-frame path and do not consume a TSO grant.
        let now = crate::ticks();
        #[cfg(feature = "local-offload")]
        if port == 4 && self.wan_ticks != 0 && !self.wan_tso_ready_at(now) {
            return false;
        }
        if port == 5 && self.lan_next > now + 4096 * self.lan_ticks {
            self.lan_deferred += 1;
            return false;
        }
        let i = self.tx;
        let data = TX + 16 * (i + 1);
        if read(TX + 16 * i + 12) & OWN != 0 || read(data + 12) & OWN != 0 {
            return false;
        }
        fence();
        // Both descriptors have completed. Return the old packet allocation
        // and retain the new one until this slot completes again.
        let bytes = &mut self.tx_buffers[i / 2];
        core::mem::swap(bytes, &mut packet.bytes);
        clean_dma_source(bytes);
        let addr = bytes.as_ptr() as usize;
        write(data, addr as u32);
        write(data + 4, (addr + header) as u32);
        write(data + 8, header as u32 | (payload as u32) << 16);
        write(
            data + 12,
            OWN | FD_LD | ((tcp as u32 / 4) << 19) | (1 << 18) | payload as u32,
        );
        descriptor(
            TX,
            i,
            context,
            mss as u32,
            OWN | (1 << 30) | (1 << 26) | (1 << 25),
        );
        self.tx = (i + 2) % COUNT;
        fence();
        write(DMA + 0x3124, (TX + self.tx * 16) as u32);
        self.sent += 1;
        let counter = &mut self.tso[usize::from(port - 4)];
        counter.0 += 1;
        counter.1 += segments as u64;
        #[cfg(feature = "local-offload")]
        if port == 4 && self.wan_ticks != 0 {
            // DPNS adds six PPPoE bytes and the two-byte PPP protocol on MAC4.
            // The other 24 bytes per segment are preamble, FCS and idle gap.
            let wire_bytes = payload + segments * (header + 24 + 8);
            self.wan_next = self.wan_next.max(now) + wire_bytes as u64 * self.wan_ticks;
        }
        if port == 5 {
            // Account for per-segment Ethernet overhead as well as the TCP payload.
            let wire_bytes = payload + segments * (header + 24);
            self.lan_next = self.lan_next.max(now) + wire_bytes as u64 * self.lan_ticks;
        }
        true
    }
    #[cfg(feature = "extended-dma")]
    pub fn paced_wan_tso_ready(&self) -> Option<bool> {
        #[cfg(feature = "local-offload")]
        { (self.wan_ticks != 0).then(|| self.wan_tso_ready_at(crate::ticks())) }
        #[cfg(not(feature = "local-offload"))]
        { None }
    }
    #[cfg(feature = "local-offload")]
    fn wan_tso_ready_at(&self, now: u64) -> bool {
        self.wan_next <= now + WAN_TSO_CREDIT_BYTES * self.wan_ticks
    }
    #[cfg(feature = "local-offload")]
    pub fn set_wan_ticks(&mut self, ticks: u64) {
        self.wan_next = 0;
        self.wan_ticks = ticks;
    }
    #[cfg(feature = "extended-dma")]
    pub fn paced_lan_tso_ready(&self) -> Option<bool> {
        (self.lan_ticks != 0).then(|| self.lan_next <= crate::ticks() + 4096 * self.lan_ticks)
    }
    #[cfg(feature = "extended-dma")]
    pub fn set_lan_ticks(&mut self, ticks: u64) {
        self.lan_next = 0;
        self.lan_ticks = ticks;
    }
    #[cfg(feature = "extended-dma")]
    pub fn enable_rx_checksum(&mut self, enabled: bool) {
        self.rx_ipc = [4, 5].map(|port| enabled && read(0x08000004 + port * 0x4000) & (1 << 9) != 0);
    }
    #[cfg(feature = "extended-dma")]
    fn rx_tcp_verified(&mut self, slot: usize, port: u8, bytes: &[u8]) -> bool {
        if !matches!(port, 4 | 5) || !(54..=1514).contains(&bytes.len())
            || bytes[12..15] != [8, 0, 0x45] || bytes[23] != 6
            || u16::from_be_bytes([bytes[20],bytes[21]]) & 0xbfff != 0 {
            return false;
        }
        let side = usize::from(port - 4);
        if !self.rx_ipc[side] && !self.audit_rx { return false; }
        // Called only for a completed FD/LD pair without error summary.
        let normal = read(RX + 16 * slot);
        let context = read(RX + 16 * (slot + 1) + 4);
        let classified = normal >> 26 == 0 && context & (1 << 6) == 0;
        if self.audit_rx {
            let class = if !classified { 2 } else {
                usize::from(vibeos_net_protocol::ipv4::inspect(bytes, bytes[..6].try_into().unwrap()).is_err())
            };
            self.audited[side][class] += 1;
            if class != 0 { return false; }
        }
        if classified && self.rx_ipc[side] {
            self.verified_rx[side] += 1;
            return true;
        }
        false
    }
    #[cfg(feature = "extended-dma")]
    pub fn configure_lan_queue(&self, encrypted: bool) {
        // A segmented LAN transmission can exceed the reset limit of 15
        // packets and 31 buffer cells. Both limits apply to MAC5 queue 0.
        let (packets, cells) = if encrypted {
            (63 << 8, 255)
        } else {
            self.original_lan_limits
        };
        update(LAN_Q0 + 0x18, 0xfff, cells);
        update(LAN_Q0, 0x7ff00, packets);
        fence();
    }
    #[cfg(feature = "extended-dma")]
    pub fn report_offloads(&self) {
        let _ = writeln!(Console, "TMU drop/q0 pktlimit/buflimit {:?}\r",
            [read(SE + 0x380000 + 4 * 258), read(LAN_Q0), read(LAN_Q0 + 0x18)]);
        for port in [4,5] {
            let mac = 0x08000000 + port * 0x4000;
            let counters = [0x81c,0x87c,0x894,0x928,0x988,0x990].map(|offset| read(mac+offset));
            let _ = writeln!(Console, "MAC{port} tx/underflow/pause/rx-crc/pause/fifo {counters:?}\r");
        }
        let _ = writeln!(Console, "RX TCP checksum enabled/verified 4/5 {:?} {:?}\r", self.rx_ipc, self.verified_rx);
        let _ = writeln!(Console, "RX checksum audit good/invalid/unclassified 4/5 {:?}\r", self.audited);
        let _ = writeln!(Console, "LAN TSO pacing deferrals {}\r", self.lan_deferred);
        let _ = writeln!(Console, "LAN TSO ticks per wire byte {}\r", self.lan_ticks);
        #[cfg(feature = "local-offload")]
        let _ = writeln!(Console, "WAN TSO ticks per wire byte {}\r", self.wan_ticks);
        let queue_overflow = [0, 1, 2, 3].map(|q| read(DMA + 0x1144 + 0x80 * q));
        let _ = writeln!(Console, "MTL RX queue missed/overflow raw {:x?}\r", queue_overflow);
        for port in [4, 5, 6] {
            let mac = 0x08000000 + port * 0x4000;
            let _ = writeln!(Console, "MAC{} feat0/1/2 rx-config rss-ctrl {:x?}\r", port,
                [read(mac+0x11c), read(mac+0x120), read(mac+0x124), read(mac+4), read(mac+0xc80)]);
        }
        let _ = writeln!(Console, "DMA RX maps/TX control {:x?} ordinary TCP checksum TX 4/5 {:?}\r",
            [read(DMA+0x1030), read(DMA+0x1034), read(DMA+0x3104)], self.checksum_tx);
    }
    pub fn status(&self) -> [u32; 9] {
        [
            read(DMA + 0x3160),
            read(DMA + 0x314c),
            read(DMA + 0x3144),
            read(RX + self.rx * 16 + 12),
            read(DMA + 0x3020),
            read(SYS + 0x14),
            read(0x8014900),
            read(0x8014928),
            read(0x801481c),
        ]
    }
}
