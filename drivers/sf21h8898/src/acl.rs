//! DPNS ingress TCAM. Mode 4 includes both Ethernet addresses and eight
//! programmable two-byte slices from the original wire header.
use crate::hnat::{update, wait, write};
const ANY: [u8; 36] = [255; 36];
pub struct Guard {
    key: [u8; 36],
    mask: [u8; 36],
}
impl Guard {
    pub fn new(port: u8) -> Self {
        let mut g = Self {
            key: [0; 36],
            mask: ANY,
        };
        g.field(138, 5, port as u64);
        g
    }
    fn field(&mut self, bit: usize, width: usize, value: u64) {
        for i in 0..width {
            let n = bit + i;
            self.mask[n / 8] &= !(1 << (n % 8));
            self.key[n / 8] |= (((value >> i) & 1) as u8) << (n % 8);
        }
    }
    pub fn source(&mut self, mac: [u8; 6]) {
        self.field(
            42,
            48,
            mac.into_iter().fold(0, |v, b| v << 8 | u64::from(b)),
        );
    }
    #[cfg(feature = "local-offload")]
    pub fn drop_wan_ipv4(index: usize) -> Result<(), &'static str> {
        let mut bare = Self::new(4);
        bare.bytes(0, &[8, 0]);
        bare.key[0] = 1;
        bare.install(index)
    }
    #[cfg(feature = "local-offload")]
    pub fn isolate_local_sockets(active: bool) -> Result<(), &'static str> {
        // The NAT table keys on the TCP tuple, not the ingress port. When a
        // local socket is installed, send physical LAN input through its
        // source-address check. Restore native LAN acceleration after teardown.
        if !active {
            return Self::drop_wan_ipv4(1);
        }
        let mut lan = Self::new(5);
        lan.key[0] = 2;
        lan.install(1)
    }
    pub fn bytes(&mut self, index: usize, bytes: &[u8]) {
        // Extracted halfwords are little-endian in the TCAM key.
        for (i, byte) in bytes.iter().enumerate() {
            let slot = 20 + ((index + i) ^ 1);
            self.key[slot] = *byte;
            self.mask[slot] = 0;
        }
    }
    pub fn ignore_psh(&mut self, flags_word: usize) {
        self.mask[20 + ((flags_word + 1) ^ 1)] |= 8;
    }
    pub fn transport(&mut self, udp: bool) {
        self.field(38, 2, 0);
        self.field(40, 2, u64::from(udp));
    }
    pub fn trap_ttl(port: u8, index: usize, at: usize) -> Result<(), &'static str> {
        let mut rule = Self::new(port);
        rule.key[0] = 2;
        rule.bytes(at, &[0]);
        rule.mask[20 + (at ^ 1)] = 1;
        rule.install(index)
    }
    pub fn install(&self, index: usize) -> Result<(), &'static str> {
        let row = index / 2;
        for (i, (key, mask)) in self
            .key
            .chunks_exact(9)
            .zip(self.mask.chunks_exact(9))
            .enumerate()
        {
            let bank = 27 + 4 * (index % 2) + i;
            for (address, data) in [(row * 2, key), (row * 2 + 1, mask)] {
                write(0x190040, u32::from_le_bytes(data[..4].try_into().unwrap()));
                write(0x190044, u32::from_le_bytes(data[4..8].try_into().unwrap()));
                write(0x190048, u32::from(data[8]));
                command(bank, address)?;
            }
        }
        write(0x190040, 8);
        command(35, row)
    }
}
fn command(bank: usize, address: usize) -> Result<(), &'static str> {
    write(0x19003c, (1 << 24) | ((bank as u32) << 16) | address as u32);
    wait(0x19003c, 1 << 31)
}
pub fn reset() -> Result<(), &'static str> {
    write(0x190004, 8);
    wait(0x190004, 8)?;
    update(0x2c000, 1 << 25, 1 << 16);
    Ok(())
}
pub fn start(ppp: bool) -> Result<(), &'static str> {
    reset()?;
    update(0x190008, 7 << 9, 3 << 9);
    // The parser numbers bits from the MSB of the first 128 wire bytes.
    // Its two-byte extractor selects the high bit of the wire halfword.
    let offsets = if ppp {
        [12, 14, 16, 18, 20, 22, 46, 54]
    } else {
        [12, 14, 16, 28, 20, 22, 46, 26]
    };
    for (i, words) in offsets.chunks(3).enumerate() {
        let mut reg = if i == 0 { 1 << 31 } else { 0 };
        for (n, offset) in words.iter().enumerate() {
            reg |= (1023 - 8 * offset) << (10 * n);
        }
        write(0x80044 + 4 * i, reg);
    }
    let mut trap = Guard {
        key: [0; 36],
        mask: ANY,
    };
    trap.key[0] = 2;
    trap.install(31)?;
    update(0x2c000, (7 << 19) | (1 << 16), (4 << 19) | (1 << 25));
    write(0x2c004, (1 << 4) | (1 << 5));
    Ok(())
}
