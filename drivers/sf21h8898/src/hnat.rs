//! SF21H8898 DPNS internal NAPT RAM, hash RAM and five-tuple lookup port.
use core::{arch::asm, ptr};
const BASE: usize = 0x11000000;
const NAT: usize = 0x188000;
pub(crate) fn read(reg: usize) -> u32 {
    unsafe { ptr::read_volatile((BASE + reg) as *const u32) }
}
pub(crate) fn write(reg: usize, value: u32) {
    unsafe {
        ptr::write_volatile((BASE + reg) as *mut u32, value);
        asm!("fence iorw, iorw");
    }
}
pub(crate) fn update(reg: usize, mask: u32, value: u32) {
    write(reg, (read(reg) & !mask) | value)
}
pub(crate) fn wait(reg: usize, bits: u32) -> Result<(), &'static str> {
    for _ in 0..100_000 {
        if read(reg) & bits == 0 {
            return Ok(());
        }
    }
    Err("DPNS timeout")
}
fn table(bank: u32, index: u16, words: &[u32]) -> Result<u32, &'static str> {
    wait(NAT + 0x3c, 1 << 31)?;
    for (i, &word) in words.iter().enumerate() {
        write(NAT + 0x40 + 4 * i, word)
    }
    write(
        NAT + 0x3c,
        (u32::from(!words.is_empty()) << 24) | (bank << 16) | u32::from(index),
    );
    wait(NAT + 0x3c, 1 << 31)?;
    Ok(read(NAT + 0x80))
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Flow {
    pub inside: u32,
    pub remote: u32,
    pub outside: u32,
    pub sport: u16,
    pub dport: u16,
    pub mapped: u16,
    pub udp: bool,
}
impl Flow {
    fn key(self, reverse: bool) -> (u32, u16, u32, u16) {
        if reverse {
            (self.remote, self.dport, self.outside, self.mapped)
        } else {
            (self.inside, self.sport, self.remote, self.dport)
        }
    }
    fn hash(self, reverse: bool) -> u16 {
        let (src, sp, dst, dp) = self.key(reverse);
        let mut key = [0u8; 37];
        key[0] = self.udp as u8;
        key[1..3].copy_from_slice(&sp.to_be_bytes());
        key[15..19].copy_from_slice(&src.to_be_bytes());
        key[19..21].copy_from_slice(&dp.to_be_bytes());
        key[33..37].copy_from_slice(&dst.to_be_bytes());
        let mut crc = 0u16;
        for byte in key {
            crc ^= (byte as u16) << 8;
            for _ in 0..8 {
                crc = if crc & 0x8000 != 0 {
                    (crc << 1) ^ 0x1021
                } else {
                    crc << 1
                }
            }
        }
        crc & 0xfff
    }
    fn entry(self, inside_port: u8) -> [u32; 6] {
        [
            self.remote,
            u32::from(self.dport) | (self.inside << 16),
            (self.inside >> 16) | (u32::from(self.sport) << 16),
            (u32::from(self.mapped) << 4) | ((self.udp as u32) << 20) | (1 << 21),
            0,
            (4 << 15) | (u32::from(inside_port) << 20),
        ]
    }
    fn lookup(self, reverse: bool) -> Result<Option<u32>, &'static str> {
        let (s, sp, d, dp) = self.key(reverse);
        let key = [
            d,
            0,
            0,
            0,
            s,
            0,
            0,
            0,
            (u32::from(sp) << 16) | u32::from(dp),
            0,
            (self.udp as u32) | ((reverse as u32) << 3),
        ];
        for (i, word) in key.into_iter().enumerate() {
            write(NAT + 0x400 + 4 * i, word)
        }
        write(NAT + 0x38, 1);
        wait(NAT + 0x38, 1)?;
        Ok((read(NAT + 0x81c) & (1 << 16) != 0).then(|| (read(NAT + 0x818) >> 5) & 0xffff))
    }
}

// Exercise both lookup directions while traffic is still trapped to the CPU.
// Slot zero has special empty-hash semantics on this part. Use slot one.
pub fn probe() -> Result<(), &'static str> {
    update(NAT + 4, 7, 1 | 1 << 6 | 1 << 16 | 1 << 24);
    update(NAT + 8, 0x07ff_ffff, 0x01000000 | 0xfac688);
    write(NAT + 0x24, 0x7ff);
    wait(NAT + 0x24, 0x7ff)?;
    let f = Flow {
        inside: 0xc0000201,
        remote: 0xc6336401,
        outside: 0xcb007101,
        sport: 21001,
        dport: 31001,
        mapped: 41001,
        udp: true,
    };
    let result = (|| {
        table(8, 0, &[f.outside])?;
        table(4, 1, &f.entry(5))?;
        table(2, f.hash(false), &[1])?;
        table(0, f.hash(true), &[1])?;
        if f.lookup(false)? != Some(2) {
            return Err("SNAT lookup");
        }
        if f.lookup(true)? != Some(2) {
            return Err("DNAT lookup");
        }
        if (Flow {
            dport: f.dport + 1,
            ..f
        })
        .lookup(false)?
        .is_some()
        {
            return Err("five-tuple alias");
        }
        Ok(())
    })();
    write(NAT + 0x24, 0x7ff);
    wait(NAT + 0x24, 0x7ff)?;
    result
}

fn se_table(id: u32, index: u16, data: &[u32]) -> Result<u32, &'static str> {
    wait(0x18003c, 1 << 31)?;
    for (i, &word) in data.iter().enumerate() {
        write(0x180040 + 4 * i, word)
    }
    write(
        0x18003c,
        ((!data.is_empty() as u32) << 24) | (id << 16) | u32::from(index),
    );
    wait(0x18003c, 1 << 31)?;
    Ok(read(0x180080))
}
fn mac_num(mac: [u8; 6]) -> u64 {
    mac.into_iter().fold(0, |v, b| (v << 8) | u64::from(b))
}
fn mac_entry(index: u16, mac: [u8; 6], port: u8, term: bool) -> Result<(), &'static str> {
    let addr = mac_num(mac);
    let mut entry = [0u32; 5];
    entry[0] = ((if term { 2 } else { 1 }) << 22) | (2 << 24) | ((term as u32) << 26);
    entry[1] = 1 << (9 + port);
    entry[2] = (addr << 4) as u32;
    entry[3] = (addr >> 28) as u32;
    entry[4] = 2;
    se_table(7, index, &entry)?;
    {
        let mut crc = 0u16;
        for b in mac {
            crc ^= u16::from(b) << 8;
            for _ in 0..8 {
                crc = if crc & 0x8000 != 0 {
                    (crc << 1) ^ 0x1021
                } else {
                    crc << 1
                }
            }
        }
        let h = crc & 1023;
        let prior = se_table(5, h, &[])?;
        if prior != 0 && prior != u32::from(index) {
            return Err("MAC hash occupied");
        }
        se_table(5, h, &[index as u32])?;
        write(0x198100, addr as u32);
        write(0x198104, (addr >> 32) as u32);
        write(0x198108, 0);
        write(0x180030, 1);
        wait(0x180030, 1)?;
        let r = read(0x198184);
        if r & (1 << 22) == 0 || ((r >> 9) & 0x7ff) != index as u32 {
            return Err("termination MAC lookup");
        }
    }
    Ok(())
}

const COUNT: usize = 32;
struct Binding {
    flow: Flow,
    expires: u64,
    inside_port: u8,
}
pub struct Engine {
    entries: [Option<Binding>; COUNT],
    routes: [Option<(u32, u64)>; 32],
    stations: [Option<([u8; 6], u8)>; 64],
    lengths: [Option<(u16, bool)>; 7],
    #[cfg(feature = "local-offload")]
    local_isolated: bool,
    pub installed: u64,
    pub visits: u64,
}
impl Engine {
    pub fn start(
        lan: [u8; 6],
        wan: [u8; 6],
        inside: u32,
        outside: u32,
        session: Option<u16>,
        ethernet_prefixes: [[u8; 3]; 2],
    ) -> Result<Self, &'static str> {
        Self::ports(false)?;
        crate::acl::reset()?;
        write(0x190004, 2);
        wait(0x190004, 2)?;
        update(0x190008, 7 << 3, 1 << 3);
        // Keep the two physical ports on their CPU path while installing tables.
        write(0x180004, (1 << 5) | (1 << 6) | (1 << 7) | (1 << 9));
        wait(0x180004, 0xffff_ffff)?;
        update(0x180010, 0xf, 0xc9);
        write(0x18000c, 0x48208208);
        update(0x24004, 0, (1 << 9) | (1 << 20));
        update(0xc004, (1 << 11) | (3 << 1), (2 << 1) | (1 << 5));
        update(0x180008, 1 << 19, (1 << 27) | (1 << 8));
        // Enable egress lookup, TPID and action tables for the two untagged links.
        update(
            0x180010,
            (1 << 30) | (1 << 14),
            (1 << 31) | (7 << 24) | (3 << 15) | (1 << 8),
        );
        se_table(14, 1, &[0x0fff_ffff])?;
        se_table(13, 0, &[0x00fffff1, 0x70 << 19, 0])?;
        for port in [4, 5, 6] {
            se_table(10, port, &[0x8100])?;
            se_table(11, port, &[0x81008100])?;
            se_table(12, port, &[0x17, 0, u32::from(port)])?;
            let ports: u64 = 0x70;
            let isolation = ports | (ports << 27);
            se_table(17, port, &[isolation as u32, (isolation >> 32) as u32])?;
            let base = usize::from(port) * 0x2000;
            for queue in 0..8 {
                write(base + 0x100000 + queue * 32, 0x11f00);
                write(base + 0x100018 + queue * 32, 0x5ee);
            }
            for (offset, val) in [
                (0x101030, 0x03020100),
                (0x101034, 0x08080808),
                (0x101070, 0x06050400),
                (0x101074, 0x08080807),
                (0x101140, 24),
            ] {
                write(base + offset, val);
            }
            if read(base + 0x101144) & 16 != 0 {
                write(base + 0x101144, 0x2f)
            }
        }
        write(0x148004, 6);
        write(0x148008, 0x07fe07ff);
        write(0x14800c, 0x00280024);
        for (r, v) in [
            (0x28004, 0x06060606),
            (0x28008, 0x06060606),
            (0x2800c, 0x06060606),
            (0x28010, 0x3d3d3d3d),
        ] {
            write(r, v);
        }
        for (idx, mac) in [lan, wan].into_iter().enumerate() {
            let value = (u64::from(session.is_some()) << 61)
                | (1u64 << 63)
                | ((idx as u64) << 62)
                | (mac_num(mac) << 12);
            se_table(9, idx as u16, &[value as u32, (value >> 32) as u32, 0, 0])?;
            mac_entry(1 + idx as u16, mac, 6, true)?;
        }
        if let Some(id) = session {
            crate::acl::start(true)?;
            se_table(16, 1, &[0x21, 0x11000000 | u32::from(id)])?;
        }
        if session.is_none() {
            Self::ethernet_guards(true, ethernet_prefixes)?;
        }
        table(8, 0, &[outside])?;
        write(8, inside);
        update(0x28, 255, 0x48);
        update(
            0xbc,
            (7 << 24) | (7 << 19),
            (1 << 24) | (1 << 19) | (1 << 18),
        );
        update(0x1800c0, 0x3ffff, (1 << 17) | 4);
        update(0, 1 << 24, 0);
        update(0x20000, 1 << 16, 1 << 19);
        update(0x1c00c, 0, (1 << 25) | (1 << 26));
        write(0x28000, 0x17666);
        Ok(Self {
            entries: core::array::from_fn(|_| None),
            routes: [None; 32],
            stations: [None; 64],
            lengths: [None; 7],
            #[cfg(feature = "local-offload")]
            local_isolated: false,
            installed: 0,
            visits: 0,
        })
    }
    fn ports(fast: bool) -> Result<(), &'static str> {
        for p in [4, 5] {
            se_table(
                1,
                p,
                &[if fast {
                    (1 << 19) | (2 << 17) | (1 << 15) | (6 << 10)
                } else {
                    0xa0000
                }],
            )?;
        }
        Ok(())
    }
    pub fn clear(&mut self) -> Result<(), &'static str> {
        Self::ports(false)?;
        #[cfg(feature = "local-offload")]
        se_table(1, 6, &[0xa0000])?;
        write(NAT + 0x24, 0xff);
        wait(NAT + 0x24, 0xff)?;
        write(0x190004, 2);
        wait(0x190004, 2)?;
        self.routes.fill(None);
        self.entries.fill_with(|| None);
        Ok(())
    }
    pub fn expire(&mut self, now: u64) -> Result<(), &'static str> {
        for (i, route) in self.routes.iter_mut().enumerate() {
            if route.is_some_and(|(_, until)| now >= until) {
                route_write(i, 0, 0)?;
                *route = None;
            }
        }
        for (i, b) in self.entries.iter_mut().enumerate() {
            if let Some(entry) = b {
                if now < entry.expires {
                    continue;
                }
                table(4, i as u16 + 1, &[0; 6])?;
                table(2, entry.flow.hash(false), &[0])?;
                table(0, entry.flow.hash(true), &[0])?;
                *b = None;
            }
        }
        #[cfg(feature = "local-offload")]
        self.restore_native_lan()?;
        Ok(())
    }
    pub fn install(
        &mut self,
        flow: Flow,
        inside: [u8; 6],
        remote: [u8; 6],
        until: u64,
    ) -> Result<(), &'static str> {
        self.install_on(flow, inside, 5, remote, until, || true)
            .map(|_| ())
    }
    pub fn install_on(
        &mut self,
        flow: Flow,
        inside: [u8; 6],
        inside_port: u8,
        remote: [u8; 6],
        until: u64,
        authorize: impl FnOnce() -> bool,
    ) -> Result<bool, &'static str> {
        if let Some(binding) = self.entries.iter_mut().flatten().find(|b| b.flow == flow) {
            if binding.inside_port == 6 && inside_port == 6 && authorize() {
                binding.expires = until;
            }
            return Ok(false);
        }
        let Some(slot) = self.entries.iter().position(Option::is_none) else {
            return Ok(false);
        };
        let index = slot as u16 + 1;
        if table(2, flow.hash(false), &[])? != 0 || table(0, flow.hash(true), &[])? != 0 {
            return Ok(false);
        }
        let pri = self.station(inside, inside_port)?;
        let public = self.station(remote, 4)?;
        if !authorize() {
            return Ok(false);
        }
        #[cfg(feature = "local-offload")]
        if inside_port == 6 && !self.local_isolated {
            crate::acl::Guard::isolate_local_sockets(true)?;
            self.local_isolated = true;
        }
        let mut data = flow.entry(inside_port);
        data[3] |= 1 << 22; // source router interface index on SNAT, LAN index 0 on DNAT
        data[4] |= (u32::from(pri) << 2) | (u32::from(public) << 13);
        table(4, index, &data)?;
        table(2, flow.hash(false), &[u32::from(index)])?;
        table(0, flow.hash(true), &[u32::from(index)])?;
        if flow.lookup(false)? != Some(2 * u32::from(index))
            || flow.lookup(true)? != Some(2 * u32::from(index))
        {
            return Err("live flow lookup");
        }
        self.entries[slot] = Some(Binding {
            flow,
            expires: until,
            inside_port,
        });
        self.installed += 1;
        Self::ports(true)?;
        Ok(true)
    }
    #[cfg(feature = "local-offload")]
    fn restore_native_lan(&mut self) -> Result<(), &'static str> {
        if self.local_isolated && self.entries.iter().flatten().all(|b| b.inside_port != 6) {
            crate::acl::Guard::isolate_local_sockets(false)?;
            self.local_isolated = false;
        }
        Ok(())
    }
    #[cfg(feature = "local-offload")]
    pub fn local_binding(&self, private_port: u16, peer_port: u16, now: u64) -> bool {
        self.entries.iter().flatten().any(|b| {
            b.inside_port == 6
                && b.expires > now
                && b.flow.sport == private_port
                && b.flow.dport == peer_port
        })
    }
    #[cfg(feature = "local-offload")]
    pub fn retire_local(&mut self) -> Result<(), &'static str> {
        for i in 0..COUNT {
            if let Some(b) = self.entries[i].as_ref().filter(|b| b.inside_port == 6) {
                let f = b.flow;
                self.retire_tcp(false, f.inside, f.sport, f.remote, f.dport)?;
            }
        }
        Ok(())
    }
    #[cfg(feature = "local-offload")]
    pub fn local_ingress(&mut self, sid: u16, peer: [u8; 6], mtu: u16) -> Result<(), &'static str> {
        crate::acl::Guard::drop_wan_ipv4(0)?;
        // The DMA descriptor supplies a logical ingress port for pipeline lookup.
        se_table(1, 6, &[(1 << 19) | (2 << 17) | (1 << 15) | (6 << 10)])?;
        for length in [mtu, mtu - 20, 40] {
            self.ppp_guard(length, sid, peer, false)?;
        }
        Ok(())
    }
    fn station(&mut self, mac: [u8; 6], port: u8) -> Result<u16, &'static str> {
        if let Some(i) = self.stations.iter().position(|s| *s == Some((mac, port))) {
            return Ok(i as u16 + 4);
        }
        let i = self
            .stations
            .iter()
            .position(Option::is_none)
            .ok_or("MAC table full")?;
        let index = i as u16 + 4;
        mac_entry(index, mac, port, false)?;
        self.stations[i] = Some((mac, port));
        Ok(index)
    }
    pub fn route(
        &mut self,
        ip: u32,
        mac: [u8; 6],
        out: usize,
        until: u64,
    ) -> Result<(), &'static str> {
        if self.routes.iter().flatten().any(|&(addr, _)| addr == ip) {
            return Ok(());
        }
        let Some(slot) = self.routes.iter().position(Option::is_none) else {
            return Ok(());
        };
        let port = [5, 4][out];
        let index = self.station(mac, port)?;
        let key = u128::from(index)
            | (u128::from(port) << 11)
            | ((out as u128) << 16)
            | (u128::from(ip) << 28);
        route_write(
            slot,
            key,
            ((1u128 << 72) - 1) ^ (u128::from(u32::MAX) << 28),
        )?;
        self.routes[slot] = Some((ip, until));
        update(0, 0, 1 << 24);
        update(0x20000, (1 << 19) | (1 << 16), 0);
        Self::ports(true)
    }
    pub fn ppp_guard(
        &mut self,
        length: u16,
        id: u16,
        peer: [u8; 6],
        udp: bool,
    ) -> Result<(), &'static str> {
        if self.lengths.contains(&Some((length, udp))) {
            return Ok(());
        }
        let Some(i) = self.lengths.iter().position(Option::is_none) else {
            return Ok(());
        };
        let mut lan = crate::acl::Guard::new(5);
        lan.bytes(0, &[8, 0, 0x45]);
        lan.bytes(4, &length.to_be_bytes());
        lan.transport(udp);
        lan.bytes(11, &[if udp { 17 } else { 6 }]);
        if !udp {
            lan.bytes(12, &[0x50, 0x10]);
            lan.ignore_psh(12);
        }
        lan.install(2 * i + 2)?;
        let mut wan = crate::acl::Guard::new(4);
        wan.source(peer);
        wan.bytes(0, &[0x88, 0x64, 0x11, 0]);
        wan.bytes(4, &id.to_be_bytes());
        wan.bytes(6, &(length + 2).to_be_bytes());
        wan.bytes(8, &[0, 0x21, 0x45]);
        wan.transport(udp);
        if !udp {
            wan.bytes(14, &[0x50, 0x10]);
            wan.ignore_psh(14);
        }
        wan.install(2 * i + 3)?;
        self.lengths[i] = Some((length, udp));
        Ok(())
    }
    pub fn ethernet_guards(tcp_controls: bool, prefixes: [[u8; 3]; 2]) -> Result<(), &'static str> {
        crate::acl::start(false)?;
        for (i, p) in [5, 4].into_iter().enumerate() {
            crate::acl::Guard::trap_ttl(p, i, 10)?;
        }
        for (side, port) in [5, 4].into_iter().enumerate() {
            for (n, proto) in [17, 6].into_iter().enumerate() {
                let mut rule = crate::acl::Guard::new(port);
                rule.bytes(0, &[8, 0, 0x45]);
                rule.bytes(11, &[proto]);
                rule.bytes(14, &prefixes[side][..2]);
                rule.bytes(6, &prefixes[side][2..]);
                if tcp_controls && proto == 6 {
                    // Permit only a 20-byte TCP header carrying ACK or PSH+ACK.
                    // The software owner receives SYN, FIN, RST and all TCP options.
                    rule.bytes(12, &[0x50, 0x10]);
                    rule.ignore_psh(12);
                }
                rule.install(2 + side * 4 + n)?;
            }
        }
        Ok(())
    }
    pub fn retire_tcp(
        &mut self,
        reverse: bool,
        src: u32,
        sport: u16,
        dst: u32,
        dport: u16,
    ) -> Result<(), &'static str> {
        for (slot, binding) in self.entries.iter_mut().enumerate() {
            if binding
                .as_ref()
                .is_some_and(|b| !b.flow.udp && b.flow.key(reverse) == (src, sport, dst, dport))
            {
                let flow = binding.as_ref().unwrap().flow;
                table(4, slot as u16 + 1, &[0; 6])?;
                table(2, flow.hash(false), &[0])?;
                table(0, flow.hash(true), &[0])?;
                *binding = None;
            }
        }
        #[cfg(feature = "local-offload")]
        self.restore_native_lan()?;
        Ok(())
    }
    pub fn sample(&mut self) {
        for n in 0..3 {
            self.visits += u64::from(read(0x189000 + 4 * n).count_ones());
        }
    }
}

fn route_write(slot: usize, key: u128, mask: u128) -> Result<(), &'static str> {
    let slice = 16 - slot % 8;
    let row = 3 - slot / 8;
    for (bank, address, data) in [
        (slice, row * 2, key),
        (slice, row * 2 + 1, mask),
        (17, row, 0),
    ] {
        write(0x190040, data as u32);
        write(0x190044, (data >> 32) as u32);
        write(0x190048, (data >> 64) as u32);
        write(0x19003c, (1 << 24) | ((bank as u32) << 16) | address as u32);
        wait(0x19003c, 1 << 31)?;
    }
    Ok(())
}
#[cfg(feature = "local-offload")]
pub fn translated_return(meta: [u32; 3]) -> bool {
    // Original ingress MAC4, destination host port 6, tunnel present and
    // normal delivery (up_reason zero). TNP does not attest to an L4 checksum.
    meta[0] & 0xfff == (6 << 6 | 4) && meta[2] & (1 << 6) != 0 && meta[2] >> 24 == 0
}

pub fn mib(index: u16) -> u32 { read(0x380000 + 4 * usize::from(index)) }

pub fn counters() {
    use core::fmt::Write;
    for (k, idx) in [
        ("ivlan-drop", 144),
        ("ivlkp-drop", 152),
        ("l2-hit", 163),
        ("l2-sa", 164),
        ("l2-drop", 166),
        ("nat-hit", 174),
        ("nat-dnat", 179),
        ("nat-drop", 259),
        ("nat-up", 260),
        ("nat-fwd", 261),
        ("l3-drop", 266),
        ("evlan-drop", 312),
        ("modify-drop", 355),
        ("tmu-drop", 258),
        ("ppp-add", 362),
        ("ppp-del", 363),
    ] {
        let _ = write!(crate::Console, " {k}={}", read(0x380000 + 4 * idx));
    }
    let _ = crate::Console.write_str("\r\n");
    for i in 0..374 {
        let v = read(0x380000 + 4 * i);
        if v != 0 {
            let _ = write!(crate::Console, " {i}:{v}");
        }
    }
    let _ = crate::Console.write_str("\r\n");
}
