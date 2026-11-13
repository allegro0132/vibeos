extern crate std;
use super::*;
use crate::mdio;
const MAC: [u8; 6] = [2, 0x42, 0x70, 4, 0, 2];
fn record(fid: u16, mac: [u8; 6]) -> [u8; 53] {
    let mut b = [0; 53];
    b[2..4].copy_from_slice(&fid.to_le_bytes());
    b[4] = 9;
    b[9] = 2; // firmware readback expands destination port 9 into bit 9
    b[30] = 1;
    b[33..39].copy_from_slice(&mac);
    b
}
struct Mock {
    regs: [u16; 96],
    entries: std::vec::Vec<[u8; 53]>,
    cursor: usize,
    reads: usize,
    mutations: std::vec::Vec<(u16, std::vec::Vec<u8>)>,
    never_end: bool,
    fail: Option<u16>,
}
impl Mock {
    fn new() -> Self {
        Self {
            regs: [0; 96],
            entries: std::vec::Vec::new(),
            cursor: 0,
            reads: 0,
            mutations: std::vec::Vec::new(),
            never_end: false,
            fail: None,
        }
    }
    fn reply(&mut self, b: &[u8]) {
        for (i, p) in b.chunks(2).enumerate() {
            self.regs[i + 2] = u16::from_le_bytes([p[0], p.get(1).copied().unwrap_or(0)]);
        }
    }
}
impl Io for Mock {
    fn now(&self) -> u64 {
        0
    }
    fn read(&mut self, r: u16) -> Result<u16, mdio::Error> {
        Ok(self.regs[r as usize])
    }
    fn write(&mut self, r: u16, v: u16) -> Result<(), mdio::Error> {
        self.regs[r as usize] = v;
        if r != 0 {
            return Ok(());
        }
        let cmd = v & 0x7fff;
        let len = self.regs[1] as usize;
        let b: std::vec::Vec<u8> = (0..len)
            .map(|i| self.regs[2 + i / 2].to_le_bytes()[i % 2])
            .collect();
        self.regs[0] = cmd;
        self.regs[1] = 0;
        if cmd != 0x0a03 {
            self.mutations.push((cmd, b.clone()));
        }
        if self.fail == Some(cmd) {
            self.regs[1] = (-7i16) as u16;
            return Ok(());
        }
        match cmd {
            0x0a03 => {
                assert_eq!(len, 53);
                assert!(b[1..].iter().all(|v| *v == 0));
                if b[0] == 1 {
                    self.cursor = 0;
                } else {
                    assert_eq!(b[0], 0);
                }
                self.reads += 1;
                let mut response = [0; 53];
                if let Some(entry) = self.entries.get(self.cursor) {
                    response = *entry;
                    self.cursor += 1;
                } else if !self.never_end {
                    response[1] = 1;
                }
                self.reply(&response);
            }
            0x0a02 => {
                assert_eq!(b, add_request(6, MAC));
                self.entries.push(record(6, MAC));
            }
            0x0a05 => {
                assert_eq!(b, remove_request(6, MAC));
                self.entries
                    .retain(|entry| entry[2..4] != [6, 0] || entry[33..39] != MAC);
            }
            _ => panic!("unexpected FDB command, no table flush permitted: {cmd:x}"),
        }
        Ok(())
    }
}

#[test]
fn packed_requests_and_readback_own_only_gateway_key() {
    let add = add_request(0x1234, MAC);
    assert_eq!(&add[..6], &[0x34, 0x12, 9, 0, 0, 0]);
    assert_eq!(add[30], 1);
    assert_eq!(&add[32..38], &MAC);
    assert!(add[6..30].iter().chain(add[38..].iter()).all(|v| *v == 0));
    assert_eq!(
        remove_request(0x1234, MAC),
        [0x34, 0x12, 2, 0x42, 0x70, 4, 0, 2, 0, 0, 0]
    );
    let mut hw = Mock::new();
    hw.entries.push(record(2, MAC));
    let mut m = Mailbox::new(&mut hw, 10);
    assert_eq!(m.find_fdb(6, MAC), Ok(None));
    m.add_gateway_fdb(6, MAC).unwrap();
    assert!(m.find_fdb(6, MAC).unwrap().unwrap().gateway(6, MAC));
    m.remove_gateway_fdb(6, MAC).unwrap();
    assert!(m.find_fdb(2, MAC).unwrap().is_some());
    assert_eq!(hw.entries.len(), 1);
    assert_eq!(hw.mutations.len(), 2);
}

#[test]
fn scan_restarts_and_never_reports_false_absence_on_malformed_or_incomplete_walk() {
    let mut hw = Mock::new();
    hw.entries.push(record(6, MAC));
    for _ in 0..2 {
        assert!(Mailbox::new(&mut hw, 10)
            .find_fdb(6, MAC)
            .unwrap()
            .is_some());
    }
    hw.entries.push(record(6, MAC));
    assert_eq!(
        Mailbox::new(&mut hw, 10).find_fdb(6, MAC),
        Err(Error::InvalidResponse)
    );
    hw.entries.clear();
    let mut b = record(6, MAC);
    b[30] = 2;
    hw.entries.push(b);
    assert_eq!(
        Mailbox::new(&mut hw, 10).find_fdb(6, MAC),
        Err(Error::InvalidResponse)
    );
    hw.entries.clear();
    hw.never_end = true;
    hw.reads = 0;
    assert_eq!(
        Mailbox::new(&mut hw, 10).find_fdb(6, MAC),
        Err(Error::InvalidResponse)
    );
    assert_eq!(hw.reads, MAX_RECORDS + 1);
    assert!(hw.mutations.is_empty());
}

#[test]
fn firmware_failures_do_not_retry_add_or_remove() {
    for command in [0x0a02, 0x0a05] {
        let mut hw = Mock::new();
        hw.fail = Some(command);
        let mut m = Mailbox::new(&mut hw, 10);
        let result = if command == 0x0a02 {
            m.add_gateway_fdb(6, MAC)
        } else {
            m.remove_gateway_fdb(6, MAC)
        };
        assert_eq!(result, Err(Error::Firmware(-7)));
        assert_eq!(hw.mutations.len(), 1);
    }
}

#[test]
fn gateway_rejects_extra_destinations_dynamic_entries_and_other_keys() {
    let entry = FdbEntry::decode(&record(6, MAC)).unwrap();
    assert!(entry.gateway(6, MAC));
    let mut extra = entry;
    extra.map[0] |= 2;
    assert!(!extra.gateway(6, MAC));
    assert!(!FdbEntry {
        static_entry: false,
        ..entry
    }
    .gateway(6, MAC));
    assert!(!FdbEntry { tci: 1, ..entry }.gateway(6, MAC));
    assert!(!FdbEntry { filter: 1, ..entry }.gateway(6, MAC));
    assert!(!entry.gateway(7, MAC));
}
