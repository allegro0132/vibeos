//! Admission for one esbuild 0.25 transform packet. No filesystem input, build,
//! plugin, subprocess, or long-lived service request can cross this boundary.
const MAX_PACKET: usize = 1024 * 1024 + 65536;
const MAX_INPUT: usize = 1024 * 1024;

pub(super) fn validate(packet: &[u8]) -> bool {
    validate_inner(packet).is_some()
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() { return None; }
        let (value, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(value)
    }
    fn byte(&mut self) -> Option<u8> { Some(self.take(1)?[0]) }
    fn u32(&mut self) -> Option<u32> { Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?)) }
    fn blob(&mut self, maximum: usize) -> Option<&'a [u8]> {
        let length = self.u32()? as usize;
        if length > maximum { return None; }
        self.take(length)
    }
    fn text(&mut self, maximum: usize) -> Option<&'a str> {
        core::str::from_utf8(self.blob(maximum)?).ok()
    }
    fn tag(&mut self, expected: u8) -> Option<()> {
        (self.byte()? == expected).then_some(())
    }
}

fn validate_inner(packet: &[u8]) -> Option<()> {
    if packet.len() < 9 || packet.len() > MAX_PACKET { return None; }
    let mut r = Reader(packet);
    if r.u32()? as usize != packet.len() - 4 { return None; }
    // The one-shot upstream synchronous channel starts with request ID zero.
    if r.u32()? != 0 { return None; }
    r.tag(6)?;
    let count = r.u32()?;
    if !(4..=5).contains(&count) { return None; }
    let mut seen = 0u8;
    for _ in 0..count {
        let field = match r.text(32)? {
            "command" => { r.tag(3)?; if r.text(16)? != "transform" { return None; } 1 }
            "inputFS" => { r.tag(1)?; r.tag(0)?; 2 }
            "input" => { r.tag(4)?; r.blob(MAX_INPUT)?; 4 }
            "flags" => {
                r.tag(5)?;
                let count = r.u32()?;
                if count > 128 { return None; }
                for _ in 0..count { r.tag(3)?; r.text(4096)?; }
                8
            }
            "mangleCache" => {
                r.tag(6)?;
                let count = r.u32()?;
                if count > 4096 { return None; }
                for _ in 0..count {
                    r.text(4096)?;
                    match r.byte()? {
                        1 => { r.tag(0)?; }
                        3 => { r.text(4096)?; }
                        _ => return None,
                    }
                }
                16
            }
            _ => return None,
        };
        if seen & field != 0 { return None; }
        seen |= field;
    }
    (seen & 15 == 15 && r.0.is_empty()).then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn string(out: &mut Vec<u8>, text: &str) {
        out.extend_from_slice(&(text.len() as u32).to_le_bytes());
        out.extend_from_slice(text.as_bytes());
    }
    fn packet(command: &str, file: bool) -> Vec<u8> {
        let mut p = vec![0; 8];
        p.push(6); p.extend_from_slice(&4u32.to_le_bytes());
        string(&mut p, "command"); p.push(3); string(&mut p, command);
        string(&mut p, "inputFS"); p.extend_from_slice(&[1, file as u8]);
        string(&mut p, "input"); p.push(4); string(&mut p, "const n: number = 42");
        string(&mut p, "flags"); p.push(5); p.extend_from_slice(&1u32.to_le_bytes());
        p.push(3); string(&mut p, "--loader=ts");
        let size = p.len() as u32 - 4;
        p[..4].copy_from_slice(&size.to_le_bytes());
        p
    }
    #[test]
    fn transform_only_no_filesystem() {
        assert!(validate(&packet("transform", false)));
        for command in ["build", "context", "serve", "format-msgs", "dispose"] {
            assert!(!validate(&packet(command, false)));
        }
        assert!(!validate(&packet("transform", true)));
    }
    #[test]
    fn framing_truncation_and_trailing_packets() {
        let good = packet("transform", false);
        for n in 0..good.len() { assert!(!validate(&good[..n])); }
        let mut extra = good.clone(); extra.extend_from_slice(&good);
        assert!(!validate(&extra));
        let mut response = good.clone(); response[4] = 1;
        assert!(!validate(&response));
        let mut wrong_id = good; wrong_id[4] = 2;
        assert!(!validate(&wrong_id));
    }
    #[test]
    fn rejects_overflow_and_duplicate_fields() {
        let mut p = packet("transform", false);
        p[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!validate(&p));
        let mut p = packet("transform", false);
        p[9..13].copy_from_slice(&5u32.to_le_bytes());
        string(&mut p, "command"); p.push(3); string(&mut p, "transform");
        let size = p.len() as u32 - 4;
        p[..4].copy_from_slice(&size.to_le_bytes());
        assert!(!validate(&p));
        assert!(!validate(&vec![0; MAX_PACKET + 1]));
    }
}
