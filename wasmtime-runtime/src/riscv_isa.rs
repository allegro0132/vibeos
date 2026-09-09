//! Allocation-free discovery of common RISC-V CPU extensions from a boot DTB.
//! This is a narrow, fail-closed FDT v17 reader, not a device-tree framework.
//! Sources: DTSpec flattened format and Linux bindings/riscv/cpus.yaml.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Features(u8);
impl Features {
    pub const NONE: Self = Self(0);
    const ALL: u8 = 15;
    pub fn bits(self) -> u8 {
        self.0
    }
    pub fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL)
    }
    /// Apply only the scalar extensions understood by this port.
    ///
    /// # Safety
    /// The embedding must establish that every CPU which can execute this
    /// engine supports these extensions. A guest-supplied DTB is not evidence.
    #[cfg(feature = "compiler")]
    pub unsafe fn configure(self, config: &mut wasmtime::Config) {
        for (bit, name) in [
            (1, "has_zba"),
            (2, "has_zbb"),
            (4, "has_zbc"),
            (8, "has_zbs"),
        ] {
            if self.0 & bit != 0 {
                unsafe {
                    config.cranelift_flag_enable(name);
                }
            }
        }
    }
}
fn word(data: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        data.get(p..p.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn region(data: &[u8], p: usize, n: usize) -> Option<&[u8]> {
    data.get(p..p.checked_add(n)?)
}
fn cstr(data: &[u8]) -> Option<(&[u8], usize)> {
    let n = data.iter().position(|b| *b == 0)?;
    Some((&data[..n], n + 1))
}
fn align4(n: usize) -> Option<usize> {
    n.checked_add(3).map(|v| v & !3)
}
fn extensions(data: &[u8]) -> Option<Features> {
    if data.is_empty() || data.last() != Some(&0) {
        return None;
    }
    let mut mask = 0;
    for name in data[..data.len() - 1].split(|b| *b == 0) {
        if name.is_empty() || name.len() > 64 {
            return None;
        }
        mask |= match name {
            b"zba" => 1,
            b"zbb" => 2,
            b"zbc" => 4,
            b"zbs" => 8,
            _ => 0,
        };
    }
    Some(Features(mask))
}
#[derive(Clone, Copy, Default)]
struct Node {
    kind: u8, // 1 root, 2 /cpus, 3 direct CPU child, 0 unrelated
    child: bool,
    address_cells: u32,
    size_cells: Option<u32>,
    cpu: bool,
    reg: Option<u64>,
    features: Option<Features>,
}
/// Return the intersection for exactly the harts the embedding can schedule.
/// Missing/duplicate CPU nodes, absent extension lists and malformed structures
/// disable discovery. Unknown extensions are ignored; they never grant support.
/// Legacy `riscv,isa` alone deliberately does not grant extra extensions.
pub fn common(dtb: &[u8], harts: &[u64]) -> Option<Features> {
    if harts.is_empty()
        || harts.len() > 64
        || dtb.len() > 1024 * 1024
        || word(dtb, 0)? != 0xd00dfeed
    {
        return None;
    }
    for (i, hart) in harts.iter().enumerate() {
        if harts[..i].contains(hart) {
            return None;
        }
    }
    let total = word(dtb, 4)? as usize;
    let dtb = dtb.get(..total)?;
    if total < 40 || word(dtb, 20)? < 17 || word(dtb, 24)? > 17 {
        return None;
    }
    let struct_offset = word(dtb, 8)? as usize;
    let strings_offset = word(dtb, 12)? as usize;
    let struct_len = word(dtb, 36)? as usize;
    let strings_len = word(dtb, 32)? as usize;
    if struct_offset < 40 || struct_offset % 4 != 0 || strings_offset < 40 {
        return None;
    }
    let structure = region(dtb, struct_offset, struct_len)?;
    let strings = region(dtb, strings_offset, strings_len)?;
    if struct_offset < strings_offset.checked_add(strings_len)?
        && strings_offset < struct_offset.checked_add(struct_len)?
    {
        return None;
    }
    let mut stack = [Node::default(); 32];
    let mut depth = 0;
    let mut p = 0usize;
    let mut root_seen = false;
    let mut cpus_seen = false;
    let mut seen = 0u64;
    let mut result = Features::ALL;
    loop {
        let token = word(structure, p)?;
        p += 4;
        match token {
            1 => {
                if depth == stack.len() {
                    return None;
                }
                let (name, used) = cstr(structure.get(p..)?)?;
                p = align4(p.checked_add(used)?)?;
                if name.len() > 256 {
                    return None;
                }
                let mut node = Node::default();
                if depth == 0 {
                    if root_seen || !name.is_empty() {
                        return None;
                    }
                    root_seen = true;
                    node.kind = 1;
                } else {
                    let parent = &mut stack[depth - 1];
                    parent.child = true;
                    if parent.kind == 1 && name == b"cpus" {
                        if cpus_seen {
                            return None;
                        }
                        cpus_seen = true;
                        node.kind = 2;
                    } else if parent.kind == 2 && name.starts_with(b"cpu@") {
                        if !matches!(parent.address_cells, 1 | 2) || parent.size_cells != Some(0) {
                            return None;
                        }
                        node.kind = 3;
                        node.address_cells = parent.address_cells;
                    }
                }
                stack[depth] = node;
                depth += 1;
            }
            2 => {
                depth = depth.checked_sub(1)?;
                let node = stack[depth];
                if node.kind == 3 {
                    if !node.cpu {
                        return None;
                    }
                    let hart = node.reg?;
                    if let Some(index) = harts.iter().position(|h| *h == hart) {
                        let bit = 1u64 << index;
                        if seen & bit != 0 {
                            return None;
                        }
                        seen |= bit;
                        result &= node.features?.0;
                    }
                }
            }
            3 => {
                let len = word(structure, p)? as usize;
                let nameoff = word(structure, p + 4)? as usize;
                p += 8;
                let data = region(structure, p, len)?;
                p = align4(p.checked_add(len)?)?;
                let (name, _) = cstr(strings.get(nameoff..)?)?;
                let node = stack.get_mut(depth.checked_sub(1)?)?;
                if node.child {
                    return None;
                }
                match (node.kind, name) {
                    (2, b"#address-cells") => {
                        if node.address_cells != 0 || len != 4 {
                            return None;
                        }
                        let cells = word(data, 0)?;
                        if !matches!(cells, 1 | 2) {
                            return None;
                        }
                        node.address_cells = cells;
                    }
                    (2, b"#size-cells") => {
                        if node.size_cells.is_some() || len != 4 {
                            return None;
                        }
                        node.size_cells = Some(word(data, 0)?);
                    }
                    (3, b"device_type") => {
                        if node.cpu || data != b"cpu\0" {
                            return None;
                        }
                        node.cpu = true;
                    }
                    (3, b"reg") => {
                        if node.reg.is_some() || len != node.address_cells as usize * 4 {
                            return None;
                        }
                        node.reg = Some(if len == 4 {
                            u64::from(word(data, 0)?)
                        } else {
                            (u64::from(word(data, 0)?) << 32) | u64::from(word(data, 4)?)
                        });
                    }
                    (3, b"riscv,isa-extensions") => {
                        if node.features.is_some() {
                            return None;
                        }
                        node.features = Some(extensions(data)?);
                    }
                    _ => (),
                }
            }
            4 => (),
            9 => {
                if depth != 0 || !root_seen || p != structure.len() {
                    return None;
                }
                let expected = if harts.len() == 64 {
                    u64::MAX
                } else {
                    (1u64 << harts.len()) - 1
                };
                return (seen == expected).then_some(Features(result));
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use self::std::vec::Vec;
    use super::*;
    struct Dtb {
        body: Vec<u8>,
        strings: Vec<u8>,
    }
    impl Dtb {
        fn new() -> Self {
            Self {
                body: Vec::new(),
                strings: Vec::new(),
            }
        }
        fn token(&mut self, n: u32) {
            self.body.extend(n.to_be_bytes());
        }
        fn begin(&mut self, name: &str) {
            self.token(1);
            self.body.extend(name.bytes());
            self.body.push(0);
            self.pad();
        }
        fn end(&mut self) {
            self.token(2);
        }
        fn pad(&mut self) {
            while self.body.len() % 4 != 0 {
                self.body.push(0);
            }
        }
        fn prop(&mut self, name: &str, data: &[u8]) {
            self.token(3);
            self.body.extend((data.len() as u32).to_be_bytes());
            self.body.extend((self.strings.len() as u32).to_be_bytes());
            self.strings.extend(name.bytes());
            self.strings.push(0);
            self.body.extend(data);
            self.pad();
        }
        fn cpu(&mut self, id: u32, extensions: Option<&[u8]>) {
            self.begin("cpu@0");
            self.prop("device_type", b"cpu\0");
            self.prop("reg", &id.to_be_bytes());
            if let Some(e) = extensions {
                self.prop("riscv,isa-extensions", e);
            }
            self.end();
        }
        fn finish(mut self) -> Vec<u8> {
            self.token(9);
            let off = 56;
            let total = off + self.body.len() + self.strings.len();
            let mut out = Vec::new();
            for n in [
                0xd00dfeed,
                total as u32,
                off as u32,
                (off + self.body.len()) as u32,
                40,
                17,
                16,
                0,
                self.strings.len() as u32,
                self.body.len() as u32,
            ] {
                out.extend(n.to_be_bytes());
            }
            out.extend([0; 16]);
            out.extend(self.body);
            out.extend(self.strings);
            out
        }
    }
    fn tree(cpus: &[(u32, Option<&[u8]>)]) -> Vec<u8> {
        let mut d = Dtb::new();
        d.begin("");
        d.begin("cpus");
        d.prop("#address-cells", &1u32.to_be_bytes());
        d.prop("#size-cells", &0u32.to_be_bytes());
        for (id, e) in cpus {
            d.cpu(*id, *e);
        }
        d.end();
        d.end();
        d.finish()
    }
    #[test]
    fn intersection_and_requested_harts() {
        let d = tree(&[
            (0, Some(b"i\0zba\0zbb\0zbc\0zbs\0")),
            (7, Some(b"i\0zbb\0future\0")),
        ]);
        assert_eq!(common(&d, &[0, 7]), Some(Features(2)));
        assert_eq!(common(&d, &[0]), Some(Features(15)));
        assert_eq!(common(&d, &[7, 0]), Some(Features(2)));
        assert_eq!(common(&d, &[1]), None);
        assert_eq!(common(&d, &[0, 0]), None);
    }
    #[test]
    fn missing_duplicate_or_unterminated_fails_closed() {
        assert_eq!(common(&tree(&[(0, None)]), &[0]), None);
        assert_eq!(common(&tree(&[(0, Some(b"zba"))]), &[0]), None);
        assert_eq!(common(&tree(&[(0, Some(b"zba\0\0"))]), &[0]), None);
        assert_eq!(
            common(&tree(&[(0, Some(b"zba\0")), (0, Some(b"zbb\0"))]), &[0]),
            None
        );
        assert_eq!(
            common(&tree(&[(0, Some(b"zba1p0\0"))]), &[0]),
            Some(Features::NONE)
        );
    }
    #[test]
    fn every_truncation_and_header_overflows_are_rejected() {
        let d = tree(&[(0, Some(b"zba\0"))]);
        for n in 0..d.len() {
            assert_eq!(common(&d[..n], &[0]), None, "length {n}");
        }
        for offset in [4, 8, 12, 20, 24, 32, 36] {
            let mut bad = d.clone();
            bad[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            // A future version is allowed when compatible with v17.
            if offset != 20 {
                assert_eq!(common(&bad, &[0]), None, "header {offset}");
            }
        }
    }
    #[test]
    fn two_cell_hart_ids_and_invalid_address_cells() {
        let mut d = Dtb::new();
        d.begin("");
        d.begin("cpus");
        d.prop("#address-cells", &2u32.to_be_bytes());
        d.prop("#size-cells", &0u32.to_be_bytes());
        d.begin("cpu@100000007");
        d.prop("device_type", b"cpu\0");
        d.prop("reg", &0x1_0000_0007u64.to_be_bytes());
        d.prop("riscv,isa-extensions", b"zbb\0");
        d.end();
        d.end();
        d.end();
        assert_eq!(common(&d.finish(), &[0x1_0000_0007]), Some(Features(2)));
        let mut d = Dtb::new();
        d.begin("");
        d.begin("cpus");
        d.prop("#address-cells", &0u32.to_be_bytes());
        d.prop("#address-cells", &1u32.to_be_bytes());
        d.prop("#size-cells", &0u32.to_be_bytes());
        d.cpu(0, Some(b"zba\0"));
        d.end();
        d.end();
        assert_eq!(common(&d.finish(), &[0]), None);
    }
    #[test]
    fn malformed_tokens_and_property_order() {
        let mut d = tree(&[(0, Some(b"zba\0"))]);
        d[56..60].copy_from_slice(&99u32.to_be_bytes());
        assert_eq!(common(&d, &[0]), None);
        let mut d = Dtb::new();
        d.begin("");
        d.begin("cpus");
        d.prop("#address-cells", &1u32.to_be_bytes());
        d.prop("#size-cells", &0u32.to_be_bytes());
        d.cpu(0, Some(b"zba\0"));
        d.prop("late", b"");
        d.end();
        d.end();
        assert_eq!(common(&d.finish(), &[0]), None);
    }
}
