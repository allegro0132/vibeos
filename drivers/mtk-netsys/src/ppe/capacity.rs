//! RAM-only maximum-geometry benchmark. Three permanently reserved 32K tables.
//! Static reciprocal UDP recipes, not dynamic NAT or production admission.
use super::{control::{Error, IngressCutoff, Registers}, Engine, Protocol, Snapshot, StagedEntry, Tuple};
pub const ENTRIES: usize = 32768;
pub const TABLE_BYTES: usize = ENTRIES * 128;
pub const BYTES: usize = 3 * TABLE_BYTES;
pub const FIRST_PORT: u16 = 1024;
pub const REMOTE_PORT: u16 = 33445;
const REGS: [usize; 11] = [0x200,0x204,0x208,0x21c,0x220,0x248,0x24c,0x374,0x308,0x30c,0x310];
const CPU: u32 = 0x20710000;

pub fn bucket(t: Tuple) -> usize {
    let ports = (u32::from(t.source_port) << 16) | u32::from(t.destination_port);
    let src = u32::from_be_bytes(t.source);
    let dst = u32::from_be_bytes(t.destination);
    let mixed = ((ports & dst) | (!ports & src)).rotate_left(8) ^ ports ^ src ^ dst;
    (((mixed ^ (mixed >> 16)) & 0x1fff) << 2) as usize
}
pub fn recipe(outbound: bool, port: u16) -> (Tuple, StagedEntry) {
    assert!((FIRST_PORT..FIRST_PORT + ENTRIES as u16).contains(&port));
    let (original, translated) = if outbound {
        let a = Tuple { source: [192,168,79,100], destination: [192,168,78,100], source_port: port, destination_port: REMOTE_PORT };
        (a, Tuple { source: [192,168,78,1], ..a })
    } else {
        let a = Tuple { source: [192,168,78,100], destination: [192,168,78,1], source_port: REMOTE_PORT, destination_port: port };
        (a, Tuple { destination: [192,168,79,100], ..a })
    };
    let entry = if outbound {
        StagedEntry::ipv4_napt(Protocol::Udp, original, translated, crate::TxPort::Wan,
            [2,0x42,0x70,4,0,1], [0xc4,0xd6,0xd3,0xa9,0x32,0xa6])
    } else {
        StagedEntry::ipv4_napt_mxl_bridge(Protocol::Udp, original, translated,
            [2,0x42,0x70,4,0,2], [0,0xe0,0x4f,0x83,0x87,0xaa])
    }.expect("fixed recipe");
    (original, entry)
}
fn fill(bytes: &mut [u8], outbound: bool, reverse: bool) -> Result<(), Error> {
    if bytes.len() != TABLE_BYTES { return Err(Error::Preconditions); }
    bytes.fill(0);
    let mut ways = [0u8; ENTRIES / 4];
    for port in FIRST_PORT..FIRST_PORT + ENTRIES as u16 {
        let (tuple, entry) = recipe(outbound, port);
        let bucket = bucket(tuple);
        let way = &mut ways[bucket / 4];
        if *way >= 4 { return Err(Error::Preconditions); }
        let at = (bucket + if reverse {3 - *way as usize} else {*way as usize}) * 128;
        *way += 1;
        bytes[at..at+128].copy_from_slice(entry.bytes());
        let tags = u32::from_le_bytes(entry.bytes()[..4].try_into().unwrap()) & ((7<<14)|(1<<18));
        bytes[at..at+4].copy_from_slice(&((1u32<<30)|(2<<28)|(1<<22)|tags).to_le_bytes());
    }
    if ways.iter().any(|v| *v != 4) { return Err(Error::Preconditions); }
    // Complete body readback, independently walking the tuple-to-slot recipe.
    ways.fill(0);
    for port in FIRST_PORT..FIRST_PORT + ENTRIES as u16 {
        let (tuple, entry) = recipe(outbound, port);
        let b = bucket(tuple); let at = (b + if reverse {3 - ways[b/4] as usize} else {ways[b/4] as usize})*128; ways[b/4] += 1;
        if bytes[at+4..at+128] != entry.bytes()[4..]
            || (u32::from_le_bytes(bytes[at..at+4].try_into().unwrap()) >> 28) & 3 != 2 {
            return Err(Error::Preconditions);
        }
    }
    Ok(())
}
fn checked(io: &mut impl Registers, offset: usize, value: u32) -> Result<(), Error> {
    io.write(offset,value); io.barrier();
    let mask = if [0x2200,0x2600,0x2e00].contains(&offset) { 0x7fffffff } else { u32::MAX };
    if io.read(offset)&mask != value&mask { return Err(Error::Readback{offset}); }
    Ok(())
}
fn idle(io: &mut impl Registers, e: Engine, timeout: u64) -> Result<(), Error> {
    let start = io.now();
    while io.read(e.offset()+0x200)&(1<<31)!=0 {
        if io.now().wrapping_sub(start)>=timeout { return Err(Error::Timeout); }
    }
    io.barrier(); Ok(())
}
pub fn configuration_register(offset: usize) -> bool {
    offset == 0x1500 || offset == 0x540 || Engine::ALL.iter().any(|e|
        REGS.iter().any(|r| offset == e.offset()+r))
}
/// # Safety
/// Own both GDMA policies; must not reopen after a deadline/owner revocation.
pub unsafe fn admit(io: &mut impl Registers, third: bool) -> Result<(), Error> {
    // MYMAC only; all other traffic remains CPU-directed, as in the paired owner.
    checked(io,0x1500,CPU | if third {12<<12} else {3<<12})?;
    checked(io,0x540,CPU | (4<<12))
}
pub fn close(io: &mut impl Registers) -> Result<(), Error> {
    let cutoff = IngressCutoff::new(CPU,Some(CPU)).unwrap();
    unsafe { cutoff.close(io) }.map_err(|_| Error::Preconditions)
}
/// # Safety
/// Caller owns all three engines, all selected ingress and NC identity-mapped
/// permanent storage at physical. No DMA or CPU aliases. Independent IRQ/task
/// cutoff must cover the callback, which alone may open ingress. Callback must
/// return with ingress closed. On ANY error caller must reset before reuse;
/// storage must remain reserved even if draining/configuration restore failed.
/// No table reference or body access occurs while hardware is enabled.
pub unsafe fn run<R: Registers>(io: &mut R, bytes: &'static mut [u8], physical: u64,
    timeout: u64, reverse: bool, window: impl FnOnce(&mut R) -> Result<(), Error>) -> Result<(), Error> {
    if bytes.len()!=BYTES || physical==0 || physical%TABLE_BYTES as u64!=0
        || physical.checked_add(BYTES as u64).is_none_or(|end| end > 1u64<<32)
        || timeout==0 || timeout >= 1<<63 || io.read(0x1500)!=CPU || io.read(0x540)!=CPU
        || io.read(0x500)!=0x20717777 {return Err(Error::Preconditions);}
    let mut saved = [[0u32;11];3];
    for (i,e) in Engine::ALL.into_iter().enumerate() {
        let s=Snapshot::read(e,|r|io.read(r));
        if s.table_base!=0 || s.busy() || s.cache_enabled() {return Err(Error::Preconditions);}
        saved[i]=REGS.map(|r|io.read(e.offset()+r));
    }
    let result=(|| {
        close(io)?;
        for (i,e) in Engine::ALL.into_iter().enumerate() {
            checked(io,e.offset()+0x21c,saved[i][3]&!((0x1f<<7)|(3<<12)|(3<<16)))?;
            idle(io,e,timeout)?;
            checked(io,e.offset()+0x200,saved[i][0]&!1)?; idle(io,e,timeout)?;
            fill(&mut bytes[i*TABLE_BYTES..(i+1)*TABLE_BYTES],i==1,reverse)?;
        }
        io.barrier();
        for (i,e) in Engine::ALL.into_iter().enumerate() {
            // 32K, 128-byte v3 records, hash mode 1, CPU miss; no autonomous build/age.
            checked(io,e.offset()+0x21c,0x00104025)?;
            checked(io,e.offset()+0x220,physical as u32+(i*TABLE_BYTES) as u32)?;
            for (r,v) in [(0x208,u32::MAX),(0x248,0),(0x24c,0xcb777),(0x374,0x7f),
                (0x308,0),(0x30c,1514|(1518<<16)),(0x310,1522|(1526<<16)),(0x204,0x200e)] {
                checked(io,e.offset()+r,v)?;
            }
            checked(io,e.offset()+0x200,saved[i][0]|1)?;
        }
        window(io)?;
        close(io)?;
        for (i,e) in Engine::ALL.into_iter().enumerate() {
            idle(io,e,timeout)?;
            checked(io,e.offset()+0x200,saved[i][0]&!1)?; idle(io,e,timeout)?;
        }
        // Detach all tables while engines remain disabled, then restore other state.
        for (i,e) in Engine::ALL.into_iter().enumerate() {
            checked(io,e.offset()+0x220,0)?;
            for j in 1..REGS.len() { checked(io,e.offset()+REGS[j],saved[i][j])?; }
            checked(io,e.offset()+0x200,saved[i][0])?;
        }
        bytes.fill(0); io.barrier();
        if bytes.iter().any(|b|*b!=0) { return Err(Error::Preconditions); }
        Ok(())
    })();
    if result.is_err() { let _=close(io); }
    result
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    fn fixed_flows_cover_all_8192_four_way_buckets_in_both_directions() {
        for outbound in [false,true] {
            let mut counts=[0u8;ENTRIES/4];
            for port in FIRST_PORT..FIRST_PORT+ENTRIES as u16 {
                counts[bucket(recipe(outbound,port).0)/4]+=1;
            }
            assert!(counts.iter().all(|c|*c==4));
            let mut table=std::vec![0xaa;TABLE_BYTES];
            fill(&mut table,outbound,false).unwrap();
            fill(&mut table,outbound,true).unwrap();
            assert_eq!(table.chunks_exact(128).filter(|e|e[3]&0x30==0x20).count(),ENTRIES);
        }
    }
    struct Mock { regs: std::collections::BTreeMap<usize,u32>, writes:usize, fail:usize }
    impl Mock { fn new(fail:usize)->Self {
        let mut regs=std::collections::BTreeMap::new();
        regs.insert(0x1500,CPU);regs.insert(0x540,CPU);regs.insert(0x500,0x20717777);
        Self {regs,writes:0,fail}
    } }
    impl Registers for Mock {
        fn read(&mut self,r:usize)->u32 {*self.regs.get(&r).unwrap_or(&0)}
        fn write(&mut self,r:usize,v:u32) {self.writes+=1; self.regs.insert(r,if self.writes==self.fail {v^1}else{v});}
        fn barrier(&mut self) {}
        fn now(&mut self)->u64 {0}
    }
    #[test]
    fn three_tables_publish_full_then_restore_and_clear() {
        let mut io=Mock::new(usize::MAX);
        let bytes=std::boxed::Box::leak(std::vec![0;BYTES].into_boxed_slice());
        unsafe { run(&mut io,bytes,0x44000000,100,false,|io| {
            for (i,e) in Engine::ALL.into_iter().enumerate() {
                assert_eq!(io.read(e.offset()+0x21c),0x00104025);
                assert_eq!(io.read(e.offset()+0x220),0x44000000+(i*TABLE_BYTES) as u32);
            }
            admit(io,true)?;
            assert_eq!(io.read(0x1500),CPU|(12<<12));
            close(io)
        }) }.unwrap();
        assert_eq!(io.read(0x1500),CPU);assert_eq!(io.read(0x540),CPU);
        for e in Engine::ALL {for r in REGS {assert_eq!(io.read(e.offset()+r),0);}}
    }
    #[test]
    fn invalid_geometry_has_no_writes_and_readback_failure_closes_both_ingresses() {
        let mut io=Mock::new(usize::MAX);
        let bytes=std::boxed::Box::leak(std::vec![0;BYTES].into_boxed_slice());
        assert_eq!(unsafe {run(&mut io,bytes,0x44001000,100,false,|_|panic!("not published"))},Err(Error::Preconditions));
        assert_eq!(io.writes,0);
        for fail in [3,11,20,44] {
            let mut io=Mock::new(fail);
            let bytes=std::boxed::Box::leak(std::vec![0;BYTES].into_boxed_slice());
            assert!(unsafe {run(&mut io,bytes,0x44000000,100,false,|io|admit(io,false))}.is_err());
            assert_eq!(io.read(0x1500),CPU);assert_eq!(io.read(0x540),CPU);
        }
    }

}
