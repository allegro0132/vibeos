//! Permanent, cache-line-isolated EQoS DMA storage with explicit CPU/physical views.
use crate::{
    backend::Memory,
    ring::{Direction, Layout, BUFFER, STRIDE},
};
use vibeos_hal::memory::{DmaCache, DmaConstraints, DmaDirection, DmaRegion};

#[repr(C, align(64))]
pub struct Storage<const N: usize> {
    tx: [[u32; 16]; N],
    rx: [[u32; 16]; N],
    tx_buffers: [[u8; BUFFER]; N],
    rx_buffers: [[u8; BUFFER]; N],
}
impl<const N: usize> Storage<N> {
    pub const fn new() -> Self {
        Self {
            tx: [[0; 16]; N],
            rx: [[0; 16]; N],
            tx_buffers: [[0; BUFFER]; N],
            rx_buffers: [[0; BUFFER]; N],
        }
    }
}
impl<const N: usize> Default for Storage<N> {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Layout,
    Cache,
}
pub struct Pool<C: DmaCache + 'static, const N: usize> {
    storage: &'static mut Storage<N>,
    physical: u64,
    layout: Layout,
    cache: C,
}
impl<C: DmaCache + 'static, const N: usize> Pool<C, N> {
    /// # Safety
    /// `physical` must be the real device-visible physical base of this exact
    /// permanently allocated storage; CPU and device views must map the same
    /// bytes. No uncached alias or competing CPU mapping may modify its lines.
    /// This pool must only be used through an exclusive serialized ring backend;
    /// raw Memory callbacks require that ring's ownership protocol.
    pub unsafe fn new(
        storage: &'static mut Storage<N>,
        physical: u64,
        cache: C,
        axi_bytes: usize,
    ) -> Result<Self, Error> {
        if !(2..=1024).contains(&N) {
            return Err(Error::Layout);
        }
        let bytes = core::mem::size_of::<Storage<N>>();
        DmaConstraints {
            address_bits: 32,
            alignment: STRIDE,
            cache_line: STRIDE,
        }
        .validate(DmaRegion { physical, bytes })
        .map_err(|_| Error::Layout)?;
        let layout = Layout {
            tx_descriptors: physical,
            rx_descriptors: physical + (N * STRIDE) as u64,
            tx_buffers: physical + (2 * N * STRIDE) as u64,
            rx_buffers: physical + (2 * N * STRIDE + N * BUFFER) as u64,
            count: N,
            axi_bytes,
        };
        layout.validate().map_err(|_| Error::Layout)?;
        // Validate each actual operation size/region, not merely a containing
        // envelope whose cache policy might differ across a reserved hole.
        for index in 0..N {
            for (base, size) in [
                (layout.tx_descriptors, STRIDE),
                (layout.rx_descriptors, STRIDE),
                (layout.tx_buffers, BUFFER),
                (layout.rx_buffers, BUFFER),
            ] {
                cache
                    .validate(DmaRegion {
                        physical: base + (index * size) as u64,
                        bytes: size,
                    })
                    .map_err(|_| Error::Cache)?;
            }
        }
        Ok(Self {
            storage,
            physical,
            layout,
            cache,
        })
    }
    pub fn layout(&self) -> Layout {
        self.layout
    }
    fn offset(&self, address: u64, bytes: usize) -> usize {
        let offset = address
            .checked_sub(self.physical)
            .expect("DMA address before pool");
        let end = offset.checked_add(bytes as u64).expect("DMA span overflow");
        assert!(
            end <= core::mem::size_of::<Storage<N>>() as u64,
            "DMA span outside pool"
        );
        offset as usize
    }
    fn descriptor(&self, address: u64, word: usize) -> usize {
        assert!(word < 4);
        let offset = self.offset(address, STRIDE);
        assert!(
            offset < 2 * N * STRIDE && offset % STRIDE == 0,
            "not a descriptor slot"
        );
        offset + word * 4
    }
    fn buffer(&self, address: u64, bytes: usize, rx: bool) -> usize {
        let base = if rx {
            self.layout.rx_buffers
        } else {
            self.layout.tx_buffers
        };
        let offset = address.checked_sub(base).expect("wrong buffer direction");
        assert!(
            bytes <= BUFFER && offset < (N * BUFFER) as u64 && offset % BUFFER as u64 == 0,
            "not a packet slot"
        );
        self.offset(address, bytes)
    }
    fn pointer(&mut self, offset: usize) -> *mut u8 {
        (self.storage as *mut Storage<N>)
            .cast::<u8>()
            .wrapping_add(offset)
    }
    fn region(&self, address: u64, bytes: usize, direction: Direction) -> DmaRegion {
        self.offset(address, bytes);
        match direction {
            Direction::Bidirectional => {
                assert_eq!(bytes, STRIDE);
                self.descriptor(address, 0);
            }
            Direction::ToDevice => {
                assert_eq!(bytes, BUFFER);
                self.buffer(address, bytes, false);
            }
            Direction::FromDevice => {
                assert_eq!(bytes, BUFFER);
                self.buffer(address, bytes, true);
            }
        }
        DmaRegion {
            physical: address,
            bytes,
        }
    }
}
fn direction(d: Direction) -> DmaDirection {
    match d {
        Direction::ToDevice => DmaDirection::ToDevice,
        Direction::FromDevice => DmaDirection::FromDevice,
        Direction::Bidirectional => DmaDirection::Bidirectional,
    }
}
// Safety follows from construction's permanent matching mappings and exclusive
// ring use. Each callback independently checks its full span/slot before access.
unsafe impl<C: DmaCache + 'static, const N: usize> Memory for Pool<C, N> {
    fn admit(&self, l: Layout) -> bool {
        l == self.layout
    }
    fn read_word(&mut self, a: u64, w: usize) -> u32 {
        let offset = self.descriptor(a, w);
        u32::from_le(unsafe { core::ptr::read_volatile(self.pointer(offset).cast::<u32>()) })
    }
    fn write_word(&mut self, a: u64, w: usize, v: u32) {
        let offset = self.descriptor(a, w);
        unsafe { core::ptr::write_volatile(self.pointer(offset).cast::<u32>(), v.to_le()) };
    }
    fn copy_tx(&mut self, a: u64, p: &[u8]) {
        let offset = self.buffer(a, p.len(), false);
        unsafe { core::ptr::copy_nonoverlapping(p.as_ptr(), self.pointer(offset), p.len()) };
    }
    fn copy_rx(&mut self, a: u64, p: &mut [u8]) {
        let offset = self.buffer(a, p.len(), true);
        unsafe { core::ptr::copy_nonoverlapping(self.pointer(offset), p.as_mut_ptr(), p.len()) };
    }
    fn for_device(&mut self, a: u64, n: usize, d: Direction) {
        let r = self.region(a, n, d);
        self.cache.for_device(r, direction(d));
    }
    fn for_cpu(&mut self, a: u64, n: usize, d: Direction) {
        let r = self.region(a, n, d);
        self.cache.for_cpu(r, direction(d));
    }
    fn barrier(&mut self) {
        self.cache.barrier();
    }
}
