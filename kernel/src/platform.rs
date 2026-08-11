//! Compatibility facade for the compile-time selected board support crate.
//!
//! Hardware descriptions live outside the kernel in `boards/`. Keeping the
//! legacy constant names here lets the MMU and drivers migrate independently
//! without copying board data back into the kernel.

#[cfg(all(feature = "qemu-virt", feature = "milkv-duo"))]
compile_error!("features `qemu-virt` and `milkv-duo` are mutually exclusive");

#[cfg(not(any(feature = "qemu-virt", feature = "milkv-duo")))]
compile_error!("exactly one board feature must be enabled: `qemu-virt` or `milkv-duo`");

#[cfg(all(feature = "qemu-virt", not(feature = "milkv-duo")))]
mod selected {
    pub use vibeos_bsp_qemu_virt::*;
}

#[cfg(all(feature = "milkv-duo", not(feature = "qemu-virt")))]
mod selected {
    pub use vibeos_bsp_milkv_duo::*;
}

#[cfg(any(
    all(feature = "qemu-virt", feature = "milkv-duo"),
    not(any(feature = "qemu-virt", feature = "milkv-duo"))
))]
mod selected {}

pub use selected::*;
