#![no_std]

//! CV1800B GPIO-backed status LED engine for the Milk-V Duo.

use vibeos_hal::StatusLedDescription;

const GPIO_DATA_OFFSET: usize = 0;
const GPIO_DIRECTION_OFFSET: usize = 0x04;
const GPIO_EXTERNAL_OFFSET: usize = 0x50;
const GPIO_REQUIRED_BYTES: usize = GPIO_EXTERNAL_OFFSET + core::mem::size_of::<u32>();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidDescription,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub pinmux: u32,
    pub direction: u32,
    pub data: u32,
    pub external: u32,
    mask: u32,
    pinmux_mask: u32,
    pinmux_function: u32,
    active_high: bool,
}

impl Snapshot {
    pub const fn configured(self) -> bool {
        self.pinmux & self.pinmux_mask == self.pinmux_function && self.direction & self.mask != 0
    }

    pub const fn on(self) -> bool {
        let asserted = if self.active_high {
            self.data & self.mask != 0 && self.external & self.mask != 0
        } else {
            self.data & self.mask == 0 && self.external & self.mask == 0
        };
        self.configured() && asserted
    }
}

/// Select the GPIO pad, preload the asserted output latch, and enable output.
///
/// Preloading prevents a visible inactive glitch while direction changes. All
/// unrelated pinmux and GPIO-bank bits are retained.
///
/// # Safety
/// The described pinmux and GPIO apertures must remain mapped, writable
/// CV1800B MMIO for this call. The caller must have exclusive ownership of the
/// selected pad and GPIO bit while initialization executes.
pub unsafe fn initialize(description: StatusLedDescription) -> Result<Snapshot, Error> {
    validate(description)?;
    let mask = gpio_mask(description);
    let pinmux = description
        .pinmux
        .start
        .checked_add(description.pinmux_register_offset)
        .ok_or(Error::InvalidDescription)?;
    update_bits(
        pinmux,
        description.pinmux_function_mask,
        description.pinmux_gpio_function,
    );
    let data = description.gpio.start + GPIO_DATA_OFFSET;
    if description.active_high {
        set_bits(data, mask);
    } else {
        clear_bits(data, mask);
    }
    set_bits(description.gpio.start + GPIO_DIRECTION_OFFSET, mask);
    Ok(snapshot(description))
}

/// Read back the pad mux, direction, output latch, and external pin level.
///
/// # Safety
/// The described apertures must remain mapped readable CV1800B MMIO and the
/// caller must serialize reads with any owner that can reconfigure the pad.
pub unsafe fn read_snapshot(description: StatusLedDescription) -> Result<Snapshot, Error> {
    validate(description)?;
    Ok(snapshot(description))
}

fn validate(description: StatusLedDescription) -> Result<(), Error> {
    let gpio_end = description
        .gpio
        .start
        .checked_add(GPIO_REQUIRED_BYTES)
        .ok_or(Error::InvalidDescription)?;
    let pinmux_register_end = description
        .pinmux
        .start
        .checked_add(description.pinmux_register_offset)
        .and_then(|address| address.checked_add(core::mem::size_of::<u32>()))
        .ok_or(Error::InvalidDescription)?;
    if description.gpio.end < gpio_end
        || description.pinmux.end < pinmux_register_end
        || description.gpio_bit >= 32
        || description.pinmux_function_mask == 0
        || description.pinmux_gpio_function & !description.pinmux_function_mask != 0
    {
        return Err(Error::InvalidDescription);
    }
    Ok(())
}

fn snapshot(description: StatusLedDescription) -> Snapshot {
    let mask = gpio_mask(description);
    Snapshot {
        pinmux: read32(description.pinmux.start + description.pinmux_register_offset),
        direction: read32(description.gpio.start + GPIO_DIRECTION_OFFSET),
        data: read32(description.gpio.start + GPIO_DATA_OFFSET),
        external: read32(description.gpio.start + GPIO_EXTERNAL_OFFSET),
        mask,
        pinmux_mask: description.pinmux_function_mask,
        pinmux_function: description.pinmux_gpio_function,
        active_high: description.active_high,
    }
}

const fn gpio_mask(description: StatusLedDescription) -> u32 {
    1u32 << description.gpio_bit
}

fn set_bits(address: usize, bits: u32) {
    write32(address, read32(address) | bits);
}

fn clear_bits(address: usize, bits: u32) {
    write32(address, read32(address) & !bits);
}

fn update_bits(address: usize, mask: u32, value: u32) {
    write32(address, (read32(address) & !mask) | (value & mask));
}

#[inline]
fn read32(address: usize) -> u32 {
    unsafe { (address as *const u32).read_volatile() }
}

#[inline]
fn write32(address: usize, value: u32) {
    unsafe { (address as *mut u32).write_volatile(value) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vibeos_hal::AddressRange;

    const DESCRIPTION: StatusLedDescription = StatusLedDescription {
        gpio: AddressRange::new(0x3000, 0x4000),
        pinmux: AddressRange::new(0x1000, 0x2000),
        pinmux_register_offset: 0x12c,
        pinmux_function_mask: 0x7,
        pinmux_gpio_function: 3,
        gpio_bit: 24,
        active_high: true,
    };

    #[test]
    fn accepts_the_duo_wiring_shape() {
        assert_eq!(validate(DESCRIPTION), Ok(()));
        assert_eq!(gpio_mask(DESCRIPTION), 1 << 24);
    }

    #[test]
    fn rejects_truncated_overflowing_and_invalid_descriptions() {
        assert_eq!(
            validate(StatusLedDescription {
                gpio: AddressRange::new(0x3000, 0x3050),
                ..DESCRIPTION
            }),
            Err(Error::InvalidDescription)
        );
        assert_eq!(
            validate(StatusLedDescription {
                pinmux: AddressRange::new(usize::MAX - 1, usize::MAX),
                ..DESCRIPTION
            }),
            Err(Error::InvalidDescription)
        );
        assert_eq!(
            validate(StatusLedDescription {
                gpio_bit: 32,
                ..DESCRIPTION
            }),
            Err(Error::InvalidDescription)
        );
    }

    #[test]
    fn snapshot_interprets_active_high_and_low_levels() {
        let high = Snapshot {
            pinmux: 3,
            direction: 1 << 24,
            data: 1 << 24,
            external: 1 << 24,
            mask: 1 << 24,
            pinmux_mask: 7,
            pinmux_function: 3,
            active_high: true,
        };
        assert!(high.on());
        assert!(Snapshot {
            data: 0,
            external: 0,
            active_high: false,
            ..high
        }
        .on());
    }
}
