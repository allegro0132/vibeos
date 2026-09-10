#![no_std]
//! GMAC4/5 EQoS controller encodings. No board clocks, PHY wiring or cache ISA.
//! These codecs are not yet a running packet device; DMA rings and platform
//! integration must establish ownership before using the prepared words.
pub mod descriptor;
pub mod mdio;
