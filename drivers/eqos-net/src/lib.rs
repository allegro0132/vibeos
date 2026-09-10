#![no_std]
//! GMAC4/5 EQoS controller encodings. No board clocks, PHY wiring or cache ISA.
//! The register engine and ring handle configuration, publication and quarantine;
//! a platform-qualified DMA memory/cache provider and firmware integration remain.
pub mod backend;
pub mod controller;
pub mod descriptor;
pub mod mdio;
pub mod ring;
