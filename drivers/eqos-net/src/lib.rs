#![no_std]
//! GMAC4/5 EQoS controller encodings. No board clocks, PHY wiring or cache ISA.
//! The register engine and ring handle configuration, publication and quarantine;
//! a permanent DMA pool binds a HAL cache service. Platform admission, PHY setup,
//! firmware integration and physical DMA/cache qualification remain required.
pub mod backend;
pub mod controller;
pub mod descriptor;
pub mod mdio;
pub mod pool;
pub mod ring;
