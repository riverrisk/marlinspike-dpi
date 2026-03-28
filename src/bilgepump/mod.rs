//! Bilgepump — stateful L2 monitoring for spoofing, manipulation, and abuse.
//!
//! Unlike stovetop (stateless per-frame), bilgepump accumulates state across
//! frames to detect temporal anomalies: ARP poisoning, MAC flapping, STP
//! root hijacking, rogue DHCP servers, and LLDP/CDP identity conflicts.
//!
//! The monitor hooks into the engine at two points:
//! - **Pre-VLAN-unwrap**: VLAN hopping detection and MAC header anomalies.
//! - **Post-decoder**: protocol-specific stateful analysis consuming parsed
//!   ARP, STP, DHCP, LLDP, and CDP fields.

pub mod alerts;
pub mod config;
pub mod detectors;
pub mod monitor;
pub mod state;
