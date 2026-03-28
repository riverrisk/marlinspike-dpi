//! Bilgepump — stateful L2 monitoring for spoofing, manipulation, and abuse.
//!
//! Unlike stovetop (stateless per-frame), bilgepump accumulates state across
//! frames to detect temporal anomalies that no single packet can reveal.
//!
//! | Check | Tag | What It Catches |
//! |-------|-----|-----------------|
//! | ARP spoof | `bilgepump:arp_spoof` | MAC/IP binding change (cache poisoning) |
//! | Gratuitous ARP | `bilgepump:arp_gratuitous` | Unsolicited ARP replies |
//! | ARP flood | `bilgepump:arp_flood` | Reply rate exceeds threshold |
//! | MAC local admin | `bilgepump:mac_local` | Locally-administered bit set (VM/spoof) |
//! | MAC multicast src | `bilgepump:mac_multicast` | Multicast bit on source MAC |
//! | MAC flapping | `bilgepump:mac_flap` | Rapid IP association changes |
//! | VLAN hopping | `bilgepump:vlan_hop` | Double-tagged 802.1Q |
//! | STP root change | `bilgepump:stp_root_change` | Root bridge election changed |
//! | STP unauthorized | `bilgepump:stp_unauthorized` | Root claim from non-whitelisted bridge |
//! | Rogue DHCP | `bilgepump:dhcp_rogue` | Unknown DHCP server responding |
//! | DHCP starvation | `bilgepump:dhcp_starvation` | Request flood (pool exhaustion) |
//! | LLDP conflict | `bilgepump:lldp_conflict` | chassis_id changed for source MAC |
//! | CDP conflict | `bilgepump:cdp_conflict` | device_id changed for source MAC |
//!
//! Hooks into the engine at two points:
//! - **Pre-VLAN-unwrap**: VLAN hopping detection and MAC header anomalies
//! - **Post-decoder**: protocol-specific stateful analysis (ARP, STP, DHCP,
//!   LLDP, CDP)
//!
//! State is in-memory with configurable TTL aging. State tables implement
//! `Serialize`/`Deserialize` for snapshot/restore across process restarts.

pub mod alerts;
pub mod config;
pub mod detectors;
pub mod monitor;
pub mod state;
