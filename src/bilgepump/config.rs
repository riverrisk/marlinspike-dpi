//! Configuration for bilgepump L2 monitoring.

use serde::{Deserialize, Serialize};

/// A known-good MAC/IP binding that should never trigger alerts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlessedBinding {
    pub mac: String,
    pub ip: String,
    pub description: Option<String>,
}

/// Controls which bilgepump checks are enabled and their thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilgepumpConfig {
    /// Master enable switch.
    pub enabled: bool,

    // ── ARP spoofing ──────────────────────────────────────────
    pub check_arp_spoofing: bool,
    /// How long a MAC/IP binding stays valid before it can be superseded
    /// without alerting (seconds).
    pub arp_binding_ttl_secs: u64,
    /// Gratuitous ARP replies exceeding this count within the window trigger
    /// a flood alert.
    pub arp_flood_threshold: usize,
    /// Window size for ARP flood detection (seconds).
    pub arp_flood_window_secs: u64,
    /// Known-good MAC/IP pairs that are never flagged.
    pub blessed_bindings: Vec<BlessedBinding>,

    // ── MAC anomalies ─────────────────────────────────────────
    pub check_mac_anomalies: bool,
    /// Number of distinct IP associations within the window that triggers
    /// a flapping alert for a single MAC.
    pub mac_flap_threshold: usize,
    /// Window size for MAC flapping detection (seconds).
    pub mac_flap_window_secs: u64,

    // ── VLAN hopping ──────────────────────────────────────────
    pub check_vlan_hopping: bool,

    // ── STP manipulation ──────────────────────────────────────
    pub check_stp_manipulation: bool,
    /// Known-good root bridge IDs. If non-empty, any root claim from a
    /// bridge not in this list triggers an alert.
    pub stp_root_whitelist: Vec<String>,

    // ── DHCP abuse ────────────────────────────────────────────
    pub check_dhcp_abuse: bool,
    /// Known-good DHCP server identifiers (server_id option).
    pub known_dhcp_servers: Vec<String>,
    /// DHCP discover/request count exceeding this in the window triggers
    /// a starvation alert.
    pub dhcp_starvation_threshold: usize,
    /// Window size for DHCP starvation detection (seconds).
    pub dhcp_starvation_window_secs: u64,

    // ── Identity conflicts ────────────────────────────────────
    pub check_identity_conflicts: bool,
    /// How long an LLDP/CDP identity record is retained (seconds).
    pub identity_ttl_secs: u64,

    // ── State aging ───────────────────────────────────────────
    /// Global TTL for state entries that don't have a specific TTL
    /// (seconds). Entries older than this are evicted.
    pub default_state_ttl_secs: u64,
}

impl Default for BilgepumpConfig {
    fn default() -> Self {
        Self {
            enabled: true,

            check_arp_spoofing: true,
            arp_binding_ttl_secs: 300, // 5 minutes
            arp_flood_threshold: 50,
            arp_flood_window_secs: 10,
            blessed_bindings: Vec::new(),

            check_mac_anomalies: true,
            mac_flap_threshold: 5,
            mac_flap_window_secs: 30,

            check_vlan_hopping: true,

            check_stp_manipulation: true,
            stp_root_whitelist: Vec::new(),

            check_dhcp_abuse: true,
            known_dhcp_servers: Vec::new(),
            dhcp_starvation_threshold: 100,
            dhcp_starvation_window_secs: 30,

            check_identity_conflicts: true,
            identity_ttl_secs: 600, // 10 minutes

            default_state_ttl_secs: 600,
        }
    }
}
