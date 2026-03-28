//! State table types for bilgepump L2 monitoring.

use std::collections::VecDeque;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Source of a MAC/IP binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingSource {
    Arp,
    Dhcp,
    Blessed,
}

/// A learned MAC-to-IP binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacIpBinding {
    pub mac: [u8; 6],
    pub ip: [u8; 4],
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub source: BindingSource,
    pub blessed: bool,
}

/// Tracks the currently-claimed STP root bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StpRootRecord {
    pub root_id: String,
    pub claiming_bridge: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub root_path_cost: u32,
}

/// A DHCP server identity observed on the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpServerRecord {
    pub server_id: String,
    pub src_mac: [u8; 6],
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub offer_count: u64,
}

/// LLDP neighbor identity for conflict detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldpIdentityRecord {
    pub chassis_id: String,
    pub system_name: String,
    pub src_mac: [u8; 6],
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// CDP neighbor identity for conflict detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdpIdentityRecord {
    pub device_id: String,
    pub platform: Option<String>,
    pub src_mac: [u8; 6],
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Sliding-window rate counter for flood/starvation detection.
#[derive(Debug, Clone, Default)]
pub struct RateCounter {
    pub timestamps: VecDeque<DateTime<Utc>>,
}

impl RateCounter {
    /// Record an event and return the count within the window.
    pub fn record(&mut self, now: DateTime<Utc>, window_secs: u64) -> usize {
        self.timestamps.push_back(now);
        self.prune(now, window_secs);
        self.timestamps.len()
    }

    /// Remove entries outside the sliding window.
    pub fn prune(&mut self, now: DateTime<Utc>, window_secs: u64) {
        let cutoff = now - chrono::Duration::seconds(window_secs as i64);
        while self.timestamps.front().is_some_and(|&t| t < cutoff) {
            self.timestamps.pop_front();
        }
    }

    pub fn count(&self) -> usize {
        self.timestamps.len()
    }
}

/// Tracks IP associations for MAC flapping detection.
#[derive(Debug, Clone, Default)]
pub struct MacFlapTracker {
    pub observations: VecDeque<MacObservation>,
}

#[derive(Debug, Clone)]
pub struct MacObservation {
    pub ip: [u8; 4],
    pub vlan_id: Option<u16>,
    pub timestamp: DateTime<Utc>,
}

impl MacFlapTracker {
    /// Record an observation and return the number of distinct IPs within the window.
    pub fn record(
        &mut self,
        ip: [u8; 4],
        vlan_id: Option<u16>,
        now: DateTime<Utc>,
        window_secs: u64,
    ) -> usize {
        self.observations.push_back(MacObservation {
            ip,
            vlan_id,
            timestamp: now,
        });

        let cutoff = now - chrono::Duration::seconds(window_secs as i64);
        while self
            .observations
            .front()
            .is_some_and(|o| o.timestamp < cutoff)
        {
            self.observations.pop_front();
        }

        // Count distinct IPs in window
        let mut seen = Vec::new();
        for obs in &self.observations {
            if !seen.contains(&obs.ip) {
                seen.push(obs.ip);
            }
        }
        seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn rate_counter_sliding_window() {
        let mut counter = RateCounter::default();
        let t0 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let t5 = t0 + chrono::Duration::seconds(5);
        let t11 = t0 + chrono::Duration::seconds(11);

        assert_eq!(counter.record(t0, 10), 1);
        assert_eq!(counter.record(t5, 10), 2);
        // t0 should be pruned after 11 seconds with a 10-second window
        assert_eq!(counter.record(t11, 10), 2);
    }

    #[test]
    fn mac_flap_distinct_ips() {
        let mut tracker = MacFlapTracker::default();
        let t0 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let t1 = t0 + chrono::Duration::seconds(1);
        let t2 = t0 + chrono::Duration::seconds(2);

        assert_eq!(tracker.record([10, 0, 0, 1], None, t0, 30), 1);
        assert_eq!(tracker.record([10, 0, 0, 2], None, t1, 30), 2);
        // Same IP again doesn't increase distinct count
        assert_eq!(tracker.record([10, 0, 0, 1], None, t2, 30), 2);
    }
}
