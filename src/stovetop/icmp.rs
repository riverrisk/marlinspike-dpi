//! ICMP anomaly detection — routing manipulation, tunneling, recon, and abuse.

use super::config::StovetopConfig;
use super::findings::{FindingKind, FindingSeverity, FrameFinding};
use super::padding::shannon_entropy;

/// ICMP type constants.
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_REDIRECT: u8 = 5;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ROUTER_ADVERTISEMENT: u8 = 9;
const ICMP_ROUTER_SOLICITATION: u8 = 10;
const ICMP_TIMESTAMP_REQUEST: u8 = 13;
const ICMP_TIMESTAMP_REPLY: u8 = 14;
const ICMP_ADDRESS_MASK_REQUEST: u8 = 17;
const ICMP_ADDRESS_MASK_REPLY: u8 = 18;

/// Minimum ICMP echo payload size to consider for tunnel detection.
const TUNNEL_MIN_PAYLOAD: usize = 64;

/// Entropy threshold for echo payloads — above this is suspicious.
const TUNNEL_ENTROPY_THRESHOLD: f64 = 6.0;

/// Inspect an ICMP packet for anomalies.
///
/// `icmp_payload` starts at the ICMP header (type, code, checksum, ...).
pub fn inspect_icmp(
    config: &StovetopConfig,
    icmp_payload: &[u8],
) -> Vec<FrameFinding> {
    if !config.check_icmp_anomalies || icmp_payload.len() < 4 {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let icmp_type = icmp_payload[0];
    let icmp_code = icmp_payload[1];

    // ICMP Redirect — routing manipulation
    if icmp_type == ICMP_REDIRECT {
        let gateway_ip = if icmp_payload.len() >= 8 {
            format!(
                "{}.{}.{}.{}",
                icmp_payload[4], icmp_payload[5], icmp_payload[6], icmp_payload[7]
            )
        } else {
            "unknown".to_string()
        };
        findings.push(FrameFinding {
            kind: FindingKind::IcmpRedirect {
                icmp_type,
                icmp_code,
                gateway_ip,
            },
            severity: FindingSeverity::Critical,
            decoder: "stovetop:icmp_redirect",
        });
    }

    // ICMP Echo tunnel detection
    if icmp_type == ICMP_ECHO_REQUEST || icmp_type == ICMP_ECHO_REPLY {
        // Echo header: type(1) + code(1) + checksum(2) + id(2) + seq(2) = 8 bytes
        if icmp_payload.len() > 8 {
            let echo_data = &icmp_payload[8..];
            if echo_data.len() >= TUNNEL_MIN_PAYLOAD {
                let entropy = shannon_entropy(echo_data);
                if entropy > TUNNEL_ENTROPY_THRESHOLD {
                    findings.push(FrameFinding {
                        kind: FindingKind::IcmpTunnel {
                            icmp_type,
                            payload_len: echo_data.len(),
                            entropy,
                        },
                        severity: FindingSeverity::High,
                        decoder: "stovetop:icmp_tunnel",
                    });
                }
            }
        }
    }

    // Router advertisement / solicitation — rogue router injection
    if icmp_type == ICMP_ROUTER_ADVERTISEMENT || icmp_type == ICMP_ROUTER_SOLICITATION {
        findings.push(FrameFinding {
            kind: FindingKind::IcmpSuspiciousType {
                icmp_type,
                icmp_code,
                type_name: icmp_type_name(icmp_type).to_string(),
            },
            severity: FindingSeverity::High,
            decoder: "stovetop:icmp_suspicious",
        });
    }

    // Deprecated types — info leakage / fingerprinting
    if matches!(
        icmp_type,
        ICMP_TIMESTAMP_REQUEST
            | ICMP_TIMESTAMP_REPLY
            | ICMP_ADDRESS_MASK_REQUEST
            | ICMP_ADDRESS_MASK_REPLY
    ) {
        findings.push(FrameFinding {
            kind: FindingKind::IcmpSuspiciousType {
                icmp_type,
                icmp_code,
                type_name: icmp_type_name(icmp_type).to_string(),
            },
            severity: FindingSeverity::Medium,
            decoder: "stovetop:icmp_suspicious",
        });
    }

    findings
}

/// Human-readable ICMP type name.
pub fn icmp_type_name(icmp_type: u8) -> &'static str {
    match icmp_type {
        0 => "Echo Reply",
        3 => "Destination Unreachable",
        4 => "Source Quench",
        5 => "Redirect",
        8 => "Echo Request",
        9 => "Router Advertisement",
        10 => "Router Solicitation",
        11 => "Time Exceeded",
        12 => "Parameter Problem",
        13 => "Timestamp Request",
        14 => "Timestamp Reply",
        17 => "Address Mask Request",
        18 => "Address Mask Reply",
        _ => "Unknown",
    }
}

/// Human-readable ICMP destination unreachable code name.
pub fn icmp_unreachable_code_name(code: u8) -> &'static str {
    match code {
        0 => "Network Unreachable",
        1 => "Host Unreachable",
        2 => "Protocol Unreachable",
        3 => "Port Unreachable",
        4 => "Fragmentation Needed",
        5 => "Source Route Failed",
        6 => "Destination Network Unknown",
        7 => "Destination Host Unknown",
        8 => "Source Host Isolated",
        9 => "Network Administratively Prohibited",
        10 => "Host Administratively Prohibited",
        11 => "Network Unreachable for ToS",
        12 => "Host Unreachable for ToS",
        13 => "Communication Administratively Prohibited",
        _ => "Unknown",
    }
}

/// Human-readable ICMP redirect code name.
pub fn icmp_redirect_code_name(code: u8) -> &'static str {
    match code {
        0 => "Redirect for Network",
        1 => "Redirect for Host",
        2 => "Redirect for ToS and Network",
        3 => "Redirect for ToS and Host",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> StovetopConfig {
        StovetopConfig::default()
    }

    #[test]
    fn detect_icmp_redirect() {
        let config = default_config();
        // Type 5 (redirect), code 1, checksum(2), gateway IP 10.0.0.1
        let icmp = vec![5, 1, 0, 0, 10, 0, 0, 1];
        let findings = inspect_icmp(&config, &icmp);
        assert!(findings
            .iter()
            .any(|f| f.decoder == "stovetop:icmp_redirect"));
        if let FindingKind::IcmpRedirect { gateway_ip, .. } = &findings[0].kind {
            assert_eq!(gateway_ip, "10.0.0.1");
        } else {
            panic!("expected IcmpRedirect finding");
        }
    }

    #[test]
    fn detect_icmp_tunnel() {
        let config = default_config();
        // Echo request with high-entropy payload
        let mut icmp = vec![8, 0, 0, 0, 0, 1, 0, 1]; // type 8, id=1, seq=1
        // Append 128 bytes of pseudo-random data (high entropy)
        for i in 0..128u8 {
            icmp.push(i.wrapping_mul(137).wrapping_add(43));
        }
        let findings = inspect_icmp(&config, &icmp);
        assert!(
            findings
                .iter()
                .any(|f| f.decoder == "stovetop:icmp_tunnel"),
            "expected tunnel finding for high-entropy echo payload"
        );
    }

    #[test]
    fn no_tunnel_for_normal_ping() {
        let config = default_config();
        // Echo request with all-zero payload (normal padding)
        let mut icmp = vec![8, 0, 0, 0, 0, 1, 0, 1];
        icmp.extend_from_slice(&[0u8; 64]);
        let findings = inspect_icmp(&config, &icmp);
        assert!(
            !findings
                .iter()
                .any(|f| f.decoder == "stovetop:icmp_tunnel"),
            "should not flag zero-payload ping as tunnel"
        );
    }

    #[test]
    fn detect_router_advertisement() {
        let config = default_config();
        let icmp = vec![9, 0, 0, 0];
        let findings = inspect_icmp(&config, &icmp);
        assert!(findings
            .iter()
            .any(|f| f.decoder == "stovetop:icmp_suspicious"));
    }

    #[test]
    fn detect_timestamp_request() {
        let config = default_config();
        let icmp = vec![13, 0, 0, 0];
        let findings = inspect_icmp(&config, &icmp);
        assert!(findings
            .iter()
            .any(|f| f.decoder == "stovetop:icmp_suspicious"));
    }

    #[test]
    fn detect_address_mask_request() {
        let config = default_config();
        let icmp = vec![17, 0, 0, 0];
        let findings = inspect_icmp(&config, &icmp);
        assert!(findings
            .iter()
            .any(|f| f.decoder == "stovetop:icmp_suspicious"));
    }

    #[test]
    fn disabled_returns_nothing() {
        let mut config = default_config();
        config.check_icmp_anomalies = false;
        let icmp = vec![5, 1, 0, 0, 10, 0, 0, 1]; // redirect
        let findings = inspect_icmp(&config, &icmp);
        assert!(findings.is_empty());
    }
}
