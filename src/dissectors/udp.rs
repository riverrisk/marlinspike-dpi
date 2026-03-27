//! UDP header parser.

/// Parsed UDP header.
#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    /// Parse a UDP header from raw bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        Some(Self {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            length: u16::from_be_bytes([data[4], data[5]]),
            checksum: u16::from_be_bytes([data[6], data[7]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_udp() {
        let mut hdr = [0u8; 8];
        hdr[0..2].copy_from_slice(&12345u16.to_be_bytes());
        hdr[2..4].copy_from_slice(&53u16.to_be_bytes());
        hdr[4..6].copy_from_slice(&42u16.to_be_bytes());
        hdr[6..8].copy_from_slice(&0xABCDu16.to_be_bytes());

        let parsed = UdpHeader::parse(&hdr).unwrap();
        assert_eq!(parsed.src_port, 12345);
        assert_eq!(parsed.dst_port, 53);
        assert_eq!(parsed.length, 42);
    }
}
