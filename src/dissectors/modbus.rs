//! Modbus/TCP dissector.
//!
//! MBAP header (7 bytes): transaction_id (2), protocol_id (2, must be 0),
//! length (2), unit_id (1). Followed by PDU: function_code (1) + data.

use std::collections::BTreeMap;

use crate::registry::{ModbusFields, PacketContext, ProtocolData, ProtocolDissector};

#[derive(Default)]
pub struct ModbusDissector;

const MODBUS_PORT: u16 = 502;

impl ProtocolDissector for ModbusDissector {
    fn name(&self) -> &str {
        "modbus"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        if src_port != MODBUS_PORT && dst_port != MODBUS_PORT {
            return false;
        }
        // Minimum MBAP header (7) + at least 1 byte PDU.
        if data.len() < 8 {
            return false;
        }
        // Protocol identifier must be 0x0000 for Modbus/TCP.
        let protocol_id = u16::from_be_bytes([data[2], data[3]]);
        if protocol_id != 0 {
            return false;
        }
        // MBAP length field = remaining bytes after length field (unit_id + PDU).
        // Must be >= 2 (unit_id + at least 1 byte function code) and match payload.
        let mbap_length = u16::from_be_bytes([data[4], data[5]]) as usize;
        if mbap_length < 2 || mbap_length > 253 {
            return false;
        }
        // Length should match: data.len() == 6 (header before length) + mbap_length
        // Allow slight mismatch for TCP reassembly, but reject wild mismatches
        let expected = 6 + mbap_length;
        if data.len() < expected || data.len() > expected + 6 {
            return false;
        }
        // Function code must be a valid Modbus function (1-127)
        let fc = data[7];
        let base_fc = fc & 0x7F;
        base_fc >= 1 && base_fc <= 127
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        if data.len() < 8 {
            return None;
        }

        let transaction_id = u16::from_be_bytes([data[0], data[1]]);
        let protocol_id = u16::from_be_bytes([data[2], data[3]]);
        if protocol_id != 0 {
            return None;
        }
        let _length = u16::from_be_bytes([data[4], data[5]]);
        let unit_id = data[6];
        let function_code = data[7];

        let is_exception = function_code & 0x80 != 0;
        let base_fc = if is_exception {
            function_code & 0x7F
        } else {
            function_code
        };

        let mut exception_code = 0u8;
        if is_exception && data.len() >= 9 {
            exception_code = data[8];
        }

        let registers = if !is_exception {
            parse_registers(base_fc, &data[8..])
        } else {
            Vec::new()
        };
        let device_identification = if !is_exception {
            parse_device_identification(base_fc, &data[8..])
        } else {
            BTreeMap::new()
        };

        Some(ProtocolData::Modbus(ModbusFields {
            transaction_id,
            unit_id,
            function_code: base_fc,
            is_exception,
            exception_code,
            registers,
            device_identification,
        }))
    }
}

/// Parse register addresses/values from the PDU data following the function code.
fn parse_registers(function_code: u8, pdu_data: &[u8]) -> Vec<(u16, u16)> {
    match function_code {
        // Read Coils (FC 1) or Read Holding Registers (FC 3).
        // Request format: start_addr(2) + quantity(2) = exactly 4 bytes.
        // Response format: byte_count(1) + register_data(byte_count).
        1 | 3 => {
            if pdu_data.is_empty() {
                return Vec::new();
            }

            // Heuristic: if first byte (as byte_count) plus 1 equals the
            // total length, this is a response.  A 4-byte request would only
            // look like a response if byte_count == 3 which is odd and
            // invalid for register data (always pairs of 2).
            let candidate_bc = pdu_data[0] as usize;
            let is_response =
                candidate_bc > 0 && candidate_bc % 2 == 0 && candidate_bc + 1 == pdu_data.len();

            if is_response {
                let byte_count = candidate_bc;
                let reg_data = &pdu_data[1..];
                let num_regs = byte_count / 2;
                (0..num_regs)
                    .filter_map(|i| {
                        let off = i * 2;
                        if off + 1 < reg_data.len() {
                            Some((
                                i as u16,
                                u16::from_be_bytes([reg_data[off], reg_data[off + 1]]),
                            ))
                        } else {
                            None
                        }
                    })
                    .collect()
            } else if pdu_data.len() >= 4 {
                // Request: start_addr + quantity.
                let start_addr = u16::from_be_bytes([pdu_data[0], pdu_data[1]]);
                let quantity = u16::from_be_bytes([pdu_data[2], pdu_data[3]]);
                vec![(start_addr, quantity)]
            } else {
                Vec::new()
            }
        }
        // Write Single Register (FC 6)
        6 => {
            if pdu_data.len() >= 4 {
                let addr = u16::from_be_bytes([pdu_data[0], pdu_data[1]]);
                let value = u16::from_be_bytes([pdu_data[2], pdu_data[3]]);
                vec![(addr, value)]
            } else {
                Vec::new()
            }
        }
        // Write Multiple Registers (FC 16)
        16 => {
            if pdu_data.len() >= 5 {
                let start_addr = u16::from_be_bytes([pdu_data[0], pdu_data[1]]);
                let quantity = u16::from_be_bytes([pdu_data[2], pdu_data[3]]);
                let byte_count = pdu_data[4] as usize;
                let values = &pdu_data[5..];
                if values.len() >= byte_count {
                    (0..quantity as usize)
                        .filter_map(|i| {
                            let off = i * 2;
                            if off + 1 < values.len() {
                                Some((
                                    start_addr + i as u16,
                                    u16::from_be_bytes([values[off], values[off + 1]]),
                                ))
                            } else {
                                None
                            }
                        })
                        .collect()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

fn parse_device_identification(function_code: u8, pdu_data: &[u8]) -> BTreeMap<String, String> {
    if function_code != 43 || pdu_data.len() < 6 || pdu_data[0] != 0x0E {
        return BTreeMap::new();
    }

    let object_count = pdu_data[5] as usize;
    let mut offset = 6;
    let mut out = BTreeMap::new();

    for _ in 0..object_count {
        if offset + 2 > pdu_data.len() {
            break;
        }
        let object_id = pdu_data[offset];
        let len = pdu_data[offset + 1] as usize;
        offset += 2;
        if offset + len > pdu_data.len() {
            break;
        }
        let value = String::from_utf8_lossy(&pdu_data[offset..offset + len]).to_string();
        offset += len;

        let key = match object_id {
            0x00 => "vendor_name",
            0x01 => "product_code",
            0x02 => "revision",
            0x03 => "vendor_url",
            0x04 => "product_name",
            0x05 => "model_name",
            0x06 => "user_application_name",
            _ => continue,
        };
        out.insert(key.to_string(), value);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_context() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 49152,
            dst_port: 502,
            vlan_id: None,
            timestamp: 0,
        }
    }

    #[test]
    fn test_parse_read_holding_registers_request() {
        // MBAP + PDU: read holding registers, start=0x0064, quantity=0x0002
        let pkt = [
            0x00, 0x01, // transaction id
            0x00, 0x00, // protocol id
            0x00, 0x06, // length
            0x01, // unit id
            0x03, // function code: read holding registers
            0x00, 0x64, // start address: 100
            0x00, 0x02, // quantity: 2
        ];

        let d = ModbusDissector;
        assert!(d.can_parse(&pkt, 49152, 502));

        let result = d.parse(&pkt, &test_context()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                assert_eq!(m.transaction_id, 1);
                assert_eq!(m.unit_id, 1);
                assert_eq!(m.function_code, 3);
                assert!(!m.is_exception);
                assert_eq!(m.registers, vec![(100, 2)]);
            }
            _ => panic!("expected Modbus"),
        }
    }

    #[test]
    fn test_parse_read_holding_registers_response() {
        // MBAP + PDU: response with 2 registers
        let pkt = [
            0x00, 0x01, // transaction id
            0x00, 0x00, // protocol id
            0x00, 0x07, // length
            0x01, // unit id
            0x03, // function code
            0x04, // byte count: 4
            0x00, 0x0A, // register 0 value: 10
            0x00, 0x14, // register 1 value: 20
        ];

        let d = ModbusDissector;
        let result = d.parse(&pkt, &test_context()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                assert_eq!(m.function_code, 3);
                assert_eq!(m.registers, vec![(0, 10), (1, 20)]);
            }
            _ => panic!("expected Modbus"),
        }
    }

    #[test]
    fn test_parse_write_single_register() {
        let pkt = [
            0x00, 0x02, // transaction id
            0x00, 0x00, // protocol id
            0x00, 0x06, // length
            0x01, // unit id
            0x06, // function code: write single register
            0x00, 0x01, // address: 1
            0x00, 0xFF, // value: 255
        ];

        let d = ModbusDissector;
        let result = d.parse(&pkt, &test_context()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                assert_eq!(m.function_code, 6);
                assert_eq!(m.registers, vec![(1, 255)]);
            }
            _ => panic!("expected Modbus"),
        }
    }

    #[test]
    fn test_parse_write_multiple_registers() {
        let pkt = [
            0x00, 0x03, // transaction id
            0x00, 0x00, // protocol id
            0x00, 0x0B, // length
            0x01, // unit id
            0x10, // function code: write multiple registers (16)
            0x00, 0x0A, // start address: 10
            0x00, 0x02, // quantity: 2
            0x04, // byte count: 4
            0x00, 0x01, // value 1
            0x00, 0x02, // value 2
        ];

        let d = ModbusDissector;
        let result = d.parse(&pkt, &test_context()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                assert_eq!(m.function_code, 16);
                assert_eq!(m.registers, vec![(10, 1), (11, 2)]);
            }
            _ => panic!("expected Modbus"),
        }
    }

    #[test]
    fn test_parse_device_identification_response() {
        let mut pkt = vec![
            0x00, 0x03, // transaction id
            0x00, 0x00, // protocol id
            0x00, 0x00, // length placeholder
            0x01, // unit id
            0x2B, // function code
            0x0E, // MEI type
            0x01, // read device id code
            0x01, // conformity level
            0x00, // more follows
            0x00, // next object id
            0x03, // number of objects
            0x00, 0x09, // vendor name
        ];
        pkt.extend_from_slice(b"Schneider");
        pkt.extend_from_slice(&[0x05, 0x07]);
        pkt.extend_from_slice(b"M580CPU");
        pkt.extend_from_slice(&[0x02, 0x04]);
        pkt.extend_from_slice(b"2.30");

        let mbap_length = (pkt.len() - 6) as u16;
        pkt[4..6].copy_from_slice(&mbap_length.to_be_bytes());

        let d = ModbusDissector;
        let result = d.parse(&pkt, &test_context()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                assert_eq!(m.function_code, 43);
                assert_eq!(
                    m.device_identification
                        .get("vendor_name")
                        .map(String::as_str),
                    Some("Schneider")
                );
                assert_eq!(
                    m.device_identification
                        .get("model_name")
                        .map(String::as_str),
                    Some("M580CPU")
                );
                assert_eq!(
                    m.device_identification.get("revision").map(String::as_str),
                    Some("2.30")
                );
            }
            _ => panic!("expected Modbus"),
        }
    }

    #[test]
    fn test_modbus_exception() {
        let pkt = [
            0x00, 0x01, // transaction id
            0x00, 0x00, // protocol id
            0x00, 0x03, // length
            0x01, // unit id
            0x83, // function code: exception (0x80 | 0x03)
            0x02, // exception code: illegal data address
        ];

        let d = ModbusDissector;
        let result = d.parse(&pkt, &test_context()).unwrap();
        match result {
            ProtocolData::Modbus(m) => {
                assert!(m.is_exception);
                assert_eq!(m.function_code, 3);
                assert_eq!(m.exception_code, 2);
            }
            _ => panic!("expected Modbus"),
        }
    }

    #[test]
    fn test_wrong_port_rejected() {
        let pkt = [0x00; 12];
        let d = ModbusDissector;
        assert!(!d.can_parse(&pkt, 1234, 5678));
    }
}
