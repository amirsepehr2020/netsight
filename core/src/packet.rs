use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol { Tcp, Udp, Other(u8) }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPacket {
    pub timestamp_micros: i64,
    pub captured_len: u32,
    pub original_len: u32,
    pub source_ip: Option<IpAddr>,
    pub destination_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub transport: Option<TransportProtocol>,
    pub payload_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizeError { Truncated, UnsupportedLink, Malformed }

/// Normalize an Ethernet frame into fields consumed by flow correlation.
/// Supports Ethernet, up to two VLAN tags, IPv4/IPv6 and TCP/UDP metadata.
pub fn normalize_ethernet(timestamp_micros: i64, captured_len: u32, original_len: u32, data: &[u8]) -> Result<NormalizedPacket, NormalizeError> {
    if data.len() < 14 { return Err(NormalizeError::Truncated); }
    let mut offset = 14usize;
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    for _ in 0..2 {
        if matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
            if data.len() < offset + 4 { return Err(NormalizeError::Truncated); }
            ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;
        } else { break; }
    }
    let (src, dst, protocol, transport_offset) = match ethertype {
        0x0800 => parse_ipv4(data, offset)?,
        0x86dd => parse_ipv6(data, offset)?,
        _ => return Err(NormalizeError::UnsupportedLink),
    };
    let (source_port, destination_port, payload_len) = match protocol {
        TransportProtocol::Tcp | TransportProtocol::Udp => {
            if data.len() < transport_offset + 8 { return Err(NormalizeError::Truncated); }
            let sp = u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
            let dp = u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);
            let header_len = if matches!(protocol, TransportProtocol::Tcp) {
                let h = ((data[transport_offset + 12] >> 4) as usize) * 4;
                if h < 20 { return Err(NormalizeError::Malformed); }
                h
            } else { 8 };
            if data.len() < transport_offset + header_len { return Err(NormalizeError::Truncated); }
            (Some(sp), Some(dp), data.len().saturating_sub(transport_offset + header_len))
        }
        _ => (None, None, data.len().saturating_sub(transport_offset)),
    };
    Ok(NormalizedPacket { timestamp_micros, captured_len, original_len, source_ip: Some(src), destination_ip: Some(dst), source_port, destination_port, transport: Some(protocol), payload_len })
}

fn parse_ipv4(data: &[u8], offset: usize) -> Result<(IpAddr, IpAddr, TransportProtocol, usize), NormalizeError> {
    if data.len() < offset + 20 { return Err(NormalizeError::Truncated); }
    let ihl = ((data[offset] & 0x0f) as usize) * 4;
    if ihl < 20 || data.len() < offset + ihl { return Err(NormalizeError::Malformed); }
    let src = IpAddr::V4(Ipv4Addr::new(data[offset+12], data[offset+13], data[offset+14], data[offset+15]));
    let dst = IpAddr::V4(Ipv4Addr::new(data[offset+16], data[offset+17], data[offset+18], data[offset+19]));
    Ok((src, dst, transport(data[offset + 9]), offset + ihl))
}

fn parse_ipv6(data: &[u8], offset: usize) -> Result<(IpAddr, IpAddr, TransportProtocol, usize), NormalizeError> {
    if data.len() < offset + 40 { return Err(NormalizeError::Truncated); }
    let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[offset+8..offset+24]).map_err(|_| NormalizeError::Malformed)?));
    let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[offset+24..offset+40]).map_err(|_| NormalizeError::Malformed)?));
    Ok((src, dst, transport(data[offset + 6]), offset + 40))
}

fn transport(value: u8) -> TransportProtocol { match value { 6 => TransportProtocol::Tcp, 17 => TransportProtocol::Udp, other => TransportProtocol::Other(other) } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalizes_ipv4_udp() {
        let mut p = vec![0u8; 14 + 20 + 8 + 3];
        p[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); p[14] = 0x45; p[23] = 17;
        p[26..30].copy_from_slice(&[192,168,1,10]); p[30..34].copy_from_slice(&[8,8,8,8]);
        p[34..36].copy_from_slice(&5353u16.to_be_bytes()); p[36..38].copy_from_slice(&53u16.to_be_bytes());
        let n = normalize_ethernet(10, p.len() as u32, p.len() as u32, &p).unwrap();
        assert_eq!(n.source_port, Some(5353)); assert_eq!(n.destination_port, Some(53)); assert_eq!(n.payload_len, 3);
    }
    #[test]
    fn rejects_short_frame() { assert_eq!(normalize_ethernet(0, 3, 3, &[0,1,2]), Err(NormalizeError::Truncated)); }
}
