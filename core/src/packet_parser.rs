use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkProtocol {
    Ethernet,
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
    Dns,
    Tls,
    Http,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketSummary {
    pub protocol: NetworkProtocol,
    pub source_mac: Option<[u8; 6]>,
    pub destination_mac: Option<[u8; 6]>,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub payload_len: usize,
    pub header_len: usize,
    pub dns_name: Option<String>,
    pub tls_server_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Truncated(&'static str),
    Unsupported(&'static str),
    Malformed(&'static str),
}

pub fn parse_packet(frame: &[u8]) -> Result<PacketSummary, ParseError> {
    if frame.len() < 14 {
        return Err(ParseError::Truncated("ethernet"));
    }

    let destination_mac = frame[0..6].try_into().unwrap();
    let source_mac = frame[6..12].try_into().unwrap();
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);

    let mut summary = PacketSummary {
        protocol: NetworkProtocol::Ethernet,
        source_mac: Some(source_mac),
        destination_mac: Some(destination_mac),
        source_ip: None,
        destination_ip: None,
        source_port: None,
        destination_port: None,
        payload_len: frame.len().saturating_sub(14),
        header_len: 14,
        dns_name: None,
        tls_server_name: None,
    };

    match ether_type {
        0x0800 => parse_ipv4(&frame[14..], &mut summary),
        0x86dd => {
            summary.protocol = NetworkProtocol::Ipv6;
            Ok(summary)
        }
        0x0806 => Ok(summary),
        _ => Ok(summary),
    }
}

fn parse_ipv4(data: &[u8], summary: &mut PacketSummary) -> Result<PacketSummary, ParseError> {
    if data.len() < 20 {
        return Err(ParseError::Truncated("ipv4"));
    }
    if data[0] >> 4 != 4 {
        return Err(ParseError::Malformed("ipv4 version"));
    }

    let ihl = ((data[0] & 0x0f) as usize) * 4;
    if ihl < 20 || data.len() < ihl {
        return Err(ParseError::Malformed("ipv4 header length"));
    }

    summary.protocol = NetworkProtocol::Ipv4;
    summary.source_ip = Some(format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]));
    summary.destination_ip = Some(format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]));
    summary.header_len += ihl;
    let payload = &data[ihl..];
    summary.payload_len = payload.len();

    match data[9] {
        6 => parse_tcp(payload, summary),
        17 => parse_udp(payload, summary),
        _ => Ok(summary.clone()),
    }
}

fn parse_tcp(data: &[u8], summary: &mut PacketSummary) -> Result<PacketSummary, ParseError> {
    if data.len() < 20 {
        return Err(ParseError::Truncated("tcp"));
    }
    let header_len = ((data[12] >> 4) as usize) * 4;
    if header_len < 20 || data.len() < header_len {
        return Err(ParseError::Malformed("tcp header length"));
    }
    summary.protocol = NetworkProtocol::Tcp;
    summary.source_port = Some(u16::from_be_bytes([data[0], data[1]]));
    summary.destination_port = Some(u16::from_be_bytes([data[2], data[3]]));
    summary.header_len += header_len;
    let payload = &data[header_len..];
    summary.payload_len = payload.len();

    if is_tls_record(payload) {
        summary.protocol = NetworkProtocol::Tls;
        summary.tls_server_name = parse_tls_sni(payload);
    } else if is_http(payload) {
        summary.protocol = NetworkProtocol::Http;
    }
    Ok(summary.clone())
}

fn parse_udp(data: &[u8], summary: &mut PacketSummary) -> Result<PacketSummary, ParseError> {
    if data.len() < 8 {
        return Err(ParseError::Truncated("udp"));
    }
    summary.protocol = NetworkProtocol::Udp;
    summary.source_port = Some(u16::from_be_bytes([data[0], data[1]]));
    summary.destination_port = Some(u16::from_be_bytes([data[2], data[3]]));
    summary.header_len += 8;
    let payload = &data[8..];
    summary.payload_len = payload.len();
    if summary.source_port == Some(53) || summary.destination_port == Some(53) {
        if let Some(name) = parse_dns_question(payload) {
            summary.protocol = NetworkProtocol::Dns;
            summary.dns_name = Some(name);
        }
    }
    Ok(summary.clone())
}

fn is_tls_record(data: &[u8]) -> bool {
    data.len() >= 5 && matches!(data[0], 20 | 21 | 22 | 23) && data[1] == 3
}

fn is_http(data: &[u8]) -> bool {
    [b"GET ", b"POST", b"PUT ", b"HEAD", b"HTTP/"].iter().any(|p| data.starts_with(p))
}

fn parse_dns_question(data: &[u8]) -> Option<String> {
    if data.len() < 13 {
        return None;
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut offset = 12;
    let mut labels = Vec::new();
    while offset < data.len() {
        let len = data[offset] as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        if len > 63 || offset + len > data.len() {
            return None;
        }
        labels.push(std::str::from_utf8(&data[offset..offset + len]).ok()?.to_string());
        offset += len;
    }
    if labels.is_empty() { None } else { Some(labels.join(".")) }
}

fn parse_tls_sni(data: &[u8]) -> Option<String> {
    if data.len() < 43 || data[0] != 22 || data[5] != 1 {
        return None;
    }
    let hs_len = ((data[6] as usize) << 16) | ((data[7] as usize) << 8) | data[8] as usize;
    if hs_len + 9 > data.len() { return None; }
    let mut p = 43;
    if p > data.len() { return None; }
    let session_len = *data.get(43 - 1)? as usize;
    p = 43 + session_len;
    if p + 2 > data.len() { return None; }
    let cipher_len = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
    p += 2 + cipher_len;
    if p >= data.len() { return None; }
    let compression_len = data[p] as usize;
    p += 1 + compression_len;
    if p + 2 > data.len() { return None; }
    let ext_len = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
    p += 2;
    let end = p.checked_add(ext_len)?.min(data.len());
    while p + 4 <= end {
        let kind = u16::from_be_bytes([data[p], data[p + 1]]);
        let len = u16::from_be_bytes([data[p + 2], data[p + 3]]) as usize;
        p += 4;
        if p + len > end { return None; }
        if kind == 0 && len >= 5 {
            let list_len = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
            if list_len + 2 > len || p + 5 > data.len() { return None; }
            let name_type = data[p + 2];
            let name_len = u16::from_be_bytes([data[p + 3], data[p + 4]]) as usize;
            if name_type == 0 && name_len <= list_len.saturating_sub(3) && p + 5 + name_len <= data.len() {
                return std::str::from_utf8(&data[p + 5..p + 5 + name_len]).ok().map(str::to_string);
            }
        }
        p += len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet_ipv4(proto: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14 + 20 + payload.len()];
        f[0..6].copy_from_slice(&[1,2,3,4,5,6]);
        f[6..12].copy_from_slice(&[7,8,9,10,11,12]);
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        f[14] = 0x45;
        f[23] = proto;
        f[26..30].copy_from_slice(&[192,168,1,10]);
        f[30..34].copy_from_slice(&[1,1,1,1]);
        f[34..].copy_from_slice(payload);
        f
    }

    #[test]
    fn parses_ipv4_tcp_ports() {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50;
        let p = parse_packet(&ethernet_ipv4(6, &tcp)).unwrap();
        assert_eq!(p.protocol, NetworkProtocol::Tcp);
        assert_eq!(p.destination_port, Some(443));
    }

    #[test]
    fn rejects_short_frames() {
        assert_eq!(parse_packet(&[0; 8]), Err(ParseError::Truncated("ethernet")));
    }
}
