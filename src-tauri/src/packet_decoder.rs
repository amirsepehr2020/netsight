use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, PartialEq)]
pub struct DecodedPacket {
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub length: u32,
    pub info: String,
    pub service_hint: Option<String>,
}

pub fn decode(frame: &[u8], wire_length: u32) -> Option<DecodedPacket> {
    if frame.len() < 14 { return None; }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    match ethertype {
        0x0800 => decode_ipv4(&frame[14..], wire_length),
        0x86dd => decode_ipv6(&frame[14..], wire_length),
        0x0806 => Some(DecodedPacket { source: "ARP".into(), destination: "ARP".into(), protocol: "ARP".into(), source_port: None, destination_port: None, length: wire_length, info: "Address Resolution Protocol".into(), service_hint: None }),
        _ => Some(DecodedPacket { source: "—".into(), destination: "—".into(), protocol: format!("EtherType 0x{ethertype:04x}"), source_port: None, destination_port: None, length: wire_length, info: "Ethernet frame".into(), service_hint: None }),
    }
}

fn decode_ipv4(b: &[u8], length: u32) -> Option<DecodedPacket> {
    if b.len() < 20 { return None; }
    let ihl = (b[0] & 0x0f) as usize * 4;
    if ihl < 20 || b.len() < ihl { return None; }
    let src = Ipv4Addr::new(b[12], b[13], b[14], b[15]).to_string();
    let dst = Ipv4Addr::new(b[16], b[17], b[18], b[19]).to_string();
    decode_l4(src, dst, b[9], &b[ihl..], length)
}

fn decode_ipv6(b: &[u8], length: u32) -> Option<DecodedPacket> {
    if b.len() < 40 { return None; }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).ok()?).to_string();
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&b[24..40]).ok()?).to_string();
    decode_l4(src, dst, b[6], &b[40..], length)
}

fn decode_l4(source: String, destination: String, proto: u8, payload: &[u8], length: u32) -> Option<DecodedPacket> {
    match proto {
        6 => {
            if payload.len() < 20 { return Some(base(source, destination, "TCP", length, "Truncated TCP header".to_string())); }
            let sp = u16::from_be_bytes([payload[0], payload[1]]);
            let dp = u16::from_be_bytes([payload[2], payload[3]]);
            Some(with_ports(source, destination, "TCP", sp, dp, length, tcp_info(payload), service_for_port(6, sp, dp)))
        }
        17 => {
            if payload.len() < 8 { return Some(base(source, destination, "UDP", length, "Truncated UDP header".to_string())); }
            let sp = u16::from_be_bytes([payload[0], payload[1]]);
            let dp = u16::from_be_bytes([payload[2], payload[3]]);
            Some(with_ports(source, destination, "UDP", sp, dp, length, "Datagram".into(), service_for_port(17, sp, dp)))
        }
        1 => Some(base(source, destination, "ICMP", length, "Internet Control Message Protocol".to_string())),
        58 => Some(base(source, destination, "ICMPv6", length, "Internet Control Message Protocol v6".to_string())),
        _ => Some(base(source, destination, "IP", length, format!("IPv{proto} payload"))),
    }
}

fn base(source: String, destination: String, protocol: &str, length: u32, info: String) -> DecodedPacket { DecodedPacket { source, destination, protocol: protocol.into(), source_port: None, destination_port: None, length, info, service_hint: None } }
fn with_ports(source: String, destination: String, protocol: &str, sp: u16, dp: u16, length: u32, info: String, service: Option<String>) -> DecodedPacket { DecodedPacket { source, destination, protocol: protocol.into(), source_port: Some(sp), destination_port: Some(dp), length, info, service_hint: service } }
fn tcp_info(b: &[u8]) -> String { let flags=b[13]; let mut names=Vec::new(); if flags&0x02!=0 {names.push("SYN")} if flags&0x10!=0 {names.push("ACK")} if flags&0x01!=0 {names.push("FIN")} if flags&0x04!=0 {names.push("RST")} if flags&0x08!=0 {names.push("PSH")} if names.is_empty(){"TCP segment".into()}else{names.join(", ")}}
fn service_for_port(proto: u8, sp: u16, dp: u16) -> Option<String> { let p=if dp!=0 {dp}else{sp}; let name=match (proto,p){(17,53)=>"DNS",(6,80)=>"HTTP",(6,443)=>"HTTPS",(6,22)=>"SSH",(6,25)=>"SMTP",(6,993)=>"IMAPS",(6,995)=>"POP3S",_=>return None}; Some(name.into()) }

#[cfg(test)]
mod tests {
    use super::*;
    fn eth_ipv4(proto:u8, payload:&[u8]) -> Vec<u8> { let mut f=vec![0u8;14+20+payload.len()]; f[12]=0x08;f[13]=0x00;f[14]=0x45;f[23]=proto;f[26]=192;f[27]=168;f[28]=1;f[29]=10;f[30]=8;f[31]=8;f[32]=8;f[33]=8;f[34..].copy_from_slice(payload);f }
    #[test] fn decodes_tcp_ports() { let mut p=vec![0u8;20];p[0]=0x1f;p[1]=0x90;p[2]=0x01;p[3]=0xbb;p[13]=0x02;let d=decode(&eth_ipv4(6,&p),54).unwrap();assert_eq!(d.protocol,"TCP");assert_eq!(d.source_port,Some(8080));assert_eq!(d.destination_port,Some(443));assert_eq!(d.service_hint.as_deref(),Some("HTTPS")); }
    #[test] fn decodes_udp_dns() { let mut p=vec![0u8;8];p[0]=0x30;p[1]=0x39;p[2]=0;p[3]=53;let d=decode(&eth_ipv4(17,&p),42).unwrap();assert_eq!(d.protocol,"UDP");assert_eq!(d.service_hint.as_deref(),Some("DNS")); }
    #[test] fn rejects_truncated_frames() { assert!(decode(&[0u8;13],13).is_none()); assert!(decode(&eth_ipv4(6,&[0u8;5]),39).is_some()); }
}
