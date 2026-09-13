use super::{parse_packet, PacketEvent};

fn ethernet_ipv4_tcp(src: [u8; 4], dst: [u8; 4], dst_port: u16) -> Vec<u8> {
    let mut p = vec![0u8; 14 + 20 + 20];
    p[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    p[14] = 0x45;
    p[23] = 6;
    p[26..30].copy_from_slice(&src);
    p[30..34].copy_from_slice(&dst);
    p[34..36].copy_from_slice(&12345u16.to_be_bytes());
    p[36..38].copy_from_slice(&dst_port.to_be_bytes());
    p[46] = 0x50;
    p
}

#[test]
fn packet_uses_capture_timestamp_and_parses_ipv4_endpoints() {
    let packet = ethernet_ipv4_tcp([192, 168, 1, 20], [142, 250, 72, 14], 443);
    let event = parse_packet(&packet, packet.len() as u32, 1_700_000_000, 123_000).expect("packet should parse");
    assert_eq!(event.timestamp, "1700000000123");
    assert_eq!(event.source, "192.168.1.20");
    assert_eq!(event.destination, "142.250.72.14");
    assert_eq!(event.protocol, "TCP");
    assert_eq!(event.service, "HTTPS");
}

#[test]
fn packet_parser_accepts_vlan_tagged_ipv4_frames() {
    let mut p = ethernet_ipv4_tcp([192, 168, 1, 20], [8, 8, 8, 8], 53);
    p[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
    p.splice(14..14, [0x00, 0x01, 0x08, 0x00]);
    let event = parse_packet(&p, p.len() as u32, 1_700_000_000, 0).expect("vlan packet should parse");
    assert_eq!(event.source, "192.168.1.20");
    assert_eq!(event.destination, "8.8.8.8");
    assert_eq!(event.protocol, "TCP");
}

#[test]
fn parser_rejects_truncated_frames() {
    let event: Option<PacketEvent> = parse_packet(&[0u8; 10], 10, 0, 0);
    assert!(event.is_none());
}
