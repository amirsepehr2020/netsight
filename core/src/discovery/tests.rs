#[cfg(test)]
mod tests {
    use super::super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn device(ip: u8) -> DeviceInfo {
        DeviceInfo {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, ip)),
            mac: None,
            hostname: None,
            vendor: None,
        }
    }

    #[test]
    fn duplicate_ips_are_removed_deterministically() {
        let mut devices = vec![device(20), device(10), device(20), device(10)];
        deduplicate_devices(&mut devices);
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(devices[1].ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)));
    }
}
