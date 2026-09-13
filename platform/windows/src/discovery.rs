use netsight_core::discovery::{deduplicate_devices, DeviceInfo, NetworkDiscovery, NetworkInfo};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

pub struct WindowsNetworkDiscovery;

impl WindowsNetworkDiscovery {
    pub fn new() -> Self { Self }

    fn run_command(program: &str, args: &[&str]) -> anyhow::Result<String> {
        let output = Command::new(program).args(args).output()?;
        if !output.status.success() { anyhow::bail!("{program} failed: {}", output.status); }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn parse_network(output: &str) -> Option<NetworkInfo> {
        let mut interface_name = String::new();
        let mut current_interface = String::new();
        let mut local_ip = None;
        let mut gateway = None;
        let mut prefix_len = None;

        for line in output.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !line.starts_with(' ') && trimmed.ends_with(':') {
                current_interface = trimmed.trim_end_matches(':').to_string();
            }
            if let Some((key, value)) = trimmed.split_once(':') {
                let key = key.trim().to_ascii_lowercase();
                let value = value.trim();
                if key.contains("ipv4") {
                    if let Ok(ip) = value.parse::<Ipv4Addr>() {
                        if !ip.is_loopback() && !ip.is_unspecified() {
                            local_ip = Some(ip);
                            interface_name = current_interface.clone();
                        }
                    }
                } else if key.contains("default gateway") {
                    if let Ok(ip) = value.parse::<Ipv4Addr>() { gateway = Some(ip); }
                } else if key.contains("subnet mask") {
                    if let Ok(mask) = value.parse::<Ipv4Addr>() { prefix_len = Some(mask_to_prefix(mask)); }
                }
            }
        }

        Some(NetworkInfo {
            interface_name: (!interface_name.is_empty()).then_some(interface_name)?,
            local_ip: IpAddr::V4(local_ip?),
            gateway: gateway.map(IpAddr::V4),
            prefix_len: prefix_len.unwrap_or(24),
        })
    }

    fn parse_arp(output: &str) -> Vec<DeviceInfo> {
        let mut devices = Vec::new();
        for line in output.lines() {
            let parts: Vec<_> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[0].parse::<Ipv4Addr>().is_ok() {
                let ip = parts[0].parse().unwrap();
                let mac = parts[1].to_ascii_lowercase();
                if mac != "ff-ff-ff-ff-ff-ff" && parts[2].eq_ignore_ascii_case("dynamic") {
                    devices.push(DeviceInfo { ip: IpAddr::V4(ip), mac: Some(mac), hostname: None, vendor: None });
                }
            }
        }
        deduplicate_devices(&mut devices);
        devices
    }
}

impl Default for WindowsNetworkDiscovery { fn default() -> Self { Self::new() } }

impl NetworkDiscovery for WindowsNetworkDiscovery {
    fn current_network(&self) -> anyhow::Result<NetworkInfo> {
        let output = Self::run_command("ipconfig", &[])?;
        Self::parse_network(&output).ok_or_else(|| anyhow::anyhow!("no active IPv4 network found"))
    }

    fn devices(&self) -> anyhow::Result<Vec<DeviceInfo>> {
        let output = Self::run_command("arp", &["-a"])?;
        Ok(Self::parse_arp(&output))
    }
}

fn mask_to_prefix(mask: Ipv4Addr) -> u8 { u32::from(mask).count_ones() as u8 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_subnet_mask() { assert_eq!(mask_to_prefix(Ipv4Addr::new(255,255,255,0)), 24); }

    #[test]
    fn parses_dynamic_arp_entries() {
        let output = "  192.168.1.1  aa-bb-cc-dd-ee-ff  dynamic\n  192.168.1.20  11-22-33-44-55-66  dynamic\n  224.0.0.251  01-00-5e-00-00-fb  static\n";
        let devices = WindowsNetworkDiscovery::parse_arp(output);
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].ip, IpAddr::V4(Ipv4Addr::new(192,168,1,1)));
        assert_eq!(devices[1].ip, IpAddr::V4(Ipv4Addr::new(192,168,1,20)));
    }
}
