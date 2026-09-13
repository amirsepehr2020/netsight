use anyhow::{Context, Result};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WifiContext {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub signal_percent: Option<u8>,
    pub radio_type: Option<String>,
    pub channel: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAdapter {
    pub name: String,
    pub description: Option<String>,
    pub ipv4: Vec<String>,
    pub gateway: Option<String>,
    pub mac: Option<String>,
    pub wifi: Option<WifiContext>,
}

pub fn discover_network_context() -> Result<Vec<NetworkAdapter>> {
    let output = Command::new("ipconfig").arg("/all").output().context("failed to start ipconfig")?;
    if !output.status.success() { anyhow::bail!("ipconfig exited with status {}", output.status); }
    let mut adapters = parse_ipconfig(&String::from_utf8_lossy(&output.stdout));
    if let Ok(wifi) = discover_wifi_context() {
        if let Some(adapter) = adapters.iter_mut().find(|a| is_wifi_name(&a.name)) { adapter.wifi = Some(wifi); }
    }
    Ok(adapters)
}

pub fn discover_wifi_context() -> Result<WifiContext> {
    let output = Command::new("netsh").args(["wlan", "show", "interfaces"]).output().context("failed to start netsh")?;
    if !output.status.success() { anyhow::bail!("netsh wlan exited with status {}", output.status); }
    Ok(parse_netsh_wifi(&String::from_utf8_lossy(&output.stdout)))
}

fn parse_ipconfig(text: &str) -> Vec<NetworkAdapter> {
    let mut result = Vec::new();
    let mut current: Option<NetworkAdapter> = None;
    for raw in text.lines() {
        let line = raw.trim_end();
        if !line.starts_with(' ') && line.ends_with(':') && !line.contains("DNS Suffix") {
            if let Some(adapter) = current.take() { result.push(adapter); }
            current = Some(NetworkAdapter { name: line.trim_end_matches(':').trim().to_string(), description: None, ipv4: Vec::new(), gateway: None, mac: None, wifi: None });
            continue;
        }
        let Some(adapter) = current.as_mut() else { continue };
        let lower = line.to_ascii_lowercase();
        if lower.contains("physical address") { adapter.mac = value_after_colon(line).map(|v| normalize_mac(&v)); }
        else if lower.contains("description") { adapter.description = value_after_colon(line); }
        else if lower.contains("ipv4 address") { if let Some(v) = value_after_colon(line) { adapter.ipv4.push(v.trim_end_matches("(Preferred)").trim().to_string()); } }
        else if lower.contains("default gateway") { adapter.gateway = value_after_colon(line); }
    }
    if let Some(adapter) = current { result.push(adapter); }
    result
}

fn parse_netsh_wifi(text: &str) -> WifiContext {
    let mut out = WifiContext::default();
    for raw in text.lines() {
        let Some(value) = value_after_colon(raw) else { continue };
        let key = raw.split(':').next().unwrap_or_default().trim().to_ascii_lowercase();
        match key.as_str() {
            "ssid" => out.ssid = Some(value),
            "bssid" => out.bssid = Some(normalize_mac(&value)),
            "signal" => out.signal_percent = value.trim_end_matches('%').trim().parse().ok(),
            "radio type" => out.radio_type = Some(value),
            "channel" => out.channel = value.parse().ok(),
            _ => {}
        }
    }
    out
}

fn value_after_colon(line: &str) -> Option<String> { line.split_once(':').map(|(_, v)| v.trim().to_string()).filter(|v| !v.is_empty()) }
fn normalize_mac(value: &str) -> String { value.trim().to_ascii_lowercase().replace('-', ":") }
fn is_wifi_name(name: &str) -> bool { let n = name.to_ascii_lowercase(); n.contains("wi-fi") || n.contains("wifi") || n.contains("wireless") }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_wifi_metadata() {
        let text = "    SSID : Home\n    BSSID : AA-BB-CC-DD-EE-FF\n    Signal : 87%\n    Radio type : 802.11ax\n    Channel : 36\n";
        let wifi = parse_netsh_wifi(text);
        assert_eq!(wifi.ssid.as_deref(), Some("Home"));
        assert_eq!(wifi.bssid.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(wifi.signal_percent, Some(87));
        assert_eq!(wifi.channel, Some(36));
    }
    #[test]
    fn parses_adapter_addresses() {
        let text = "Wi-Fi:\n   Description . . . . : Adapter\n   Physical Address. . : AA-BB-CC-DD-EE-FF\n   IPv4 Address. . . . : 192.168.1.15(Preferred)\n   Default Gateway . . : 192.168.1.1\n";
        let adapters = parse_ipconfig(text);
        assert_eq!(adapters.len(), 1);
        assert_eq!(adapters[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(adapters[0].ipv4, vec!["192.168.1.15"]);
        assert_eq!(adapters[0].gateway.as_deref(), Some("192.168.1.1"));
    }
}
