use serde::Serialize;

#[derive(Clone, Serialize)]
pub struct DeviceCorrelation {
    pub device_ip: String,
    pub process: Option<String>,
    pub pid: Option<u32>,
    pub remote_address: String,
    pub service: String,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

pub fn correlate(ip: &str, process: Option<&str>, pid: Option<u32>, remote: &str, service: &str, confidence: u8) -> DeviceCorrelation {
    let mut evidence = Vec::new();
    if process.is_some() { evidence.push("local process".into()); }
    if !remote.is_empty() { evidence.push("connection endpoint".into()); }
    if service != "Unknown" { evidence.push("service intelligence".into()); }
    DeviceCorrelation {
        device_ip: ip.into(), process: process.map(str::to_owned), pid, remote_address: remote.into(), service: service.into(), confidence, evidence,
    }
}
