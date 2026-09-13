use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkInfo {
    pub interface_name: String,
    pub local_ip: IpAddr,
    pub gateway: Option<IpAddr>,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceInfo {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
}

pub trait NetworkDiscovery {
    fn current_network(&self) -> anyhow::Result<NetworkInfo>;
    fn devices(&self) -> anyhow::Result<Vec<DeviceInfo>>;
}

pub fn deduplicate_devices(devices: &mut Vec<DeviceInfo>) {
    devices.sort_by_key(|device| device.ip);
    devices.dedup_by_key(|device| device.ip);
}
