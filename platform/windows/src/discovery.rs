use netsight_core::discovery::{DeviceInfo, NetworkDiscovery, NetworkInfo};
use std::net::{IpAddr, Ipv4Addr};

pub struct WindowsNetworkDiscovery;

impl WindowsNetworkDiscovery {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsNetworkDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkDiscovery for WindowsNetworkDiscovery {
    fn current_network(&self) -> anyhow::Result<NetworkInfo> {
        // Phase 1 keeps platform probing isolated. Real Windows adapter/gateway
        // enumeration will be added here without coupling the core domain to Win32.
        Ok(NetworkInfo {
            interface_name: "unprobed".to_string(),
            local_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            gateway: None,
            prefix_len: 0,
        })
    }

    fn devices(&self) -> anyhow::Result<Vec<DeviceInfo>> {
        Ok(Vec::new())
    }
}
