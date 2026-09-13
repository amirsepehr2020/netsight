use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceObservation {
    pub timestamp: SystemTime,
    pub mac: Option<String>,
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub device_type: Option<String>,
}

impl DeviceObservation {
    pub fn new(timestamp: SystemTime, ip: IpAddr) -> Self {
        Self { timestamp, mac: None, ip, hostname: None, vendor: None, device_type: None }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceTraffic { pub packets: u64, pub bytes_up: u64, pub bytes_down: u64 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSummary {
    pub id: String,
    pub mac: Option<String>,
    pub ips: Vec<IpAddr>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub device_type: Option<String>,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub traffic: DeviceTraffic,
    pub active_connections: u32,
    pub services: Vec<String>,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone)]
struct DeviceRecord {
    id: String, mac: Option<String>, ips: BTreeSet<IpAddr>, hostname: Option<String>,
    vendor: Option<String>, device_type: Option<String>, first_seen: SystemTime,
    last_seen: SystemTime, traffic: DeviceTraffic, active_connections: u32,
    services: BTreeSet<String>, confidence: u8, evidence: BTreeSet<String>,
}

impl DeviceRecord {
    fn summary(&self) -> DeviceSummary {
        DeviceSummary {
            id: self.id.clone(), mac: self.mac.clone(), ips: self.ips.iter().copied().collect(),
            hostname: self.hostname.clone(), vendor: self.vendor.clone(), device_type: self.device_type.clone(),
            first_seen: self.first_seen, last_seen: self.last_seen, traffic: self.traffic.clone(),
            active_connections: self.active_connections, services: self.services.iter().cloned().collect(),
            confidence: self.confidence, evidence: self.evidence.iter().cloned().collect(),
        }
    }
}

/// Bounded per-device intelligence. MAC is the preferred stable identity; IPs are aliases.
#[derive(Debug)]
pub struct DeviceRegistry {
    retention: Duration, max_devices: usize, devices: HashMap<String, DeviceRecord>,
    mac_index: HashMap<String, String>, ip_index: HashMap<IpAddr, String>,
}

impl DeviceRegistry {
    pub fn new(retention: Duration, max_devices: usize) -> Self {
        Self { retention, max_devices: max_devices.max(1), devices: HashMap::new(), mac_index: HashMap::new(), ip_index: HashMap::new() }
    }

    pub fn observe(&mut self, observation: DeviceObservation) -> String {
        let mac = normalize_mac(observation.mac.as_deref());
        let id = mac.as_deref().and_then(|m| self.mac_index.get(m).cloned())
            .or_else(|| self.ip_index.get(&observation.ip).cloned())
            .unwrap_or_else(|| mac.as_deref().map(|m| format!("mac:{m}")).unwrap_or_else(|| format!("ip:{}", observation.ip)));
        if !self.devices.contains_key(&id) {
            self.devices.insert(id.clone(), DeviceRecord {
                id: id.clone(), mac: mac.clone(), ips: BTreeSet::new(), hostname: None, vendor: None,
                device_type: None, first_seen: observation.timestamp, last_seen: observation.timestamp,
                traffic: DeviceTraffic::default(), active_connections: 0, services: BTreeSet::new(), confidence: 20,
                evidence: BTreeSet::new(),
            });
        }
        let d = self.devices.get_mut(&id).unwrap();
        d.ips.insert(observation.ip);
        d.last_seen = d.last_seen.max(observation.timestamp);
        if d.mac.is_none() { d.mac = mac.clone(); }
        if d.hostname.is_none() { d.hostname = clean(observation.hostname); }
        if d.vendor.is_none() { d.vendor = clean(observation.vendor); }
        if d.device_type.is_none() { d.device_type = clean(observation.device_type); }
        if d.mac.is_some() { d.evidence.insert("mac".into()); }
        if d.hostname.is_some() { d.evidence.insert("hostname".into()); }
        if d.vendor.is_some() { d.evidence.insert("vendor".into()); }
        d.confidence = 20 + if d.mac.is_some() {35} else {0} + if d.hostname.is_some() {20} else {0} + if d.vendor.is_some() {15} else {0} + if d.device_type.is_some() {10} else {0};
        self.ip_index.insert(observation.ip, id.clone());
        if let Some(m) = mac { self.mac_index.insert(m, id.clone()); }
        self.evict_if_needed();
        id
    }

    pub fn record_traffic(&mut self, id: &str, bytes: u64, outbound: bool) {
        if let Some(d) = self.devices.get_mut(id) {
            d.traffic.packets = d.traffic.packets.saturating_add(1);
            if outbound { d.traffic.bytes_up = d.traffic.bytes_up.saturating_add(bytes); }
            else { d.traffic.bytes_down = d.traffic.bytes_down.saturating_add(bytes); }
        }
    }
    pub fn set_connections(&mut self, id: &str, active: u32) { if let Some(d)=self.devices.get_mut(id) { d.active_connections=active; } }
    pub fn add_service(&mut self, id: &str, service: impl Into<String>) { if let Some(d)=self.devices.get_mut(id) { let s=service.into().trim().to_string(); if !s.is_empty(){d.services.insert(s);} } }
    pub fn get(&self, id: &str) -> Option<DeviceSummary> { self.devices.get(id).map(DeviceRecord::summary) }
    pub fn by_ip(&self, ip: IpAddr) -> Option<DeviceSummary> { self.ip_index.get(&ip).and_then(|id| self.get(id)) }
    pub fn list(&self) -> Vec<DeviceSummary> { let mut v:Vec<_>=self.devices.values().map(DeviceRecord::summary).collect(); v.sort_by(|a,b| b.last_seen.cmp(&a.last_seen).then_with(||a.id.cmp(&b.id))); v }
    pub fn len(&self)->usize { self.devices.len() }
    pub fn is_empty(&self)->bool { self.devices.is_empty() }
    pub fn prune(&mut self, now: SystemTime) { let ids:Vec<_>=self.devices.values().filter(|d| now.duration_since(d.last_seen).map(|a|a>self.retention).unwrap_or(false)).map(|d|d.id.clone()).collect(); for id in ids { self.remove(&id); } }
    fn remove(&mut self,id:&str){ if self.devices.remove(id).is_some(){self.mac_index.retain(|_,v|v!=id);self.ip_index.retain(|_,v|v!=id);} }
    fn evict_if_needed(&mut self){ while self.devices.len()>self.max_devices { if let Some(id)=self.devices.values().min_by_key(|d|d.last_seen).map(|d|d.id.clone()){self.remove(&id)}else{break} } }
}

fn normalize_mac(v: Option<&str>)->Option<String>{let s=v?.trim().to_ascii_lowercase().replace('-',":");(!s.is_empty()).then_some(s)}
fn clean(v:Option<String>)->Option<String>{v.map(|s|s.trim().to_string()).filter(|s|!s.is_empty())}

#[cfg(test)]
mod tests {
    use super::*;
    fn observation(ts:SystemTime,mac:&str,ip:&str)->DeviceObservation{DeviceObservation{timestamp:ts,mac:Some(mac.into()),ip:ip.parse().unwrap(),hostname:Some("phone.local".into()),vendor:Some("Example".into()),device_type:Some("Phone".into())}}
    #[test] fn merges_mac_when_ip_changes(){let now=SystemTime::now();let mut r=DeviceRegistry::new(Duration::from_secs(300),10);let a=r.observe(observation(now,"AA-BB-CC-DD-EE-FF","192.168.1.10"));let b=r.observe(observation(now+Duration::from_secs(1),"aa:bb:cc:dd:ee:ff","192.168.1.42"));assert_eq!(a,b);assert_eq!(r.len(),1);assert_eq!(r.get(&a).unwrap().ips.len(),2);}
    #[test] fn aggregates_traffic_and_services(){let mut r=DeviceRegistry::new(Duration::from_secs(300),10);let id=r.observe(observation(SystemTime::now(),"00:11:22:33:44:55","192.168.1.10"));r.record_traffic(&id,500,true);r.record_traffic(&id,1500,false);r.add_service(&id,"YouTube");r.add_service(&id,"YouTube");let d=r.get(&id).unwrap();assert_eq!(d.traffic.packets,2);assert_eq!(d.traffic.bytes_up,500);assert_eq!(d.traffic.bytes_down,1500);assert_eq!(d.services,vec!["YouTube"]);}
    #[test] fn prunes_stale_devices(){let now=SystemTime::now();let mut r=DeviceRegistry::new(Duration::from_secs(10),10);let id=r.observe(observation(now-Duration::from_secs(11),"00:11:22:33:44:55","192.168.1.10"));r.prune(now);assert!(r.get(&id).is_none());}
    #[test] fn enforces_capacity(){let now=SystemTime::now();let mut r=DeviceRegistry::new(Duration::from_secs(300),2);let old=r.observe(observation(now,"00:00:00:00:00:01","192.168.1.1"));r.observe(observation(now+Duration::from_secs(1),"00:00:00:00:00:02","192.168.1.2"));r.observe(observation(now+Duration::from_secs(2),"00:00:00:00:00:03","192.168.1.3"));assert_eq!(r.len(),2);assert!(r.get(&old).is_none());}
}
