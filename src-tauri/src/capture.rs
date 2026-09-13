use crate::intelligence;
use libloading::Library;
use serde::Serialize;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex};
use std::thread;
use tauri::{AppHandle, Emitter};

#[repr(C)]
struct PcapIf { next: *mut PcapIf, name: *mut c_char, description: *mut c_char, addresses: *mut c_void, flags: u32 }
#[repr(C)]
struct PcapPkthdr { ts_sec: i64, ts_usec: i64, caplen: u32, len: u32 }

type FindAllDevs = unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int;
type FreeAllDevs = unsafe extern "C" fn(*mut PcapIf);
type OpenLive = unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut c_void;
type NextEx = unsafe extern "C" fn(*mut c_void, *mut *const PcapPkthdr, *mut *const u8) -> c_int;
type Close = unsafe extern "C" fn(*mut c_void);
type Datalink = unsafe extern "C" fn(*mut c_void) -> c_int;
type PcapFns = (FindAllDevs, FreeAllDevs, OpenLive, NextEx, Close, Datalink);

const DLT_NULL: c_int = 0;
const DLT_EN10MB: c_int = 1;
const DLT_RAW: c_int = 12;

#[derive(Clone, Serialize)]
pub struct CaptureInterface { pub name: String, pub description: Option<String> }

#[derive(Clone, Serialize)]
pub struct PacketEvent {
    pub timestamp: String,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub size: u32,
    pub service: String,
    pub confidence: u8,
}

pub struct CaptureController {
    pub running: Arc<AtomicBool>,
    pub packets: Arc<Mutex<u64>>,
    pub dropped: Arc<Mutex<u64>>,
}

impl Default for CaptureController {
    fn default() -> Self {
        Self { running: Arc::new(AtomicBool::new(false)), packets: Arc::new(Mutex::new(0)), dropped: Arc::new(Mutex::new(0)) }
    }
}

impl CaptureController { pub fn stop(&self) { self.running.store(false, Ordering::Relaxed); } }

fn load() -> Result<(Library, PcapFns), String> {
    #[cfg(target_os = "windows")]
    {
        let lib = unsafe { Library::new("wpcap.dll") }
            .map_err(|e| format!("Npcap/wpcap.dll not available: {e}"))?;
        let f = unsafe {
            (
                *lib.get::<FindAllDevs>(b"pcap_findalldevs\0").map_err(|e| e.to_string())?,
                *lib.get::<FreeAllDevs>(b"pcap_freealldevs\0").map_err(|e| e.to_string())?,
                *lib.get::<OpenLive>(b"pcap_open_live\0").map_err(|e| e.to_string())?,
                *lib.get::<NextEx>(b"pcap_next_ex\0").map_err(|e| e.to_string())?,
                *lib.get::<Close>(b"pcap_close\0").map_err(|e| e.to_string())?,
                *lib.get::<Datalink>(b"pcap_datalink\0").map_err(|e| e.to_string())?,
            )
        };
        Ok((lib, f))
    }
    #[cfg(not(target_os = "windows"))]
    { Err("Packet capture is currently Windows-only.".into()) }
}

pub fn list_interfaces() -> Result<Vec<CaptureInterface>, String> {
    let (_lib, (find, free, _, _, _, _)) = load()?;
    let mut list = std::ptr::null_mut();
    let mut err = [0i8; 256];
    if unsafe { find(&mut list, err.as_mut_ptr()) } != 0 { return Err(cstr(err.as_ptr())); }
    let mut out = Vec::new();
    let mut cur = list;
    while !cur.is_null() {
        unsafe {
            let name = if (*cur).name.is_null() { String::new() } else { CStr::from_ptr((*cur).name).to_string_lossy().into_owned() };
            let description = if (*cur).description.is_null() { None } else { Some(CStr::from_ptr((*cur).description).to_string_lossy().into_owned()) };
            out.push(CaptureInterface { name, description });
            cur = (*cur).next;
        }
    }
    unsafe { free(list) };
    Ok(out)
}

pub fn start(app: AppHandle, controller: Arc<CaptureController>, interface: Option<String>) -> Result<(), String> {
    if controller.running.swap(true, Ordering::SeqCst) { return Ok(()); }
    let interface = interface
        .or_else(default_interface)
        .or_else(|| list_interfaces().ok().and_then(|v| v.into_iter().find(|i| i.name.contains("NPF")).map(|i| i.name)))
        .ok_or_else(|| "No active Npcap capture interface found. Check that Npcap is installed and your network adapter is enabled.".to_string())?;
    let running = controller.running.clone();
    let packets = controller.packets.clone();
    let dropped = controller.dropped.clone();
    thread::spawn(move || {
        let result = capture_loop(&app, &interface, running.clone(), packets, dropped);
        if let Err(message) = result { let _ = app.emit("capture:error", serde_json::json!({ "message": message })); }
        running.store(false, Ordering::Relaxed);
        let _ = app.emit("capture:state", serde_json::json!({ "active": false }));
    });
    Ok(())
}

fn default_interface() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        let script = r#"$c=Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object {$_.IPv4DefaultGateway -and $_.IPv4Address} | Select-Object -First 1; if($c){$a=Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object {$_.ifIndex -eq $c.InterfaceIndex} | Select-Object -First 1; if($a){$a.InterfaceGuid}}"#;
        let guid = Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", script]).output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().trim_matches('{').trim_matches('}').to_string())
            .filter(|s| !s.is_empty())?;
        let needle = guid.to_ascii_lowercase();
        return list_interfaces().ok()?.into_iter().find(|i| i.name.to_ascii_lowercase().contains(&needle)).map(|i| i.name);
    }
    #[allow(unreachable_code)] None
}

fn capture_loop(app: &AppHandle, interface: &str, running: Arc<AtomicBool>, packets: Arc<Mutex<u64>>, dropped: Arc<Mutex<u64>>) -> Result<(), String> {
    let (_lib, (_, _, open, next, close, datalink)) = load()?;
    let name = CString::new(interface).map_err(|_| "Invalid capture interface name".to_string())?;
    let mut err = [0i8; 256];
    let handle = unsafe { open(name.as_ptr(), 65535, 1, 100, err.as_mut_ptr()) };
    if handle.is_null() { return Err(cstr(err.as_ptr())); }
    let linktype = unsafe { datalink(handle) };
    if !matches!(linktype, DLT_EN10MB | DLT_RAW | DLT_NULL) {
        unsafe { close(handle) };
        return Err(format!("Unsupported capture link type {linktype}. Select the active Wi-Fi/Ethernet adapter in Settings."));
    }
    let mut hdr = std::ptr::null();
    let mut data = std::ptr::null();
    let _ = app.emit("capture:state", serde_json::json!({ "active": true, "interface": interface }));
    while running.load(Ordering::Relaxed) {
        let rc = unsafe { next(handle, &mut hdr, &mut data) };
        if rc == 1 && !hdr.is_null() && !data.is_null() {
            let h = unsafe { &*hdr };
            let bytes = unsafe { std::slice::from_raw_parts(data, h.caplen as usize) };
            if let Some(event) = parse_packet_link(bytes, h.len, h.ts_sec, h.ts_usec, linktype) {
                if let Ok(mut n) = packets.lock() { *n += 1; }
                let _ = app.emit("capture:packet", event);
            }
        } else if rc < 0 {
            if let Ok(mut n) = dropped.lock() { *n += 1; }
            break;
        }
    }
    unsafe { close(handle) };
    Ok(())
}

fn parse_packet(b: &[u8], size: u32, ts_sec: i64, ts_usec: i64) -> Option<PacketEvent> {
    parse_packet_link(b, size, ts_sec, ts_usec, DLT_EN10MB)
}

fn parse_packet_link(b: &[u8], size: u32, ts_sec: i64, ts_usec: i64, linktype: c_int) -> Option<PacketEvent> {
    let (network_offset, ethertype) = match linktype {
        DLT_EN10MB => ethernet_network_offset(b)?,
        DLT_RAW => (0usize, 0x0800u16),
        DLT_NULL => {
            if b.len() < 4 { return None; }
            (4usize, 0x0800u16)
        }
        _ => return None,
    };
    if ethertype != 0x0800 || b.len() < network_offset + 20 { return None; }
    let ip = network_offset;
    let ihl = ((b[ip] & 0x0f) as usize) * 4;
    if (b[ip] >> 4) != 4 || ihl < 20 || b.len() < ip + ihl { return None; }
    let src = format!("{}.{}.{}.{}", b[ip + 12], b[ip + 13], b[ip + 14], b[ip + 15]);
    let dst = format!("{}.{}.{}.{}", b[ip + 16], b[ip + 17], b[ip + 18], b[ip + 19]);
    let proto = b[ip + 9];
    let protocol = match proto { 6 => "TCP", 17 => "UDP", 1 => "ICMP", _ => "IP" }.to_string();
    let mut service = "Unknown".to_string();
    let mut confidence = 0u8;
    let l4 = ip + ihl;
    if (proto == 6 || proto == 17) && b.len() >= l4 + 4 {
        let sp = u16::from_be_bytes([b[l4], b[l4 + 1]]);
        let dp = u16::from_be_bytes([b[l4 + 2], b[l4 + 3]]);
        let port = if dp != 0 { dp } else { sp };
        let base = intelligence::port(port, if proto == 6 { "TCP" } else { "UDP" });
        service = base.service.into();
        confidence = base.confidence;
        if port == 53 && proto == 17 && b.len() >= l4 + 8 {
            if let Some(domain) = dns_name(&b[l4 + 8..]) {
                let d = intelligence::domain(&domain);
                service = d.service.into();
                confidence = d.confidence;
            }
        }
        if proto == 6 && port == 443 {
            let tcp_hlen = if b.len() >= l4 + 13 { ((b[l4 + 12] >> 4) as usize) * 4 } else { 0 };
            if tcp_hlen >= 20 && b.len() >= l4 + tcp_hlen {
                if let Some(domain) = tls_sni(&b[l4 + tcp_hlen..]) {
                    let d = intelligence::domain(&domain);
                    service = d.service.into();
                    confidence = d.confidence;
                }
            }
        }
        if service == "Unknown" { if let Some(hint) = intelligence::ip_hint(&dst) { service = hint.service.into(); confidence = hint.confidence; } }
    }
    Some(PacketEvent { timestamp: format_timestamp(ts_sec, ts_usec), source: src, destination: dst, protocol, size, service, confidence })
}

fn ethernet_network_offset(data: &[u8]) -> Option<(usize, u16)> {
    if data.len() < 14 { return None; }
    let mut offset = 14usize;
    let mut ether = u16::from_be_bytes([data[12], data[13]]);
    while matches!(ether, 0x8100 | 0x88a8 | 0x9100) {
        if data.len() < offset + 4 { return None; }
        ether = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
    }
    Some((offset, ether))
}

fn dns_name(data: &[u8]) -> Option<String> {
    if data.len() < 13 { return None; }
    let mut pos = 12usize;
    let mut labels = Vec::new();
    for _ in 0..32 {
        let n = *data.get(pos)? as usize;
        pos += 1;
        if n == 0 { break; }
        if n & 0xc0 != 0 || n > 63 || pos + n > data.len() { return None; }
        labels.push(std::str::from_utf8(&data[pos..pos + n]).ok()?.to_string());
        pos += n;
    }
    if labels.is_empty() { None } else { Some(labels.join(".")) }
}

fn tls_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 || data[0] != 0x16 { return None; }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let end = data.len().min(5 + record_len).min(16384);
    if end < 9 || data[5] != 0x01 { return None; }
    let hello_len = ((data[6] as usize) << 16) | ((data[7] as usize) << 8) | data[8] as usize;
    let hello_end = (9 + hello_len).min(end);
    let mut p = 9usize;
    if p + 2 + 32 + 1 > hello_end { return None; }
    p += 2 + 32;
    let session_len = data[p] as usize; p += 1 + session_len;
    if p + 2 > hello_end { return None; }
    let cipher_len = u16::from_be_bytes([data[p], data[p + 1]]) as usize; p += 2 + cipher_len;
    if p + 1 > hello_end { return None; }
    let compression_len = data[p] as usize; p += 1 + compression_len;
    if p + 2 > hello_end { return None; }
    let extensions_len = u16::from_be_bytes([data[p], data[p + 1]]) as usize; p += 2;
    let ext_end = (p + extensions_len).min(hello_end);
    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
        let ext_len = u16::from_be_bytes([data[p + 2], data[p + 3]]) as usize;
        p += 4;
        if p + ext_len > ext_end { return None; }
        if ext_type == 0 && ext_len >= 5 {
            let list_len = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
            let mut q = p + 2;
            let list_end = (q + list_len).min(p + ext_len);
            while q + 3 <= list_end {
                let name_type = data[q];
                let name_len = u16::from_be_bytes([data[q + 1], data[q + 2]]) as usize;
                q += 3;
                if q + name_len > list_end { return None; }
                if name_type == 0 {
                    let name = std::str::from_utf8(&data[q..q + name_len]).ok()?;
                    if name.contains('.') && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') { return Some(name.to_ascii_lowercase()); }
                }
                q += name_len;
            }
        }
        p += ext_len;
    }
    None
}

fn cstr(p: *const c_char) -> String { if p.is_null() { "Unknown Npcap error".into() } else { unsafe { CStr::from_ptr(p).to_string_lossy().into_owned() } } }
fn format_timestamp(sec: i64, usec: i64) -> String { let millis = sec.saturating_mul(1000).saturating_add(usec / 1000); millis.to_string() }

#[cfg(test)]
mod capture_tests;

#[cfg(target_os = "windows")]
use std::process::Command;
