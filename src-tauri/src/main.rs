#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tauri::State;

#[derive(Clone, Serialize)]
struct NetworkState {
    connected: bool,
    interface: String,
    local_ip: Option<String>,
    gateway: Option<String>,
    capture_available: bool,
}

#[derive(Clone, Serialize)]
struct Device { ip: String, mac: String, hostname: Option<String>, vendor: String, status: String }

#[derive(Clone, Serialize)]
struct CaptureState { active: bool, packets: u64, dropped: u64 }

#[derive(Default)]
struct AppState { capture: Arc<Mutex<CaptureState>> }

#[tauri::command]
fn network_state() -> NetworkState {
    #[cfg(target_os = "windows")]
    {
        let text = Command::new("ipconfig").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
        let local_ip = text.lines().find_map(|line| {
            let trimmed = line.trim();
            if trimmed.contains("IPv4") { trimmed.split(':').nth(1).map(|v| v.trim().trim_end_matches("(Preferred)").trim().to_string()) } else { None }
        });
        return NetworkState { connected: local_ip.is_some(), interface: "Windows network adapter".into(), local_ip, gateway: None, capture_available: true };
    }
    #[allow(unreachable_code)]
    NetworkState { connected: false, interface: "Unknown".into(), local_ip: None, gateway: None, capture_available: false }
}

#[tauri::command]
fn discover_devices() -> Vec<Device> {
    #[cfg(target_os = "windows")]
    {
        let text = Command::new("arp").arg("-a").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
        return text.lines().filter_map(|line| {
            let p: Vec<&str> = line.split_whitespace().collect();
            if p.len() >= 2 && p[0].parse::<std::net::Ipv4Addr>().is_ok() && p[1].contains('-') {
                Some(Device { ip:p[0].into(), mac:p[1].into(), hostname:None, vendor:"Unknown".into(), status:"Online".into() })
            } else { None }
        }).collect();
    }
    #[allow(unreachable_code)] Vec::new()
}

#[tauri::command]
fn capture_status(state: State<AppState>) -> CaptureState { state.capture.lock().unwrap().clone() }

#[tauri::command]
fn set_capture(active: bool, state: State<AppState>) -> CaptureState {
    let mut current = state.capture.lock().unwrap();
    current.active = active;
    current.clone()
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![network_state, discover_devices, capture_status, set_capture])
        .run(tauri::generate_context!())
        .expect("error while running NETSIGHT");
}
