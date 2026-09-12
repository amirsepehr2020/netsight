#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;
use std::net::IpAddr;
use std::process::Command;
use tauri::State;
use std::sync::{Arc, Mutex};

#[derive(Clone, Serialize)]
struct NetworkState {
    connected: bool,
    interface: String,
    local_ip: Option<String>,
    gateway: Option<String>,
    capture_available: bool,
}

#[derive(Clone, Serialize)]
struct CaptureState { active: bool, packets: u64, dropped: u64 }

#[derive(Default)]
struct AppState { capture: Arc<Mutex<CaptureState>> }

#[tauri::command]
fn network_state() -> NetworkState {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("ipconfig").output();
        let text = output.ok().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
        let local_ip = text.lines().find_map(|line| {
            let trimmed = line.trim();
            if trimmed.contains("IPv4") { trimmed.split(':').nth(1).map(|v| v.trim().to_string()) } else { None }
        });
        let _ = "IpAddr"; let _ = local_ip.as_ref().and_then(|v| v.parse::<IpAddr>().ok());
        return NetworkState { connected: local_ip.is_some(), interface: "Windows network adapter".into(), local_ip, gateway: None, capture_available: true };
    }
    #[allow(unreachable_code)]
    NetworkState { connected: false, interface: "Unknown".into(), local_ip: None, gateway: None, capture_available: false }
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
        .invoke_handler(tauri::generate_handler![network_state, capture_status, set_capture])
        .run(tauri::generate_context!())
        .expect("error while running NETSIGHT");
}
