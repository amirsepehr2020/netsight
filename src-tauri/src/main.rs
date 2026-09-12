#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod capture;

use capture::{CaptureController, CaptureInterface};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::Arc;
use tauri::State;

#[derive(Clone, Serialize)]
struct NetworkState { connected: bool, interface: String, local_ip: Option<String>, gateway: Option<String>, capture_available: bool }
#[derive(Clone, Serialize)]
struct Device { ip: String, mac: String, hostname: Option<String>, vendor: String, status: String }
#[derive(Clone, Serialize, Default)]
struct CaptureState { active: bool, packets: u64, dropped: u64 }
#[derive(Clone, Serialize, Deserialize)]
struct ProcessConnection { process: String, pid: u32, protocol: String, local_address: String, remote_address: String, state: String }
struct AppState { capture: Arc<CaptureController> }
impl Default for AppState { fn default() -> Self { Self { capture: Arc::new(CaptureController::default()) } } }

#[tauri::command]
fn network_state() -> NetworkState {
    #[cfg(target_os = "windows")]
    { let text=Command::new("ipconfig").output().ok().map(|o|String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default(); let local_ip=text.lines().find_map(|line|{let t=line.trim();if t.contains("IPv4"){t.split(':').nth(1).map(|v|v.trim().trim_end_matches("(Preferred)").trim().to_string())}else{None}}); let gateway=Command::new("powershell").args(["-NoProfile","-Command","(Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway}).IPv4DefaultGateway.NextHop | Select-Object -First 1"]).output().ok().map(|o|String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|s|!s.is_empty()); return NetworkState{connected:local_ip.is_some(),interface:"Windows network adapter".into(),local_ip,gateway,capture_available:cfg!(target_os="windows")}; }
    #[allow(unreachable_code)] NetworkState{connected:false,interface:"Unknown".into(),local_ip:None,gateway:None,capture_available:false}
}

#[tauri::command]
fn discover_devices() -> Vec<Device> {
    #[cfg(target_os = "windows")]
    { let text=Command::new("arp").arg("-a").output().ok().map(|o|String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default(); return text.lines().filter_map(|line|{let p:Vec<&str>=line.split_whitespace().collect();if p.len()>=2&&p[0].parse::<std::net::Ipv4Addr>().is_ok()&&p[1].contains('-'){Some(Device{ip:p[0].into(),mac:p[1].into(),hostname:None,vendor:"Unknown".into(),status:"Online".into()})}else{None}}).collect(); }
    #[allow(unreachable_code)] Vec::new()
}

#[tauri::command]
fn process_connections() -> Result<Vec<ProcessConnection>, String> {
    #[cfg(target_os = "windows")]
    {
        let script = r#"$rows = @(); Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {$_.RemoteAddress -and $_.RemoteAddress -notin @('0.0.0.0','::','127.0.0.1','::1')} | ForEach-Object { $p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; if($p){$rows += [PSCustomObject]@{process=$p.ProcessName;pid=$_.OwningProcess;protocol='TCP';local_address="$($_.LocalAddress):$($_.LocalPort)";remote_address="$($_.RemoteAddress):$($_.RemotePort)";state="$($_.State)"}} }; $rows | ConvertTo-Json -Compress"#;
        let output=Command::new("powershell").args(["-NoProfile","-NonInteractive","-Command",script]).output().map_err(|e|e.to_string())?;
        if !output.status.success(){return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());}
        let text=String::from_utf8_lossy(&output.stdout).trim().to_string(); if text.is_empty(){return Ok(Vec::new());}
        let value:serde_json::Value=serde_json::from_str(&text).map_err(|e|format!("Process connection data invalid: {e}"))?;
        let items=if value.is_array(){value}else{serde_json::Value::Array(vec![value])};
        return Ok(items.into_iter().filter_map(|v|serde_json::from_value(v).ok()).collect());
    }
    #[allow(unreachable_code)] Err("Local process mapping is currently Windows-only.".into())
}

#[tauri::command] fn list_capture_interfaces()->Result<Vec<CaptureInterface>,String>{capture::list_interfaces()}
#[tauri::command] fn start_capture(interface:Option<String>,app:tauri::AppHandle,state:State<AppState>)->Result<(),String>{capture::start(app,state.capture.clone(),interface)}
#[tauri::command] fn stop_capture(state:State<AppState>)->bool{state.capture.stop();true}
#[tauri::command] fn capture_status(state:State<AppState>)->CaptureState{CaptureState{active:state.capture.running.load(std::sync::atomic::Ordering::Relaxed),packets:*state.capture.packets.lock().unwrap(),dropped:*state.capture.dropped.lock().unwrap()}}

fn main(){tauri::Builder::default().manage(AppState::default()).invoke_handler(tauri::generate_handler![network_state,discover_devices,process_connections,list_capture_interfaces,start_capture,stop_capture,capture_status]).run(tauri::generate_context!()).expect("error while running NETSIGHT");}
