#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod capture;
mod intelligence;
mod device_intelligence;
mod settings;

use capture::{CaptureController, CaptureInterface};
use serde::{Deserialize, Serialize};
use settings::{AppSettings, SettingsStore};
use std::process::Command;
use std::sync::Arc;
use tauri::State;

#[derive(Clone, Serialize)]
struct NetworkState {
    connected: bool,
    interface: String,
    local_ip: Option<String>,
    gateway: Option<String>,
    capture_interface: Option<String>,
    capture_available: bool,
}

#[derive(Clone, Serialize)]
struct Device { ip: String, mac: String, hostname: Option<String>, vendor: String, status: String }

#[derive(Clone, Serialize, Default)]
struct CaptureState { active: bool, packets: u64, dropped: u64 }

#[derive(Clone, Serialize, Deserialize)]
struct ProcessConnection { process: String, pid: u32, protocol: String, local_address: String, remote_address: String, state: String }

struct AppState { capture: Arc<CaptureController>, settings: SettingsStore }
impl Default for AppState { fn default() -> Self { Self { capture: Arc::new(CaptureController::default()), settings: SettingsStore::default() } } }

#[tauri::command]
fn network_state() -> NetworkState {
    #[cfg(target_os = "windows")]
    {
        let script = r#"$c=Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object {$_.IPv4DefaultGateway -and $_.IPv4Address} | Select-Object -First 1; if($c){$ip=$c.IPv4Address[0].IPAddress; $gw=$c.IPv4DefaultGateway.NextHop; $a=Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object {$_.ifIndex -eq $c.InterfaceIndex} | Select-Object -First 1; [PSCustomObject]@{ip=$ip;gateway=$gw;alias=$a.Name}|ConvertTo-Json -Compress}else{'{}'}"#;
        let value = Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", script]).output().ok()
            .and_then(|o| serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&o.stdout).trim().to_string()).ok())
            .unwrap_or(serde_json::json!({}));
        let local_ip = value.get("ip").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_owned);
        let gateway = value.get("gateway").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_owned);
        let capture_interface = capture::default_interface();
        return NetworkState { connected: local_ip.is_some(), interface: value.get("alias").and_then(|v| v.as_str()).unwrap_or("Windows network adapter").to_string(), local_ip, gateway, capture_interface, capture_available: true };
    }
    #[allow(unreachable_code)]
    NetworkState { connected: false, interface: "Unknown".into(), local_ip: None, gateway: None, capture_interface: None, capture_available: false }
}

#[tauri::command]
fn discover_devices() -> Vec<Device> {
    #[cfg(target_os = "windows")]
    {
        let script = r#"$c=Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object {$_.IPv4DefaultGateway -and $_.IPv4Address} | Select-Object -First 1; if(!$c){'[]'; exit}; $local=$c.IPv4Address[0].IPAddress; $neighbors=Get-NetNeighbor -InterfaceIndex $c.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.LinkLayerAddress -and $_.State -eq 'Reachable' -and $_.IPAddress -ne $local -and $_.IPAddress -notmatch '^(0|224|239|255)\.'}; $rows=@($neighbors|ForEach-Object {[PSCustomObject]@{ip=$_.IPAddress;mac=($_.LinkLayerAddress -replace '-',':').ToUpper();status='Online'}}); if($rows.Count -eq 0){'[]'}else{$rows|Sort-Object ip -Unique|ConvertTo-Json -Compress}"#;
        let output = Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", script]).output().ok();
        let text = output.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
        if text.is_empty() { return Vec::new(); }
        let value = serde_json::from_str::<serde_json::Value>(&text).unwrap_or(serde_json::Value::Array(Vec::new()));
        let rows = match value { serde_json::Value::Array(v) => v, other => vec![other] };
        return rows.into_iter().filter_map(|v| {
            let ip = v.get("ip")?.as_str()?.to_string();
            let mac = v.get("mac")?.as_str()?.to_string();
            let vendor = vendor_from_mac(&mac);
            Some(Device { ip, mac, hostname: None, vendor, status: "Online".into() })
        }).collect();
    }
    #[allow(unreachable_code)] Vec::new()
}

fn vendor_from_mac(mac: &str) -> String {
    let oui = mac.replace(':', "").to_ascii_uppercase();
    match oui.get(0..6) {
        Some("3C5A37") | Some("AC37EF") | Some("D8BB2C") => "Samsung".into(),
        Some("001A11") | Some("3C5AB4") | Some("F0B479") => "Google".into(),
        Some("001C42") | Some("0025BC") => "Apple".into(),
        Some("28CD1C") | Some("8C8590") => "Xiaomi".into(),
        Some("A4B197") | Some("B4D5BD") => "Intel".into(),
        _ => "Unknown".into(),
    }
}

#[tauri::command]
fn process_connections() -> Result<Vec<ProcessConnection>, String> {
    #[cfg(target_os = "windows")]
    {
        let script = r#"$rows=@(Get-NetTCPConnection -ErrorAction SilentlyContinue|Where-Object {$_.RemoteAddress -and $_.RemoteAddress -notin @('0.0.0.0','::','127.0.0.1','::1')}|ForEach-Object {$p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue;if($p){[PSCustomObject]@{process=$p.ProcessName;pid=[int]$_.OwningProcess;protocol='TCP';local_address=\"$($_.LocalAddress):$($_.LocalPort)\";remote_address=\"$($_.RemoteAddress):$($_.RemotePort)\";state=\"$($_.State)\"}}});$rows|ConvertTo-Json -Compress"#;
        let output=Command::new("powershell").args(["-NoProfile","-NonInteractive","-Command",script]).output().map_err(|e|e.to_string())?;
        if !output.status.success(){return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());}
        let text=String::from_utf8_lossy(&output.stdout).trim().to_string();
        if text.is_empty(){return Ok(Vec::new());}
        let value:serde_json::Value=serde_json::from_str(&text).map_err(|e|format!("Process connection data invalid: {e}"))?;
        let items=match value{serde_json::Value::Array(items)=>items,other=>vec![other]};
        return Ok(items.into_iter().filter_map(|v|serde_json::from_value(v).ok()).collect());
    }
    #[allow(unreachable_code)] Err("Local process mapping is currently Windows-only.".into())
}

#[tauri::command]
fn correlate_connection(device_ip:String, process:Option<String>, pid:Option<u32>, remote_address:String, service:String, confidence:u8) -> device_intelligence::DeviceCorrelation {
    device_intelligence::correlate(&device_ip, process.as_deref(), pid, &remote_address, &service, confidence)
}

#[tauri::command] fn list_capture_interfaces()->Result<Vec<CaptureInterface>,String>{capture::list_interfaces()}
#[tauri::command] fn get_settings(state:State<AppState>)->AppSettings{state.settings.get()}
#[tauri::command] fn set_settings(settings:AppSettings,state:State<AppState>)->AppSettings{state.settings.set(settings)}
#[tauri::command] fn start_capture(interface:Option<String>,app:tauri::AppHandle,state:State<AppState>)->Result<(),String>{let chosen=interface.or_else(||state.settings.get().capture_interface);capture::start(app,state.capture.clone(),chosen)}
#[tauri::command] fn stop_capture(state:State<AppState>)->bool{state.capture.stop();true}
#[tauri::command] fn capture_status(state:State<AppState>)->CaptureState{CaptureState{active:state.capture.running.load(std::sync::atomic::Ordering::Relaxed),packets:*state.capture.packets.lock().unwrap(),dropped:*state.capture.dropped.lock().unwrap()}}

fn main(){tauri::Builder::default().manage(AppState::default()).invoke_handler(tauri::generate_handler![network_state,discover_devices,process_connections,correlate_connection,list_capture_interfaces,get_settings,set_settings,start_capture,stop_capture,capture_status]).run(tauri::generate_context!()).expect("error while running NETSIGHT");}
