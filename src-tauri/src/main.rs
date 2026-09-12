#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod capture;
mod intelligence;
mod device_intelligence;
mod settings;

use capture::{CaptureController, CaptureInterface};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::Arc;
use tauri::State;

#[derive(Clone, Serialize)] struct NetworkState { connected: bool, interface: String, local_ip: Option<String>, gateway: Option<String>, capture_available: bool }
#[derive(Clone, Serialize)] struct Device { ip: String, mac: String, hostname: Option<String>, vendor: String, model: Option<String>, status: String }
#[derive(Clone, Serialize, Default)] struct CaptureState { active: bool, packets: u64, dropped: u64 }
#[derive(Clone, Serialize, Deserialize)] struct ProcessConnection { process: String, pid: u32, protocol: String, local_address: String, remote_address: String, state: String }
struct AppState { capture: Arc<CaptureController>, settings: SettingsStore }
impl Default for AppState { fn default() -> Self { Self { capture: Arc::new(CaptureController::default()), settings: SettingsStore::default() } } }

#[tauri::command]
fn network_state() -> NetworkState {
    #[cfg(target_os = "windows")]
    { let text=Command::new("ipconfig").output().ok().map(|o|String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default(); let local_ip=text.lines().find_map(|line|{let t=line.trim();if t.contains("IPv4"){t.split(':').nth(1).map(|v|v.trim().trim_end_matches("(Preferred)").trim().to_string())}else{None}}); let gateway=Command::new("powershell").args(["-NoProfile","-Command","(Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway}).IPv4DefaultGateway.NextHop | Select-Object -First 1"]).output().ok().map(|o|String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|s|!s.is_empty()); return NetworkState{connected:local_ip.is_some(),interface:"Windows network adapter".into(),local_ip,gateway,capture_available:true}; }
    #[allow(unreachable_code)] NetworkState{connected:false,interface:"Unknown".into(),local_ip:None,gateway:None,capture_available:false}
}

#[tauri::command]
fn discover_devices() -> Vec<Device> {
    #[cfg(target_os = "windows")]
    {
        let text=Command::new("arp").arg("-a").output().ok().map(|o|String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
        text.lines().filter_map(|line|{
            let p:Vec<&str>=line.split_whitespace().collect();
            if p.len()<2 || p[0].parse::<std::net::Ipv4Addr>().is_err() || !p[1].contains('-') { return None; }
            let ip=p[0].to_string();
            let mac=p[1].to_string();
            let hostname=resolve_hostname(&ip);
            let vendor=vendor_from_mac(&mac);
            let model=infer_model(hostname.as_deref(), &vendor);
            Some(Device{ip,mac,hostname,vendor,model,status:"Online".into()})
        }).collect()
    }
    #[allow(unreachable_code)] Vec::new()
}

#[cfg(target_os = "windows")]
fn resolve_hostname(ip:&str)->Option<String>{
    let script=format!("try {{ Resolve-DnsName -Name '{}' -Type PTR -ErrorAction Stop | Select-Object -First 1 -ExpandProperty NameHost }} catch {{ }}", ip.replace('\'', "''"));
    let out=Command::new("powershell").args(["-NoProfile","-NonInteractive","-Command",&script]).output().ok()?;
    let name=String::from_utf8_lossy(&out.stdout).trim().trim_end_matches('.').to_string();
    if name.is_empty(){None}else{Some(name)}
}

fn vendor_from_mac(mac:&str)->String{
    let prefix=mac.replace('-',":").to_ascii_uppercase().split(':').take(3).collect::<Vec<_>>().join(":");
    match prefix.as_str(){
        "00:1A:11"|"3C:5A:B4"|"F4:F5:D8"=>"Google".into(),
        "00:50:F2"|"28:18:78"|"7C:ED:8D"=>"Microsoft".into(),
        "3C:22:FB"|"A8:51:AB"|"F0:18:98"=>"Apple".into(),
        "00:16:6C"|"EC:1F:72"|"B4:6B:FC"=>"Samsung".into(),
        "00:E0:4C"|"28:FF:3C"|"7C:10:C9"=>"Realtek".into(),
        "40:16:7E"|"50:C7:BF"|"AC:84:C6"=>"Xiaomi".into(),
        "C8:3A:35"|"CC:32:E5"|"18:3D:A2"=>"Huawei".into(),
        "3C:84:6A"|"80:86:F2"|"A4:4E:31"=>"TP-Link".into(),
        _=>"Unknown".into()
    }
}

fn infer_model(hostname:Option<&str>,vendor:&str)->Option<String>{
    let h=hostname?.trim();
    if h.is_empty(){return None;}
    let lower=h.to_ascii_lowercase();
    if h.starts_with("SM-"){return Some(format!("Samsung {}",h));}
    if lower.starts_with("iphone"){return Some("Apple iPhone".into());}
    if lower.starts_with("ipad"){return Some("Apple iPad".into());}
    if lower.contains("macbook"){return Some("Apple MacBook".into());}
    if lower.contains("pixel"){return Some("Google Pixel".into());}
    if lower.starts_with("redmi"){return Some("Xiaomi Redmi".into());}
    if lower.starts_with("poco"){return Some("POCO".into());}
    if lower.starts_with("mi-")||lower.starts_with("mi "){return Some("Xiaomi Mi".into());}
    if vendor!="Unknown" && h.len()<=40 {return Some(h.to_string());}
    None
}

#[tauri::command]
fn process_connections() -> Result<Vec<ProcessConnection>, String> {
    #[cfg(target_os = "windows")]
    { let script=r#"$rows=@(Get-NetTCPConnection -ErrorAction SilentlyContinue|Where-Object {$_.RemoteAddress -and $_.RemoteAddress -notin @('0.0.0.0','::','127.0.0.1','::1')}|ForEach-Object {$p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue;if($p){[PSCustomObject]@{process=$p.ProcessName;pid=[int]$_.OwningProcess;protocol='TCP';local_address=\"$($_.LocalAddress):$($_.LocalPort)\";remote_address=\"$($_.RemoteAddress):$($_.RemotePort)\";state=\"$($_.State)\"}}});$rows|ConvertTo-Json -Compress"#; let output=Command::new("powershell").args(["-NoProfile","-NonInteractive","-Command",script]).output().map_err(|e|e.to_string())?; if !output.status.success(){return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());} let text=String::from_utf8_lossy(&output.stdout).trim().to_string(); if text.is_empty(){return Ok(Vec::new());} let value:serde_json::Value=serde_json::from_str(&text).map_err(|e|format!("Process connection data invalid: {e}"))?; let items=match value{serde_json::Value::Array(items)=>items,other=>vec![other]}; return Ok(items.into_iter().filter_map(|v|serde_json::from_value(v).ok()).collect()); }
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
