use crate::{intelligence, packet_decoder};
use libloading::Library;
use serde::Serialize;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex};
use std::thread;
use tauri::{AppHandle, Emitter};

#[repr(C)] struct PcapIf { next: *mut PcapIf, name: *mut c_char, description: *mut c_char, addresses: *mut c_void, flags: u32 }
#[repr(C)] struct PcapPkthdr { ts_sec: i64, ts_usec: i64, caplen: u32, len: u32 }
type FindAllDevs = unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int;
type FreeAllDevs = unsafe extern "C" fn(*mut PcapIf);
type OpenLive = unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut c_void;
type NextEx = unsafe extern "C" fn(*mut c_void, *mut *const PcapPkthdr, *mut *const u8) -> c_int;
type Close = unsafe extern "C" fn(*mut c_void);
type PcapFns = (FindAllDevs, FreeAllDevs, OpenLive, NextEx, Close);

#[derive(Clone, Serialize)] pub struct CaptureInterface { pub name: String, pub description: Option<String> }
#[derive(Clone, Serialize)] pub struct PacketEvent { pub timestamp: String, pub source: String, pub destination: String, pub protocol: String, pub size: u32, pub service: String, pub confidence: u8, pub source_port: Option<u16>, pub destination_port: Option<u16>, pub info: String }
pub struct CaptureController { pub running: Arc<AtomicBool>, pub packets: Arc<Mutex<u64>>, pub dropped: Arc<Mutex<u64>> }
impl Default for CaptureController { fn default() -> Self { Self { running: Arc::new(AtomicBool::new(false)), packets: Arc::new(Mutex::new(0)), dropped: Arc::new(Mutex::new(0)) } } }
impl CaptureController { pub fn stop(&self) { self.running.store(false, Ordering::SeqCst); } }

fn load() -> Result<(Library, PcapFns), String> {
    #[cfg(target_os = "windows")]
    { let lib = unsafe { Library::new("wpcap.dll") }.map_err(|e| format!("Npcap packet capture is unavailable (wpcap.dll): {e}"))?; let f = unsafe { (*lib.get::<FindAllDevs>(b"pcap_findalldevs\0").map_err(|e|e.to_string())?, *lib.get::<FreeAllDevs>(b"pcap_freealldevs\0").map_err(|e|e.to_string())?, *lib.get::<OpenLive>(b"pcap_open_live\0").map_err(|e|e.to_string())?, *lib.get::<NextEx>(b"pcap_next_ex\0").map_err(|e|e.to_string())?, *lib.get::<Close>(b"pcap_close\0").map_err(|e|e.to_string())?) }; Ok((lib,f)) }
    #[cfg(not(target_os = "windows"))] { Err("Packet capture is currently Windows-only.".into()) }
}

pub fn list_interfaces() -> Result<Vec<CaptureInterface>, String> {
    let (_lib,(find,free,_,_,_))=load()?; let mut list=std::ptr::null_mut(); let mut err=[0i8;256]; if unsafe{find(&mut list,err.as_mut_ptr())}!=0{return Err(cstr(err.as_ptr()));}
    let mut out=Vec::new(); let mut cur=list; while !cur.is_null(){unsafe{let name=if (*cur).name.is_null(){String::new()}else{CStr::from_ptr((*cur).name).to_string_lossy().into_owned()}; let description=if (*cur).description.is_null(){None}else{Some(CStr::from_ptr((*cur).description).to_string_lossy().into_owned())}; if !name.is_empty(){out.push(CaptureInterface{name,description});} cur=(*cur).next;}} unsafe{free(list)}; Ok(out)
}

pub fn start(app: AppHandle, controller: Arc<CaptureController>, interface: Option<String>) -> Result<(), String> {
    if controller.running.swap(true,Ordering::SeqCst){return Ok(());}
    let interface = match interface.or_else(||list_interfaces().ok().and_then(|v|v.into_iter().find(|i|!i.name.is_empty()).map(|i|i.name))) { Some(v)=>v, None=>{controller.running.store(false,Ordering::SeqCst); return Err("No Npcap capture interface found. Install Npcap and restart NETSIGHT.".into());} };
    let running=controller.running.clone(); let packets=controller.packets.clone(); let dropped=controller.dropped.clone();
    thread::spawn(move||{let result=capture_loop(&app,&interface,running.clone(),packets,dropped); if let Err(message)=result{let _=app.emit("capture:error",serde_json::json!({"message":message}));} running.store(false,Ordering::SeqCst); let _=app.emit("capture:state",serde_json::json!({"active":false}));}); Ok(())
}

fn capture_loop(app:&AppHandle,interface:&str,running:Arc<AtomicBool>,packets:Arc<Mutex<u64>>,dropped:Arc<Mutex<u64>>)->Result<(),String>{
    let (_lib,(_,_,open,next,close))=load()?; let name=CString::new(interface).map_err(|_|"Invalid capture interface name".to_string())?; let mut err=[0i8;256]; let handle=unsafe{open(name.as_ptr(),65535,1,250,err.as_mut_ptr())}; if handle.is_null(){return Err(format!("Could not open capture interface: {}",cstr(err.as_ptr())));} let mut hdr=std::ptr::null(); let mut data=std::ptr::null(); let _=app.emit("capture:state",serde_json::json!({"active":true,"interface":interface}));
    while running.load(Ordering::Relaxed){let rc=unsafe{next(handle,&mut hdr,&mut data)}; if rc==1&&!hdr.is_null()&&!data.is_null(){let h=unsafe{&*hdr}; let bytes=unsafe{std::slice::from_raw_parts(data,h.caplen as usize)}; if let Some(event)=parse_packet(bytes,h.ts_sec,h.ts_usec,h.len){if let Ok(mut n)=packets.lock(){*n+=1;} let _=app.emit("capture:packet",event);}}else if rc==0{continue}else if rc<0{if let Ok(mut n)=dropped.lock(){*n+=1;}break;}}
    unsafe{close(handle)}; Ok(())
}

fn parse_packet(b:&[u8],ts_sec:i64,ts_usec:i64,size:u32)->Option<PacketEvent>{
    let decoded=packet_decoder::decode(b,size)?; let mut service=decoded.service_hint.clone().unwrap_or_else(||"Unknown".into()); let mut confidence=decoded.service_hint.as_ref().map(|_|90).unwrap_or(0);
    if service=="Unknown" { if let Some(d)=intelligence::ip_hint(&decoded.destination){service=d.service.into();confidence=d.confidence;} }
    Some(PacketEvent{timestamp:format_timestamp(ts_sec,ts_usec),source:decoded.source,destination:decoded.destination,protocol:decoded.protocol,size:decoded.length,service,confidence,source_port:decoded.source_port,destination_port:decoded.destination_port,info:decoded.info})
}

fn cstr(p:*const c_char)->String{if p.is_null(){"Unknown Npcap error".into()}else{unsafe{CStr::from_ptr(p).to_string_lossy().into_owned()}}}
fn format_timestamp(sec:i64,usec:i64)->String{let micros=usec.max(0) as u64; let total=sec.max(0) as u64; let h=(total/3600)%24;let m=(total/60)%60;let s=total%60;format!("{h:02}:{m:02}:{s:02}.{:06}",micros)}
