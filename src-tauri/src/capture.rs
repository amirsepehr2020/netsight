use crate::intelligence;
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
#[derive(Clone, Serialize)] pub struct PacketEvent { pub timestamp: String, pub source: String, pub destination: String, pub protocol: String, pub size: u32, pub service: String, pub confidence: u8 }
pub struct CaptureController { pub running: Arc<AtomicBool>, pub packets: Arc<Mutex<u64>>, pub dropped: Arc<Mutex<u64>> }
impl Default for CaptureController { fn default() -> Self { Self { running: Arc::new(AtomicBool::new(false)), packets: Arc::new(Mutex::new(0)), dropped: Arc::new(Mutex::new(0)) } } }
impl CaptureController { pub fn stop(&self) { self.running.store(false, Ordering::Relaxed); } }

fn load() -> Result<(Library, PcapFns), String> {
    #[cfg(target_os = "windows")]
    {
        let lib = unsafe { Library::new("wpcap.dll") }.map_err(|e| format!("Npcap/wpcap.dll not available: {e}"))?;
        let f = unsafe {
            (*lib.get::<FindAllDevs>(b"pcap_findalldevs\0").map_err(|e|e.to_string())?, *lib.get::<FreeAllDevs>(b"pcap_freealldevs\0").map_err(|e|e.to_string())?, *lib.get::<OpenLive>(b"pcap_open_live\0").map_err(|e|e.to_string())?, *lib.get::<NextEx>(b"pcap_next_ex\0").map_err(|e|e.to_string())?, *lib.get::<Close>(b"pcap_close\0").map_err(|e|e.to_string())?)
        };
        Ok((lib,f))
    }
    #[cfg(not(target_os = "windows"))] { Err("Packet capture is currently Windows-only.".into()) }
}

pub fn list_interfaces() -> Result<Vec<CaptureInterface>, String> {
    let (_lib,(find,free,_,_,_))=load()?; let mut list=std::ptr::null_mut(); let mut err=[0i8;256]; if unsafe{find(&mut list,err.as_mut_ptr())}!=0{return Err(cstr(err.as_ptr()));}
    let mut out=Vec::new(); let mut cur=list; while !cur.is_null(){unsafe{let name=if (*cur).name.is_null(){String::new()}else{CStr::from_ptr((*cur).name).to_string_lossy().into_owned()}; let description=if (*cur).description.is_null(){None}else{Some(CStr::from_ptr((*cur).description).to_string_lossy().into_owned())}; out.push(CaptureInterface{name,description}); cur=(*cur).next;}} unsafe{free(list)}; Ok(out)
}

pub fn start(app: AppHandle, controller: Arc<CaptureController>, interface: Option<String>) -> Result<(), String> {
    if controller.running.swap(true,Ordering::SeqCst){return Ok(());} let interface=interface.or_else(||list_interfaces().ok().and_then(|v|v.into_iter().find(|i|!i.name.is_empty()).map(|i|i.name))).ok_or("No Npcap capture interface found")?; let running=controller.running.clone(); let packets=controller.packets.clone(); let dropped=controller.dropped.clone();
    thread::spawn(move||{let result=capture_loop(&app,&interface,running.clone(),packets,dropped); if let Err(message)=result{let _=app.emit("capture:error",serde_json::json!({"message":message}));} running.store(false,Ordering::Relaxed); let _=app.emit("capture:state",serde_json::json!({"active":false}));}); Ok(())
}

fn capture_loop(app:&AppHandle,interface:&str,running:Arc<AtomicBool>,packets:Arc<Mutex<u64>>,dropped:Arc<Mutex<u64>>)->Result<(),String>{
    let (_lib,(_,_,open,next,close))=load()?; let name=CString::new(interface).map_err(|_|"Invalid capture interface name".to_string())?; let mut err=[0i8;256]; let handle=unsafe{open(name.as_ptr(),65535,1,250,err.as_mut_ptr())}; if handle.is_null(){return Err(cstr(err.as_ptr()));} let mut hdr=std::ptr::null(); let mut data=std::ptr::null(); let _=app.emit("capture:state",serde_json::json!({"active":true,"interface":interface}));
    while running.load(Ordering::Relaxed){let rc=unsafe{next(handle,&mut hdr,&mut data)}; if rc==1&&!hdr.is_null()&&!data.is_null(){let h=unsafe{&*hdr}; let bytes=unsafe{std::slice::from_raw_parts(data,h.caplen as usize)}; if let Some(event)=parse_packet(bytes,h.len){if let Ok(mut n)=packets.lock(){*n+=1;} let _=app.emit("capture:packet",event);}}else if rc<0{if let Ok(mut n)=dropped.lock(){*n+=1;}break;}}
    unsafe{close(handle)}; Ok(())
}

fn parse_packet(b:&[u8],size:u32)->Option<PacketEvent>{
    if b.len()<34{return None;} let ethertype=u16::from_be_bytes([b[12],b[13]]); if ethertype!=0x0800{return None;} let ihl=((b[14]&0x0f)as usize)*4; if ihl<20||b.len()<14+ihl{return None;} let src=format!("{}.{}.{}.{}",b[26],b[27],b[28],b[29]); let dst=format!("{}.{}.{}.{}",b[30],b[31],b[32],b[33]); let proto=b[23]; let protocol=match proto{6=>"TCP",17=>"UDP",1=>"ICMP",_=>"IP"}.to_string(); let mut service="Unknown".to_string(); let mut confidence=0u8; let l4=14+ihl;
    if(proto==6||proto==17)&&b.len()>=l4+4{let sp=u16::from_be_bytes([b[l4],b[l4+1]]);let dp=u16::from_be_bytes([b[l4+2],b[l4+3]]);let port=if dp!=0{dp}else{sp}; let base=intelligence::port(port, if proto==6{"TCP"}else{"UDP"}); service=base.service.into(); confidence=base.confidence;
        if port==53&&proto==17{if let Some(domain)=dns_name(&b[l4+8..]){let d=intelligence::domain(&domain);service=d.service.into();confidence=d.confidence;}}
        if port==443&&proto==6{if let Some(domain)=tls_sni(&b[l4+20..]){let d=intelligence::domain(&domain);service=d.service.into();confidence=d.confidence;}}
        if service=="Unknown"{if let Some(hint)=intelligence::ip_hint(&dst){service=hint.service.into();confidence=hint.confidence;}}
    }
    Some(PacketEvent{timestamp:timestamp(),source:src,destination:dst,protocol,size,service,confidence})
}

fn dns_name(data:&[u8])->Option<String>{if data.len()<13{return None;}let mut pos=12;let mut labels=Vec::new();for _ in 0..32{let n=*data.get(pos)?as usize;pos+=1;if n==0{break;}if n&0xc0!=0||n>63||pos+n>data.len(){return None;}labels.push(std::str::from_utf8(&data[pos..pos+n]).ok()?.to_string());pos+=n;}if labels.is_empty(){None}else{Some(labels.join("."))}}
fn tls_sni(data:&[u8])->Option<String>{if data.len()<5||data[0]!=0x16{return None;}let record_len=u16::from_be_bytes([data[3],data[4]])as usize;let end=data.len().min(5+record_len).min(8192);let mut i=5;while i+5<end{if data[i]==0&&data[i+1]==0{let n=u16::from_be_bytes([data[i+2],data[i+3]])as usize;if n>0&&n<256&&i+4+n<=end{if let Ok(s)=std::str::from_utf8(&data[i+4..i+4+n]){if s.contains('.')&&s.chars().all(|c|c.is_ascii_alphanumeric()||c=='.'||c=='-'){return Some(s.to_string());}}}}i+=1;}None}
fn cstr(p:*const c_char)->String{if p.is_null(){"Unknown Npcap error".into()}else{unsafe{CStr::from_ptr(p).to_string_lossy().into_owned()}}}
fn timestamp()->String{use std::time::{SystemTime,UNIX_EPOCH};SystemTime::now().duration_since(UNIX_EPOCH).map(|d|d.as_millis().to_string()).unwrap_or_default()}
