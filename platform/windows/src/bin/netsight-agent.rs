#[cfg(windows)]
mod windows_agent {
    use anyhow::{Context, Result};
    use netsight_core::dashboard::DashboardSnapshot;
    use netsight_core::device::{DeviceObservation, DeviceRegistry};
    use netsight_core::live_timeline::LiveTimeline;
    use netsight_core::model::CaptureState;
    use netsight_core::packet::normalize_ethernet;
    use netsight_core::session::SessionStore;
    use netsight_core::traffic::{FlowKey, TrafficAggregator};
    use netsight_windows::{list_capture_devices, CaptureConfig, CaptureEvent, CaptureSession};
    use std::io::{Read, Write};
    use std::net::{IpAddr, TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, SystemTime};

    const BIND: &str = "127.0.0.1:8765";

    #[derive(Clone)]
    struct Shared {
        snapshot: Arc<Mutex<String>>,
        sessions: Arc<Mutex<SessionStore>>,
    }

    pub fn run() -> Result<()> {
        let devices = list_capture_devices().context("unable to enumerate Npcap devices; install Npcap and grant capture permission")?;
        let device = devices.first().context("no Npcap capture device is available")?.clone();
        let adapter_ips = netsight_windows::discover_network_context().unwrap_or_default().into_iter()
            .flat_map(|a| a.ipv4.into_iter()).filter_map(|v| v.parse::<IpAddr>().ok()).collect::<Vec<_>>();

        let db_path = session_db_path();
        if let Some(parent) = db_path.parent() { std::fs::create_dir_all(parent).context("failed to create NetSight data directory")?; }
        let session_store = SessionStore::open(&db_path).context("failed to open persistent session store")?;
        let session_id = session_store.start(&device.name).context("failed to create capture session")?;
        let shared = Shared {
            snapshot: Arc::new(Mutex::new(DashboardSnapshot::new(CaptureState::Starting, device.name.clone()).to_json()?)),
            sessions: Arc::new(Mutex::new(session_store)),
        };
        start_http_server(shared.clone())?;

        let (session, events) = CaptureSession::start(&device.name, CaptureConfig::default()).context("failed to start Npcap capture")?;
        let mut registry = DeviceRegistry::new(Duration::from_secs(300), 512);
        let mut traffic = TrafficAggregator::new();
        let mut timeline = LiveTimeline::new(Duration::from_secs(120), 5000);
        persist_and_publish(&shared, &session_id, DashboardSnapshot::from_runtime(CaptureState::Running, &device.name, &registry, &traffic, &timeline))?;

        for event in events {
            match event {
                CaptureEvent::Packet(packet) => {
                    if let Ok(normalized) = normalize_ethernet(packet.timestamp_micros, packet.captured_len, packet.original_len, &packet.data) {
                        let (Some(source), Some(destination)) = (normalized.source_ip, normalized.destination_ip) else { continue };
                        let local_source = adapter_ips.contains(&source);
                        let local_destination = adapter_ips.contains(&destination);
                        let device_ip = if local_source { source } else if local_destination { destination } else { source };
                        let id = registry.observe(DeviceObservation::new(SystemTime::now(), device_ip));
                        let protocol = protocol_name(normalized.transport);
                        traffic.record(FlowKey { source, destination, protocol, source_port: normalized.source_port, destination_port: normalized.destination_port }, normalized.captured_len as u64);
                        let service = service_for_port(normalized.destination_port.or(normalized.source_port));
                        registry.record_traffic(&id, normalized.captured_len as u64, local_source);
                        registry.add_service(&id, service);
                        timeline.ingest(&normalized, id, service);
                        persist_and_publish(&shared, &session_id, DashboardSnapshot::from_runtime(CaptureState::Running, &device.name, &registry, &traffic, &timeline))?;
                    }
                }
                CaptureEvent::Error(error) => {
                    persist_and_publish(&shared, &session_id, DashboardSnapshot::from_runtime(CaptureState::Failed, &device.name, &registry, &traffic, &timeline))?;
                    eprintln!("capture error: {error}");
                    break;
                }
                CaptureEvent::Stopped => break,
            }
        }

        session.stop()?;
        persist_and_publish(&shared, &session_id, DashboardSnapshot::from_runtime(CaptureState::Idle, &device.name, &registry, &traffic, &timeline))?;
        let store = shared.sessions.lock().map_err(|_| anyhow::anyhow!("session store lock poisoned"))?;
        store.finish(&session_id)?;
        Ok(())
    }

    fn session_db_path() -> PathBuf {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(local_app_data).join("NetSight").join("sessions.db");
        }
        PathBuf::from("netsight-sessions.db")
    }

    fn protocol_name(protocol: Option<netsight_core::packet::TransportProtocol>) -> String {
        match protocol {
            Some(netsight_core::packet::TransportProtocol::Tcp) => "TCP".into(),
            Some(netsight_core::packet::TransportProtocol::Udp) => "UDP".into(),
            Some(netsight_core::packet::TransportProtocol::Other(n)) => format!("IP/{n}"),
            None => "IP".into(),
        }
    }

    fn service_for_port(port: Option<u16>) -> &'static str {
        match port { Some(53)=>"DNS",Some(80)=>"HTTP",Some(443)=>"HTTPS/TLS",Some(123)=>"NTP",Some(22)=>"SSH",Some(5353)=>"mDNS",_=>"Unknown" }
    }

    fn persist_and_publish(shared: &Shared, session_id: &str, snapshot: DashboardSnapshot) -> Result<()> {
        let json = snapshot.to_json()?;
        let store = shared.sessions.lock().map_err(|_| anyhow::anyhow!("session store lock poisoned"))?;
        store.append_snapshot(session_id, &json)?;
        drop(store);
        *shared.snapshot.lock().map_err(|_| anyhow::anyhow!("dashboard snapshot lock poisoned"))? = json;
        Ok(())
    }

    fn start_http_server(shared:Shared)->Result<()> {
        let listener=TcpListener::bind(BIND).with_context(||format!("failed to bind dashboard bridge at {BIND}"))?;
        thread::Builder::new().name("netsight-dashboard-http".into()).spawn(move||{
            for stream in listener.incoming().flatten(){
                let state=shared.clone();
                let _=thread::spawn(move||{let _=handle_http(stream,state);});
            }
        }).context("failed to start dashboard HTTP worker")?;
        Ok(())
    }

    fn handle_http(mut stream:TcpStream,shared:Shared)->Result<()> {
        let mut request=[0u8;4096];
        let size=stream.read(&mut request)?;
        let request=String::from_utf8_lossy(&request[..size]);
        let path=request.lines().next().and_then(|line|line.split_whitespace().nth(1)).unwrap_or("/");
        let (status,content_type,body)=match path {
            "/api/snapshot" => ("200 OK","application/json",shared.snapshot.lock().map_err(|_| anyhow::anyhow!("snapshot lock poisoned"))?.clone()),
            "/api/sessions" => {
                let sessions=shared.sessions.lock().map_err(|_| anyhow::anyhow!("session store lock poisoned"))?.list()?;
                ("200 OK","application/json",serde_json::to_string(&sessions_json(&sessions))?)
            }
            p if p.starts_with("/api/sessions/") => {
                let id=&p[14..];
                let snapshot=shared.sessions.lock().map_err(|_| anyhow::anyhow!("session store lock poisoned"))?.load_latest_snapshot(id)?;
                match snapshot {
                    Some(body)=>("200 OK","application/json",body),
                    None=>("404 Not Found","application/json","{\"error\":\"session not found\"}".to_string()),
                }
            }
            "/api/health"=>("200 OK","application/json","{\"ok\":true,\"service\":\"netsight-agent\"}".to_string()),
            _=>("404 Not Found","application/json","{\"error\":\"not found\"}".to_string())
        };
        let response=format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.as_bytes().len());
        stream.write_all(response.as_bytes())?;
        Ok(())
    }

    fn sessions_json(sessions: &[netsight_core::session::SessionSummary]) -> Vec<serde_json::Value> {
        sessions.iter().map(|s| serde_json::json!({
            "id": s.id,
            "capture_device": s.capture_device,
            "state": s.state,
            "started_at_ms": s.started_at_ms,
            "finished_at_ms": s.finished_at_ms,
            "snapshot_count": s.snapshot_count,
        })).collect()
    }
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> { windows_agent::run() }

#[cfg(not(windows))]
fn main() { eprintln!("netsight-agent is supported on Windows with Npcap."); }
