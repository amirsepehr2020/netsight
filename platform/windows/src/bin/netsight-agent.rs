#[cfg(windows)]
mod windows_agent {
    use anyhow::{Context, Result};
    use netsight_core::dashboard::DashboardSnapshot;
    use netsight_core::device::{DeviceObservation, DeviceRegistry};
    use netsight_core::live_timeline::LiveTimeline;
    use netsight_core::model::{CaptureHealth, CaptureState};
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
        health: Arc<Mutex<CaptureHealth>>,
    }

    pub fn list_adapters_json() -> Result<String> {
        let devices = list_capture_devices().context("unable to enumerate Npcap capture devices")?;
        let value: Vec<serde_json::Value> = devices
            .into_iter()
            .map(|d| serde_json::json!({"name": d.name}))
            .collect();
        Ok(serde_json::to_string(&value)?)
    }

    pub fn run() -> Result<()> {
        let devices = list_capture_devices().context("unable to enumerate Npcap devices; install Npcap and grant capture permission")?;
        let requested = std::env::var("NETSIGHT_CAPTURE_DEVICE").ok();
        let device = requested
            .as_deref()
            .and_then(|name| devices.iter().find(|d| d.name == name))
            .or_else(|| devices.first())
            .context("no Npcap capture device is available")?
            .clone();

        let adapter_ips = netsight_windows::discover_network_context()
            .unwrap_or_default()
            .into_iter()
            .flat_map(|a| a.ipv4.into_iter())
            .filter_map(|v| v.parse::<IpAddr>().ok())
            .collect::<Vec<_>>();
        let db_path = session_db_path();
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).context("failed to create NetSight data directory")?;
        }
        let session_store = SessionStore::open(&db_path).context("failed to open persistent session store")?;
        let session_id = session_store.start(&device.name).context("failed to create capture session")?;
        let shared = Shared {
            snapshot: Arc::new(Mutex::new(DashboardSnapshot::new(CaptureState::Starting, device.name.clone()).to_json()?)),
            sessions: Arc::new(Mutex::new(session_store)),
            health: Arc::new(Mutex::new(CaptureHealth { queue_capacity: CaptureConfig::default().queue_capacity as u64, ..Default::default() })),
        };
        start_http_server(shared.clone())?;
        let config = CaptureConfig::default();
        let (session, events) = CaptureSession::start(&device.name, config).context("failed to start Npcap capture")?;
        let mut registry = DeviceRegistry::new(Duration::from_secs(300), 512);
        let mut traffic = TrafficAggregator::new();
        let mut timeline = LiveTimeline::new(Duration::from_secs(120), 5000);
        persist_and_publish(&shared, &session_id, DashboardSnapshot::from_runtime(CaptureState::Running, &device.name, &registry, &traffic, &timeline))?;

        for event in events {
            match event {
                CaptureEvent::Packet(packet) => {
                    let metrics = session.metrics();
                    {
                        let mut h = shared.health.lock().map_err(|_| anyhow::anyhow!("health lock poisoned"))?;
                        h.packets_received = metrics.packets_received;
                        h.packets_dropped = metrics.packets_dropped;
                        h.bytes_received = metrics.bytes_received;
                        h.queue_depth = metrics.queue_depth;
                        h.queue_capacity = metrics.queue_capacity;
                        h.capture_errors = metrics.capture_errors;
                    }
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
        if let Ok(v) = std::env::var("LOCALAPPDATA") { PathBuf::from(v).join("NetSight").join("sessions.db") } else { PathBuf::from("netsight-sessions.db") }
    }
    fn protocol_name(p: Option<netsight_core::packet::TransportProtocol>) -> String {
        match p { Some(netsight_core::packet::TransportProtocol::Tcp) => "TCP".into(), Some(netsight_core::packet::TransportProtocol::Udp) => "UDP".into(), Some(netsight_core::packet::TransportProtocol::Other(n)) => format!("IP/{n}"), None => "IP".into() }
    }
    fn service_for_port(p: Option<u16>) -> &'static str {
        match p { Some(53) => "DNS", Some(80) => "HTTP", Some(443) => "HTTPS/TLS", Some(123) => "NTP", Some(22) => "SSH", Some(5353) => "mDNS", _ => "Unknown" }
    }
    fn persist_and_publish(s: &Shared, id: &str, snap: DashboardSnapshot) -> Result<()> {
        let json = snap.to_json()?;
        s.sessions.lock().map_err(|_| anyhow::anyhow!("session store lock poisoned"))?.append_snapshot(id, &json)?;
        *s.snapshot.lock().map_err(|_| anyhow::anyhow!("snapshot lock poisoned"))? = json;
        Ok(())
    }
    fn start_http_server(s: Shared) -> Result<()> {
        let l = TcpListener::bind(BIND).with_context(|| format!("failed to bind dashboard bridge at {BIND}"))?;
        thread::Builder::new().name("netsight-dashboard-http".into()).spawn(move || {
            for stream in l.incoming().flatten() { let st = s.clone(); let _ = thread::spawn(move || { let _ = handle_http(stream, st); }); }
        }).context("failed to start dashboard HTTP worker")?;
        Ok(())
    }
    fn handle_http(mut stream: TcpStream, s: Shared) -> Result<()> {
        let mut req = [0u8; 4096]; let size = stream.read(&mut req)?; let request = String::from_utf8_lossy(&req[..size]);
        let path = request.lines().next().and_then(|x| x.split_whitespace().nth(1)).unwrap_or("/");
        let (status, ct, body) = match path {
            "/api/snapshot" => ("200 OK", "application/json", s.snapshot.lock().map_err(|_| anyhow::anyhow!("snapshot lock poisoned"))?.clone()),
            "/api/health" => ("200 OK", "application/json", serde_json::json!({"ok":true,"service":"netsight-agent"}).to_string()),
            "/api/diagnostics" => { let h = s.health.lock().map_err(|_| anyhow::anyhow!("health lock poisoned"))?.clone(); ("200 OK", "application/json", serde_json::json!({"health":h,"drop_rate_percent":h.drop_rate_percent(),"queue_utilization_percent":h.queue_utilization_percent()}).to_string()) },
            "/api/sessions" => { let v = s.sessions.lock().map_err(|_| anyhow::anyhow!("session store lock poisoned"))?.list()?; ("200 OK", "application/json", serde_json::to_string(&sessions_json(&v))?) },
            p if p.starts_with("/api/sessions/") => { let id = &p[14..]; match s.sessions.lock().map_err(|_| anyhow::anyhow!("session store lock poisoned"))?.load_latest_snapshot(id)? { Some(v) => ("200 OK", "application/json", v), None => ("404 Not Found", "application/json", "{\"error\":\"session not found\"}".into()) } },
            _ => ("404 Not Found", "application/json", "{\"error\":\"not found\"}".into()),
        };
        let response = format!("HTTP/1.1 {status}\r\nContent-Type: {ct}\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.as_bytes().len());
        stream.write_all(response.as_bytes())?; Ok(())
    }
    fn sessions_json(v: &[netsight_core::session::SessionSummary]) -> Vec<serde_json::Value> { v.iter().map(|s| serde_json::json!({"id":&s.id,"capture_device":&s.capture_device,"state":&s.state,"started_at_ms":s.started_at_ms,"finished_at_ms":s.finished_at_ms,"snapshot_count":s.snapshot_count})).collect() }
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--list-adapters") {
        println!("{}", windows_agent::list_adapters_json()?);
        return Ok(());
    }
    windows_agent::run()
}

#[cfg(not(windows))]
fn main() { eprintln!("netsight-agent is supported on Windows with Npcap."); }
