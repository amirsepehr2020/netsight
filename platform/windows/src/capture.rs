//! Real Windows packet capture using Npcap/libpcap.
//!
//! Npcap must be installed on the host for live capture. This module deliberately
//! exposes packet bytes plus timestamps; higher layers remain responsible for
//! protocol/service classification and persistence.

#[cfg(windows)]
use anyhow::{Context, Result};
#[cfg(windows)]
use pcap::{Active, Capture, Device};
#[cfg(windows)]
use std::sync::mpsc::{self, Receiver, Sender};
#[cfg(windows)]
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
#[cfg(windows)]
use std::thread::{self, JoinHandle};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureDevice { pub name: String, pub description: Option<String> }

#[derive(Debug, Clone)]
pub struct CapturedPacket { pub timestamp_micros: i64, pub captured_len: u32, pub original_len: u32, pub data: Vec<u8> }

#[derive(Debug, Clone)]
pub struct CaptureConfig { pub snaplen: i32, pub read_timeout_ms: i32, pub promiscuous: bool, pub immediate_mode: bool, pub queue_capacity: usize }

impl Default for CaptureConfig {
    fn default() -> Self { Self { snaplen: 65_535, read_timeout_ms: 250, promiscuous: true, immediate_mode: true, queue_capacity: 4096 } }
}

#[derive(Debug, Clone, Default)]
pub struct CaptureMetrics {
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub bytes_received: u64,
    pub queue_depth: u64,
    pub queue_capacity: u64,
    pub capture_errors: u64,
}

#[derive(Debug)]
pub enum CaptureEvent { Packet(CapturedPacket), Error(String), Stopped }

#[cfg(windows)]
pub fn list_capture_devices() -> Result<Vec<CaptureDevice>> {
    Ok(Device::list().context("failed to enumerate Npcap capture devices")?.into_iter().map(|d| CaptureDevice { name: d.name, description: d.desc }).collect())
}

#[cfg(not(windows))]
pub fn list_capture_devices() -> anyhow::Result<Vec<CaptureDevice>> { Ok(Vec::new()) }

#[cfg(windows)]
pub struct CaptureSession {
    stop_tx: Option<Sender<()>>, worker: Option<JoinHandle<()>>, metrics: Arc<CaptureMetricsAtomic>
}

#[cfg(windows)]
struct CaptureMetricsAtomic { received: AtomicU64, dropped: AtomicU64, bytes: AtomicU64, errors: AtomicU64, depth: AtomicU64 }

#[cfg(windows)]
impl CaptureMetricsAtomic {
    fn snapshot(&self, capacity: usize) -> CaptureMetrics { CaptureMetrics { packets_received: self.received.load(Ordering::Relaxed), packets_dropped: self.dropped.load(Ordering::Relaxed), bytes_received: self.bytes.load(Ordering::Relaxed), queue_depth: self.depth.load(Ordering::Relaxed), queue_capacity: capacity as u64, capture_errors: self.errors.load(Ordering::Relaxed) } }
}

#[cfg(windows)]
impl CaptureSession {
    pub fn start(device_name: &str, config: CaptureConfig) -> Result<(Self, Receiver<CaptureEvent>)> {
        let device = Device::list().context("failed to enumerate Npcap devices")?.into_iter().find(|d| d.name == device_name).with_context(|| format!("capture device not found: {device_name}"))?;
        let mut builder = Capture::from_device(device).context("failed to create capture builder")?.snaplen(config.snaplen).timeout(config.read_timeout_ms);
        if config.promiscuous { builder = builder.promisc(true); }
        if config.immediate_mode { builder = builder.immediate_mode(true); }
        let mut capture = builder.open().context("failed to open Npcap capture handle")?;
        let (event_tx, event_rx) = mpsc::sync_channel(config.queue_capacity.max(1));
        let (stop_tx, stop_rx) = mpsc::channel();
        let metrics = Arc::new(CaptureMetricsAtomic { received: AtomicU64::new(0), dropped: AtomicU64::new(0), bytes: AtomicU64::new(0), errors: AtomicU64::new(0), depth: AtomicU64::new(0) });
        let worker_metrics = Arc::clone(&metrics);
        let capacity = config.queue_capacity.max(1);
        let worker = thread::Builder::new().name("netsight-capture".into()).spawn(move || run_capture_loop(&mut capture, stop_rx, event_tx, worker_metrics, capacity)).context("failed to spawn capture worker")?;
        Ok((Self { stop_tx: Some(stop_tx), worker: Some(worker), metrics }, event_rx))
    }

    pub fn metrics(&self, queue_capacity: usize) -> CaptureMetrics { self.metrics.snapshot(queue_capacity) }

    pub fn stop(mut self) -> Result<()> {
        if let Some(tx) = self.stop_tx.take() { let _ = tx.send(()); }
        if let Some(worker) = self.worker.take() { worker.join().map_err(|_| anyhow::anyhow!("capture worker panicked"))?; }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for CaptureSession { fn drop(&mut self) { if let Some(tx)=self.stop_tx.take(){let _=tx.send(());} if let Some(worker)=self.worker.take(){let _=worker.join();} } }

#[cfg(windows)]
fn run_capture_loop(capture: &mut Capture<Active>, stop_rx: Receiver<()>, event_tx: mpsc::SyncSender<CaptureEvent>, metrics: Arc<CaptureMetricsAtomic>, capacity: usize) {
    loop {
        if stop_rx.try_recv().is_ok() { let _=event_tx.send(CaptureEvent::Stopped); break; }
        match capture.next_packet() {
            Ok(packet) => {
                let timestamp_micros=packet.header.ts.tv_sec as i64*1_000_000+packet.header.ts.tv_usec as i64;
                metrics.received.fetch_add(1, Ordering::Relaxed); metrics.bytes.fetch_add(packet.header.caplen as u64, Ordering::Relaxed);
                let event=CaptureEvent::Packet(CapturedPacket{timestamp_micros,captured_len:packet.header.caplen,original_len:packet.header.len,data:packet.data.to_vec()});
                match event_tx.try_send(event) { Ok(())=>{metrics.depth.fetch_add(1,Ordering::Relaxed);}, Err(mpsc::TrySendError::Full(_))=>metrics.dropped.fetch_add(1,Ordering::Relaxed), Err(mpsc::TrySendError::Disconnected(_))=>break }
                if metrics.depth.load(Ordering::Relaxed)>0 { metrics.depth.fetch_sub(1, Ordering::Relaxed); }
            }
            Err(pcap::Error::TimeoutExpired)=>continue,
            Err(err)=>{metrics.errors.fetch_add(1,Ordering::Relaxed);let _=event_tx.send(CaptureEvent::Error(err.to_string()));break;}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn default_capture_config_is_bounded(){let c=CaptureConfig::default();assert_eq!(c.snaplen,65_535);assert!(c.read_timeout_ms>0);assert!(c.promiscuous);assert!(c.queue_capacity>0);}
    #[test] fn packet_lengths_are_preserved(){let p=CapturedPacket{timestamp_micros:1,captured_len:4,original_len:8,data:vec![1,2,3,4]};assert_eq!(p.captured_len as usize,p.data.len());assert!(p.original_len>=p.captured_len);}
    #[test] fn metrics_default_to_zero(){let m=CaptureMetrics::default();assert_eq!(m.packets_received,0);assert_eq!(m.packets_dropped,0);assert_eq!(m.capture_errors,0);}
}
