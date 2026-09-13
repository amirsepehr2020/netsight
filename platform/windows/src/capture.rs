//! Real Windows packet capture using Npcap/libpcap.
//!
//! The capture boundary is deliberately bounded: packets enter a finite queue,
//! oversized frames are rejected, and overload is observable through counters.

#[cfg(windows)]
use anyhow::{Context, Result};
#[cfg(windows)]
use pcap::{Active, Capture, Device};
#[cfg(windows)]
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
#[cfg(windows)]
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
#[cfg(windows)]
use std::thread::{self, JoinHandle};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureDevice { pub name: String, pub description: Option<String> }

#[derive(Debug, Clone)]
pub struct CapturedPacket { pub timestamp_micros: i64, pub captured_len: u32, pub original_len: u32, pub data: Vec<u8> }

#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub snaplen: i32,
    pub read_timeout_ms: i32,
    pub promiscuous: bool,
    pub immediate_mode: bool,
    pub queue_capacity: usize,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self { snaplen: 65_535, read_timeout_ms: 250, promiscuous: true, immediate_mode: true, queue_capacity: 4096 }
    }
}

#[derive(Debug, Default, Clone)]
pub struct CaptureStats {
    pub captured: u64,
    pub queued: u64,
    pub dropped_queue_full: u64,
    pub dropped_oversized: u64,
    pub errors: u64,
}

#[cfg(windows)]
#[derive(Debug, Default)]
struct AtomicCaptureStats { captured: AtomicU64, queued: AtomicU64, dropped_queue_full: AtomicU64, dropped_oversized: AtomicU64, errors: AtomicU64 }

#[cfg(windows)]
impl AtomicCaptureStats {
    fn snapshot(&self) -> CaptureStats { CaptureStats { captured: self.captured.load(Ordering::Relaxed), queued: self.queued.load(Ordering::Relaxed), dropped_queue_full: self.dropped_queue_full.load(Ordering::Relaxed), dropped_oversized: self.dropped_oversized.load(Ordering::Relaxed), errors: self.errors.load(Ordering::Relaxed) } }
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
pub struct CaptureSession { stop_tx: Option<mpsc::Sender<()>>, worker: Option<JoinHandle<()>>, stats: Arc<AtomicCaptureStats> }

#[cfg(windows)]
impl CaptureSession {
    pub fn start(device_name: &str, config: CaptureConfig) -> Result<(Self, Receiver<CaptureEvent>)> {
        let device = Device::list().context("failed to enumerate Npcap devices")?.into_iter().find(|d| d.name == device_name).with_context(|| format!("capture device not found: {device_name}"))?;
        let mut builder = Capture::from_device(device).context("failed to create capture builder")?.snaplen(config.snaplen).timeout(config.read_timeout_ms);
        if config.promiscuous { builder = builder.promisc(true); }
        if config.immediate_mode { builder = builder.immediate_mode(true); }
        let mut capture = builder.open().context("failed to open Npcap capture handle")?;
        let (event_tx, event_rx) = mpsc::sync_channel(config.queue_capacity.max(64));
        let (stop_tx, stop_rx) = mpsc::channel();
        let stats = Arc::new(AtomicCaptureStats::default());
        let worker_stats = Arc::clone(&stats);
        let worker = thread::Builder::new().name("netsight-capture".into()).spawn(move || run_capture_loop(&mut capture, stop_rx, event_tx, worker_stats, config.snaplen.max(0) as usize)).context("failed to spawn capture worker")?;
        Ok((Self { stop_tx: Some(stop_tx), worker: Some(worker), stats }, event_rx))
    }

    pub fn stats(&self) -> CaptureStats { self.stats.snapshot() }

    pub fn stop(mut self) -> Result<()> {
        if let Some(tx) = self.stop_tx.take() { let _ = tx.send(()); }
        if let Some(worker) = self.worker.take() { worker.join().map_err(|_| anyhow::anyhow!("capture worker panicked"))?; }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for CaptureSession {
    fn drop(&mut self) { if let Some(tx) = self.stop_tx.take() { let _ = tx.send(()); } if let Some(worker) = self.worker.take() { let _ = worker.join(); } }
}

#[cfg(windows)]
fn run_capture_loop(capture: &mut Capture<Active>, stop_rx: Receiver<()>, event_tx: SyncSender<CaptureEvent>, stats: Arc<AtomicCaptureStats>, max_packet_size: usize) {
    loop {
        if stop_rx.try_recv().is_ok() { let _ = event_tx.send(CaptureEvent::Stopped); break; }
        match capture.next_packet() {
            Ok(packet) => {
                stats.captured.fetch_add(1, Ordering::Relaxed);
                let len = packet.header.caplen as usize;
                if len > max_packet_size { stats.dropped_oversized.fetch_add(1, Ordering::Relaxed); continue; }
                let event = CaptureEvent::Packet(CapturedPacket { timestamp_micros: packet.header.ts.tv_sec as i64 * 1_000_000 + packet.header.ts.tv_usec as i64, captured_len: packet.header.caplen, original_len: packet.header.len, data: packet.data.to_vec() });
                match event_tx.try_send(event) {
                    Ok(()) => { stats.queued.fetch_add(1, Ordering::Relaxed); }
                    Err(TrySendError::Full(_)) => { stats.dropped_queue_full.fetch_add(1, Ordering::Relaxed); }
                    Err(TrySendError::Disconnected(_)) => break,
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(err) => { stats.errors.fetch_add(1, Ordering::Relaxed); let _ = event_tx.send(CaptureEvent::Error(err.to_string())); break; }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn default_capture_config_is_bounded() { let config = CaptureConfig::default(); assert_eq!(config.snaplen, 65_535); assert!(config.read_timeout_ms > 0); assert!(config.promiscuous); assert!(config.queue_capacity >= 64); }
    #[test] fn packet_lengths_are_preserved() { let packet = CapturedPacket { timestamp_micros: 1, captured_len: 4, original_len: 8, data: vec![1,2,3,4] }; assert_eq!(packet.captured_len as usize, packet.data.len()); assert!(packet.original_len >= packet.captured_len); }
    #[test] fn stats_default_to_zero() { let stats = CaptureStats::default(); assert_eq!(stats.captured + stats.queued + stats.dropped_queue_full + stats.dropped_oversized + stats.errors, 0); }
}
