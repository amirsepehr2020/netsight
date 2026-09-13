const API_BASE = "http://127.0.0.1:8765";
const $ = (id) => document.getElementById(id);
let previous = null;
let previousAt = 0;
let historicalSession = null;

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes;
  let unit = "B";
  for (const next of units) { value /= 1024; unit = next; if (value < 1024) break; }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${unit}`;
}
function formatRate(bytes, previous, elapsedMs) {
  if (previous == null || !elapsedMs) return `${formatBytes(0)}/s`;
  return `${formatBytes(Math.max(0, bytes - previous) * 1000 / elapsedMs)}/s`;
}
function stateLabel(state) { return ({ Running:"Capturing", Starting:"Starting…", Stopping:"Stopping…", Failed:"Capture error", Idle:"Idle" })[state] || state; }
function escapeHtml(value) { return String(value).replace(/[&<>'"]/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"})[c]); }
function formatSessionTime(ms) { return new Date(Number(ms)).toLocaleString(); }

function render(snapshot) {
  const now = Date.now(), elapsed = now - previousAt;
  $("capture-status").textContent = historicalSession ? "Historical session" : stateLabel(snapshot.state);
  $("capture-status").classList.toggle("ns-status-error", snapshot.state === "Failed");
  $("capture-device").textContent = snapshot.capture_device || "No adapter";
  $("device-count").textContent = snapshot.devices.length;
  $("flow-count").textContent = snapshot.traffic.active_flows;
  $("download-rate").textContent = historicalSession ? formatBytes(snapshot.traffic.bytes) : formatRate(snapshot.traffic.bytes, previous?.bytes, elapsed);
  $("upload-rate").textContent = formatBytes(snapshot.devices.reduce((sum, d) => sum + d.bytes_up, 0));

  $("flow-body").innerHTML = snapshot.flows.slice(0,100).map((flow) => {
    const ports = flow.source_port && flow.destination_port ? `${flow.source_port} → ${flow.destination_port}` : "—";
    return `<tr><td>${escapeHtml(flow.source)}</td><td>${escapeHtml(flow.destination)}</td><td><span class="ns-service">${escapeHtml(flow.protocol)}</span></td><td>${escapeHtml(ports)}</td><td>${formatBytes(flow.bytes)}</td><td>${flow.packets}</td></tr>`;
  }).join("") || `<tr><td colspan="6" class="ns-empty">No flow data in this session.</td></tr>`;

  $("device-body").innerHTML = snapshot.devices.slice(0,100).map((device) => `<tr><td>${escapeHtml(device.hostname || device.id)}</td><td>${escapeHtml(device.ip || "—")}</td><td>${escapeHtml(device.device_type || "Unknown")}</td><td>${formatBytes(device.bytes_down)}</td><td>${formatBytes(device.bytes_up)}</td><td>${device.confidence}%</td></tr>`).join("") || `<tr><td colspan="6" class="ns-empty">No devices observed.</td></tr>`;
  $("timeline-list").innerHTML = snapshot.timeline.slice(-40).reverse().map((sample) => `<div class="ns-timeline-row"><span>${new Date(Number(sample.timestamp_ms)).toLocaleTimeString()}</span><strong>${escapeHtml(sample.device)}</strong><span>${escapeHtml(sample.service)}</span><span>${escapeHtml(sample.protocol)}</span><span>${formatBytes(sample.bytes_up + sample.bytes_down)}</span></div>`).join("") || `<div class="ns-empty">No timeline data.</div>`;
  $("view-subtitle").textContent = historicalSession ? `Read-only history: ${escapeHtml(historicalSession)}` : "Live visibility across your connected network.";
  $("live-button").hidden = !historicalSession;
  previous = snapshot.traffic;
  previousAt = now;
}

async function loadSessions() {
  try {
    const response = await fetch(`${API_BASE}/api/sessions`, { cache:"no-store" });
    if (!response.ok) throw new Error();
    const sessions = await response.json();
    $("session-list").innerHTML = sessions.map((session) => `<button class="ns-session" data-session="${escapeHtml(session.id)}"><span><strong>${escapeHtml(session.capture_device)}</strong><small>${formatSessionTime(session.started_at_ms)}</small></span><span class="ns-session-meta"><em class="ns-session-state ${escapeHtml(session.state)}">${escapeHtml(session.state)}</em><small>${session.snapshot_count} snapshots</small></span></button>`).join("") || `<div class="ns-empty">No capture sessions yet.</div>`;
    document.querySelectorAll(".ns-session").forEach((button) => button.addEventListener("click", () => openSession(button.dataset.session)));
  } catch { $("session-list").innerHTML = `<div class="ns-empty">Session history is available when netsight-agent is running.</div>`; }
}

async function openSession(id) {
  try {
    const response = await fetch(`${API_BASE}/api/sessions/${encodeURIComponent(id)}`, { cache:"no-store" });
    if (!response.ok) throw new Error();
    historicalSession = id;
    render(await response.json());
    location.hash = "overview";
  } catch { historicalSession = null; }
}
function returnLive() { historicalSession = null; previous = null; previousAt = 0; poll(); }
$("live-button").addEventListener("click", returnLive);

async function poll() {
  if (historicalSession) return;
  try {
    const response = await fetch(`${API_BASE}/api/snapshot`, { cache:"no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
  } catch {
    $("capture-status").textContent = "Agent offline";
    $("capture-status").classList.add("ns-status-error");
    $("capture-device").textContent = "Start netsight-agent on Windows";
  }
}

poll();
loadSessions();
setInterval(poll, 500);
setInterval(loadSessions, 2000);
