const API_BASE = "http://127.0.0.1:8765";
const $ = (id) => document.getElementById(id);

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes;
  let unit = "B";
  for (const next of units) {
    value /= 1024;
    unit = next;
    if (value < 1024) break;
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${unit}`;
}

function formatRate(bytes, previous, elapsedMs) {
  if (!previous || !elapsedMs) return formatBytes(0) + "/s";
  return `${formatBytes(Math.max(0, bytes - previous) * 1000 / elapsedMs)}/s`;
}

function stateLabel(state) {
  return ({ Running: "Capturing", Starting: "Starting…", Stopping: "Stopping…", Failed: "Capture error", Idle: "Idle" })[state] || state;
}

let previous = null;
let previousAt = 0;

function render(snapshot) {
  const now = Date.now();
  const elapsed = now - previousAt;
  $("capture-status").textContent = stateLabel(snapshot.state);
  $("capture-status").classList.toggle("ns-status-error", snapshot.state === "Failed");
  $("capture-device").textContent = snapshot.capture_device || "No adapter";
  $("device-count").textContent = snapshot.devices.length;
  $("flow-count").textContent = snapshot.traffic.active_flows;
  $("download-rate").textContent = formatRate(snapshot.traffic.bytes, previous?.bytes, elapsed);
  $("upload-rate").textContent = formatBytes(snapshot.devices.reduce((sum, d) => sum + d.bytes_up, 0));

  const rows = snapshot.flows.slice(0, 100).map((flow) => {
    const ports = flow.source_port && flow.destination_port ? `${flow.source_port} → ${flow.destination_port}` : "—";
    return `<tr><td>${escapeHtml(flow.source)}</td><td>${escapeHtml(flow.destination)}</td><td><span class="ns-service">${escapeHtml(flow.protocol)}</span></td><td>${escapeHtml(ports)}</td><td>${formatBytes(flow.bytes)}</td><td>${flow.packets}</td></tr>`;
  }).join("");
  $("flow-body").innerHTML = rows || `<tr><td colspan="6" class="ns-empty">Waiting for live traffic…</td></tr>`;

  const deviceRows = snapshot.devices.slice(0, 100).map((device) => `<tr><td>${escapeHtml(device.hostname || device.id)}</td><td>${escapeHtml(device.ip || "—")}</td><td>${escapeHtml(device.device_type || "Unknown")}</td><td>${formatBytes(device.bytes_down)}</td><td>${formatBytes(device.bytes_up)}</td><td>${device.confidence}%</td></tr>`).join("");
  $("device-body").innerHTML = deviceRows || `<tr><td colspan="6" class="ns-empty">No devices observed yet.</td></tr>`;

  const timelineRows = snapshot.timeline.slice(-40).reverse().map((sample) => `<div class="ns-timeline-row"><span>${new Date(Number(sample.timestamp_ms)).toLocaleTimeString()}</span><strong>${escapeHtml(sample.device)}</strong><span>${escapeHtml(sample.service)}</span><span>${escapeHtml(sample.protocol)}</span><span>${formatBytes(sample.bytes_up + sample.bytes_down)}</span></div>`).join("");
  $("timeline-list").innerHTML = timelineRows || `<div class="ns-empty">Timeline will appear as packets arrive.</div>`;
  previous = snapshot.traffic;
  previousAt = now;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[c]);
}

async function poll() {
  try {
    const response = await fetch(`${API_BASE}/api/snapshot`, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
  } catch (error) {
    $("capture-status").textContent = "Agent offline";
    $("capture-status").classList.add("ns-status-error");
    $("capture-device").textContent = "Start netsight-agent on Windows";
  }
}

poll();
setInterval(poll, 500);
