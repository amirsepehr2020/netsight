# NETSIGHT Architecture & Product Design

**Date:** 2026-09-12
**Status:** Design approved in conversation; implementation follows written-spec review.

## 1. Product Goal

NETSIGHT is a Windows-first local network visibility application designed to make network activity understandable without sacrificing an expert inspection mode. It discovers devices on the local LAN, captures observable traffic, summarizes flows, observes DNS/TLS metadata where available, and identifies likely services with explicit confidence rather than pretending uncertain results are certain.

The product must feel professional, fast, calm, precise, and transparent. It is not intended to decrypt HTTPS, steal credentials/cookies, or provide covert interception.

## 2. Technology Architecture

- Windows desktop shell: Tauri 2
- Native/core layer: Rust
- UI: React + Vite + TypeScript
- Packet capture: Npcap/libpcap-compatible capture on Windows
- Event-driven communication between Rust and UI
- Local discovery and network-interface management separated from capture
- Service detection separated from packet parsing and traffic aggregation

```text
NETSIGHT UI
React + TypeScript
Dashboard / Devices / Traffic / Packets / Services
          |
     Tauri Commands + Event Stream
          |
       Rust Core
  -------------------------
  Network Manager
  Device Discovery
  Packet Capture
  DNS Observer
  Service Detector
  Traffic Aggregator
          |
    Windows Network
      Npcap + Win APIs
```

## 3. Core Data Flow

```text
Network Interface
      |
      +--> Network Manager --> current adapter/IP/gateway/status
      |
      +--> Device Discovery --> IP/MAC/hostname/vendor/last-seen
      |
      +--> Packet Capture --> normalized packets
                                  |
                     +------------+-------------+
                     |            |             |
                    DNS         TCP/UDP      TLS metadata
                     |            |             |
                     +------------+-------------+
                                  |
                         Service Detector
                                  |
                         Traffic Aggregator
                                  |
                           Tauri Events
                                  |
                              React UI
```

The system uses bounded event/packet queues and backpressure so a busy network cannot unboundedly grow memory usage. Capture drops are measurable and surfaced to the UI when relevant.

## 4. Event Model

Primary events:

- `network.changed`
- `device.discovered`
- `device.updated`
- `traffic.updated`
- `packet.captured`
- `service.detected`
- `capture.started`
- `capture.stopped`
- `error.occurred`

Each event should include a timestamp and sequence identifier where ordering matters.

## 5. Core Domain Models

Initial Rust domain types:

- `NetworkInterface`
- `NetworkState`
- `Device`
- `PacketSummary`
- `Flow`
- `ServiceIdentity`
- `TrafficSnapshot`
- `CaptureState`
- `DetectionConfidence`

The UI consumes stable serialized DTOs rather than depending directly on low-level capture structs.

## 6. Device Discovery

Discovery targets the whole local network visible from the selected interface. Device records may contain:

- IP address
- MAC address when observable
- hostname when available
- vendor/OUI when resolvable
- online/last-seen state
- upload/download totals
- observed services

Discovery must clearly distinguish unavailable fields from unknown values.

## 7. Packet Capture and Visibility

NETSIGHT captures only traffic observable by the host and adapter/capture mode. It must not imply that all LAN traffic is visible when the Wi-Fi adapter/AP does not expose it.

Capture responsibilities:

1. Select a valid capture interface.
2. Apply appropriate capture filters where possible.
3. Decode enough link/IP/TCP/UDP metadata for summaries.
4. Forward normalized packet summaries to aggregation and UI streams.
5. Maintain bounded buffers and drop counters.
6. Expose clear errors for missing Npcap, unsupported adapters, permission issues, or capture failures.

HTTPS payloads are not decrypted. TLS metadata is used only when observable.

## 8. Service Detection

Service detection combines multiple non-invasive signals:

- DNS names
- observed domains
- TLS metadata such as SNI when available
- destination IP/ranges
- ports and protocols
- known service signatures
- traffic context

Results include confidence and evidence/source. Examples:

```text
YouTube       96%   DNS + TLS + IP
Likely GitHub 71%   DNS
Unknown        —    insufficient evidence
```

The detector must prefer `Unknown`/`Likely` over fabricated certainty.

## 9. UI/UX Architecture

Navigation:

- Overview
- Devices
- Traffic
- Packets
- Services

Overview provides network status, device count, traffic totals, active services, and a live traffic visualization.

Devices provides searchable device cards/table and per-device details.

Traffic provides live upload/download and service-level traffic summaries.

Packets provides an expert packet table with protocol filters/search and a packet inspector.

Services provides service identities, device count, traffic, confidence, and evidence.

Two presentation levels are required:

- Easy Mode: human-readable service/device summaries.
- Expert Mode: raw packet/network metadata.

## 10. Visual Design System

Brand: **NETSIGHT**

Tagline: **Know what's moving.**

Colors:

- Ink 950: `#0B1118`
- Ink 900: `#111923`
- Text 100: `#F5F7FA`
- Mint 500: `#35F2C1`
- Blue 500: `#4EA1FF`

Typography: Inter, Segoe UI, Arial, sans-serif.

The visual language is dark, premium, technical, restrained, and alive. Mint-to-blue gradients are reserved for brand moments and important highlights. Subtle glass surfaces, restrained glow, smooth short animations, strong spacing, and minimal icons are preferred over visual clutter.

The existing logo assets in `assets/brand/` are the source of truth for the brand mark.

## 11. UI States

Every major screen must have intentional states for:

- loading
- no network
- no devices
- capture unavailable
- Npcap missing
- permission denied
- capturing
- paused
- error
- empty search
- unknown service

## 12. Safety and Transparency Boundary

NETSIGHT is designed for networks and systems the operator is authorized to monitor. It must not implement credential theft, cookie/session theft, covert interception, HTTPS decryption of third-party traffic, or similar abuse-enabling behavior.

The UI should distinguish:

- observed fact
- inferred/likely identity
- unknown/unavailable data

## 13. Windows Delivery

The application is Windows-first. The release path should produce a distributable desktop installer/build and clearly handle the Npcap dependency. Elevated privileges should be requested only where required by the selected capture/discovery operation.

## 14. Quality Requirements

The implementation should include:

- unit tests for packet normalization and service detection logic
- tests for confidence/evidence mapping
- integration coverage for Rust-to-UI event serialization
- UI verification for loading/error/empty/live states
- graceful handling of high traffic and capture drops
- clean separation between capture adapters and higher-level business logic

## 15. Initial Product Milestone

The first usable milestone should provide:

1. NETSIGHT desktop shell and branded UI.
2. Interface/network status detection.
3. Local device discovery.
4. Start/stop live packet capture.
5. Traffic aggregation.
6. DNS observation where available.
7. Initial service detection with confidence/evidence.
8. Overview, Devices, Traffic, Packets, and Services views.
9. Clear capture limitations/errors.

Later milestones can deepen protocol decoding, improve service databases, add richer historical analytics, and optimize performance without changing the core architecture.
