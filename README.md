# NETSIGHT

> **Know what's moving.**

NETSIGHT is a Windows network visibility and packet analysis project designed to make local-network activity understandable without sacrificing technical depth.

## What NETSIGHT aims to do

- Discover devices visible on the local network
- Show IP, MAC, hostname, vendor, and traffic statistics where available
- Capture observable network traffic
- Inspect packets with technical detail
- Resolve observable DNS/domain information
- Group traffic into recognizable services when identification is reliable
- Present the same activity in both an approachable view and an expert packet view

## Current v0.1

The first Windows desktop milestone is now in `main` and includes:

- Tauri 2 + Rust desktop shell
- React + Vite + TypeScript UI
- Finished NETSIGHT dark/premium visual system
- Overview, Devices, Traffic, Packets, and Services views
- Easy / Expert mode switch
- Device detail drawer with visibility/evidence messaging
- Windows network-state and ARP-based local device discovery commands
- Windows GitHub Actions build pipeline

Traffic capture and deeper service detection are the next native-core milestones; the current UI does not pretend its sample traffic is live capture data.

## Important visibility boundary

NETSIGHT reports only information that the host can legitimately observe. Wi-Fi infrastructure, encryption, adapter capabilities, and network topology can limit visibility into traffic between other devices. The application must distinguish observed facts from inferred or likely service identification.

## Brand

**NETSIGHT** — **Know what's moving.**

The visual identity is based on an eye/network mark: the eye represents visibility and the connected nodes represent network activity.

See [`BRAND.md`](BRAND.md) for the complete identity guidelines and [`assets/brand/`](assets/brand/) for the SVG assets.

## Project status

🟢 **Brand foundation** — complete

🟢 **Windows application shell + UI** — complete for v0.1

🟢 **Local device discovery foundation** — complete for v0.1

🟡 **Traffic capture** — next milestone

🟡 **Service identification engine** — next milestone

## Safety & scope

NETSIGHT is intended for networks and systems the user owns or is authorized to analyze. It is designed for network observability, troubleshooting, learning, and diagnostics.
