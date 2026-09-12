# NETSIGHT Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first usable Windows NETSIGHT desktop application with a polished branded UI, network/interface visibility, local device discovery, live observable traffic capture, aggregation, and transparent service identification.

**Architecture:** Tauri 2 hosts a React/Vite/TypeScript UI over a Rust core. Native networking is isolated behind adapters; packet capture feeds bounded normalized events into traffic/service detection, while stable DTOs/events cross the Tauri boundary.

**Tech Stack:** Tauri 2, Rust, React, Vite, TypeScript, Npcap/libpcap-compatible capture, Windows networking APIs, Vitest/React Testing Library, Rust unit/integration tests.

**Spec:** `docs/superpowers/specs/2026-09-12-netsight-architecture-design.md`

## Global Constraints

- Windows-first desktop application.
- Capture only traffic observable by the host/adapter; never imply complete LAN visibility.
- Never decrypt third-party HTTPS or collect credentials/cookies/sessions.
- Distinguish observed, inferred/likely, and unknown data in the UI.
- Use bounded queues/backpressure and expose meaningful capture-drop/errors.
- UI must support Overview, Devices, Traffic, Packets, and Services plus Easy/Expert presentation.
- Brand colors: `#0B1118`, `#111923`, `#F5F7FA`, `#35F2C1`, `#4EA1FF`.

---

### Task 1: Application scaffold

**Files:**
- Create: `src-tauri/` Rust/Tauri application structure.
- Create: `src/` React/Vite/TypeScript application structure.
- Create: `package.json`, `vite.config.*`, `tsconfig*.json`, `src-tauri/Cargo.toml`, Tauri config.
- Preserve: `assets/brand/*`.

- [ ] Create the minimal Tauri + React application scaffold.
- [ ] Add the branded shell and verify the frontend builds.
- [ ] Run frontend build and Rust/Tauri checks.
- [ ] Commit the scaffold.

### Task 2: Domain models and event contracts

**Files:**
- Create: `src-tauri/src/domain/*.rs`.
- Create: `src-tauri/src/events.rs`.
- Create: `src-tauri/src/commands.rs`.
- Create: matching TypeScript DTO/event types under `src/types/`.

- [ ] Define stable models for network state, devices, packets, flows, services, confidence, and capture state.
- [ ] Define serialized event envelopes with timestamp/sequence where needed.
- [ ] Add unit tests for serialization and confidence/evidence mapping.
- [ ] Commit.

### Task 3: Network interface manager

**Files:**
- Create: `src-tauri/src/network/manager.rs` and Windows adapter helpers.
- Modify: `src-tauri/src/commands.rs`.
- Create: tests under `src-tauri/tests/`.

- [ ] Implement current-interface discovery, local IP, gateway/status where available.
- [ ] Expose interface selection and network-change events.
- [ ] Handle unavailable adapters cleanly.
- [ ] Test parsing/normalization and command serialization.
- [ ] Commit.

### Task 4: Local device discovery

**Files:**
- Create: `src-tauri/src/discovery/mod.rs`, discovery adapter(s), vendor lookup support.
- Modify: domain models/events.
- Create: discovery tests.

- [ ] Discover visible LAN peers using safe local-network mechanisms.
- [ ] Track IP/MAC/hostname/vendor/last-seen with explicit unknown fields.
- [ ] Emit discovered/updated device events.
- [ ] Add deterministic tests for merge/update behavior.
- [ ] Commit.

### Task 5: Packet capture adapter

**Files:**
- Create: `src-tauri/src/capture/mod.rs` and Npcap adapter.
- Create: normalized packet parser modules.
- Modify: capture commands/events.

- [ ] Detect Npcap and available capture interfaces.
- [ ] Implement start/stop capture with bounded channels.
- [ ] Normalize Ethernet/IP/TCP/UDP/DNS/TLS metadata without payload decryption.
- [ ] Track capture drops and surface errors.
- [ ] Add parser tests with synthetic packet fixtures.
- [ ] Commit.

### Task 6: Traffic aggregation and DNS observation

**Files:**
- Create: `src-tauri/src/traffic/aggregator.rs` and DNS observer/parser.
- Create: flow aggregation tests.

- [ ] Aggregate upload/download totals by device, endpoint, protocol, and service candidate.
- [ ] Observe DNS names when visible and associate them with flows/devices.
- [ ] Keep aggregation bounded and efficient.
- [ ] Test byte accounting and flow expiry/update behavior.
- [ ] Commit.

### Task 7: Service detection engine

**Files:**
- Create: `src-tauri/src/services/detector.rs`, evidence/signature modules.
- Create: service detection tests.

- [ ] Combine DNS, TLS metadata, destination IP/range, port/protocol, and known signatures.
- [ ] Produce identity, confidence, and evidence/source.
- [ ] Prefer `Unknown`/`Likely` over fabricated certainty.
- [ ] Test high-confidence, low-confidence, and unknown cases.
- [ ] Commit.

### Task 8: Event bridge and Tauri commands

**Files:**
- Modify: `src-tauri/src/lib.rs`/main entry.
- Modify: command/event modules.
- Create: Rust-to-UI integration tests where practical.

- [ ] Wire capture/discovery/traffic/services into the event stream.
- [ ] Expose commands for interface state, discovery refresh, capture start/stop, and mode/settings state.
- [ ] Ensure bounded event delivery and graceful shutdown.
- [ ] Test event serialization and command failures.
- [ ] Commit.

### Task 9: NETSIGHT UI shell and design system

**Files:**
- Create: `src/app/*`, `src/components/*`, `src/styles/*`.
- Use: `assets/brand/logo.svg`, `logo-mark.svg`, `favicon.svg`.

- [ ] Build dark premium shell with sidebar/top status and responsive layout.
- [ ] Implement design tokens, cards, tables, badges, confidence indicators, charts, and empty/error states.
- [ ] Add subtle motion/glow without visual clutter.
- [ ] Verify desktop and small-window layouts.
- [ ] Commit.

### Task 10: Overview, Devices, Traffic, Services views

**Files:**
- Create: `src/features/overview/*`, `devices/*`, `traffic/*`, `services/*`.
- Modify: app routing/navigation.

- [ ] Connect live event data to overview metrics and live traffic chart.
- [ ] Build device list/details and traffic summaries.
- [ ] Build service table with confidence/evidence.
- [ ] Implement loading, no-network, no-device, capture-unavailable, error, and empty states.
- [ ] Add UI tests for key states.
- [ ] Commit.

### Task 11: Expert Packets view

**Files:**
- Create: `src/features/packets/*`.
- Create: packet inspector components.

- [ ] Implement searchable/filterable packet table.
- [ ] Add TCP/UDP/DNS/TLS filters and packet detail inspector.
- [ ] Clearly distinguish observed packet metadata from inferred service identity.
- [ ] Add tests for filters and empty/loading states.
- [ ] Commit.

### Task 12: Capture onboarding, errors, and Windows packaging

**Files:**
- Modify: Tauri config and installer/build configuration.
- Create: Npcap/capture onboarding UI and release docs.

- [ ] Add clear Npcap-missing and permission guidance.
- [ ] Request elevation only when required.
- [ ] Produce a Windows distributable build/installer configuration.
- [ ] Verify startup, shutdown, missing dependency, and capture-failure paths.
- [ ] Commit.

### Task 13: Full verification and release candidate

**Files:**
- Modify: tests/docs/config only as needed.

- [ ] Run Rust tests/checks.
- [ ] Run frontend tests and production build.
- [ ] Run Tauri build/package verification.
- [ ] Exercise live UI with mock/synthetic data and real capture when available.
- [ ] Review safety/visibility wording and ensure no unsupported certainty.
- [ ] Create final release-candidate commit and PR.
