# NETSIGHT Wireshark Core Rebuild Design

## Goal
NETSIGHT is a Windows-first passive network analyzer that provides the core workflow users expect from Wireshark—select an interface, capture frames, inspect protocol metadata, filter packets, and correlate observed endpoints with devices/services—while keeping the presentation simpler.

## Current root causes addressed
- Capture startup could leave the controller permanently marked running when interface discovery failed.
- Packet parsing was IPv4-only and discarded non-IPv4 frames.
- Packet timestamps were generated from the UI process clock instead of the capture header.
- The UI displayed a packet list but did not expose ports, frame information, or a functional display filter.
- Capture availability was reported as true even when `wpcap.dll`/Npcap was unavailable.
- Device discovery and capture responsibilities were mixed conceptually; broadcast/multicast ARP entries must never become normal devices.

## Architecture
Rust owns capture, raw-frame decoding, capture state, interface selection, and evidence extraction. React owns navigation, filtering controls, rendering, and interaction. Device discovery remains a separate best-effort local-network feature. No active probing or intrusive network actions are performed.

## Capture contract
`list_capture_interfaces` returns the usable Npcap interfaces. `start_capture(interface)` fails explicitly when Npcap or the requested interface is unavailable and resets the running flag on all startup failures. Capture emits `capture:state`, `capture:packet`, and `capture:error` events.

## Packet model
Each packet exposes timestamp, source, destination, protocol, frame length, optional source/destination ports, human-readable protocol info, service hint, and confidence. The decoder accepts Ethernet IPv4, IPv6, ARP, TCP, UDP, ICMP, and ICMPv6 without panicking on truncated frames. Service labels are evidence-based and may remain `Unknown`.

## UI behavior
Capture is manual. The user selects an interface before starting. The Packets view supports text filtering across addresses, ports, protocol, service and info, plus protocol chips. Selecting a packet opens an inspector with endpoint, protocol, ports, timestamp, frame length, info, and confidence.

## Device/service correlation
A device is an observed local endpoint from ARP discovery. Traffic association occurs only when packet endpoints match the device IP. Services are derived from observed ports and visible protocol signals; HTTPS is not decrypted.

## Packaging
The Windows bundle must build with the same Rust and frontend validation used by CI. Npcap is a runtime prerequisite for raw packet capture; NETSIGHT must surface a clear error instead of silently appearing to do nothing when it is absent.

## Testing
Rust unit tests cover packet decoding, truncation, interface/capture state, and ARP filtering. Frontend compilation is validated by `npm run build`. Windows packaging is validated by GitHub Actions before an artifact is treated as release-ready.
