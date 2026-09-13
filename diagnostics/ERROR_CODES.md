# NetSight diagnostic codes

Stable codes make failures searchable and reproducible.

## Capture
- CAPTURE-0001: capture subsystem initialized
- CAPTURE-0002: capture start requested
- CAPTURE-0003: capture stopped
- CAPTURE-0010: adapter unavailable
- CAPTURE-0011: permission/backend initialization failed
- CAPTURE-0012: capture backend produced no frames

## Discovery
- DISCOVERY-0010: no active network adapter
- DISCOVERY-0011: gateway could not be determined
- DISCOVERY-0012: device probe failed

## Analysis
- ANALYSIS-0010: malformed packet
- ANALYSIS-0011: unsupported protocol
- SERVICE-0010: service could not be identified

Codes are intentionally stable; user-facing text can change without changing the code.
