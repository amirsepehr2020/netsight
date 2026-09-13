# Service Identification Engine

Production-oriented service identification layer for NETSIGHT.

## Goals
- Correlate observable network metadata with known services.
- Keep evidence and confidence explicit.
- Never claim a service when evidence is insufficient.
- Keep the engine independent from the UI and packet-capture backend.

## Observable evidence
- DNS names
- Destination IPs
- Ports and protocols
- TLS metadata when available
- Connection and traffic patterns

Encrypted application payloads are not inspected or decrypted by this layer.
