# NETSIGHT End-to-End Test Plan

## Capture
- Select an available capture interface.
- Start/stop capture without crashing.
- Confirm packet history respects the configured limit.
- Confirm privacy mode prevents payload/content exposure in the UI.

## Discovery and correlation
- Discover local network devices from observed traffic.
- Correlate local process connections with device/connection records.
- Resolve observed DNS domains into service identities when evidence is sufficient.
- Preserve `Unknown` when evidence is insufficient.

## Packet Inspector
- Open a packet/connection record.
- Verify source, destination, protocol, size, service, confidence and evidence are displayed.
- Verify encrypted traffic is described without claiming payload decryption.

## Full scenario
`Wi-Fi → Device → Packet → Process → Domain → Service → UI`

The CI build is the automated gate for compile/test regressions. Runtime capture validation requires a Windows host with a supported capture driver/interface and is intentionally not represented as a fake CI success.
