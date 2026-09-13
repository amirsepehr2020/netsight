# Persistent Capture Sessions

Production milestone for persistent capture history.

## Session lifecycle

`Starting -> Running -> Stopping -> Stopped`

Unexpected termination is represented as `RecoveryRequired` and can be recovered on the next application start.

## Storage contract

The persistence layer stores session metadata and flow records in SQLite. Flow records are written in batches and indexed by timestamp, device, service, and protocol. Retention removes completed sessions older than the configured age.

## Recovery

On startup, sessions left in `Starting`, `Running`, or `Stopping` are marked `RecoveryRequired` rather than being silently discarded. A recovery pass can close the recovered session while preserving already committed flow rows.

## Performance

Writers use bounded batches and transactions. The capture/analysis pipeline remains independent from SQLite latency; persistence failures are surfaced as diagnostics instead of blocking the capture loop indefinitely.
