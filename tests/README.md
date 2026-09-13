# NetSight test strategy

- Unit tests: pure parsing, state machines, service scoring, aggregation.
- Integration tests: adapter discovery, capture lifecycle, DNS pipeline.
- Packet fixtures: deterministic PCAP/PCAPNG inputs for parser and service detection tests.
- Diagnostics: every subsystem exposes structured status and stable error codes.

The first implementation deliberately keeps capture backends behind platform boundaries so the analyzer can be tested without requiring a live Wi-Fi adapter.
