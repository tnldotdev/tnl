# browser clienthello fixtures

[clienthello_test.go](../clienthello_test.go) checks that ingress reads the outer
hostname `route.example` from these browser TLS records and replays every byte
unchanged. Both contain an ECH GREASE extension.

| File                      | Browser             | Captured   |
| ------------------------- | ------------------- | ---------- |
| `chromium-ech-grease.bin` | Google Chrome 152   | 2026-09-03 |
| `firefox-ech-grease.bin`  | Mozilla Firefox 154 | 2026-09-03 |

Captured on macOS 26.6.2 with fresh browser profiles and a local HTTP CONNECT
recorder, which saved the first complete ClientHello and closed the connection.
There were no saved TLS sessions for this hostname. Keep captures that cover a
distinct browser shape or regression beyond the synthetic tests.
