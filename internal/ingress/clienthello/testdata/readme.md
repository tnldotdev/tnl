# browser clienthello fixtures

[clienthello_test.go](../clienthello_test.go) checks that ingress reads the outer
hostname `route.example` from these browser TLS records and replays every byte
unchanged. both contain an ECH grease extension.

| file                      | browser             | captured   |
| ------------------------- | ------------------- | ---------- |
| `chromium-ech-grease.bin` | Google Chrome 152   | 2026-09-03 |
| `firefox-ech-grease.bin`  | Mozilla Firefox 154 | 2026-09-03 |

captured on macOS 26.6.2 with fresh browser profiles and a local HTTP CONNECT
recorder, which saved the first complete ClientHello and closed the connection.
there were no saved TLS sessions for this hostname. keep captures that cover a
distinct browser shape or regression beyond the synthetic tests.
