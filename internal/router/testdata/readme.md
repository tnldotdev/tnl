# browser clienthello fixtures

These TLS records were captured on macOS 26.6.2 from fresh browser profiles
connecting to `route.example` through a local HTTP CONNECT recorder. The
recorder saved the first complete ClientHello and then closed the connection.
The profiles had no TLS sessions for the synthetic hostname, so the captures do
not contain resumption pre-shared keys.

| File                      | Browser             | Captured   |
| ------------------------- | ------------------- | ---------- |
| `chromium-ech-grease.bin` | Google Chrome 152   | 2026-09-03 |
| `firefox-ech-grease.bin`  | Mozilla Firefox 154 | 2026-09-03 |

Both fixtures contain an ECH grease extension and a plaintext outer SNI. Keep a
fixture only while it represents a distinct ClientHello shape or a regression
that synthetic parser tests do not capture as clearly.
