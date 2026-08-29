# tnl

a public url for localhost.

## Go organization

- `internal/naming` owns canonical public-hostname policy.
- `internal/proxyproto` owns strict PROXY protocol v2 framing.
- `internal/router` performs bounded TLS ClientHello inspection for routing.
- `internal/tailtransport` carries lease traffic over Tailcat.
- `pkg/protocol/corev1` contains generated Go types for the core API contract.
- `cmd/tnl` and `cmd/tnld` are the client and core-service entry points.

## Hosted service

The hosted web and accounts service is maintained separately from this public
core repository. Core API contracts and shared conformance fixtures remain in
`api` so hosted integrations can consume the same definitions.

## Development

Install the pinned toolchain and run the repository checks:

```console
brew install mise
mise trust
mise install
mise exec -- task format-check lint test build
```

This repository is Go-only and does not require Node.

The opt-in Tailcat capacity and churn benchmarks are documented in
[`docs/benchmarks`](docs/benchmarks/README.md).
