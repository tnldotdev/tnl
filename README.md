# tnl

a public url for localhost.

## Go organization

- `internal/api` serves bounded core HTTP responses using the generated contract.
- `internal/naming` owns canonical public-hostname policy.
- `internal/proxyproto` owns strict PROXY protocol v2 framing.
- `internal/router` performs bounded TLS ClientHello inspection for routing.
- `internal/tailtransport` carries lease traffic over Tailcat.
- `internal/observability` exports provider-neutral Prometheus metrics.
- `pkg/protocol/corev1` contains generated Go types for the core API contract.
- `cmd/tnl` and `cmd/tnld` are the client and core-service entry points.

## Daemon roles

`tnld` accepts `--mode=standalone|edge|worker` (`TNLD_MODE`). `standalone` is
the default and owns durable SQLite state. `edge` also owns durable state;
`worker` is stateless and does not require `--state-dir`. These modes establish
the process boundaries for later clustered routing; edge-to-worker dispatch and
durable worker assignment are not implemented yet.

Prometheus metrics are served on the private
`--metrics-listen=127.0.0.1:9090` listener by default. Set
`TNLD_METRICS_LISTEN` to another private address or to an empty value to disable
the listener. The endpoint exports bounded-cardinality TNL metrics plus the
standard Go and process collectors.

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
