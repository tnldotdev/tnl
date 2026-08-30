# tnl

a public url for localhost.

## Go organization

- `internal/api` serves bounded core HTTP responses using the generated contract.
- `internal/auth`, `internal/credentials`, and `internal/state` own standalone identity and token storage.
- `internal/naming` owns canonical public-hostname policy.
- `internal/proxyproto` owns strict PROXY protocol v2 framing.
- `internal/router` performs bounded TLS ClientHello inspection for routing.
- `internal/routes`, `internal/ingress`, and `internal/worker` coordinate leases and forward public streams.
- `internal/workersession` carries edge-to-worker control and data over authenticated WSS and yamux.
- `internal/publication` terminates application TLS and proxies only to a literal-loopback HTTP target.
- `internal/tailtransport` carries lease traffic over Tailcat.
- `internal/observability` exports provider-neutral Prometheus metrics.
- `pkg/protocol/corev1` contains generated Go types for the core API contract.
- `cmd/tnl` and `cmd/tnld` are the client and core-service entry points.

## Daemon roles

`tnld` accepts `--mode=standalone|edge|worker` (`TNLD_MODE`). `standalone` owns
SQLite state, the core HTTPS API, public SNI ingress, and a local route worker.
`edge` owns state, the API, ingress, and authenticated worker sessions. `worker`
is stateless and connects outbound to an edge. Worker membership and route
assignments are intentionally ephemeral.

Prometheus metrics are served on the private
`--metrics-listen=127.0.0.1:9090` listener by default. Set
`TNLD_METRICS_LISTEN` to another private address or to an empty value to disable
the listener. The endpoint exports bounded-cardinality TNL metrics plus the
standard Go and process collectors.

Generate deployment credentials with:

```console
tnl token bootstrap
tnl token worker
```

A standalone deployment needs a control TLS certificate, a standard Tailscale
DERP map JSON file, and explicit control and public listeners:

```console
export TNLD_BOOTSTRAP_TOKEN="$(tnl token bootstrap)"
tnld --mode=standalone \
  --state-dir=./state \
  --control-listen=127.0.0.1:8443 \
  --public-listen=:443 \
  --control-cert-file=control.crt \
  --control-key-file=control.key \
  --relay-map-file=derp-map.json \
  --relay-profile=default
```

Exchange the bootstrap token once, then publish a loopback HTTP service with an
application certificate valid for the route hostname:

```console
export TNL_CORE_URL=https://core.example
export TNL_BOOTSTRAP_TOKEN="$TNLD_BOOTSTRAP_TOKEN"
export TNL_ACCESS_TOKEN="$(tnl auth exchange)"
unset TNL_BOOTSTRAP_TOKEN
tnl publish \
  --hostname=demo.example \
  --target=http://127.0.0.1:3000 \
  --cert-file=demo.example.crt \
  --key-file=demo.example.key \
  --relay-map-file=derp-map.json
```

For split deployments, configure the edge with the same `--worker-token` used
by workers. A worker connects to
`wss://EDGE_HOST/internal/v1/worker` and requires the approved DERP map. Run
`tnld --help` and `tnl COMMAND --help` for all flags and environment variables.

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

The opt-in complete route-path Fly benchmark is documented in
[`docs/benchmarks`](docs/benchmarks/README.md).
