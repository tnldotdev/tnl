# tnl

A public URL for localhost.

TNL is a standalone-preview tunnel service. `tnld` owns the control API,
hostname claims, public TLS ingress, and durable SQLite state. `tnl` claims a
hostname and carries public connections to one literal-loopback HTTP service.

The standalone deployment is the supported preview path. Split edge and worker
modes are experimental.

## Install

Release archives contain `tnl` and `tnld` for macOS and Linux on amd64 and
arm64. Each release also publishes checksums, SPDX SBOMs, a Sigstore bundle,
and a multi-platform daemon image at `ghcr.io/0xcadams/tnl`.

See [release installation and verification](docs/releases.md) before running a
downloaded artifact. macOS binaries are not Apple-signed or notarized.

## Standalone quick start

A deployment needs two DNS records pointing to the host:

- `core.example.com` for the control API on TCP 443.
- `*.apps.example.com` for public routes on TCP 443.

The reference deployment is under [`deploy`](deploy):

```console
cd deploy
install -m 0600 .env.example .env
```

Add an approved Tailscale DERP map as `derp-map.json` and replace every value
in `.env`. Generate `TNLD_BOOTSTRAP_TOKEN` with:

```console
tnl token bootstrap
```

Start the daemon after replacing every placeholder:

```console
docker compose pull
docker compose up -d
curl --fail https://core.example.com/v1/capabilities
```

The Compose deployment runs the container as a non-root user with a read-only
root filesystem and keeps `/var/lib/tnl` in a named volume. See the complete
[self-hosting guide](docs/self-hosting.md) for DNS, firewall,
metrics, and backup requirements.

## Publish

Exchange the deployment bootstrap token on a client, then remove it from the
client environment. Keep the returned access token and the approved relay map
private to that client:

```console
export TNL_CORE_URL=https://core.example.com
read -rsp 'Bootstrap token: ' TNL_BOOTSTRAP_TOKEN && printf '\n'
export TNL_BOOTSTRAP_TOKEN
export TNL_ACCESS_TOKEN="$(tnl auth exchange)"
unset TNL_BOOTSTRAP_TOKEN

tnl public 3000 \
  --host=demo \
  --relay-map-file=derp-map.json
```

Access tokens expire after 30 days. Re-exchange the bootstrap token before a
later client restart or hostname administration operation when necessary.

With automatic certificates enabled, the route becomes available at
`https://demo.apps.example.com`. Omit `--host` to allocate a stable random name
for that local target. Use `tnl host list` to list active claims and
`tnl host release HOSTNAME` to permanently release and tombstone one.

Manual application certificates require an ECDSA P-256 key and exactly one DNS
SAN equal to the complete route hostname. Pass them with `--cert-file` and
`--key-file`.

## Components

- `internal/api` serves bounded core HTTP responses using the generated contract.
- `internal/auth`, `internal/credentials`, and `internal/state` own standalone identity and token storage.
- `internal/naming` owns canonical public-hostname policy.
- `internal/routes`, `internal/ingress`, and `internal/worker` coordinate leases and forward public streams.
- `internal/publication` terminates application TLS and proxies only to a literal-loopback HTTP target.
- `internal/tailtransport` carries lease traffic over Tailcat.
- `internal/observability` exports provider-neutral Prometheus metrics.
- `pkg/protocol/corev1` contains generated Go types for the core API contract.
- `cmd/tnl` and `cmd/tnld` are the client and daemon entry points.

The hosted web and accounts service is maintained separately. Core contracts
and conformance fixtures remain under `api`.

## Development

Install the pinned toolchain and run the repository checks:

```console
brew install mise
mise trust
mise install
mise exec -- task format-check lint test build package
```

The opt-in complete route-path Fly benchmark is documented in
[`docs/benchmarks`](docs/benchmarks/README.md).
