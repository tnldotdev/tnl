# tnl

A public URL for localhost.

tnl is a self-hosted tunnel service. `tnld` owns the control API,
hostname claims, public TLS ingress, and durable SQLite state. `tnl` claims a
hostname and carries public connections to one literal-loopback HTTP service.

Run one standalone daemon for the smallest deployment, or separate the stateful
edge from a fixed pool of stateless route workers.

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

Set `TNL_IMAGE`, `TNLD_DOMAIN`, and the ACME account values in `.env`, then
start the daemon:

```console
docker compose pull
docker compose up -d
curl --fail https://core.example.com/v1/capabilities
docker compose exec tnld tnld bootstrap-token --state-dir /var/lib/tnl
```

The Compose deployment runs the container as a non-root user with a read-only
root filesystem and keeps `/var/lib/tnl` in a named volume. See the complete
[self-hosting guide](docs/self-hosting.md) for DNS, firewall,
metrics, and backup requirements.

## Publish

A core that advertises browser login can save a revocable access credential in
the client's private state directory:

```console
export TNL_CORE_URL=https://core.example.com
tnl login
tnl public 3000 --host=demo
```

The command prints the account URL and one-time code to approve. Use
`tnl logout` to revoke and remove the saved credential.

For a self-hosted core without browser login, `tnl login` securely prompts for
the bootstrap token printed by the daemon command above and stores a revocable
access credential in the client's private state directory. The client fetches
the deployment's pinned relay region from the core API:

```console
export TNL_CORE_URL=https://core.example.com
tnl login
tnl public 3000 --host=demo
```

Bootstrap-issued access tokens expire after 30 days. Browser-issued credentials
expire at the earlier of 30 days and the external account session. Authenticate
again before a later client restart or hostname administration operation when
necessary.

With automatic certificates enabled, the route becomes available at
`https://demo.apps.example.com`. Omit `--host` to allocate a stable random name
for that local target. Use `tnl host list` to list active claims and
`tnl host release HOSTNAME` to permanently release and tombstone one.

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
