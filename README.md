# tnl

public urls for localhost.

tnl is a self-hosted tunnel service. `tnld` owns the control API,
hostname claims, public TLS ingress, and durable SQLite state. `tnl` claims a
hostname and carries public connections to one literal-loopback HTTP service.

Run one standalone daemon for the smallest deployment, or separate the stateful
edge from a fixed pool of stateless route workers.

## Install

Install a stable release with Homebrew:

```console
brew install tnldotdev/tap/tnl
```

The formula installs both `tnl` and `tnld` on macOS or Linux. Homebrew
packages are published only for stable releases.

Release archives contain `tnl` and `tnld` for macOS and Linux on amd64 and
arm64. Each release also publishes checksums, SPDX SBOMs, a Sigstore bundle,
and a multi-platform daemon image at `ghcr.io/tnldotdev/tnl`.

See [release installation and verification](docs/releases.md) before running a
downloaded artifact. macOS binaries are not Apple-signed or notarized.

## Standalone quick start

A deployment needs one static wildcard DNS record pointing to public ingress:

- `*.example.com` for the server API and public routes on TCP 443.

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
curl --fail https://tnl.example.com/v1/capabilities
docker compose exec tnld tnld login-token --state-dir /var/lib/tnl
```

The Compose deployment runs the container as a non-root user with a read-only
root filesystem and keeps `/var/lib/tnl` in a named volume. See the complete
[self-hosting guide](docs/self-hosting.md) for DNS, firewall,
metrics, and backup requirements.

## Publish

A server with browser login enabled can save a revocable access credential in
the client's private state directory:

```console
tnl login https://tnl.example.com
tnl public 3000
```

The command prints the account URL and one-time code to approve. Use
`tnl logout` to revoke and remove the saved credential.

For a server without browser login, `tnl login` securely prompts for the login
token printed by the daemon command above and stores a revocable access
credential in the client's private state directory. The client fetches the
deployment's pinned relay region from the server API:

```console
tnl login https://tnl.example.com
tnl host claim demo
tnl public 3000 --name=demo
```

Access credentials expire after 30 days. Authenticate again before a later
client restart or hostname administration operation when necessary.

The named route becomes available at `https://demo.example.com`. Omitting
`--name` allocates a fresh friendly ephemeral name for every invocation. A
persistent base may serve its apex and descendants up to eight labels deep.

Use `tnl host claim`, `tnl host list`, and `tnl host release HOSTNAME` to manage
persistent bases and verified custom domains. Managed bases remain bound to
their original owner after release; released custom domains are transferable
after fresh DNS proof.

## Framework development

`tnl dev` starts a development server and publishes it after the framework has
registered its loopback port. The integration is active only beneath
`tnl dev`, so the project's usual development command remains local.

For Next.js 15.2 or newer, install the adapter and update `next.config.ts`:

```console
pnpm add --save-dev @tnldotdev/next
```

```ts
import { withTnl } from "@tnldotdev/next";

export default withTnl({});
```

For Vite 6 or newer, install the plugin:

```console
pnpm add --save-dev @tnldotdev/vite
```

Add it to `vite.config.ts`:

```ts
import { defineConfig } from "vite";
import tnl from "@tnldotdev/vite";

export default defineConfig({
  plugins: [tnl()],
});
```

Add one shared project script:

```json
{
  "scripts": {
    "dev:public": "tnl dev -- pnpm dev"
  }
}
```

Ordinary `pnpm dev` remains local. Run the public server with:

```console
pnpm dev:public
```

Each developer can select a hostname in their local shell:

```console
export TNL_NAME=chase.example.com
pnpm dev:public
```

Another developer can use `TNL_NAME=john.example.com`. The flag form is:

```console
tnl dev --name chase.example.com -- pnpm dev
```

The signed-in user must own the custom domain or an eligible parent claim.
Separate users cannot currently share one parent claim.

For another framework, provide its fixed port:

```console
tnl dev --port=3000 -- pnpm dev
```

The public proxy connects only to a literal-loopback target. HTTP, streaming
responses, and WebSocket hot reload use the public HTTPS URL printed by `tnl`.

## Components

- `internal/api` serves bounded server HTTP responses using the generated contract.
- `internal/auth`, `internal/credentials`, and `internal/state` own standalone identity and token storage.
- `internal/naming` owns canonical public-hostname policy.
- `internal/routes`, `internal/ingress`, and `internal/worker` coordinate leases and forward public streams.
- `internal/publication` terminates application TLS and proxies only to a literal-loopback HTTP target.
- `internal/tailtransport` carries lease traffic over Tailcat.
- `internal/observability` exports provider-neutral Prometheus metrics.
- `pkg/protocol/serverv1` contains generated Go types for the server API contract.
- `cmd/tnl` and `cmd/tnld` are the client and daemon entry points.

The hosted web and accounts service is maintained separately. Server contracts
and conformance fixtures remain under `api`.

## Development

Install the pinned toolchain and run the repository checks:

```console
brew install mise
mise trust
mise install
mise exec -- pnpm install --frozen-lockfile
mise exec -- task format-check generate-check lint test build package
```

The opt-in complete route-path Fly benchmark is documented in
[`docs/benchmarks`](docs/benchmarks/README.md).
