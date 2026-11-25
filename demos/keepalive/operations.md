# Keepalive operations

Cloudflare serves the visitor and restart pages. The `keepalive` team delegates
only `hosts.keepthisalive.com` to tnl. Each fleet has its own tnl deployment,
Cloudflare Worker, enrollment credential, and wildcard certificate.

| Deployment | Visitor page             | Restart page                   | tnl shared hostname                 |
| ---------- | ------------------------ | ------------------------------ | ----------------------------------- |
| `prod`     | `keepthisalive.com`      | `start.keepthisalive.com`      | `site.prod.hosts.keepthisalive.com` |
| `ramp`     | `ramp.keepthisalive.com` | `start-ramp.keepthisalive.com` | `site.ramp.hosts.keepthisalive.com` |

The production wildcard covers `site.prod.hosts.keepthisalive.com` and each
`p-….prod.hosts.keepthisalive.com`. Ramp has the same layout under `ramp.hosts`.
Each fleet's page, hosting worker, and proxy accept donors only from that fleet.
The old `keepalive` deployment remains declared during cutover. Its `*.live.hosts`
certificate and enrolled identities cannot start the new deployments.

## Build and provision one fleet

From the repository root, with the matching `tnl` on `PATH`:

```sh
mise exec -- task js:keepalive:build
fleet=ramp
config=demos/keepalive/wrangler.ramp.jsonc
project=project-4f913a3d642157c67aba9a09bb376e5529dd1bafe419aba2
server=https://control.tnl.dev
tnl --config demos/keepalive/tnl.config.ts apply --server "$server" --team keepalive --deployment "$fleet" --diff
tnl --config demos/keepalive/tnl.config.ts apply --server "$server" --team keepalive --deployment "$fleet"
deployment=$(tnl --no-config deployment show "$fleet" --server "$server" --team keepalive \
  --project-key "$project" --output json | jq -er '.id | select(test("^dpl_[A-Za-z0-9]{22}$"))')
```

For production use `fleet=prod` and `config=demos/keepalive/wrangler.jsonc`.
Builds go to `dist-ramp/` and `dist/`, respectively. Each build pins its own
hostnames and release. Compare the expected release ID and
`X-Keepalive-Host-Parent` from `/__keepalive/release` on **both** public origins
before starting a browser test. Stop if either changes.

## Deploy or rotate the Worker credential

The credential can manage only the `production` service on the selected
deployment. Do not use a personal access token or add connection or publication
permissions. The Worker exchanges it for a short-lived token. The browser
receives only a one-use enrollment key.

Signing credentials expire after at most 30 days (`720h`). Rotate around day 25. Expiry blocks new enrollments, not already-running hosts. Save the
credential name and request ID to retry an interrupted rotation. In a shell
with `pipefail`, send the secret and the matching deployment ID in one Worker
version:

```sh
credential_name="keepalive-$fleet-$(date -u +%Y%m%d%H%M%S)"
request_id=$(uuidgen)
(
  set -eu
  set -o pipefail
  set +x
  umask 077
  test -n "$deployment"
  dir=$(mktemp -d)
  trap 'rm -f "$dir/secrets.json"; rmdir "$dir"' EXIT
  tnl auth credential create "$credential_name" \
    --team keepalive --server "$server" --project-key "$project" \
    --deployment-id "$deployment" --manage production \
    --expires-in 720h --idempotency-key "$request_id" |
    jq -Rse '{DEPLOYMENT_CREDENTIAL: (rtrimstr("\n") | select(startswith("tnc_")))}' \
      > "$dir/secrets.json"
  jq -e '.DEPLOYMENT_CREDENTIAL | type == "string"' "$dir/secrets.json" >/dev/null
  mise exec -- wrangler deploy --config "$config" \
    --var "DEPLOYMENT_ID:$deployment" --secrets-file "$dir/secrets.json"
)
```

On later code-only deploys pass the same `--var "DEPLOYMENT_ID:$deployment"`.
Wrangler retains the existing secret. To verify a rotation, `POST
/__keepalive/config` with a matching `Origin` checks the binding; a new
volunteer must enroll and serve to prove the token exchange. Only then use
`tnl publisher list --team keepalive --server "$server"` and
`tnl publisher revoke OLD_PUBLISHER_ID --team keepalive --server "$server"`
to retire that fleet's previous Worker credential, not a browser identity.

## Prove certificate reuse

Use an empty ramp fleet and a private directory kept between tests:

```sh
mise exec -- task js:keepalive:restart \
  RELEASE="$(jq -er .id demos/keepalive/dist-ramp/release.json)" \
  PROFILE_DIR="$HOME/Library/Application Support/keepalive-tests"
```

The test stops the seed, closes Chrome, and reopens the same profile. It
requires a new run from the same publisher, then a volunteer from a fresh
profile. Both must serve the pinned HTML and JavaScript and install the seed's
certificate without requesting issuance. It leaves the seed profile on disk.
Do not archive or share that directory: it contains the publisher's keys.

For the first production cutover, verify the new production seed and invited
host on their exact publisher hostnames before switching public visitor traffic.
Keep the old Worker version and its deployment available for rollback. Exercise
repeated fresh issuance, expiry, and issuer delays against the local test
issuer; two production wildcards still share a registered-domain quota.

If a volunteer copies the site but cannot enroll, inspect the Worker's
`keepalive invitation check` event. It records the upstream HTTP status,
`timeout`, or `transport`. Only `204` from the exact inviter allows enrollment.
