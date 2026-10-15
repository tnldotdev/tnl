# run split server roles on fly

These manifests own the control, ingress, and two relay services for staging
and production. Start a new deployment with a **fresh PostgreSQL database**:
the clean-slate baseline in this checkout does not upgrade an older schema.
Keep the direct migration URL and pooled serving URL separate. Back up the
storage key with the database.

Each environment has its own four apps, DNS names, database, cluster secret,
and Route 53 zones. Only control receives database, storage, DNS, login, and
website credentials. Ingress and relays receive only the cluster secret.
Provision apps and public addresses with `flyctl` and bind the public DNS to
those addresses before starting control. Keep private 9443 (control), 9445
(relay forwarding), and 9090 (metrics) inside Fly's private network. On the
control app, provide `TNLD_INGRESS_IPV4_ADDRESSES` with the ingress public IPv4
address and the matching managed/server zone IDs; control advertises TCP ports
only after ingress forwards them. Set AWS credentials for Route 53 on control.
The ingress public IPv4 must be **dedicated** to that app; a shared IPv4 cannot
forward its allocated TCP ports. For a new staging environment, create the four
apps in the selected Fly organization and allocate addresses before deploying:

```sh
for role in control ingress relay-a relay-b; do
  flyctl apps create "tnl-$role-staging" --org tnl
  flyctl ips allocate-v4 --app "tnl-$role-staging"
  flyctl ips allocate-v6 --app "tnl-$role-staging"
done
```

Do the same with `production` only when creating that separate environment.
Record the assigned ingress address for the environment's control settings.

## select an image

Record a full source commit and an immutable, published image digest. Check
the local manifests without changing a server:

```sh
IMAGE='ghcr.io/tnldotdev/tnl@sha256:replace-with-published-digest'
COMMIT='replace-with-full-40-character-commit'
mise exec -- task deploy:manifests
mise exec -- task deploy:check IMAGE="$IMAGE" COMMIT="$COMMIT"
docker run --rm "$IMAGE" version
```

The `version` output must include that commit. `deploy:manifests` checks the
local topology and port mapping without pulling an image. `deploy:check` also
verifies the selected image's embedded commit and Linux amd64 platform digest.
Use the **same digest** for all four roles and the migrator. `tnld migrate`
accepts only the direct URL; serving control accepts only the pooled URL.
Migrate the empty database before starting a new environment. For a schema
change, stop old control processes before migrating unless the old version is
documented as compatible; control requires the exact schema version it knows.
For example, with the direct URL supplied in a private shell:

```sh
docker run --rm --env TNLD_DATABASE_DIRECT_URL "$IMAGE" migrate
```

Deploy staging only after provisioning its apps, DNS, secrets, and fresh
database. The operator selects the same image and commit used by the migration:

```sh
mise exec -- task deploy:staging IMAGE="$IMAGE" COMMIT="$COMMIT"
```

`deploy:staging` validates the image and applies each role manifest with
`flyctl deploy --image <digest> --ha=false`. On a new installation it starts
control before ingress and relays; with existing control Machines, it updates
ingress before control can offer the new TCP ports. Inspect the running image
and process state with `flyctl machine list --json --app tnl-ingress-staging`.
This small topology uses one ingress Machine and one Machine per relay app:
the ingress ID and each relay ID in the manifests must be unique among live
processes. Separate Fly apps do not guarantee separate physical hosts. If you
add replicas, configure distinct per-Machine IDs and reachable internal relay
addresses before starting them. Do not deploy by
tag or let Fly build from the working tree. Start control, then ingress and the
two relays on a new database. For existing serving processes, verify the
migration compatibility and roll the roles deliberately. Releases publish an
image and its digest; CI does not update production apps. After staging
qualification, an operator can use `task deploy:production IMAGE=... COMMIT=...`
with a separately migrated production database. That command also verifies the
selected image; no CI workflow calls it.

## provision production credentials

Store a private JSON file outside this checkout, owned by the operator and
mode 0600. `mise exec -- task deploy:production:provision
CREDENTIALS=/private/production.json` validates it and **stages** Fly secrets
on the four production apps without restarting Machines. Its shape is:

```json
{
  "environment": "production",
  "control": {
    "TNLD_DATABASE_URL": "postgresql://user:password@pool.example.com/tnl?sslmode=require",
    "TNLD_STORAGE_KEY": "<32 random bytes, unpadded base64url>",
    "TNLD_LOGIN_TOKEN": "tnl_login_<generated-token>",
    "TNLD_CLUSTER_SECRET": "<high-entropy shared secret>",
    "TNLD_INGRESS_IPV4_ADDRESSES": "192.0.2.11",
    "TNLD_ROUTE53_MANAGED_ZONE_ID": "<managed-zone-id>",
    "TNLD_ROUTE53_SERVER_ZONE_ID": "<server-zone-id>",
    "TNLD_WEBHOOK_SECRET": "<mailer secret>",
    "TNLD_WEB_SERVICE_SECRET": "<website secret>",
    "TNLD_PUBLIC_URL_USAGE_TOKEN": "<usage receiver token>"
  },
  "ingress": { "TNLD_CLUSTER_SECRET": "<same secret>" },
  "relay-a": { "TNLD_CLUSTER_SECRET": "<same secret>" },
  "relay-b": { "TNLD_CLUSTER_SECRET": "<same secret>" }
}
```

Add AWS Route 53 credentials to the `control` object when they are not provided
through a control-only role. Set the paired website and mailer secrets to match
their separately provisioned receivers. The direct migration URL does **not**
belong in this JSON or any Fly app. Generate the login token with the selected `tnld login-token`
and retain it privately. Staging needs its own independently provisioned
secrets. Never check credential JSON or the direct URL into the repository.

## qualify staging before promotion

Both ingress manifests forward **443/tcp and 1024-65535/tcp** to ingress with
PROXY v2. The control manifests inventory the same TCP range. Fly must apply
the new ports to **all** ingress Machines; merely updating the image does not
qualify the port configuration. `deploy:staging:qualify` checks each running
Machine's image and ingress port mapping, then makes an HTTPS visitor request
and a TLS Redis PING over a published TCP port. Prepare test-owned HTTP and
Redis targets on staging's managed domain with the selected `tnl` binary and a
dedicated staging team.
Use `tnl url certificate <redis-host> --directory /private/visitor-cert` to
obtain a scoped visitor certificate; the publisher checks it before forwarding
Redis commands. Provide the printed public URL, Redis hostname, allocated port,
and the private certificate/key paths:

```sh
HTTP_URL='https://replace-with-test-host.tnl.wtf'
REDIS_HOST='replace-with-redis-host.tnl.wtf'
REDIS_PORT='replace-with-allocated-port'
mise exec -- task deploy:staging:qualify IMAGE="$IMAGE" COMMIT="$COMMIT" \
  HTTP_URL="$HTTP_URL" EXPECT='known-response' REDIS_HOST="$REDIS_HOST" REDIS_PORT="$REDIS_PORT" \
  REDIS_CERT=/private/visitor-cert/client-cert.pem REDIS_KEY=/private/visitor-cert/client-key.pem
```

This command reads Fly and registry state and sends visitor traffic; it does
not deploy or publish anything. A TCP connect alone cannot prove destination
port preservation: the Redis response must come from the intended target.
Check a denied visitor from outside its IP policy separately, as well as
control `/v1/ready`, relay leases, and the publisher's output. Use the
[self-hosting guide](https://tnl.dev/docs/self-hosting) for the smaller
standalone Compose deployment and the public server setup.
