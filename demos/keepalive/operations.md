# Deploy Keepalive

From the repository root:

```sh
mise exec -- task js:keepalive:deploy
```

This builds the site and deploys it directly to `keepthisalive.com` and
`start.keepthisalive.com`. Wrangler uses the production deployment ID in
`wrangler.jsonc` and keeps the existing Worker secret.

If the fleet is empty, open [start.keepthisalive.com](https://start.keepthisalive.com)
and click **start hosting**. Use the same Chrome profile to reuse the seed's
certificate. Check the live site at [keepthisalive.com](https://keepthisalive.com).

## Rotate the Worker credential

From `demos/keepalive`, use the following commands. The credential
can enroll browsers for one service on one deployment. It expires after 30
days; rotate around day 25. Keep the name and request ID for retries.

```sh
name="keepalive-prod-$(date -u +%Y%m%d%H%M%S)"
request_id=$(uuidgen)
(
  set -eu
  set +x
  deployment=$(tnl deployment show prod --team keepalive --output json | jq -er .id)
  secret=$(tnl auth credential create "$name" --team keepalive \
    --deployment-id "$deployment" --manage production \
    --expires-in 720h --idempotency-key "$request_id")
  printf '%s' "$secret" | mise exec -- wrangler secret put DEPLOYMENT_CREDENTIAL --config wrangler.jsonc
)
```

Once a new volunteer enrolls and serves, revoke the old Worker identity with
`tnl publisher revoke OLD_PUBLISHER_ID --team keepalive`.

## Load tests

Use the separate `ramp` deployment for load tests. It has its own Worker
(`wrangler.ramp.jsonc`), credential, and certificate under
`*.ramp.hosts.keepthisalive.com`. Production deploys do not use it.

To check certificate reuse on an empty ramp fleet, run from the repo root:

```sh
mise exec -- task js:keepalive:restart \
  RELEASE="$(jq -er .id demos/keepalive/dist-ramp/release.json)" \
  PROFILE_DIR="$HOME/Library/Application Support/keepalive-tests"
```

The test reopens the seed's Chrome profile and invites a fresh browser. Both
must serve the pinned bytes with the same certificate and no new issuance
requests. Keep the seed profile private; it holds the publisher's keys.
