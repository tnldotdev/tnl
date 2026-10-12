# deploy the tnl server

Merges to `main` deploy staging (`tnl.wtf`). Every published `v*` release,
including RCs, advances the `production` branch and deploys production
(`tnl.dev`). The release image and staging image come from their respective
workflows; the Fly manifests do not pin an old image. `scripts/deploy-server.ts`
checks the selected image's commit and version, migrates control with its direct
PostgreSQL URL, then updates the existing Fly Machines. Each role ends on the
same Linux amd64 image digest without changing Machine counts.

| Role    | Staging app           | Production app           |
| ------- | --------------------- | ------------------------ |
| Control | `tnl-control-staging` | `tnl-control-production` |
| Ingress | `tnl-ingress-staging` | `tnl-ingress-production` |
| Relay A | `tnl-relay-a-staging` | `tnl-relay-a-production` |
| Relay B | `tnl-relay-b-staging` | `tnl-relay-b-production` |

Both environments run in Fly `sjc`, with two control processes, two ingress
processes, and two relay processes in each of two relay services. The intended
counts are in `process-counts.json`. Each relay service has one `udp` Machine
that receives public QUIC and one TCP-only `app` Machine. Preserve the
per-Machine ingress and relay IDs and the relay's Machine-specific internal
address when changing a service. `TNLD_MANAGED_URL_MODE=generated` keeps the
hosted member namespace format independent of the server default.

## setup

Create the four Fly apps per environment in the `tnl` organization, assign
their public IPs, and store those IPs in the [hosted AWS stack](https://github.com/tnldotdev/tnl.dev/blob/main/deploy/aws/README.md).
That stack owns DNS, Fly OIDC roles, and the zones; `tnl` does not apply it.
Create separate `tnl-control` PlanetScale branches and give control its pooled
runtime URL. Put the branch's **direct** migrator URL in the matching `tnl`
GitHub Environment, `deploy-staging` or `deploy-production`, as
`TNLD_DATABASE_DIRECT_URL`. Set `FLY_API_TOKEN` in each Environment for its
Fly apps. Allow `main` in `deploy-staging` and `production` in
`deploy-production`; production must not require manual approval if every
release should deploy. Create `production` from a commit on `main` before the
first release deployment, and permit the release workflow to fast-forward it.
The PlanetScale branch IDs checked in `scripts/deploy-server.ts` prevent an
Environment from migrating the other branch.

Store pooled URLs, cluster secrets, login token, storage key, website and
webhook secrets, and usage receiver token as Fly secrets, not GitHub secrets
or manifest values. Control assumes the Fly app-scoped AWS role from the hosted
stack. Give ingress and both relays the same environment-specific cluster
secret. Assign distinct `TNLD_INGRESS_ID` values on ingress Machines and
distinct `TNLD_RELAY_ID` values on relay Machines. Set each relay's
`TNLD_INTERNAL_RELAY_ADDRESS` to
`<machine-id>.vm.<relay-app>.internal:9445`. Start control, ingress, relay A,
then relay B. Server state lives in PlanetScale; do not attach a Fly volume.

## rollout and checks

Staging builds an image for each successfully checked `main` commit. The
release workflow publishes a signed image, then fast-forwards `production`
and dispatches the production deployment with that image's digest. Production
checks the signed tag and release artifact before migrating. Both workflows
run `tnld migrate` before updating control; it must remain compatible with
currently serving processes. A failed migration stops the rollout. The script
checks Machine counts, identities, image digests, and relay service layout.
It updates manually created Machines that `flyctl deploy --update-only` skips.

After a rollout, check control's `/v1/ready`, all Machine readiness states,
login at `account.<domain>`, a new publish run with both publisher connections,
and allowed and rejected visits. In production, stop one process of each role
in turn and check an existing public URL and a new publish run through the
survivors. Restore the process before testing the next role. Keep the previous
image digest for a manual rolling rollback; do not run an older control process
against a newer schema.

Adding Machines is an operator change: copy a running Machine's service and
environment settings, assign a new identity and exact relay internal address,
then verify its lease and ready publisher connections. Keep exactly one public
UDP receiver per relay service. Update `process-counts.json` after verification
and before the next routine deployment.
