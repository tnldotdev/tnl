# fixed-list publisher groups

one `tnl publisher serve` process can host a fixed list of provisioned group
identities, including identities from different teams or servers:

```sh
tnl publisher serve \
  --identity-file /run/secrets/team-a.json \
  --identity-file /run/secrets/team-b.json \
  --binding-file /etc/tnl/team-a.binding.json \
  --binding-file /etc/tnl/team-b.binding.json \
  --state-dir /state \
  --identity-dir /identity
```

omitting `--group` selects identity-bound mode even for one file. the existing
single-group command, including bootstrap, detach and user-supervisor installation,
continues to accept `--group NAME`. fixed-list mode runs in the foreground under
an operator's process supervisor and requires explicit state and identity
directories. it does not load a project checkout or select a saved person session.
remove `TNL_GROUP_IDENTITY`, enrollment credentials and server/team overrides.

## local dependency boundary

portable identity files remain identity-only. a separate private, operator-owned
JSON binding names one canonical control URL and immutable team, group and
publisher IDs. binding order need not match identity order. unknown, duplicate or
unmatched bindings fail before any group acquires a lease. friendly project,
group, service and instance names are not dependency lookup keys.

```json
{
  "version": 1,
  "identity": {
    "control_url": "https://control.example.com",
    "team_id": "team_...",
    "group_id": "pgrp_...",
    "publisher_identity_id": "pub_..."
  }
}
```

use the exact IDs from the provisioned identity, including the actual publisher
ID prefix. binding files must be regular, private files owned by the running uid;
use absolute paths. `server_ca_pem` optionally contains the control server's
private trust roots. it does not change relay or target trust.

AWS discovery needs an explicit private credential file. for example,
add these fields to the binding:

```json
{
  "aws": {
    "credentials_file": "/run/secrets/team-a-aws.json",
    "role_arn": "arn:aws:iam::123456789012:role/team-a-publisher",
    "role_region": "us-east-1"
  },
  "discovery": [
    {
      "type": "eks",
      "region": "us-east-1",
      "cluster": "production",
      "protocol": "kubernetes",
      "account": "123456789012"
    }
  ]
}
```

the credential file contains `access_key_id`, `secret_access_key`, optional
`session_token`, and optional RFC 3339 `expires_at`. each SDK signing operation
reads that same file. replace files atomically before expiry; rotation also works
for credentials without an expiry. omit
`role_arn` and `role_region` to use the file's credentials directly. an assumed
role uses only that explicit source. the AWS default chain, shared config,
process AWS credentials, ambient endpoint overrides and task roles are not
selected in fixed-list mode.

discovery permissions match the normalized exact selector and protocol. `account`
is a separate local constraint: assignments omit it, and the scoped provider
applies it to both STS caller identity and the described resource ARN. duplicate
selectors are rejected even if their account constraints differ. these local
permissions do not expand the assignments control authorizes. missing, unsafe or
expired selected credentials retain an authentication failure through SDK signing;
they block new target connections rather than using last-success metadata.
AssumeRole runs inside the discovery deadline and provider slot, without detached
SDK credential-cache refreshes; resolver shutdown cancels and joins that work.
embedded callers can provide their own per-group `targetdiscovery.Provider` to
`publisherjob.GroupRunner`; a nil provider is rejected.

optional `deployment` uses the existing `PublisherDeploymentReport` fields and
must match the identity's instance. it is validated and signed with that group's
runtime assertions. fixed-list mode ignores ambient deployment metadata.

## lifecycle and storage

`publisherjob.GroupRunner` owns assembly for foreground, installed and fixed-list
group jobs. it verifies identity possession, retains the immutable identity,
creates group-local discovery, and runs `grouppublisher.Runtime`. each runtime
independently renews its lease and joins its service assignments.

the engine exposes `StandaloneGroups` separately from user-session connector
capability. startup-list replacement occurs under the engine's service lock.
malformed identity/binding input and duplicate publisher ownership fail locally
before leases; remote authorization and control failures block or retry only
the affected group. disabled jobs and process shutdown cancel and join their
workers. a fixed-list process's next invocation reinstalls its explicit list.
omission from that next list explicitly retires a replica from the active group
catalog before adding replacements. the catalog bounds 256 active references per
server, not all historical invocations. retirement preserves the private identity,
certificates and a version-1 immutable selection pin; it neither revokes control
authority nor silently deletes it. explicit reactivation must use the original
publisher and key. retained history consumes disk until an operator retires its
control authority and deliberately archives or removes its private state.

startup admits four finite setup operations at a time, each with a 30-second
deadline. provider work admits eight operations in FIFO order, with existing
discovery deadlines. startup releases its slot before a healthy group
enters its lease loop. retries use exponential backoff with added jitter; the
maximum base delay is one minute, plus up to 25 percent jitter. this provides
bounded concurrency and independent scheduling, not memory or crash isolation.

SQLite state is task-local. durable identities are cataloged by canonical server
and immutable group identity. certificate files and `publisher.lock` use the
existing canonical-server/team/publisher scope. matching names in different
teams cannot select each other's keys or certificate cache. the runner preserves
the certificate recovery check: after acquiring `publisher.lock`, read the lease
and assignments. the required `certificate_state_plans` list includes every
submitted plan and is empty for a fresh publisher identity. control
records those plans in the same transaction as issuance and preserves them after
order/run cleanup. a restored old plan cannot satisfy a newer missing plan.
the local `certificate-plans-v1.json` checkpoint is synced before returning a
pending CSR for issuance. missing checkpointed files fail before generating keys;
startup also checks the control inventory to detect a wholly older local snapshot.
missing or corrupt checkpoints, uncheckpointed material and partial snapshots
fail closed; the publisher does not reconstruct checkpoints from remaining files.
restore the complete private identity directory, including all plans, pending
keys/CSRs, staged/current material and the checkpoint, while the replica is stopped.

the single PostgreSQL baseline includes the checkpoint table and issuance trigger.
schema 1 and the baseline identity are fixed. checkpoint and selection-pin files
use fixed format version 1, without format negotiation or import paths. active
catalog entries require their selection pins; retirement preserves those pins.

lifecycle frames identify server, team ID, group ID, publisher and instance, and
show `starting`, `reconciling`, `ready`, `retrying` or `blocked`. registry status
uses the same observations. the old unused publication-progress callback was
removed; the command does not claim to report certificate provisioning stages.

## evidence

`task go:test:publisher-groups` covers provider denial, scoped discovery, duplicate
ownership, independent blocked/stopped workers and joined cancellation with races.
`task go:test:integration:publisher-groups` owns disposable PostgreSQL and runs
the real CLI in a Linux-isolated process with real control/authority, ingress and
relays. its two same-named cross-team groups use independent signing identities,
certificates and targets. it checks visitor bytes, A-only stop/start/apply/revoke
without changing B's exact publish run, and durable certificate reuse after
process restart. the shared fixture
supplies local DNS and certificate workers; it does not qualify a deployed AWS
role, cloud resource, or public ACME provider. routine AWS coverage uses signed
SDK requests with local HTTPS and selected credential files; exact cloud-selector
permission checks run before the injected provider.
