# applied projects and publisher groups

Control stores one desired configuration for a `(team_id, project_key)` pair.
Applying it reconciles saved services, declared team grants, publisher groups,
and exact publisher grants in one PostgreSQL transaction. A failed apply rolls
back all of those changes.

```http
PUT /v1/projects/example/configuration
Authorization: Bearer <person-access-token>
Content-Type: application/json

{
  "team_id": "team_...",
  "source_fingerprint": "<64 lowercase hex characters>",
  "expected_revision": 0,
  "configuration": {
    "oauth": true,
    "webhooks": {
      "payments": {"service": "app", "path": "/hooks/payments", "provider": "stripe"}
    },
    "publishers": {"production": {"description": "externally operated replicas"}},
    "services": {
      "app": {"target": "app", "public_url": {}},
      "api": {
        "publisher": "production",
        "target": "http://api.internal:3000",
        "access": {"team": true}
      },
      "web": {
        "publisher": "production",
        "target": "http://web.internal:3000",
        "public_url": {"domain_id": "domain_...", "hostname": "preview.example.com"}
      }
    }
  }
}
```

The example's `api` is private HTTP. Only `public_url` selects public HTTPS.
The protocol defaults to `http`, the publisher to `local`, and the saved name
to the service key. `local` cannot be declared as a named publisher group.
Named groups imply publisher pooling. Public group services use stable shared
saved public URLs authorized through the existing domain and hostname rules.

## apply boundary

The CLI evaluates project configuration locally. It sends a normalized value,
not a TypeScript file. Public HTTP targets are HTTP/HTTPS origins without
userinfo. Literal private targets normalize to `host:port`; a private HTTP
origin uses port 80 or 443 when omitted. HTTPS requires the explicit target TLS
snapshot; HTTP forbids one. Transport/trust remains independent of visitor TLS. Targets and
the normalized document are encrypted with control's storage key and included
in storage-key rotation. Visitor inventory never contains these targets.

Local targets may also be `app` (HTTP only), `compose:SERVICE:PORT`, or
`docker:CONTAINER:PORT`. Control validates and retains these descriptors; only
the local runtime resolves them. Descriptor names are bounded identifiers, not
filesystem paths or command text. Named groups require actual origins or
`host:port` addresses usable from their replicas.

All protocols use `target_tls` for publisher-to-target trust. Its fields are
`hostname`, optional `ca_pem`,
and `digest`. The PEM snapshot contains CA certificates only and augments the
publisher's system roots. Compute the digest as lowercase hex SHA-256 of
`"tnl-target-tls/v1\x00" + hostname + "\x00" + caPEM`. The applying client obtains
this snapshot from `target.tls`, whose optional fields are `server_name` and
project-relative `ca_file`. Saved private-service metadata retains the equivalent
approved target trust and revision. The publisher selects direct TLS or native
PostgreSQL/MySQL negotiation from the service protocol. Service-level `tls` and
target trust attached to a plaintext HTTP origin are invalid. Omitting target
trust never disables managed visitor TLS. Visitors do not receive target trust
through run selection. Control never reads a CA file or fetches a bundle URL.

Local realization captures a managed endpoint too. `worktree_label` supplies its
readable DNS label; `worktree_key` and the project source bind the allocation to
one worktree and membership. An optional `domain_id` selects a ready team domain;
otherwise control captures the default. Local plans cover the exact hostname,
and later default changes preserve that hostname, port, domain and plan. Saved
ad-hoc creation accepts the equivalent fields in `placement`. Publisher reads
return `source` for exact local project/service/worktree matching. No private
creation or realization creates a public URL row or an application-stream key.

Public URL settings are retained in `public_url`:

```json
{
  "domain_id": "<domain-id>",
  "access": { "mode": "restricted", "ip": ["192.0.2.0/24"] },
  "limits": {
    "http": { "total": 100, "concurrency": 4, "rate": { "count": 10, "per": "1s", "burst": 20 } },
    "traffic": { "connections": 5 }
  },
  "ephemeral": false
}
```

An omitted remote hostname uses the service `name` beneath the selected domain.
The complete public access policy is compiled through the existing encrypted IP
grant and mode contracts. HTTP limits travel in the publisher assignment;
control binds declared traffic limits when creating each publish run, including
when a publisher submits a different selection. Policy and limit changes keep
the saved URL ID and replace the affected publisher grants.

Named groups require saved pooled URLs and reject `ephemeral: true` explicitly.
Local deferred declarations retain it for their per-worktree runtime.

## root integration declarations

`oauth` is a boolean and `webhooks` is a map of endpoint names to
`service`, `path`, `provider`, optional `delivery`, `methods`, and `source_ips`.
They are part of the normalized document, hash, revision, encrypted storage, and
manager status. An OAuth-only or webhook-only edit advances the desired revision
without replacing unrelated group grants or public URLs.

Webhook declarations use the existing provider, path, method, and source-policy
validation. Their normal form matches app registration: provider-specific
delivery defaults, `POST` when methods are omitted, and sorted method/source
lists. An explicit empty `source_ips` list is invalid; omitting it preserves the
provider-catalog policy.

Each endpoint names a declared local HTTP service with `public_url` enabled.
App listeners, addresses, Compose services, and Docker containers are eligible;
unknown, private, and remotely assigned receivers are rejected. The existing local
handler owns delivery when the app runs. Applying declarations does not fetch
provider catalogs, create OAuth/webhook public URLs, or provision a handler on
an externally operated group. Root declarations are not included in remote
group service assignments.

The complete wire configuration includes `oauth` and `webhooks`, even when they
are `false` and `{}`. `expected_revision` is required on every apply, including
a retry of already-applied content. Source-fingerprint checks precede content
replay handling.

The CLI derives `source_fingerprint` from the credential-free repository origin
and the exact project-relative source location. That identity must be stable
across clones and Git worktrees; absolute checkout paths and worktree names do
not belong in it. Control rejects the same project label with another source
fingerprint, including otherwise identical configuration.

The first apply uses revision `0`. A changed document requires the current
revision. Retrying already-applied normalized content returns its current
revision without creating resources or grants again. A stale changed document
returns `409`. Read `GET /v1/projects/{project_key}/configuration?team_id=...`
to obtain the current desired state and member acknowledgements.

Only a current team owner/admin can apply, read the complete configuration, or
issue group enrollment credentials. Changing a target or trust snapshot closes
old publications and revokes their grants before replacing assignments. Moving
a service between groups retains its saved service ID while revoking the old
group's grants. Removing a group revokes its members and bootstrap credentials.
All local declarations defer allocation to the per-worktree runtime. Applying
them does not allocate shared local resources or combine worktree previews.

## local realization and ownership

`PUT /v1/projects/{project_key}/local-services/{service}` realizes one local
declaration. Send `team_id`, `source_fingerprint`, `worktree_key`, and the
normalized service `configuration`. For a public service, also send the exact
`public_url_id` allocated by the caller's normal app runtime. Member URLs must
match the caller's membership. Shared URLs are accepted only for the caller's own
personal team when current namespace authorization selects shared scope on a
custom domain owned by that team. Organization shared
URLs and another member's or team's URLs are rejected. Private services
are allocated by this endpoint with worktree-scoped saved names. A retry returns
the same ID; a same-name saved service is never adopted.

`GET /v1/projects/{project_key}/local-services/{service}?team_id=...&source_fingerprint=...&worktree_key=...`
reads that exact private binding for a currently authorized private visitor.
It returns the same `LocalProjectService` identity and approved protocol/TLS
metadata as realization, without configuration, targets, or credentials.
The read never allocates or updates a service and needs no manager permission.
Missing or unauthorized bindings return `404`; an authorized binding with a
different source fingerprint returns `409`. Other teams, projects, worktrees,
and saved names are never searched as a fallback.

After automatic ephemeral URL expiry, the runtime may bind its replacement exact
URL ID to the same source/worktree entry. A healthy binding cannot be replaced
this way.

Realization records provenance before the first apply. Later applies reconcile
those exact resources, including creating or removing the configuration-owned
team visitor grant. Other visitor grants remain independent. Removing a local
declaration retires its realized resources; a fresh listener is needed when the
public resource's hostname, domain, name, or lifetime setting changes. Once a
configuration exists, startup must send its current local declaration. Startup
does not apply remote group changes.

Normal definition/delete APIs and revocation of configuration-owned visitor or
group publisher grants return HTTP `409` with code `project_managed`. Change the
declaration and apply it. Additional visitor grants may still be created and
revoked. Revoking a publisher identity or group member remains an immediate
operational action. An unrelated apply does not replace an already-revoked grant.

`GET /v1/projects/{project_key}/public-metadata?team_id=...` provides browser
preparation with `source_fingerprint` and `services`, each containing only
`service`, `public_url_id`, and `hostname`. Managers see the project's public
services, including realized local worktree URLs before or after first apply;
other signed-in callers see only services they may visit. Separate worktree URLs
may repeat a service key with distinct immutable IDs. The complete
configuration endpoint remains manager-only.

Local `http` settings are retained in the normalized wire document. Named
publisher groups reject `http` settings, including readiness and path mounts,
until their worker contract can execute them. Public origins use the runtime's
`NormalizeTarget` rules: an explicit port and no trailing slash for HTTP/HTTPS
origins. Private HTTP origins remain byte-stream address shorthand, with default
ports 80 and 443 and no implied publisher TLS.

## visitor assignment release

`DELETE /v1/visitor-ingress-assignments/{connector_session_id}` releases only the
signed-in person's exact device assignment. It is retry-stable, frees a pending
reservation immediately, and cannot invalidate a sibling assignment. Releasing a
bound session revokes it and closes its admitted streams; active rechecks observe
that revocation. Clients should release unused or trust-failed pending assignments
and release their bound session when shutting down.

For a missing slot, call
`POST /v1/private-services/{private_service_id}/ingress-assignment` with `device_id`
and an optional `exclude_ingress_id` for the healthy sibling. It returns one setup
and requires capacity on only one live, non-draining process. The exclusion is a
placement hint, not authorization; both singular renewal and pair startup require
the current person, enrolled device, and private service grant. Pair startup still
reserves two distinct addresses atomically. Single-slot exhaustion returns `503`
with `placement_unavailable`; release unused reservations before retrying.

## replica lifecycle

1. A person creates a bounded enrollment with
   `POST /v1/projects/{project_key}/publisher-groups/{group_name}/enrollments`.
   The body contains `team_id`, `max_members` (1–256), and `expires_in`
   (60–86400 seconds).
2. Each replica creates and persists its own Ed25519 key before posting its
   public key and enrollment credential to `POST /v1/publisher-groups/enroll`.
   A retry with the same key returns the same identity without consuming another
   enrollment use. One key cannot enroll into another group.
3. The running replica uses the signed `inspect` and `start` actions at
   `POST /v1/publisher-runtime`, with its immutable group ID as `scope_id` and a
   fresh random `process_run_id`. The assertion binds the action, run and expected
   epoch. Start returns the two-minute group lease and records control-observed
   egress once for the replica, independently of its number of services. Its
   existing polling loop uses `renew` to refresh that evidence and lease. See
   [publisher egress](../../../docs/maintainers/publisher-egress.md) for the proof
   encoding, retries and replacement fencing.
4. `GET /v1/publisher-groups/assignments`, authorized by that lease, returns only
   the replica's group's services, targets, trust revisions, and exact native
   publisher grant IDs. The replica exchanges an assertion for each grant using
   the normal authority publisher-token API and runs the existing public/private
   publish lifecycle. Private run keys are independently generated per run.
5. After reconciling workers, the replica posts `revision`, `configuration_hash`,
   and `healthy` to `/v1/publisher-groups/ack`. Control rejects acknowledgements
   for replaced revisions. Lease expiry makes member health unobserved.
6. After joining its workers, the replica sends `stop` for its current run and
   epoch. Control retains its last observation with offline lease status. A crash
   becomes offline at lease expiry without a cleanup request.

Provisioning and verification do not call this runtime interface. The low-level
`/v1/publisher-groups/lease` exchange still supports assignment preflight, but
rotating that token does not record egress or advance the runtime epoch.

A team manager can revoke one replica with
`DELETE /v1/projects/{project_key}/publisher-groups/{group_name}/members/{publisher_identity_id}?team_id=...`.
The revocation closes that member's public and private runs and invalidates its
lease and native grants in the same transaction. Other group members continue
serving. Group description changes, enrollment, and member revocation append
`group.update` service-audit facts without configuration or target payloads.
The general publisher-identity revocation API records the same group fact when
the revoked identity belongs to a group.

`controlclient.Client` exposes these operations. `native.NewGroup` accepts the
replica's persisted member/key, control URL, native control, group control, and
assertion exchanger. `Poll` returns assignments; `Service(assignment)` returns
the existing exact-grant `*native.Native`; `Acknowledge` reports the polled
revision/hash and health. The adapter keeps an independent assignment snapshot
so callers cannot widen an assignment by editing returned values.

`internal/grouppublisher.Runtime` owns the deployed replica lifecycle, including
the explicit runtime start, renewal and stop. `native.NewGroup` remains a scoped
assignment adapter; constructing it or polling during preflight does not claim
that a remote process has started.

The normalized document is bounded to 512 KiB, 128 services, 32 webhook endpoints,
and 32 named groups.
A project permits at most 256 active enrolled replicas across its groups.
