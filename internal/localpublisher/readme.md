# native project owner

One native process owns app registrations, named CLI leases, publication workers,
and readiness proofs for one canonical project and client-state root. Host
placement listens on `127.0.0.1` with an assigned TCP port. The HTTP contract is
`api/local-publisher/v1/openapi.yaml`; generate only this contract with:

```sh
mise exec -- go generate ./pkg/api/localpublisherv1
```

## private discovery

`privateprotocol.DescriptorPath(stateRoot, projectRoot)` selects
`<stateRoot>/runtime/owner-<first 24 hex characters of sha256(projectRoot)>.json`.
The state root and runtime directory are verified through clientstate's private
file helpers. Directories must be mode `0700`; descriptors must be regular files,
mode `0600`, owned by the current user. Reads reject symlinks and path replacement.
Writes replace the descriptor atomically; an old owner cannot remove its
replacement's descriptor during shutdown.

The descriptor and hidden endpoint commands return this JSON shape:

```json
{
  "version": 1,
  "url": "http://127.0.0.1:49152",
  "capability": "<64 lowercase hex characters>",
  "owner_id": "<32 lowercase hex characters>",
  "scope": "app",
  "service": "web"
}
```

`scope` is `owner`, `app`, or `invocation`. An owner descriptor has neither
`service` nor `invocation_id`; an invocation descriptor has only `invocation_id`.
Every request sends `Authorization: Bearer <capability>`. Requests reject any
`Origin` header, a different HTTP authority, or a non-loopback peer. POST bodies
require `Content-Type: application/json`, reject unknown fields and trailing
JSON, and are bounded to 64 KiB. The client does not use environment proxies or
follow redirects.

## routes and SDK mapping

| method and path                 | capability     | request and result                                                                                             |
| ------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------- |
| `GET /v1/health`                | any            | `204` after authentication                                                                                     |
| `POST /v1/capabilities`         | owner          | `{scope:"app",service}` or `{scope:"invocation",invocation_id}` -> endpoint descriptor                         |
| `POST /v1/prepare`              | app            | `{version:1,directory,service?,framework,owner,pid}` -> assignment                                             |
| `POST /v1/register`             | app            | `{version:1,registration_id,owner,target}` -> `204`; replaces the bound listener after joining the old worker  |
| `POST /v1/renew`                | matching scope | registration plus the current bound `target` -> `204`; extends the 20-second lease                             |
| `POST /v1/unregister`           | matching scope | registration plus the current bound `target` -> `204` after stop and join                                      |
| `GET /v1/status`                | any            | native snapshot; app/invocation capabilities see only their own service and publications                       |
| `GET /v1/events?after=<cursor>` | owner          | exclusive native journal events; expired cursors return `410`                                                  |
| `POST /v1/check`                | owner          | `{services?:[name]}` -> snapshot after fresh public checks                                                     |
| `POST /v1/leases`               | owner          | `{service,owner,pid}` -> registration with resolved private target; configured non-app services only           |
| `POST /v1/ad-hoc/register`      | invocation     | `{version:1,invocation_id,owner,pid,target,publisher_id,server_url?,allow_ip?,allow_all_ips?}` -> registration |

An assignment is
`{version:1,registration_id,service,hostname,public_url,project}`. Its `project`
is `projectmeta.PublicMetadata`, including protocol-specific service metadata.
Framework values are `node`, `bun`, `vite`, `next`, and `python`. Each application
generates its own 32-hex-character `owner` and reports its live process ID. The
owner ID in a request is distinct from the native process's descriptor
`owner_id`.

An SDK first requests `tnl runtime endpoint --directory <directory>
[--service <name>] [--state-dir <path>]`, then calls prepare and register. Its
endpoint capability is restricted to the selected app service. Renew and
unregister include the last registered target; before registration, target may
be omitted. Replacing a listener calls register with the new target. A `401` or
`runtime.registration_stale` requires new endpoint discovery, preparation, and
registration. The replacement process's `owner_id` and capabilities are new.

Ad-hoc callers select `--invocation-id <id>` instead of `--service`; they submit
the locally stored publisher identity ID, never an old publication bearer
credential. HTTP invocation allocation, worker execution, journal updates, and
cleanup use the same manager and worker implementation as configured services.

Problems are `{code,message}` with authored messages. Important codes are
`runtime.unauthorized`, `runtime.forbidden`, `runtime.owner_conflict`,
`runtime.registration_stale`, `runtime.cursor_expired`, and
`runtime.authentication_required`.

## parent CLI and sibling integration

The parent dispatch wires these command types and functions:

- `runtimeCommand.Endpoint runtimeEndpointOptions` -> `runRuntimeEndpoint`.
  The embedded `runtimeOptions` contains required `Directory string` and optional
  `StateDir string`; endpoint options add `Service string` and
  `InvocationID string`.
- `runtimeCommand.OwnerEndpoint runtimeOptions` -> `runRuntimeOwnerEndpoint`.
- `runtimeCommand.Serve runtimeOptions` -> `runRuntimeServe`.
- Named publication ->
  `runNamedPublish(ctx, projectConfiguration, stateDir, service, *publishOutput)`.
  `localpublisher.LeaseClient` renews and rediscovers replacement owners.

`runtimeConfigurePublication(ctx, database, project, service, *publisher.Config)`
is the admission/access integration hook. It runs for configured and invocation
workers before worker fencing wraps `PromoteVisitor`,
`AuthorizeVisitorCertificate`, and `AdmitRequest`.
`runtimeVisitorTLS(ctx, database, project, service)` supplies visitor TLS
credentials for public database readiness checks. Both hooks are installed by
the parent/access integration.

`runtimeAttachIntegrations(ctx, database, project, service, tunnel, *publisher.Config)`
attaches companion publisher lifecycles and returns their cancel-and-join function.
OAuth response recording is installed before this hook. A project requiring
OAuth, webhook, or alias companions fails with `IntegrationURLNotReady` until a
scoped companion lifecycle is installed. The current server enrollment boundary
accepts saved `app` URLs only; companion-purpose grant support belongs to the
server/parent integration. The owner never calls the old team-session companion
launchers.

`runtimeTargetResolver` implements `projectpublisher.TargetResolver` for exact
Compose/Docker discovery. Address targets have a complete host default.
`runtimeOwnerTransport` implements `projectpublisher.OwnerTransportResolver`
for owner placement. Container orchestration installs these resolvers; no
container name is guessed or private address substituted for a public probe.

## workers, readiness, and observations

`clientruntime.New` requires the open `*clientstate.Database`. Manager updates
use `CommitSnapshot`; direct and named publication updates share that database's
native journal. A snapshot contains `services`, `publications`, and one opaque
exclusive `cursor`. `status --all --output json` returns independent snapshots
under `projects`; it does not combine unrelated project cursors.

Status reads snapshots only. Wait calls the owner's check endpoint. HTTP checks
renew an in-memory, single-use proof for one exact publish run and readiness
path. The publisher verifies and strips that proof before forwarding. A public
HTTP request cannot assert readiness by setting the probe header itself. Checks
discard responses after owner, registration, target, run, or readiness changes.

`clientruntime.CheckPublicTCP(ctx, TCPProbeOptions)` and `ProbeTCP` are shared
with remote CLI checks. PostgreSQL and MySQL perform their public TLS
negotiation, Redis uses verified TLS and PING, and SSH requires a bounded public
SSH-2.0 banner. PostgreSQL/MySQL probes stop at verified protocol TLS; they do
not authenticate to the database or issue queries. These probes use the public
address, never the private target.

Configured workers use team sessions for saved-URL management and enrollment,
then pass the grant-scoped `publisheridentity/native.Native` adapter to
`publisher.Run`. Run creation uses scoped signing, not the team session.
Inspection policy includes mode, retention, and byte budget; summary observations
map directly into the native recorder. TCP saved addresses are reserved before
`projectmeta.NewService` emits metadata. Preview association and OAuth response
observation use the same worker lifecycle; the companion lifecycle hook joins
its workers before that lifecycle closes.
