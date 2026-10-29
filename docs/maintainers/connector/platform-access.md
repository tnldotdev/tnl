# platform access integration

provider workloads use the native connection owner for HTTP, PostgreSQL, MySQL,
opaque TCP, and Kubernetes. the SDK acquires a runtime assertion; authority
verifies it against saved policy. application protocols share native key,
session, renewal, and private IPC ownership.

## build-to-runtime manifest

run `tnl generate` in the source checkout and package
`.tnl/generated/workloads.json` with the application and matching native binary.
the manifest selects a saved policy and acquisition method:

```json
{
  "schema": 1,
  "server": "https://control.example.test",
  "team": "acme",
  "project_key": "storefront-<source-derived-key>",
  "source_fingerprint": "<64 lowercase hexadecimal characters>",
  "project_label": "storefront",
  "workloads": {
    "storefront": {
      "provider": "vercel",
      "services": ["inventory", "models"],
      "max_duration_seconds": 3600,
      "acquisition": { "method": "vercel-oidc" }
    }
  },
  "services": { "inventory": "http", "models": "postgres" }
}
```

the manifest contains no service IDs, targets, secrets, assertions, keys, human
state, or authority to grant access. native context/start load this bounded file
directly. runtime invocation needs no Git, configuration loader, or handle made
during the build. the manifest's explicit service subset prevents a later policy
addition from silently widening an older artifact.

## runtime identity and assertion attachment

`POST /v1/workload-sessions/identity` accepts
`{team_id, project_key, source_fingerprint, workload, assertion}`. authority
verifies the issuer, signature, audience, and current saved policy. it returns a
nonsecret `binding`, verified `assertion_expires_at`, and current policy service names. the binding covers the
canonical team, project, workload, source, and verified provider identity. token
timestamps and GitHub JTI can rotate without changing it. GitHub repository,
repository owner, run, attempt, and check-run IDs remain part of the identity.
the binding grants no visitor access and cannot replace key proof.

SDK caches select an owner only after this operation succeeds. they never decode
JWT claims to reuse a native owner. owners are bounded to 32 per SDK instance;
service name and assertion digest are not owner keys.

the native owner creates its ephemeral Ed25519 key and exchanges the assertion
with an explicit requested service subset. exchange retains its key and nonce
across a lost-response retry. session credentials remain native-private.

every later workload await or HTTP fetch acquires the caller's current assertion
and passes it over stdin or capability-authenticated local IPC. for a new exact
assertion or an expired native verification observation, native calls
`POST /v1/workload-sessions/{session_id}/assertions` with the session credential
and `{assertion, signature}`. the signature covers SHA-256 of compact JSON:

```json
["tnl-workload-attach/v1", "session ID", "assertion SHA-256 in unpadded base64url"]
```

authority verifies the assertion against current policy again. control compares
its verified immutable identity to the stored execution, verifies the existing
session key, and atomically consumes a GitHub JTI. retries may attach the same
assertion to its exact session; another key, job, or assertion with that JTI
cannot take it over. attachment cannot expand issued service IDs or extend the
session deadline. a denial does not poison another service's preparation.

an authenticated, key-proved request returns HTTP 410 when control confirms
that the session lease or fixed window expired. HTTP 403 remains a denial for a
revoked session, changed identity, or changed policy; it cannot trigger silent
replacement. a lost exchange retains its key/nonce until control confirms its
outcome, including expiry.

## sdk calls

```ts
import { tnl } from "@tnldotdev/tnl";

export async function GET() {
  const inventory = await tnl.connect("inventory");
  return inventory.fetch("/stock");
}
```

set `TNL_WORKLOAD`, or select the only policy matching one runtime provider hint
(`VERCEL=1`, `FLY_APP_NAME`, or `GITHUB_ACTIONS=true`). hints select acquisition;
control decides identity. ambiguous selections fail before acquiring a token.
`TNL_CONNECTION_HANDLE` selects a caller-owned prepared owner instead.

TypeScript's server-only `configureWorkload({name, token})` installs one fixed
callback that reads the current request. `{name, tokenFile}` selects a bounded
file. Python exposes `configure_workload(name, token=...)` and `token_file=...`;
callbacks may return a string or an awaitable string. the callback is invoked at
each workload await. neither API has a global current-token setter.

Vercel's pinned Node helper reads request context first, then a bounded runtime
token file or environment fallback, without development CLI refresh. Fly uses
the trusted audience and `/.fly/api`; GitHub uses the canonical control origin.
generic token files are reread without fallback after a selected file fails.

awaiting returns a coherent, non-awaitable protocol snapshot. synchronous reads
use an already prepared handle; they do not acquire or verify another caller's
assertion. await the handle at the current request boundary before creating a
new database client. a returned HTTP `fetch` resolves the current verified owner
for each invocation, including after owner recovery.

`prepared` reads and CLI `read` are local-only operations. they fail for an
unprepared sibling without provider, control, or listener work. async awaits use
the separate `prepare` operation over direct authenticated IPC. caller-prepared
CLI startup still prepares its selected aggregate before reporting ready.

the warm path retains an exact-assertion selector only until authority's verified
expiry. native assertion and service observations have a 30-second refresh bound
and are checked against the live session. in focused fixtures, one cold service
uses three helper processes (`context`, `identity`, `start`), followed by direct
IPC; ten warm requests add zero helpers and zero control calls within that
observation window. periodic renewal and rechecks still contact control. a new
assertion performs identity selection and authenticated attachment before reuse.

when Python delegates Fly assertion acquisition entirely to native code, Python
does not have the exact assertion bytes. it intentionally performs native
identity selection on every await, plus direct IPC acquisition/attachment; it
does not cache by workload name or decoded claims. request callbacks, token
files, Vercel fallback sources, and GitHub acquisition provide exact bytes and
can use the bounded verified selector cache.

## process, sessions, and listeners

the native process belongs to its application. human renewal has no one-hour
process cutoff. workload sessions default to one hour, have a six-hour maximum,
and retain 90-second leases renewed every 30 seconds. native process lifetime
and local IPC lifetime are separate from session authorization deadlines.

the authorized service-ID snapshot is separate from prepared listeners. only
the requested service opens ingress paths and performs verified TLS preflight.
service failure, policy narrowing, or a denied read does not stop other services.
renewal accepts a shorter control deadline and leaves valid listeners stable.

after fixed or idle-lease expiry, reusable providers need a fresh verified
assertion and a newly authorized session. the process retains its loopback
listener, but future accepts use new session adapters. accepted streams keep
their old subject; bytes and rights are never replayed into a replacement.
GitHub executions cannot replace their fenced key/session this way.

an OS-held lifetime lock distinguishes process death from an IPC timeout. SDK
recovery creates a replacement only after native proves that lock is released.
temporary read failures retain the existing owner. stop and revocation remain
idempotent for expired or already revoked sessions.

HTTP uses a reusable pool of at most eight connections, a bounded pending-call
budget, and at most four draining pool generations. pool keys include the opaque
native adapter `transport_id`, so a replacement session at the same address
cannot reuse an old session's TLS connection. old streams keep their original
bounds. requests retain application
headers, streamed upload bytes, response streams, and caller cancellation.
redirects are always manual. there is no SDK-imposed 30-second total-body abort
and no credential-driven application replay. managed TLS and control's current
authorization still bound admitted streams. MySQL SSL option objects are mutable
because drivers can normalize them; pinned mysql2 negotiation and hostname
behavior require real-driver qualification, not an options-shape test.

## publisher boundaries

applications supply their own authentication headers, which the publisher
forwards unchanged after visitor admission. installed publisher readiness proofs
remain run-bound and use the configured readiness path. see
[compose publisher](../../../deploy/publisher/compose/readme.md).

the PostgreSQL baseline identity is
`tnl-control-fresh-v1-practical-cutover`, at version 1. it includes verified
session bindings and removes the former HTTP-only credential storage. use a
fresh database and coordinated baseline rollout.

## local qualification

```console
mise exec -- task js:test:connections
mise exec -- task py:check
mise exec -- task go:test:connections
mise exec -- task go:test:integration:workload
mise exec -- task go:test:integration:workload-http
mise exec -- task go:test:integration:workload-runtime
```

these targets distinguish SDK contract fixtures, real native subprocess/IPC and
TLS fixtures, PostgreSQL-backed authority verification, and separated runtime
transports. they do not establish native process lifetime inside a deployed
provider sandbox. the retired no-native HTTP artifact check does not qualify
this boundary. see [local Vercel qualification](vercel-functions.md).
