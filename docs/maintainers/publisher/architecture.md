# publisher architecture

The publisher owns one publication's visitor TLS, certificate installation,
publisher connections, visitor admission, and target forwarding. App and group
orchestration compose that reusable runtime. They do not belong in command
handlers or in the publication-serving root.

## implementation map

Paths below are relative to `internal/publisher`.

| Owner                                                                | Responsibility                                                                                                                     |
| -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Root package                                                         | Public and managed visitor frontend, certificates, publisher connections, live authorization, drain, and request observations      |
| `app`                                                                | Registration manager, leases, journal/events, configured workers, exact-run observations, and automatic readiness                  |
| `local`                                                              | Native project process, descriptor/launch ownership, worker/API construction, registration/invocation handoff, and joined shutdown |
| `localapi`, `localapi/protocol`                                      | Private scoped HTTP serving and bounded app/CLI request/assignment protocol                                                        |
| `invocation`                                                         | Reusable publish/install selection, project metadata, native grants, local realization, previews, and companion workers            |
| `identity`, `identity/credentialfile`                                | Defining native signing adapter, enrollment/grants, and private portable identity files                                            |
| `setup`                                                              | Explicit installation, enrollment journals, privileged handoff, and failed-install cleanup                                         |
| `managed`, `adhoc`                                                   | Managed private/service publication and temporary public URL allocation, respectively                                              |
| `group`, `runtime`                                                   | Applied assignment reconciliation and identity-bound runtime lease/egress lifetime                                                 |
| `target`                                                             | Immutable target capture, Docker/Compose identity, approved private plans and preflight                                            |
| `target/discovery`, `target/discovery/rdsroots`, `target/kubernetes` | Bounded AWS metadata, pinned RDS roots, and authenticated Kubernetes targets                                                       |
| `proxy`, `inspection`                                                | Local HTTP forwarding/mounts and bounded body-free protocol summaries                                                              |
| `integrations`                                                       | OAuth/webhook/alias worker election, selection, readiness, locks, and drain                                                        |
| `toolbar`, `browserapi`                                              | Development browser source/bundle and generated browser validators                                                                 |
| `deployment`, `deployment/aws`, `demo`                               | Offline infrastructure rendering, explicit AWS bootstrap, and demo composition                                                     |

Cross-role publisher signature verification lives in `internal/security/publisherproof`;
validated provenance lives in `internal/policy/publisherprovenance`. Installed job
storage and supervisor scheduling live in `internal/client/service`. Target TLS
mechanics live in `internal/transport/targettransport`. These owners are below
the app and invocation operations that use them.

`local` composes `app`, `localapi`, and `invocation.ProjectRuntime`. The API
imports app state and its protocol, never `local`. The publication-serving root
does not import app/group/invocation orchestration. `cmd/tnl` supplies selected
inputs, interactive authentication, browser opening, and semantic output callbacks;
the operation owns remote calls, retries, allocation, and cleanup.

## local identity and registration

`internal/client/project` selects and canonicalizes the configuration directory,
evaluates configuration once, and transfers that snapshot over the private owner
pipe. Runtime trust capture uses the resolved target, not another evaluation.
`LocalPublicationIdentity` and `LocalWorktreeKey` need neither Git nor an origin;
initializing Git, changing origin, or changing branch keeps the local identity.
Portable apply and workload manifests use the separate Git-based `SourceIdentity`.

One owner retains one evaluated configuration for the canonical project and
client-state root. Discovery and named leases compare the complete digest,
including provenance and server/team selection. After changing configuration,
restart the project's apps and named local publishers together. A mismatched
owner fails with restart instructions.

The native owner binds loopback HTTP and writes a descriptor in a verified
mode-0700 state directory. Apps receive service-scoped capabilities; ad-hoc
callers receive invocation-scoped capabilities. Owner credentials, signing keys,
and control sessions remain native. See the
[private registration contract](../../../internal/publisher/localapi/readme.md).
Connector owner IPC is a different capability boundary.

Preparation reserves ownership without claiming a listener. SDK registration
acknowledges the actual bound listener, including port 0, not readiness or
provisioning. Replacement cancels and joins the old publication before starting
another. Unregister, app exit, and expired renewal stop publication. The manager
joins integrations and drains publishers before exiting after its cleanup grace;
it never starts or terminates application processes.

Registered, routable, and ready are separate facts. Each routable public run gets
one automatic readiness budget of two minutes, including probes and backoff.
The GET uses normal DNS/TLS, no redirects, headers only, and a five-second
deadline. The default path `/` accepts 2xx, never tnl diagnostics. Retry delay
starts at 500 milliseconds and doubles to two seconds. A proof binds the exact
run and path and is removed before target forwarding. Observation acceptance
checks registration, nonzero run, target, owner, and path together.

Success or budget exhaustion stops that checker. Repeated ready events do not
restart it. Target replacement invalidates the observation without granting a new
budget; an active checker can use its remaining budget. Drain/replacement/shutdown
cancel and join it. `Workers.checkService` returns whether its captured result was
accepted, not a later snapshot's readiness. `tnl wait` can check again; failure
leaves publication running. Ad-hoc readiness is routability, not a public GET.

`tnl status` reads local observations; server scope fetches saved state for known
public URL IDs. `tnl watch` resumes an exclusive bounded local cursor; expired
cursors fail with an authored diagnostic. `tnl ping` uses no owner proof. The
journal survives restart without credentials, bodies, or OAuth state.

## allocation, groups, and target ownership

A saved public URL outlives normal publish runs. Each new run increments its run
number and gets two connection slots on different relay services. Ad-hoc
allocation instead binds one invocation ID and namespace grant to one temporary
URL. The registration handler owns cleanup after allocation, then transfers it
to the worker. Canceled setup and lost registration acknowledgments stop and
join cleanup. A failed process leaves ephemeral expiry as the final boundary.
No worker allocates a second URL for the same prepared handle.

Explicit publisher files fail closed when invalid. App calls never implicitly
install a grant. `pkg/tnl.Open` owns its listener and temporary URL, using the
selected native publisher identity. Python starts ASGI lifespan and a port-0
listener before registration; unregister joins native drain before ASGI shutdown.
Its status poller observes the exact ready registration/run without a public GET.

Named groups pull only control's assigned revision and acknowledge that revision
and hash. Multiple members have independent keys, runs, assignments, and durable
certificate scopes. New visitors may select another ready member; admitted bytes
never migrate. Infrastructure owns capacity and replacement. Preserve the whole
replica-private identity/certificate directory after issuance begins; the signing
key alone cannot restore missing TLS keys. Runtime SQLite and its wrapping key
remain task-local. See [group lifetimes](publisher-groups.md),
[applied revisions](../control/applied-projects.md), and
[client state](../development/client-state.md).

Target captures pin the selected container/resource identity for each new
connection. A replaced target never receives replayed bytes. Host-side Compose
discovery checks exact project/worktree/service/container identity; a publisher
inside Docker uses its configured private target. tnl neither creates app
processes nor injects cross-container app credentials. AWS discovery runs with
the publisher's selected credentials and network, not control's.
See [target discovery](aws-target-discovery.md), [bootstrap](aws-bootstrap.md),
[generation](publisher-generation.md), [provenance](publisher-provenance.md), and
[egress evidence](publisher-egress.md).

## integration urls and aliases

`integrations` elects one worker per saved project integration URL using shared
client state. It reuses the publication runtime for certificates, visitor TLS,
policy, and publisher connections. A prepared run proxies a captured local target
or a publisher-owned handler. Header observers run before response headers reach
the visitor without disabling compression. Revision changes cancel and join the
old preparation; hostname locks stay held through drain and cleanup.

Aliases select one local HTTP entry service with an explicit `publicURL` block.
Their names may contain several DNS labels. Selection is persistent and separate
from readiness: registration never takes an override back, `use` requires a ready
receiver and explicit takeover of a live owner, and `release` returns selection
to the primary checkout even if stopped. Every request binds selection revision
and destination tunnel/run. A handoff rejects new work at the old publisher while
admitted requests finish. Alias runs do not inherit preview shares or feedback.
Framework metadata admits only aliases reaching the entry or mounted service.

OAuth uses a bounded, ten-minute, single-use state digest. It records the
initiating public URL/run separately from the destination app. An alias-origin
callback returns to the initiating alias for its host-only cookies. The final
single-use return hop rejects a replaced alias or app run. The application still
validates state/PKCE and exchanges the code. Control and relay never receive
OAuth state or callback bodies. tnl does not rewrite app cookies left on a stable
alias hostname.

Webhook declarations and receiver selection are separate. All declarations for
an endpoint must agree on service, exact escaped path, methods, and source policy;
SQLite rejects conflicting names/paths atomically. Ingress admits the union of
source ranges; the publisher checks source/path/method before reading a body.
Only ready, live tunnels of the named service receive traffic. Fanout sends the
same bytes/signature input to every receiver and acknowledges only when all
return 2xx. No local retry or replay journal exists. GET/HEAD/OPTIONS verification
requires matching bounded responses. Selected delivery uses one explicit live
claim; force-selection may replace it while dispatched requests finish.

Webhook names retain their 64-bit, 13-character HMAC suffix; OAuth uses its
separate purpose and six-character suffix. Changed declarations drain before a
new run resolves source ranges. Control's bounded documented-feed catalog and the
client's ETag/last-good cache cannot turn an unavailable feed into unrestricted
policy. Overrides replace catalog ranges. Lookups are not delivery measurements.
Status reads declarations, receiver claims, saved hostnames, and readiness in one
SQLite snapshot; a live provisioning owner remains selected but is not ready.
Keep request bodies, provider signatures, OAuth state, and credentials out of it.

For visitor TLS, admission, request streaming, and the retry boundary, see
[transport architecture](../transport/architecture.md). For app metadata and SDK
exports, see [development architecture](../development/architecture.md).
