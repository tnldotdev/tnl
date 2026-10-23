# workload sessions

control authorizes GitHub Actions, Vercel functions, Fly Machines, and configured
OIDC workloads as visitors. a workload never becomes a human identity, enrolls
a human device, receives a publisher grant, or creates a control session.

## bind policy during apply

`tnl apply` stores `configuration.workloads[NAME]` alongside the saved project
revision. each policy has a provider, trusted issuer/key endpoint/audience,
provider identity constraints, service keys, and a duration in whole seconds.
the default window is one hour; the hard limit is six hours. policy service keys
must select named publisher assignments. exchange captures those assignments'
exact saved service IDs.

GitHub declarations use `provider: github` with the existing nested `github`
workflow constraints. apply binds immutable repository and owner IDs,
`workflow_ref`, `ref`, events, and optional environment and reusable
`job_workflow_ref` constraints.

only a current team owner or admin can apply. the native apply path infers an
omitted repository from the GitHub origin, reads immutable metadata with existing
`gh api` authentication or the public GitHub API, and submits that metadata as a
trusted operator claim. private first binding needs metadata access. this path
never starts GitHub login. an unchanged repository reuses its saved IDs, including
when the operator no longer has GitHub authentication. a renamed or recreated
repository cannot authenticate using a matching name alone.

source identity remains separate from workload principal scope. the request
selects a team ID or exact team-name selector in `team_id`, project key, source
fingerprint, and workload name. control resolves the selector and checks its
saved project. assertion claims cannot create a policy or establish a provider
binding.

## provider trust and acquisition

the TypeScript Vercel declaration is:

```ts
workloads: {
  storefront: {
    provider: "vercel",
    teamId: "team_...",
    projectId: "prj_...",
    environment: "production",
    services: ["inventory", "models"],
  },
}
```

trusted setup also needs the real team slug and project issuer mode. provide
`teamSlug` and `issuerMode: "team" | "global"` explicitly, or give apply
`VERCEL_TOKEN` access to the project's `/v9/projects/{id}` and team's `/v2/teams/{id}`
metadata. unchanged applies can reuse saved issuer metadata. team mode derives
`https://oidc.vercel.com/TEAM_SLUG`; global mode uses `https://oidc.vercel.com`.
the audience is `https://vercel.com/TEAM_SLUG`. verification requires signed
`owner_id`, `project_id`, `owner`, `environment`, and consistent `sub` claims.
the issuer is never inferred from an unverified JWT or `.vercel/project.json`.

Vercel functions acquire tokens inside a request with
`getVercelOidcToken()` from `@vercel/oidc`. version 4 reads request context,
then `VERCEL_OIDC_TOKEN_FILE`, then `VERCEL_OIDC_TOKEN`. do not cache tokens or
call the request helper at module initialization. the Go acquisition adapter
accepts a callback or uses the documented file-before-environment precedence.

Fly declarations use `provider: "fly"`, exact `org`, `orgId`, `app`, `appId`,
and optional `machineId`. issuer and JWKS are derived only from saved `org`:
`https://oidc.fly.io/ORG` and its `/.well-known/jwks`. the audience is
`https://fly.io/ORG`. the machine acquires a signed, text/plain JWT with
`POST http://localhost/v1/tokens/oidc` and `{"aud":"https://fly.io/ORG"}` over
the fixed `/.fly/api` Unix socket. control checks signed org/app IDs and names,
machine ID, machine name, and consistent `sub`. `FLY_APP_NAME` and
`FLY_MACHINE_ID` cannot authorize an exchange.

generic `provider: "oidc"` requires explicit HTTPS `issuer`, `jwksUrl`,
`audience`, and nonempty exact string `claims` selectors. acquisition uses a
configured `tokenFile` or an SDK callback. `AssertionSource` requires exactly
one assertion, token file, or callback. files are bounded and reread; an empty
or unreadable configured file fails without fallback. human OIDC authentication
continues through its separate issuer/session engine.

provider references: [Vercel token claims and acquisition](https://vercel.com/docs/oidc/reference),
[Fly trust and claims](https://fly.io/docs/security/openid-connect/), and
[Fly token wire format](https://docs.fly.io/api/machines/tokens/request-an-oidc-token.md).

## exchange and renew

the authority API serves:

| method   | endpoint                                   | purpose                                                      |
| -------- | ------------------------------------------ | ------------------------------------------------------------ |
| `POST`   | `/v1/workload-sessions/exchange`           | exchange a signed provider assertion and ephemeral-key proof |
| `POST`   | `/v1/workload-sessions/{session_id}/renew` | renew the visitor lease                                      |
| `DELETE` | `/v1/workload-sessions/{session_id}`       | revoke the workload session                                  |

for GitHub, the issuer is exactly `https://token.actions.githubusercontent.com`; signing
keys come only from its fixed JWKS URL. the audience is the canonical HTTPS
control origin. verification requires RS256, one exact audience, bounded typed
claims, fresh `iat`, `nbf`, and `exp`, and signed `run_id`, `run_attempt`, and
`check_run_id`. `GITHUB_JOB` and an invented job ID are not job identity.

the canonical request is
`{team_id, project_key, source_fingerprint, workload, nonce, assertion, public_key, signature, services?}`.
there is no request-selected issuer or provider override. the native process
generates one in-memory Ed25519 key and random session nonce. its exchange proof
binds the assertion digest, team selector, project, source fingerprint, nonce,
explicit workload name, and optional service subset. `workloadproof.Exchange`
owns the exact digest encoding. the GitHub execution fence is the team/project/repository/run/attempt/check-run
tuple. the first successful transaction fixes the key, policy, subset, service
IDs, and absolute deadline. a different key or a broader subset cannot take
over that execution. concurrent connections can use the same session.

the signature is Ed25519 over SHA-256 of the UTF-8 compact JSON array
`["tnl-workload-exchange/v1", team_id, project_key, source_fingerprint, workload, nonce, assertion_digest, services]`.
`assertion_digest` is unpadded base64url of SHA-256 of the exact assertion bytes.
`services` is lexically sorted, or JSON `null` when omitted. `public_key` and
`signature` are unpadded base64url. a nonce is 16–128 base64url characters.

session responses identify their `provider` and workload-session `subject`.
GitHub responses additionally require
`github: {repository_id, repository_owner_id, run_id, run_attempt, check_run_id}`;
each ID is a positive decimal string of at most 20 digits. Vercel, Fly, and
generic OIDC responses omit `github`. top-level GitHub run fields are not part
of the common session. responses also contain the control-verified identity and
policy `binding`. the native client validates the provider variant and rejects
renewals or assertion attachments that change the binding, provider, subject,
or GitHub execution metadata.

GitHub JTI replay consumption and session creation commit atomically. an identical
assertion and key recover a lost response, including the original encrypted
credential. another assertion with the same JTI cannot move to another session.
exchange retries never renew the lease or extend the absolute window.

Vercel, Fly, and generic OIDC tokens may be reusable. their session fence is the
team/project/nonce tuple. retries require the original key, workload, subject,
and service scope. another process can create a separately key-bound session
with a new nonce while its signed identity and saved policy remain valid.
continuous applications acquire a current provider assertion and create a new
session after the old fixed window; renewal never extends the old window.

the lease lasts at most 90 seconds. renew after 30 seconds using the returned
`renew_after`; renewals retain the fixed absolute deadline. policy removal or
changed claim constraints revoke issued sessions in the apply transaction.
service narrowing removes issued rights permanently; later additions never
expand an existing session. apply and exchange serialize on the same team lock.

## use visitor capabilities

the control API accepts the workload credential only at:

| method   | endpoint                                                        |
| -------- | --------------------------------------------------------------- |
| `GET`    | `/v1/workload/services`                                         |
| `POST`   | `/v1/workload/services/{service_id}/authorization`              |
| `POST`   | `/v1/workload/services/{service_id}/ingress-assignments`        |
| `POST`   | `/v1/workload/services/{service_id}/client-certificate`         |
| `POST`   | `/v1/workload/services/{service_id}/run`                        |
| `GET`    | `/v1/workload/ingress-assignments/{session_id}/transport-trust` |
| `DELETE` | `/v1/workload/ingress-assignments/{session_id}`                 |

inventory contains each authorized configuration service key, its exact saved
service ID, protocol, and visitor endpoint. EKS services also expose the approved
nonsecret `kubernetes_auth: {provider: "eks", cluster, region}` descriptor for
native client authentication. human visitor inventory exposes the same hint.
neither inventory exposes RDS selectors, publisher target addresses, CA bundles,
or application credentials. the job cannot read management configuration.

HTTP uses the same key-bound native owner and session as the other protocols.
the SDK no longer mints a separate HTTP-only credential. public native access
can use the session's service-scoped client certificate; SDK access uses the
authenticated local connector for both public and services. see
[platform access integration](../connector/platform-access.md) for verified owner selection
and authenticated rotating-assertion attachment.

certificate issuance requires a CSR signed by the already-bound workload key.
the service-scoped certificate and private connector handle expire at the fixed
session deadline, at most six hours. they prove key possession; every admission
and active authorization still checks the current renewable 90-second lease,
service rights, revocation, and infrastructure deadlines. renewing a lease does
not replace the certificate or disconnect admitted streams. an expired lease
cannot admit a new stream even while its certificate remains valid. active
streams recheck within 30 seconds and close by their last successful decision's
deadline if control is unavailable. cleanup may release only an exact owned
connector handle after session expiry or revocation.

`New` in `internal/connector/workload` owns the ephemeral key. `Exchange`, `Renew`,
`Revoke`, `ListServices`, `CheckService`, `CreateIngressAssignments`, and
`ServiceClientCertificate` return generated contract types. `SelectServiceRun`
returns the selected publisher run and approved protocol, trust revision, and
managed endpoint. `CreateIngressAssignment` replaces one failed connection slot,
excluding its healthy sibling's ingress. an idempotency key recovers only its
original still-unclaimed handles; it cannot renew their deadlines.

`Session`, `Subject`, `PublicKey`, and `Sign` let the native job runtime retain
execution state and prove connector key possession. `ClientTLSCertificate`
returns the service certificate with an opaque TLS signer. raw private keys do
not leave `workloadclient`. the caller owns the session's renewal and revocation
loop. `Exchange(ctx, team, project, sourceFingerprint, workload, assertion, services)`
uses the canonical exchange contract. a named workload and optional subset
select only that policy's exact service IDs; inventory never unions other
workloads or human membership.

## deploy without git

`tnl generate` writes `.tnl/generated/workloads.json`. package this nonsecret
manifest with the server artifact. it contains schema 1, canonical `server`,
`team` selector, `project_key`, `source_fingerprint`, `project_label`, a
`services` protocol map, and `workloads[NAME]` with provider, services,
`max_duration_seconds`, and `acquisition: {method, audience?, token_file?}`.
methods are `github-actions`, `vercel-oidc`, `fly-machine-api`, `callback`, and
`token-file`. it includes no target, policy authority, signing key, assertion,
human state, checkout path, or `.vercel` file dependency.

the native machine contract accepts
`runtime connections context --directory APP --workload NAME --workload-manifest PATH`
and the same flags for `start`. it loads the manifest directly without Git or
config evaluation. context has `workload`, and assertions go over stdin/private
IPC. the manifest selects policy and acquisition; control's saved policy grants
authority. fingerprints must match the applied source.

the Node SDK reads this same schema from its fixed `.tnl/generated/workloads.json`
artifact path for all workload protocols. it acquires a platform assertion
for each await or HTTP request, verifies identity through control, and selects a
bounded native owner by that verified identity and policy. explicit `TNL_WORKLOAD` or the server-only
`configureWorkload` source selects the saved policy. see
[sdk calls](../connector/platform-access.md#sdk-calls) for the
callback and token-file API, provider selection, cache, and error boundaries.
prepared native handles take precedence for all protocols.

## connect from a native job

`NewWorkloadControl` in `internal/connector/stream` supplies the production control adapter:

```go
control, err := tcpconnect.NewWorkloadControl(job)
if err != nil {
    return err
}
run, err := control.ResolveService(ctx, serviceID)
if err != nil {
    return err
}
return tcpconnect.Serve(ctx, listener, tcpconnect.Config{
    Control: control,
    ServiceID: serviceID,
    IdentityID: "",
    Protocol: run.Protocol,
    TrustRevision: run.TrustRevision,
    Endpoint: run.Endpoint,
    ServiceTLS: visitorTLS,
})
```

the caller owns the loopback listener. `visitorTLS` verifies the control-owned
service hostname with normal roots. opaque TCP uses the connector's TLS helper;
HTTP, PostgreSQL, MySQL and Kubernetes clients negotiate native TLS through the
connector. public native clients connect directly with the workload's
`ClientTLSCertificate`. public HTTP selects that certificate as its credential;
a denied workload never falls back to browser approval or another credential.

`tcpconnect.NewControl` remains the human adapter. both adapters implement
`ConnectorSigner`, `ConnectorAssignment`, and
`ResolveService`. `tcpconnect.Signer` carries `Subject`, `PublicKey`, and
`Sign`, with no raw signing key. `NewControlWithConfig(ControlConfig)` exposes
the `Signer`, `Assignment`, `Resolve`, `Release`, and `Close` hooks for native
connection owners. `Serve` closes its adapter and releases only its own handles;
it does not revoke a shared workload session.

## subject and data-plane boundary

`tunnelv1.VisitorSubject` has exactly two validated variants:

```json
{"kind":"human_device","identity_id":"id_…","device_id":"vdev_…"}
{"kind":"workload_session","workload_session_id":"wls_…"}
```

`VisitorConnectorClaim.Digest` defines the subject-aware connector key proof.
the baseline stores a workload session foreign key separately from nullable
human identity/device foreign keys and enforces the exclusive variants.

the state APIs available to transport adapters are `AuthenticateVisitorConnector`,
`SelectVisitorServiceRun`, `AuthorizeServiceStream`,
`RecheckVisitorServiceStream`, and `AuthorizeVisitorServiceConnector`.
`VisitorSubjectAccess` and `AuthenticateVisitorSubjectKey` share current permission
and key checks across both variants. protocol version 1 carries the tagged
subject through private hello, acceptance, ingress HTTP projections, relay
forwarding, and the publisher's control request. removed human-only fields are
rejected. ingress binds the observed source and one-use assignment; the
publisher rechecks that subject, source, admitted grant revision, exact service
and run before opening the target. human visitors use the same transport path
with their actual enrolled device subject.

workload audit rows identify the session; its durable execution references identify
the run, attempt, and check-run. authenticated trace-only attributes carry the
same references. raw assertions, session credentials, and application credentials
are excluded.

## retain workload history

control and standalone run workload cleanup immediately at startup, drain
available batches, then wait one minute after an empty or failed sweep. each
iteration has a five-second deadline and removes at most 1,000 rows from each
of nine relations. phases commit separately, in dependency order; retries keep
committed progress. concurrent workers skip locked rows. cleanup counts and
failures use the existing cleanup metrics with kind `workloads` and worker log.

workload history follows service audit's 30-day retention:

- audit events remain for 30 days after their event time;
- GitHub JTI/assertion digests remain for 30 days after assertion expiry;
- certificates remain for 30 days after certificate expiry and until no direct
  visitor references them;
- connector handles remain until both their fixed expiry and any revocation
  are over 30 days old, and until no private stream references them;
- ingress retry results remain until their session's absolute expiry, lease
  expiry, and any revocation are over 30 days old;
- sessions and their exact service snapshot remain until their absolute expiry,
  lease expiry, any revocation, and original assertion expiry are over 30 days
  old, and until all other session references have been removed.

private streams and direct visitors keep their existing 24-hour history after
their decision expires or they close. cleanup never deletes a live decision or
cascades through a subject, stream, certificate, or admission reference. rows
blocked by references are excluded before each batch limit, so they cannot
prevent later eligible rows from being collected. retained references can extend
the history window; retention is a minimum age, not an exact deletion deadline.

lease loss and revocation never shorten the replay fence. while any original
assertion can still be accepted, exchange retains its nonce/job ownership and
JTI binding. expired or revoked sessions cannot renew, attach an assertion,
recover a credential through exchange, or authorize visitors. after history is
removed, old credentials and assertions still fail closed. new sessions always
require a currently valid provider assertion and saved policy; GitHub execution
ownership is historical for the retention window, not a permanent job registry.

revoke and exact-handle release remain repeatable after expiry or revocation
while their stored ownership proof remains. once cleanup removes a handle,
release returns the existing service-access denial. once cleanup removes the
session, revoke and release return the existing workload denial (HTTP 403).
neither endpoint reports successful authenticated deletion from a missing row:
an opaque ID and an unverifiable old bearer cannot establish ownership. these
operations never recreate state or refresh retention on a repeated stop.

## saved cloud selectors

`ProjectServiceConfiguration.target_discovery` contains `type`, `region`, and
the exact `cluster` or `instance`, with the optional RDS `endpoint` selector.
`target` is empty for discovery and `target_tls` is absent. EKS requires
`kubernetes`; RDS requires the specified `postgres` or `mysql` protocol. control
validates and saves this descriptor and returns it only to the assigned
publisher. apply performs no AWS access or target/TLS fetch. the publisher's
provider discovery owns the resolved address, trusted TLS evidence, and protocol
verification before dialing.

## verify

the fresh PostgreSQL baseline and control's matching identity are
`tnl-control-fresh-v1-visitors`.
its connector constraint allows workload auth material through six hours;
current authorization remains bounded by the renewable lease. it requires the
same fresh-database, coordinated-baseline rollout as the assembled services work.

```console
mise exec -- task go:test:integration:workload
mise exec -- task go:test:integration:workload-runtime
mise exec -- task go:test:integration:workload-http
```

the target uses disposable PostgreSQL, real control/authority HTTP handlers,
signed local GitHub, Vercel, Fly, and generic OIDC JWKS fixtures with their configured issuers, and the
native adapter. state tests cover concurrent exchange/apply, replay recovery,
key/scope takeover rejection, narrowing, fixed expiry, public/private visitor
admission, and bounded history cleanup with retained replay and live-reference
fences. HTTP tests cover repeated expired/revoked deletion and denial after
ownership proof is collected. the runtime target uses two ingress and two relay
processes over
QUIC and TLS/TCP, publisher-owned service TLS, public mTLS, private/public HTTP
streams, and a native PostgreSQL client. it crosses two real 90-second lease
cycles with the same key and connections, then checks fixed expiry, lease loss,
active revocation, subject spoofing, and connector replay. it takes about four
minutes with both transports running in parallel and needs Docker and Pebble.
