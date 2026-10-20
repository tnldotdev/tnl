# workload sessions

control authorizes a GitHub job as a workload visitor. a job never becomes a
human identity, enrolls a human device, receives a publisher grant, or creates a
control session.

## bind policy during apply

`tnl apply` stores `configuration.ci[NAME]` alongside the saved project revision.
each policy contains exact repository and owner IDs, `workflow_ref`, `ref`, event
names, optional environment and reusable `job_workflow_ref` constraints, service
keys, and a duration in whole seconds. the default window is one hour; the hard
limit is six hours. policy service keys must select named publisher assignments.
exchange captures those assignments' exact saved service IDs.

only a current team owner or admin can apply. the native apply path infers an
omitted repository from the GitHub origin, reads immutable metadata with existing
`gh api` authentication or the public GitHub API, and submits that metadata as a
trusted operator claim. private first binding needs metadata access. this path
never starts GitHub login. an unchanged repository reuses its saved IDs, including
when the operator no longer has GitHub authentication. a renamed or recreated
repository cannot authenticate using a matching name alone.

source identity remains separate from job principal scope. the request selects
an exact team ID, project key, and CI name. control checks those scopes against
its saved project; assertion claims cannot create a policy or establish the
repository binding.

## exchange and renew

the authority API serves:

| method   | endpoint                                   | purpose                                                    |
| -------- | ------------------------------------------ | ---------------------------------------------------------- |
| `POST`   | `/v1/workload-sessions/github`             | exchange a signed GitHub assertion and ephemeral-key proof |
| `POST`   | `/v1/workload-sessions/{session_id}/renew` | renew the visitor lease                                    |
| `DELETE` | `/v1/workload-sessions/{session_id}`       | revoke the workload session                                |

the issuer is exactly `https://token.actions.githubusercontent.com`; signing
keys come only from its fixed JWKS URL. the audience is the canonical HTTPS
control origin. verification requires RS256, one exact audience, bounded typed
claims, fresh `iat`, `nbf`, and `exp`, and signed `run_id`, `run_attempt`, and
`check_run_id`. `GITHUB_JOB` and an invented job ID are not job identity.

the native process generates one in-memory Ed25519 key. its exchange proof binds
the assertion digest, team, project, explicit CI name, and optional service
subset. the execution fence is the team/project/repository/run/attempt/check-run
tuple. the first successful transaction fixes the key, policy, subset, service
IDs, and absolute deadline. a different key or a broader subset cannot take
over that execution. concurrent connections can use the same session.

JTI replay consumption and session creation commit atomically. an identical
assertion and key recover a lost response, including the original encrypted
credential. another assertion with the same JTI cannot move to another session.
exchange retries never renew the lease or extend the absolute window.

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

`internal/workloadclient.New` owns the ephemeral key. `Exchange`, `Renew`,
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
loop. a named CI policy and optional subset select only that policy's exact
service IDs; inventory never unions other CI policies or human membership.

## connect from a native job

`internal/tcpconnect.NewWorkloadControl` supplies the production control adapter:

```go
control, err := tcpconnect.NewWorkloadControl(job)
if err != nil {
    return err
}
run, err := control.ResolvePrivateService(ctx, serviceID)
if err != nil {
    return err
}
return tcpconnect.Serve(ctx, listener, tcpconnect.Config{
    Control: control,
    PrivateServiceID: serviceID,
    IdentityID: "",
    Protocol: run.Protocol,
    TrustRevision: run.TrustRevision,
    ManagedTLS: run.ManagedTLS,
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
`PrivateConnectorSigner`, `PrivateConnectorAssignment`, and
`ResolvePrivateService`. `tcpconnect.Signer` carries `Subject`, `PublicKey`, and
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
`SelectVisitorServiceRun`, `AuthorizePrivateServiceStream`,
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
`tnl-control-fresh-v1-services-oidc-company-managed-http-dns-egress-deployment-workload-visitors`.
its connector constraint allows workload auth material through six hours;
current authorization remains bounded by the renewable lease. it requires the
same fresh-database, coordinated-baseline rollout as the assembled services work.

```console
mise exec -- task go:test:integration:workload
mise exec -- task go:test:integration:workload-runtime
```

the target uses disposable PostgreSQL, real control/authority HTTP handlers,
signed local GitHub JWKS fixtures with the fixed production issuer, and the
native adapter. state tests cover concurrent exchange/apply, replay recovery,
key/scope takeover rejection, narrowing, fixed expiry, and public/private visitor
admission. the runtime target uses two ingress and two relay processes over
QUIC and TLS/TCP, publisher-owned service TLS, public mTLS, private/public HTTP
streams, and a native PostgreSQL client. it crosses two real 90-second lease
cycles with the same key and connections, then checks fixed expiry, lease loss,
active revocation, subject spoofing, and connector replay. it takes about four
minutes with both transports running in parallel and needs Docker and Pebble.
