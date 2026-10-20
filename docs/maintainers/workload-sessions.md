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

| method | endpoint                                                 |
| ------ | -------------------------------------------------------- |
| `GET`  | `/v1/workload/services`                                  |
| `POST` | `/v1/workload/services/{service_id}/authorization`       |
| `POST` | `/v1/workload/services/{service_id}/ingress-assignments` |
| `POST` | `/v1/workload/services/{service_id}/client-certificate`  |

inventory contains visitor endpoints, not publisher targets or application
credentials. certificate issuance requires a CSR signed by the already-bound
workload key and produces a short, service-scoped workload certificate. the
existing public certificate authorization path recognizes that subject and
rechecks its current rights. active decisions end at the workload lease or
absolute deadline, or an earlier infrastructure deadline.

`internal/workloadclient.New` owns the ephemeral key. `Exchange`, `Renew`,
`Revoke`, `ListServices`, `CheckService`, `CreateIngressAssignments`, and
`ServiceClientCertificate` return generated contract types. `Session`, `Subject`,
and `Sign` let the native job runtime retain execution state and prove connector
key possession. it stores no JWT or human session.
`ClientTLSCertificate` returns the short certificate paired with the in-memory
workload key for a native public service client.

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
and key checks across both variants. the current private transport's hello,
forwarding, ingress HTTP projections, and publisher connector request still use
human fields; their subject-aware wire mapping and the job runtime are the next
data-plane integration boundary. no workload substitutes fake human IDs there.

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

```console
mise exec -- task go:test:integration:workload
```

the target uses disposable PostgreSQL, real control/authority HTTP handlers,
signed local GitHub JWKS fixtures with the fixed production issuer, and the
native adapter. state tests cover concurrent exchange/apply, replay recovery,
key/scope takeover rejection, narrowing, fixed expiry, and public/private visitor
admission. they do not claim private wire or job-runtime qualification.
