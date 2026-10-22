# bounded deduplication ledger

the frozen role layout shares equivalent mechanics at their existing owners.
this ledger accounts for every candidate from the original organization plan,
including work already completed in #448. paths below are the final paths.

## candidate decisions

### inspection summary persistence: implemented

- `internal/client/state/inspections.go` owns
  `InspectionRecordFromSummary`, the one mapping from an observation to the
  persisted record fields, including duration units and database result fields.
- `internal/publisher/app/inspection.go` and
  `internal/publisher/invocation/inspection.go` use that mapping.
- the invocation adapter still clears HTTP `result` before recording. the app
  adapter still preserves the supplied result. SQLite's existing HTTP validator
  requires an empty result; changing the app adapter's handling would be a
  behavior change, so the shared mapping does not normalize it.
- recorder construction, checkout scope, retention, observer composition, and
  joined recorder shutdown remain with their current callers.

retained unique evidence:

- `cmd/tnl/cli_integration_test.go`:
  `TestSummaryRecorderKeepsHTTPAndDatabaseResults` proves the invocation's HTTP
  normalization and MySQL error/result-set persistence through real SQLite.
- `internal/publisher/app/inspection_test.go`:
  `TestAppSummaryObservationPreservesHTTPResultPolicy` proves the app's distinct
  HTTP result handling, duration conversion, database outcomes, and tunnel scope.
- `internal/client/state/inspections_test.go`: the three `TestInspection*` tests
  retain protocol rejection, filtering, cross-worktree numbering, retention, and
  per-service byte accounting.

### managed http target setup: implemented

`internal/publisher/managed_http_target.go` owns `ManagedHTTPTarget.dial`:
the ten-second setup context, observed TCP dial, selected target transport's
security handshake, and raw-socket close on handshake failure. these three
equivalent paths use it:

- `internal/publisher/managed_http.go`: direct managed HTTP.
- `internal/publisher/managed_stream.go`: connector HTTP.
- `internal/publisher/managed_kubernetes.go`: Kubernetes HTTP and upgrades.

`httpstream.Serve` still owns successful connection cleanup. the caller still
chooses its URL scheme and admission behavior. Kubernetes watch limits, cluster
authentication, browser credentials, and request policy are distinct. native
PostgreSQL and MySQL setup in `managed_stream.go` remains separate: MySQL dials
before the visitor handshake to obtain its server-first greeting, and native
setup tracks raw sockets across cancellation and promotion.

retained unique evidence in `internal/publisher/`:

- `managed_target_test.go`:
  `TestManagedVisitorTLSWithPlaintextHTTPTarget`.
- `managed_http_admission_test.go`:
  `TestManagedHTTPAdmissionPreservesApplicationAuthWithoutClientCertificate`.
- `managed_kubernetes_test.go`:
  `TestKubernetesDecisionExpiryClosesWatchBothAccessPaths`,
  `TestKubernetesWatchAndUpgradesRevokeBothAccessPaths`, and
  `TestKubernetesRejectsTargetTrustAndBoundsLongWatch`.
- `managed_cancellation_test.go`:
  `TestManagedSetupCancellationClosesBothNativeSockets` retains the separate
  native socket-ownership boundary.

### csr digest: existing shared implementation; distinct request hashes retained

`internal/control/state/certificates.go` already owns `validateCertificateCSR`.
both `validateCertificateIssuanceRequest` in that file and
`CreatePrivateCertificateIssuance` in
`internal/control/state/managed_certificates.go` use it. it validates the CSR
signature and DNS-only shape, then returns `sha256.Sum256(der)`. no second CSR
validator or digest algorithm is needed.

the surrounding request hashes and publisher keys are different contracts:

- `internal/control/api/public/responses.go`:
  `certificateIssuanceRequestDigest` hashes an eight-byte big-endian publish run
  number followed by the CSR.
- `internal/control/state/managed_certificates.go`: the managed request hashes
  `service + NUL + runID + NUL + directory + NUL`, followed by the CSR. its
  CSR digest separately coordinates compatible certificate order reuse.
- `internal/publisher/certificates.go`: the public idempotency key is
  `certificate_` plus the raw-base64url CSR digest.
- `internal/publisher/managed_certificates.go`: the managed idempotency key is
  the hex CSR digest.

these already use Go's SHA-256 implementation. merging their envelopes or key
encodings would change existing request identity and stored comparisons.

retained unique evidence:

- `internal/control/state/acme_work_integration_test.go`:
  `TestIntegrationCertificateIssuanceCreation` checks exact request replay and
  changed-digest rejection.
- `internal/control/state/managed_certificates_integration_test.go`:
  `TestIntegrationManagedCertificateRunAuthority` checks pending-order recovery
  across run replacement, same-publisher sibling reuse, changed-CSR rejection,
  expanded-identifier rejection, and cached-install authority.
- `internal/publisher/certificate_transactions_test.go`: the
  `TestCertificateTransaction*` tests retain response-loss recovery and bounded
  pending/terminal handling for public publication.

### workload renewal and attach validation: already shared in #448

`internal/connector/workload/client.go` calls `validateSessionUpdate` from both
`Client.Renew` and `Client.Attach`. it reuses `validateSession`, checks immutable
session/provider/execution fields and the original expiry, and permits only a
subset of the current services. attach retains assertion signing and its
expired-session error handling; renewal retains its credential-only request.

`internal/connector/workload/client_test.go` retains
`TestSessionUpdatesShareImmutableAndNarrowingBoundary` and
`TestSessionRenewalRetainsProviderExecutionAndCopiesMetadata`. there is no
remaining duplicate update validator to replace.

### kubernetes credential-source preparation: implemented

`internal/connector/kubeconfig/credentials.go` owns `ResolveSource`. it resolves
selected paths, uses an approved EKS hint only when no source was selected, and
validates the single source. it reads no token, executes no plugin, and performs
no AWS discovery during preparation.

both `prepareKubernetesConnection` in `internal/connector/kubernetes.go` and
`nativeConnectionBackend.prepareKube` in `internal/connector/owner.go` use it.
their lifetime differences remain explicit:

- the command prepares a persistent local context and immutable private profile;
  its exec helper reads that profile when a credential is requested.
- the native owner retains source selection in its prepared connection, chooses
  local or workload-session context ownership, and points exec at its live
  handle. its credential expiry is bounded by the connection's expiry.
- `internal/publisher/target/kubernetes/target.go` verifies the publisher's
  discovered cluster endpoint and CA. this is target trust, not visitor
  credential selection; it must not read the connector's kubeconfig or token.

retained unique evidence:

- `internal/connector/kubeconfig/credentials_test.go`:
  `TestSelectedUserPreservesTokenPathAndRejectsClientCertForwarding` and
  `TestEKSPreparationDoesNotCallAWSAndComposesFreshToken` now exercise shared
  resolution before their existing real credential operations.
- the same file's
  `TestResolveSourceRejectsConflictingAndIncompleteSelections` covers explicit
  selection precedence, partial/conflicting selections, unused unsupported
  hints, preparation before file creation, and fresh token reads.
- `internal/connector/context_test.go`:
  `TestConnectionKubernetesUsesSavedAuthHint` proves the native owner uses the
  saved service hint rather than an unapplied local selector.
- `internal/publisher/target/kubernetes/target_test.go`:
  `TestEKSDiscoveryOwnsIndependentClusterTrust` retains independent target trust.

### common private-run validation: implemented on the existing bindings

the existing helpers in `internal/control/state/private_runs_types.go` own
checked run/assignment bindings, lifecycle classification, and revision bounds.
`privateRunAuthorization` in `internal/control/state/private_runs.go` already
shares token, active-lifetime, and current publisher-grant validation across
heartbeat, certificate, and visitor callers.

`activePrivateRun` now shares the identical closed/lease/lifecycle check between
that token authorization path and `lockPrivateConnectionRun` in
`internal/control/state/private_connections.go`. its boundary test also checks
the exact lease deadline and an explicitly closed row.

`privateAssignments` and `replenishPrivateConnections` now also use the existing
`privateRunBinding.matches` rather than repeating its three field comparisons.
preparation, signed start, connection claims, and close retain their operation
checks. preparation accepts a prepared run; signed start binds publisher keys
and the captured certificate plan; a connection claim binds a relay lease and
assignment; close does not require a still-live publisher lease. those checks
cannot become one policy or lifecycle validator without changing behavior.

retained unique evidence:

- `internal/control/state/private_runs_boundaries_test.go`:
  `TestPrivateRunLifecycleBoundary`, `TestPrivateRunAssignmentBindingBoundary`,
  and `TestPrivateRunCredentialHashVectors`.
- `internal/control/state/controlstatedb/private_service_authority_integration_test.go`:
  `TestIntegrationPrivateServiceAuthority` retains stale claims, one surviving
  connection, replacement fencing, disconnect, demotion, and recovery.

### ready-connection count: implemented

`countReadyPrivateConnections` in
`internal/control/state/private_connections.go` owns the repeated query used by
ready, disconnect, and heartbeat (`internal/control/state/private_runs.go`). it
accepts the caller's `pgx.Tx`, preserving visibility of the uncommitted slot
transition. predicates still require a ready/open slot and the matching relay
process, lease revision, service, unexpired lease, and non-draining state.

the richer `privateConnectedRelays` query remains separate because it returns
routing metadata and locks relay rows `FOR SHARE`. visitor-capacity and public
connection queries also retain their different predicates and projections.
no SQL source, schema, generated database output, or hash context changed.

retained unique evidence:

- `internal/control/state/private_slots_review_integration_test.go`:
  `TestIntegrationSharedPrivateSlotLifecycleReview` checks canonical private
  slots and isolation from live public slots.
- `TestIntegrationPrivateServiceAuthority` above exercises all three count
  callers, including the uncommitted ready/disconnect transitions.
- `TestIntegrationManagedCertificateRunAuthority` above checks heartbeat
  readiness after certificate installation and replacement.

### service-access projection wrappers: implemented

`internal/control/api/public/private_services.go` calls
`internal/control/api/serviceaccess` directly for services, grants, and
invitations; the three forwarding-only wrappers are removed.
`internal/control/api/public/applied_private_lookup.go` also calls that owner
directly and still removes only target TLS from its lookup response.
`serviceaccess.Summary` remains distinct from `Service`: list summaries omit
target TLS and HTTP limits, while the applied lookup retains its HTTP limits.
authority handlers already call the same projection owner directly.

retained unique evidence in `internal/control/api/public/`:

- `service_access_integration_test.go`:
  `TestIntegrationPrivateServiceAccessClient` checks control-session service
  grants and invitations through the real API/client boundary.
- `service_actor_integration_test.go`:
  `TestIntegrationServiceActorAccessPagination` checks the signed-human bridge's
  bounded, service-scoped grant and secretless invitation pages.

## focused qualification

all commands ran from the role-organization worktree through `mise exec --`.
the focused routine selections passed for:

- `internal/client/state`, `internal/publisher/app`, and `internal/publisher`:
  inspection persistence, managed HTTP admission, Kubernetes watches/upgrades
  and target trust, setup cancellation, and certificate transactions.
- `internal/connector/kubeconfig`, `internal/connector/workload`,
  `internal/control/state`, and `internal/control/api/public`: source selection,
  real exec credentials, workload update validation, private-run boundaries,
  certificate work, and response projections.
- `internal/connector`, `cmd/tnl`, and
  `internal/publisher/target/kubernetes`: saved-hint preparation, CLI inspection
  persistence, independent cluster trust, and bounded request classification.

the focused commands were:

```console
mise exec -- task go:test:focused PACKAGES='./internal/client/state ./internal/publisher/app ./internal/publisher ./internal/publisher/target/kubernetes' RUN='^Test(AppSummaryObservation|Inspection|ManagedHTTP|ManagedVisitorTLSWithPlaintextHTTPTarget|ManagedSetupCancellation|Kubernetes|Verify|ResolveEKS|CertificateIssuance|CertificateTransaction)'
mise exec -- task go:test:focused PACKAGES='./internal/connector/kubeconfig ./internal/connector/workload ./internal/control/state ./internal/control/api/public ./internal/control/api/authority' RUN='^Test(ResolveSource|SelectedUser|EKSPreparation|ClientGoExec|Credential|Prepare|SessionUpdates|SessionRenewal|PrivateRun|PrivateMetadata|CanonicalCertificate|CertificateWork|CertificateIssuance|PrivateSelection|GetLocalProjectService|WebsiteService)'
mise exec -- task go:test:focused PACKAGES='./internal/connector ./cmd/tnl ./internal/publisher/target/kubernetes' RUN='^Test(ConnectionKubernetesUsesSavedAuthHint|SummaryRecorderKeepsHTTPAndDatabaseResults|EKSDiscoveryOwnsIndependentClusterTrust|ClassificationOmitsUnboundedNamesAndQueries)$'
```

the additional disposable PostgreSQL run passed all six selected tests with
the integration Task's race detector:

```console
mise exec -- task go:test:integration RUN='^TestIntegration(SharedPrivateSlotLifecycleReview|PrivateServiceAuthority|ManagedCertificateRunAuthority|ServiceActorAccessPagination|PrivateServiceAccessClient|CertificateIssuanceCreation)$'
```

after sharing the active-run lifetime check, these narrower follow-up commands
also passed:

```console
mise exec -- task go:test:focused PACKAGES='./internal/control/state' RUN='^TestPrivateRun(LifecycleBoundary|AssignmentBindingBoundary|CredentialHashVectors)$'
mise exec -- task go:test:integration RUN='^TestIntegration(SharedPrivateSlotLifecycleReview|PrivateServiceAuthority|ManagedCertificateRunAuthority)$'
```

`git diff --check` passed. formatting was limited to the edited files. no tests
were removed or merged, and no generated Go outputs were edited.
