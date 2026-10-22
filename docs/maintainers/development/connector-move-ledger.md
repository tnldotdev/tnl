# connector move ledger

The native connector implementation now lives in `internal/connector`. This is
the connector-owned part of the second organization PR, based on
`bc1efd09c871124a62281d968c7cad2ba9913a7b` in
`0xcadams/role-organization`. The shared worktree is still being integrated;
there is no tested implementation commit yet.

## implementation ownership

| old source                                                | actual destination and responsibility                                                                                                                                                                                          |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `internal/tcpconnect/*.go`, `readme.md`                   | `internal/connector/stream/`, including device/workload control adapters, assignment reservation/release, accepted-peer validation, preflight, two ingress paths, native bytes, and half-close                                 |
| `internal/connectionruntime/*.go`                         | `internal/connector/runtime/`, including the unchanged owner IPC contracts, bounded handle reads, owner lock, atomic prepared snapshots, listener generations, and terminal `ListenerSwitch` behavior                          |
| `internal/workloadclient/*.go`                            | `internal/connector/workload/`, including assertion acquisition, provider execution validation, immutable session binding, refresh, and fixed expiry                                                                           |
| `internal/kubeconfig/*.go`                                | `internal/connector/kubeconfig/`, including selected-user credentials, bounded exec helpers, projection locks, and owned cleanup                                                                                               |
| service selection in `cmd/tnl/connect.go`                 | `internal/connector/selection.go`: configured key/override selection, exact local/applied visitor binding, and ID-first inventory selection                                                                                    |
| start/reload in `cmd/tnl/connect.go`                      | `internal/connector/foreground.go`: selected listener ownership, preparation, readiness, exact reserved-port metadata reload, and installed attempt execution                                                                  |
| installed job mutation in `cmd/tnl/connect.go`            | `internal/connector/installed.go`: connector inventory, stop, joined removal, and remembered-port release                                                                                                                      |
| `cmd/tnl/connect_stdio.go`                                | `internal/connector/stdio.go`: authenticated stdio setup, nonblocking descriptor duplication, cancellation, and joined close                                                                                                   |
| context/manifest resolution in `cmd/tnl/connections.go`   | `internal/connector/context.go`: canonical project, configured scope, applied binding, config digest, and deployment manifest selection                                                                                        |
| detached native owner startup in `cmd/tnl/connections.go` | `internal/connector/launch.go`: assertion acquisition, bounded startup handshake, environment filtering, child identity, failed-output cleanup, termination, and join                                                          |
| `cmd/tnl/connections_backend.go`                          | `internal/connector/owner.go`: the actual private `nativeConnectionBackend`, configured/service/session state, immutable publication, preparation gates, authorization refresh, assertion replacement, and owner liveness      |
| service preparation in that backend                       | `internal/connector/prepare.go`: per-service adapter/listener ownership, transport generation identity, readiness, and atomic publication                                                                                      |
| human/workload context and exchange                       | `internal/connector/session.go`: the human context contract, typed identity operation, and same-key/same-assertion exchange retries                                                                                            |
| `cmd/tnl/connect_kubernetes.go`                           | `internal/connector/kubernetes.go`: local Kubernetes preparation and credential operation; backend session projection/credential methods remain with its state in `owner.go`                                                   |
| backend close                                             | `internal/connector/shutdown.go`: joined operations/workers, concurrent assignment cleanup and session revocation, caller cleanup budget, and session kubeconfig cleanup                                                       |
| handle operations in `cmd/tnl/connections.go`             | `internal/connector/handle_operations.go`: typed prepared read, explicit prepare, attach, status, and joined stop                                                                                                              |
| `cmd/tnl/connect_native.go`                               | `internal/connector/validation.go`: the concrete `Profile` contract, approved endpoint validation, native command description, and MySQL server-root selection; human/JSON presentation remains in `cmd/tnl/connect_native.go` |
| server/state opening in `cmd/tnl/server.go`               | `internal/client/server/state.go`: `clientserver.Open`; the command wrapper and connector context use that one implementation                                                                                                  |

The moved children retain their existing Go package names (`tcpconnect`,
`connectionruntime`, `workloadclient`, `kubeconfig`). Their old directories have
no implementation or compatibility facades. No canonical `pkg/api` or public Go
package moved, and no generated contract, stored encoding, token, migration,
certificate export, or SDK capability was added.

Normal connection preparation still uses device/workload admission and managed
server TLS. It does not export application client certificates.
`EnsureServiceClientCertificate`, including locks, CSR creation, durable storage,
and explicit export, remains owned by client state. Connector owner IPC remains
separate from publisher app registration IPC.

## reusable operations and command glue

The actual root API is:

```go
Operations{OpenSession: SessionOpener}
NewSession(database, store, authenticated, identity, currentMembership)

Operations.Start(ctx, StartOptions, input, output, diagnostics)
Operations.RunInstalled(ctx, job, ready)
Operations.ServeOwner(ctx, OwnerServeOptions, input, readinessOutput)
StartOwner(ctx, OwnerStartOptions, input, readinessOutput)

ResolveContext(ctx, ContextOptions)
Identify(ctx, ContextOptions, boundedNativeRequest)
ConfiguredService(project, name)
Select(ctx, ServiceReader, project, name, team)
SelectService(inventory, name, team)
ValidateMode(StartOptions)
ValidateServiceMode(StartOptions, service)
ValidateService(service)

ReadPrepared(ctx, handlePath, service)
Prepare(ctx, handlePath, service)
Attach(ctx, handlePath, boundedNativeRequest)
Status(ctx, handlePath)
Stop(ctx, handlePath)
KubeCredential(ctx, handlePath, service)
WriteKubeCredential(ctx, profilePath, output)
Jobs(ctx, supervisorOptions, name, action)
Reason(err)
```

`StartOptions.Ready` supplies presentation; `Starting`, `PublicationReady`, and
`Prepared` report detached command lifecycle observations. They do not own
listeners, adapters, sessions, cleanup, or the backend. The native launch/serve
writers carry their existing bounded readiness protocol, including cleanup when
the launcher cannot deliver its result.

`cmd/tnl/connect.go` retains Kong flags, terminal prompts/browser composition,
supervisor preflight presentation, project/server/team flag resolution, command
dispatch, and output. `cmd/tnl/connections.go` retains the runtime command flags,
dispatch, capabilities presentation, and JSON results. The backend and operation
implementation are not retained behind those command adapters.

The narrow human opener currently adapts the existing shared command
`openTeamSession` context into `connector.Session`; connector closes the database
and owns the native operation lifetime. `cmd/tnl/server.go` now delegates to the
reusable `clientserver.Open`. This is the only added shared implementation file
outside the connector and its test fixtures.

### parent caller integration

The publisher owner must integrate its command callers, rather than restore
command-local forwarding implementations:

- `cmd/tnl/private_publisher_identity.go`: `privateServiceSelection` becomes
  `connector.SelectService`.
- `cmd/tnl/publisher_background.go` and any remaining private-publish caller:
  `validateProfileService` becomes `connector.ValidateService`.
- `cmd/tnl/group_workflow_integration_test.go` and
  `group_identity_workflow_integration_test.go`: use
  `connector.Select(ctx, control, project.Project, name, team)` for configured
  selection. The connector-owned SSH workflow already uses this API. These
  suites compose shared command/workflow fixtures and stay with
  those fixtures; no private test hooks were exported to relocate them.
- The group identity workflow's `serviceConnectionProfile` assertion should use
  the selected service's exact ID/managed hostname for its renamed-DNS network
  probe. Profile construction/identity assertions now live in connector's
  `TestNativeProfileSeparatesLocalDialAndVerifiedIdentity`; the private profile
  constructor was not exported for a test.

The global import integration remains parent-owned. Connector imports use the
actual shared destinations: `client/{auth,authority,control,server,state,project,service,filelock}`,
`client/project/{meta,workloadmanifest}`, `transport/*`, `security/workloadproof`,
`naming/opaqueid`, `policy/visitorsubject`, and `publisher/identity`.

## moved command suites

All named assertions retain their names unless a split is explicitly noted.
Routine means no external infrastructure; integration continues to require
`-tnl-test-tier=integration`.

| original file under `cmd/tnl`     | destination                                    | tests and preserved boundary                                                                                                                                                                                                                                |
| --------------------------------- | ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `connect_lifecycle_test.go`       | `internal/connector/connect_lifecycle_test.go` | `TestConnectMetadataLifecycle`: exact service/port reload, protocol mismatch, readiness, and no replay                                                                                                                                                      |
| `connect_stdio_test.go`           | `internal/connector/connect_stdio_test.go`     | `TestConnectStdioHalfCloseRemoteEOFAndCancellationJoin`: descriptor cancellation and worker join                                                                                                                                                            |
| `connections_lifetime_test.go`    | same basename under `internal/connector`       | `TestConnectionProcessLifetimeDoesNotResurrectWorkloadSessions`: human process persistence versus workload expiry                                                                                                                                           |
| `connections_isolation_test.go`   | same basename under `internal/connector`       | `TestConnectionBackendPreparedReadSurvivesStalledSibling`, `TestConnectionApprovedMetadataRefreshRetainsExactServiceScope`, `TestConnectionCleanupRevokesSessionWhileFailedReleasesUseOneBudget`, `TestConnectionCloseHonorsCallerBudget`                   |
| `connections_prepared_test.go`    | same basename under `internal/connector`       | `TestConnectionPreparedOnlyAndVerifiedWarmWorkBudget`: prepared-only reads, verified assertion reuse, transport identity, and bounded cold/warm control work                                                                                                |
| `connections_replacement_test.go` | same basename under `internal/connector`       | `TestConnectionReplacementRetainsLostExchangeKeyAndNarrowedScope`, `TestConnectionPendingReplacementIsRevokedAfterInventoryFailure`                                                                                                                         |
| `connections_shared_test.go`      | same basename under `internal/connector`       | integration `TestIntegrationConnectionSharedOwnerStalledSibling` and white-box re-exec `TestConnectionSharedOwnerSubprocess`; real HTTP/PostgreSQL owner while a sibling stalls                                                                             |
| `connections_test.go`             | `internal/connector/context_test.go`           | `TestConnectionContextAppliedTeamNameWithoutHumanState`, `TestConnectionKubernetesUsesSavedAuthHint`                                                                                                                                                        |
| `connect_selection_test.go`       | `internal/connector/selection_test.go`         | `TestConnectConfiguredPrivateSelectionUsesExactVisitorBinding`, `TestConnectConfiguredNameCollisionIsRejected`; exact visitor inventory and no friendly-name fallback                                                                                       |
| `connect_test.go`                 | `internal/connector/connect_test.go`           | `TestConnectListenRejectsNonLoopbackAndInvalidPorts`, `TestConnectSelectionRequiresExactIdentityInventoryAndTeam`                                                                                                                                           |
| `connect_native_test.go`          | `internal/connector/validation_test.go`        | `TestNativeHTTPBrowserInstructionsRequireLocalDNSAndAllocatedPort`, `TestNativeHTTPCurlDialsOverrideWithVerifiedAuthority`, `TestNativeProfileSeparatesLocalDialAndVerifiedIdentity`, `TestConnectModeMatrix`, `TestNativeMySQLRequiresExplicitServerRoots` |
| `workload_manifest_test.go`       | `internal/connector/workload_manifest_test.go` | `TestWorkloadManifestWithoutGitOrRuntimeConfig`: deployment manifests never evaluate local runtime configuration or persist assertions                                                                                                                      |
| `connections_native_test.go`      | `tests/integration/connector/native_test.go`   | black-box `TestIntegrationConnectionNativeOwnerHTTP`, `TestIntegrationConnectionNativeOwnerKubernetes`, `TestIntegrationConnectionDrizzleKit`; built CLI, admitted TLS, credentials, cancellation, and real Drizzle migration                               |

Command-only cases remain in `cmd/tnl`: shorthand/removed flags, install preflight,
effective flag/server/team selection, machine-error presentation, and
`TestConnectionReadUsesOnlyExistingPreparedOwner`. The latter still calls the
real command and uses only the runtime's public test backend contract.

The native presentation assertions are split into command-owned
`TestNativeHTTPOutputQualifiesURLAndLocalListener` and
`TestNativeProfileOutputUsesSharedRendererWidth`; profile metadata/instruction
assertions remain with the private constructor in connector. The detached test
helper uses a prepared `connector.Profile` fixture, without exporting the
constructor. `TestConnectionMachineErrorsAreOwnedAndSafeWithoutOutputFlag`
continues to verify redaction and `EADDRINUSE` classification from the command.
`TestVercelWorkloadTrustedSetup` remains with its command setup owner.

## child suites and helpers

| original owner/file                                                         | actual destination                                  | unchanged tests/selectors and boundary                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| --------------------------------------------------------------------------- | --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `internal/connectionruntime/context_test.go`                                | `internal/connector/runtime/context_test.go`        | `TestConnectionIPCInheritsProcessObservationContext`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `internal/connectionruntime/listener_test.go`                               | `internal/connector/runtime/listener_test.go`       | `TestListenerReplacementKeepsAddressAndNeverReplaysAcceptedBytes`, `TestOwnerRecoveryRequiresReleasedLifetimeLock`, `TestListenerCloseJoinsAnUndeliveredAccept`, `TestListenerNextAfterTerminalCloseIsImmediatelyClosed`, `TestListenerConcurrentNextAndCloseCannotReviveAccepts`                                                                                                                                                                                                                                                                                                       |
| `internal/connectionruntime/owner_test.go`                                  | `internal/connector/runtime/owner_test.go`          | `TestConnectionPreparedReadDoesNotWaitForSiblingNetwork`, `TestConnectionHandleReadersRejectFIFOWithoutWaitingForWriter`, `TestConnectionPreparedSiblingNeverStartsNetworkWork`, `TestConnectionOwnerPrivateSnapshotsAndJoinedStop`, `TestConnectionOwnerFailureQuiescesAndSetupAlwaysCloses`, `TestConnectionHandleRejectsSymlinksPermissionsAndExpiry`, `TestConnectionJSONRejectsDuplicateUnknownTrailingAndOversize`, `TestConnectionStopCancelsHangingCredentialAndJoins`, `TestConnectionIPCRejectsWrongProofProjectAndBrowserOrigin`, `TestConnectionAbsoluteDeadlineStopsOwner` |
| `internal/connectionruntime/process_test.go`, `tracing_test.go`             | matching files under `internal/connector/runtime`   | `TestConnectionOwnerKernelDeathRecovery`, `TestConnectionOwnerReadinessAndIPCDoNotWaitForExporter`; re-exec/trace helpers move with these white-box suites                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `internal/workloadclient/client_test.go`                                    | `internal/connector/workload/client_test.go`        | `TestSessionUpdatesShareImmutableAndNarrowingBoundary`, `TestSessionProviderExecutionValidation`, `TestSessionRenewalRetainsProviderExecutionAndCopiesMetadata`, `TestSessionDecoderRejectsLegacyExecutionFields`                                                                                                                                                                                                                                                                                                                                                                       |
| `internal/workloadclient/assertion_test.go`                                 | `internal/connector/workload/assertion_test.go`     | `TestAssertionSourceOneOfAndRotation`, `TestFlyMachineTokenWire`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `internal/kubeconfig/config_test.go`                                        | `internal/connector/kubeconfig/config_test.go`      | `TestPreparePreservesExistingConfiguration`, `TestPrepareQualifiesOtherInstallationAcrossFiles`, `TestPrepareLocksConcurrentContexts`, `TestPrepareRejectsUnsafeYAMLAndSymlinks`, `TestSessionPlanUsesSameContextAndPrivateExclusiveFile`, `TestOwnedNamespaceAndExtraFieldsSurviveRefresh`, `TestCleanupRetainsChangedSessionFile`                                                                                                                                                                                                                                                     |
| `internal/kubeconfig/credentials_test.go`                                   | `internal/connector/kubeconfig/credentials_test.go` | `TestCredentialOutputProcess`, `TestCredentialOutputBoundThroughCopyAndSubprocess`, `TestCredentialExecHelper`, `TestClientGoExecComposesCertificateAndToken`, `TestSelectedUserPreservesTokenPathAndRejectsClientCertForwarding`, `TestCredentialKeepsSecretsOutOfPreparationMetadata`, `TestEKSGetTokenExecProcess`, `TestEKSPreparationDoesNotCallAWSAndComposesFreshToken`, `TestCredentialProfilesDoNotReplaceExistingContextCredentials`                                                                                                                                          |
| `internal/tcpconnect/connect_test.go`                                       | `internal/connector/stream/connect_test.go`         | `TestOpaquePreflightVerifiesTLSBeforeReadyWithoutApplicationBytes`, `TestManagedConnectorReadinessAcrossReachabilityAndProtocols`, `TestConnectorTwoAuthenticatedMuxPathsAndSurvivingIngress`, `TestSingleOpaqueStreamNeverReopensAfterAdmission`, `TestConnectorInvalidAdmissionOrServiceCertificateNeverForwardsOrRetries`, `TestConnectorRevokedSessionStopsOnlyItsActiveStreams`, `TestConnectorNeverRetriesAnAttemptedAssignment`, `TestConnectorRejectsStaleApprovedRevisionBeforeOpeningStream`, `TestConnectorPreservesNativeBytesForHTTPAndTCP`                                |
| `internal/tcpconnect/control_test.go`                                       | `internal/connector/stream/control_test.go`         | `TestControlDevicePersistsRetryKeyAndRejectsChangedEnrollment`, `TestControlAssignmentFailureConsumesOnlyRequestedSlot`, `TestControlSelectionBindsDeviceServiceProtocolAndRevision`                                                                                                                                                                                                                                                                                                                                                                                                    |
| `internal/tcpconnect/lifecycle_test.go`                                     | `internal/connector/stream/lifecycle_test.go`       | `TestConnectorAssignmentConflictKeepsHealthyOtherPath`, `TestAssignmentCleanupSharesCallerCancellation`, `TestMetadataReloadClassificationAndSafeFormatting`                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `internal/tcpconnect/{lifecycle,assignment_retry,sshd}_integration_test.go` | matching files under `internal/connector/stream`    | integration `TestIntegrationPrivateConnectorReleasesLowCapacityReservations`, `TestIntegrationPrivatePublisherRecoversCommittedLostResponses`, `TestIntegrationPrivateConnectorRecoversCommittedAssignments`, `TestIntegrationExistingOpenSSHOverPrivateTCP`; white-box fixtures stay with stream                                                                                                                                                                                                                                                                                       |
| `internal/tcpconnect/native_fixture_test.go`                                | `internal/connector/stream/native_fixture_test.go`  | shared stream test fixture lifecycle; no exported internals                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `cmd/tnl/connections_ingress_fixture_test.go`                               | `internal/testutil/connectorfixture/ingress.go`     | test-only `connectorfixture.Ingress`, shared by the white-box owner re-exec and black-box built-owner suites; no product import                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `packages/py/tests/testdata/connection_owner/main.go`                       | same helper path                                    | imports `connector/runtime` and `client/project/meta`; Python helper build target remains stable                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |

The built-owner suite's build working directory is now `../../..`. Its Drizzle
fixture resolves to
`../../../packages/ts/test/fixtures/connections/installed-drizzle.ts` after the
SDK fixture move. Fixture contents, subprocess flags, and native protocol bytes
were not changed. No connector-owned generators or embedded assets need moving.

## discovery and validation handoff

The task owner has already updated these paths in the concurrent tree; parent
must confirm them after the final import freeze and run the existing public
targets:

- `go:test:connections`: runtime/workload children, connector root, command
  presentation, and `tests/integration/connector` native-owner tests.
- `go:test:connections:budget`: connector root's exact warm/cold budget test.
- `go:test:owner-lifecycle`: `internal/connector/...`; preserve the `TestListener`
  terminal-close selectors as well as `TestConnection`, assignment, and cleanup.
- `go:test:kubernetes` and `go:test:client-tracing`: retain the moved kubeconfig,
  stream, owner, and trace helpers in their existing selectors.
- `go:test:integration:owner-lifecycle`: root white-box shared-owner proof under
  the disposable PostgreSQL harness.
- `go:test:integration:connections`: `tests/integration/connector` Drizzle test
  under the disposable PostgreSQL harness, with the built SDK dependency.
- `go:test:integration:private-claims` and `go:test:integration:private-sshd`:
  stream's unchanged integration names, tier flags, and prerequisites.
- `py:check`: rebuild the unchanged Python connection-owner helper path against
  its new imports. The installed native owner suites still build `./cmd/tnl`.
- Routine/race discovery must include `internal/connector/...`. Do not classify
  the root's re-exec helper as an independent black-box integration suite.

Observed validation on macOS, in the uncommitted shared worktree:

| command/check                                                                                       | result                                                                                                                                                       |
| --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| scoped `mise exec -- gofmt -w` on connector, moved tests/helper, and edited command/shared wrappers | passed; parses the moved Go sources                                                                                                                          |
| scoped `git diff --check`                                                                           | passed                                                                                                                                                       |
| `mise exec -- go build ./internal/connector/...`                                                    | blocked before connector compilation by concurrent imports naming removed shared/publisher packages; no dependencies were added and no build pass is claimed |
| routine/race/integration and global generation/Tasks                                                | deferred to parent after the final path/import freeze, as requested                                                                                          |

The remaining evidence is a frozen-tree compile, test discovery, and the above
public targets with their normal prerequisites. Record that implementation SHA
and actual results in the parent organization ledger; this document is a move
inventory, not a substitute for those runs.
