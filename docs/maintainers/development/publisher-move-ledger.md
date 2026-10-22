# publisher move ledger

execution base: `bc1efd09`, branch `0xcadams/role-organization`.
this is the publisher workstream of the second PR. the parent owns final consumer
imports, root Tasks/manifests, global generation/formatting, and delivery.
the listed moves and app/publish operation extractions are implemented in the
uncommitted shared worktree. following the frozen import sweep, the complete
publisher subtree, installed service, and command tests compile and pass. focused
runtime/race qualification and the remaining parent integration work are recorded
below; this ledger does not claim a validated PR.

## defining owners

| source owner                                                  | destination                           | preserved contents                                                                                            |
| ------------------------------------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `clientruntime`                                               | `publisher/app`                       | manager, registration leases, journal, events, ping, readiness, tracing, darwin journal proof                 |
| `projectpublisher` workers/private/readiness                  | `publisher/app`                       | same package as manager; accepted-result `checkService`, once-per-run budget, cancellation and cleanup fences |
| `projectpublisher/target.go`, `targets.go`, `targets_test.go` | `publisher/target`                    | immutable captures, target revisions and stale-result rejection                                               |
| `publishertarget`                                             | `publisher/target`                    | Docker/Compose resolution, platform socket handling, Compose integration, readme                              |
| `localpublisher`                                              | `publisher/localapi`                  | HTTP server, leases, capability checks and contract assertions                                                |
| `privateprotocol`                                             | `publisher/localapi/protocol`         | endpoint transport, bounded protocol and unchanged `testdata/runtime.json`                                    |
| `privatepublisher`                                            | `publisher/managed`                   | complete run lifecycle, discovery, admission observation, transport and cleanup tests                         |
| `publisherprovision`                                          | `publisher/setup`                     | publication/group installation journals                                                                       |
| `publisheridentity/native`                                    | `publisher/identity`                  | defining `Native` type, all embedded methods, native signing and `publishingtest` fixtures                    |
| `publisheridentity/credentialfile`                            | `publisher/identity/credentialfile`   | portable credentials, rename/state tests, unix/other ownership implementations                                |
| `publisheridentity` proof/group/runtime                       | `security/publisherproof`             | cross-role signature verification; package name currently retained as `publisheridentity`                     |
| `grouppublisher`                                              | `publisher/group`                     | assignments, runtime, discovery and tracing tests                                                             |
| `publisherruntime`                                            | `publisher/runtime`                   | identity-bound runtime lease and tests                                                                        |
| `adhoc`                                                       | `publisher/adhoc`                     | invocation allocation/run/cleanup and tests                                                                   |
| `integrationurls`                                             | `publisher/integrations`              | OAuth/webhook/alias election and worker tests                                                                 |
| `localproxy`                                                  | `publisher/proxy`                     | HTTP forwarding, TLS, mount, readiness and header tests                                                       |
| `targetdiscovery`                                             | `publisher/target/discovery`          | AWS adapters, bounded requests/cache and tests                                                                |
| `rdsroots`                                                    | `publisher/target/discovery/rdsroots` | `source.pem`, `bundles.json`, embed, update command and tests                                                 |
| `kubernetes`                                                  | `publisher/target/kubernetes`         | authenticated targets, request streaming and tests                                                            |
| `protocolinspection`                                          | `publisher/inspection`                | PostgreSQL/MySQL/Redis parsers; shared inspection values belong to observability                              |
| `feedbacktoolbar`                                             | `publisher/toolbar`                   | every TS/TSX/CSS source/test, ambient declarations, Go embed/injection, committed `toolbar.js`                |
| `publisherapi`                                                | `publisher/browserapi`                | generated browser validators and generation directive                                                         |
| `publisherdeployment`                                         | `publisher/deployment`                | renderer, storage checks, manifest/golden tests, fixture/storage-check commands and instructions              |
| `awsbootstrap`                                                | `publisher/deployment/aws`            | bootstrap/enrollment adapters, tests and control integration                                                  |
| `demo`                                                        | `publisher/demo`                      | server, tests, embedded `page.html`                                                                           |

`internal/publisher` remains the publication-serving root. packages keep their
existing Go package names except the combined `app` and `target` packages.
there are no old-path compatibility packages.

## installed target extraction

the core move placed `publisherjob` in `client/service` during this workstream.
the following files now belong below both app and installed operations:

- `private_target_plan.go` -> `publisher/target/private_plan.go`;
  `PrivateTargetPlan.Normalize` replaces the private `normalize` method.
- `private_target.go` -> `publisher/target/private.go`; `PrivateTargetHooks`
  uses target's own resolver/snapshot definitions.
- `private_http.go` -> `publisher/target/private_http.go`.
- job-to-plan conversion remains `client/service/private_plan.go`; captured-job
  CA conversion remains `client/service/target_options.go`.
- `target.ErrScope` defines the existing error value; installed jobs refer to
  that same value, preserving `errors.Is` and authored diagnostics.
- `private_target_validation_test.go` -> `target/private_validation_test.go`.
  private HTTP wire tests move to `target/private_http_test.go`; the installed-job
  target-TLS rejection assertion remains in `client/service/private_http_test.go`
  as `TestPrivateJobRejectsUncapturedTargetTLSName`.

consumer symbol rewrites required by the parent: `PrivateTargetPlan`,
`PrivateTargetHooks`, `PublishPrivate`, `PrivateTransport`, `PreflightPrivate`,
and `PrivateTarget` are defined by `publisher/target`, not `client/service`.
`TargetOptions(Job)` remains installed-job ownership.
the installed engine, group worker, validation assertions, and command target
preflight assertions have been updated to call the defining target operations.
the only `client/service` edits made by this workstream are this target-plan
ownership change and its direct consumers/tests.

## command extraction

- process construction, descriptor locks, child launch/discovery, capabilities,
  HTTP serving/shutdown, registration preparation, invocation allocation and
  sweep/join implementation move from `cmd/tnl/app_runtime*.go` to
  `publisher/local`.
- `cmd/tnl/app_runtime.go` retains Kong input definitions, stdin selection,
  endpoint JSON encoding and calls to the real process operations.
- public/private worker configuration is constructed above `publisher/app` by
  `publisher/invocation.ProjectRuntime`; the API package does not import the
  process package.
- project metadata, authority/domain selection, exact native grant selection,
  preview association, local realization, mounts and integration worker
  operations are extracted into `publisher/invocation` with their real
  implementations, rather than forwarding back into commands.
- `target_ca.go` -> `publisher/proxy/target_ca.go` (`TargetOptionsForCA`).
- `publish_targets.go` -> `publisher/target/binding.go`
  (`RuntimeTargetBinding` takes its resolver explicitly).

### operation source map

| original command source                                                                                       | defining operation owner                                                                                                                                                                                          |
| ------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `app_runtime.go`                                                                                              | `local/runtime.go`: `ResolveProject`, `EnsureOwner`, `OwnerEndpoint`, `Endpoint`, `Serve`, private registration gates and request implementation; selected projects use `projectconfig.Project` directly          |
| `app_runtime_invocation.go`                                                                                   | `local/invocation.go`: validate, allocate, reserve, register, transfer cleanup ownership, and clean failed/lost acknowledgments                                                                                   |
| `app_private.go`                                                                                              | `invocation/private.go`: private target preflight/pinning, signed run preparation, observations, bounded retry and joined publication                                                                             |
| `app_runtime_integrations.go`                                                                                 | `invocation/app_integrations.go`: scoped OAuth/webhook/alias construction and reverse-order stop                                                                                                                  |
| public configuration from `app_runtime.go`                                                                    | `invocation/public.go`: `ProjectRuntime.PublicConfiguration`; the process constructs `app.Workers` and its manager above these operations                                                                         |
| configured-service projection from `app_runtime.go`                                                           | `app/configuration.go`: `ConfiguredServices`, shared by process construction and command observation                                                                                                              |
| `publish.go` foreground implementation                                                                        | `invocation/publication.go`: `PublishHTTP`, including demo/guest lifetime, preflight, tunnel journal, exact native grant, integrations, publication and joined cleanup                                            |
| `publish_named.go` lease loop                                                                                 | `invocation/named.go`: `PublishNamed`; the command supplies the narrow owner-resolver callback (`local.EnsureOwner`)                                                                                              |
| `publish_enrolled.go`                                                                                         | `invocation/enrolled.go`: `PublishEnrolled`, scoped identity/file loading, allocation, target/traffic checks, managed delegation and runtime lifetime                                                             |
| `private_publish.go`                                                                                          | `invocation/private_publication.go`: `PublishPrivate`, `CapturePrivateTargetTrust`, `SigningIdentity`; command callbacks carry private lifecycle values for human/NDJSON presentation                             |
| `publisher_background.go` operation implementation                                                            | `invocation/background.go`: `InstallEnrolled`, `InstallBackgroundJob`, exact-grant inventory/selection and configured-scope checks                                                                                |
| `publish_retained.go` durable-state selection                                                                 | `invocation/retained.go`: `SelectRetained`; the exact `foreground:` SHA-256 derivation is `RetainedScope`                                                                                                         |
| `publish_install.go` selection/preparation                                                                    | `invocation/install.go`: `InstallHTTP`; flags, interactive authentication, platform selection and presentation remain command inputs                                                                              |
| `publish_install.go` isolated journal, privilege transfer, bounded register input, installation and wait      | `setup/installation.go`: `InstallPublication`, `DeliverInstallation`, `RegisterInput`, `Register`, `WaitReady`; private-result JSON stays command-owned; payload parsing still precedes service-option resolution |
| `publisher_runtime.go` foreground lifetime                                                                    | `invocation/runtime.go`: runtime renew/bind/stop; runtime status fields remain presentation in the command                                                                                                        |
| `publish_setup.go`, `publisher_selection.go`, `project_metadata.go`, `local_project_service.go`, `preview.go` | `invocation/{selection,identity,metadata,service,preview}.go`; selected team facts, native grants, metadata and preview/realization implementation                                                                |
| `integration_urls.go`, alias worker/selection implementation from `alias.go`                                  | `invocation/{integrations,alias,integration_identity}.go`; progress/telemetry are semantic callbacks; terminal and NDJSON rendering remain in commands                                                            |
| `publish_identity.go`, `publication_control.go`, `guest.go`                                                   | `invocation/{foreground_identity,control,guest}.go`; exact native/guest authority and cleanup                                                                                                                     |
| `inspection_observation.go` recorder implementation                                                           | `invocation/inspection.go`; warning frames remain in the command                                                                                                                                                  |
| `publisher_background.go` bounded trust input                                                                 | `setup/trust.go`: `ReadTrust`, same 128 KiB bound and scope-error identity                                                                                                                                        |

### exact remaining command glue

- `app_runtime.go`: Kong fields, snapshot stdin selection, endpoint JSON output,
  and adapting the command's selected-project wrapper to the canonical process
  API. it contains no registration, worker, listener, child-launch or drain loop.
- `publish.go`: command dispatch, flag conflicts and selected-service validation,
  selected input construction, interactive authentication callback, browser
  opening, human/NDJSON callbacks, and once-only telemetry presentation.
- `publish_named.go`: selected server/team/project input constraints and the
  process-resolver/presentation arguments for `PublishNamed`.
- `publish_enrolled.go`: command-input protocol/limit checks and presentation
  callbacks for the discovered scoped grant. the canonical operation owns every
  remote request, allocation and cleanup.
- `private_publish.go`: flag and platform preflight, selected installation
  settings, private human/NDJSON encoding, and detached lifecycle notifications.
- `publish_install.go`: project flag defaults, platform service selection,
  installing/job presentation, and private-result JSON encoding.
- `publisher_background.go`: Kong fields and input adaptation to the canonical
  background installation operation. `publisher_background_adapter_test.go`
  only adapts existing CLI-flag assertions to that same operation.
- `publish_retained.go`: immutable-image/flag validation and applying the result
  of canonical retained-state selection. `publish_auth.go` translates prompts and
  limit flags; it does not implement authentication or publication engines.
- `publisher_runtime.go`: runtime status presentation. alias command presentation
  remains in `alias.go`; its selection operation is `ChooseAlias`.

the local owner has explicit resolver/publication settings instead of process
configuration globals. the owner API only imports app state and its protocol; it
does not import `publisher/local`. invocation operations take settings and semantic
callbacks and do not call command handlers.

### bounded equivalent helper consolidation

- exact address normalization and enrolled-address matching now have one defining
  implementation in `target/address.go`; command tests call that implementation.
- explicit current-IP expansion uses `invocation.AccessIPPrefixes` from both
  publication and URL management, preserving the canonical-prefix and 256-entry
  bounds.
- app and scoped-run summary-to-record mapping share `app.SummaryObservation`.
  the ordinary foreground HTTP observer retains its distinct empty-result
  normalization; it was not merged with the raw summary mapping.
- target-plan normalization/preflight, bounded installation trust reads and
  configured-service projection have one lower implementation for their callers.

## generator and asset mappings

| authoritative source                       | generator/output/path users                                                                                                                                                               |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| browser OpenAPI source (parent-owned move) | `publisher/browserapi/generate.go` now calls `../../../scripts/generate/publisher-model.ts`; output `publisher/browserapi/model.gen.ts`; toolbar imports updated                          |
| toolbar TS/TSX/CSS                         | `publisher/toolbar/generate.go` calls `../../../scripts/build/feedback-toolbar.ts`; `toolbar.js` moved byte-for-byte; source/test/tsconfig relative depth fixed                           |
| toolbar browser fixture                    | Fira Code asset now `../../browserfonts/...`; browser JSON fixture URLs now `../../../api/fixtures/publisher/v1/...`                                                                      |
| deployment renderer                        | `deployment/generate.go` still runs its local `cmd/fixture`; fixture output traverses three parent directories to the assets-owned final `deploy/publisher/fargate/*` destination         |
| RDS catalog                                | embed resources moved together; update command stays under the catalog owner and writes `internal/publisher/target/discovery/rdsroots/{source.pem,bundles.json}` from the repository root |
| registration protocol                      | `localapi/protocol/testdata/runtime.json` moved unchanged beside protocol tests                                                                                                           |
| Compose target test                        | repository-root traversal is now three parents; binary fixture build follows the assets-owned `./tests/integration/fixtures/compose-publisher`                                            |

parent-owned integration updates: root toolbar/browsers Vitest selectors, lint and
coverage paths, generated drift inventory, script builder input/output paths,
OpenAPI generator input, Task package selection/shards, and public API fixture
imports. SDK source/tests belong to the SDK workstream.

## test and assertion ownership

all tests, fuzz targets, benchmarks, build constraints and package-local assets in
the defining-owner table move with their owners. their assertion names remain
unchanged unless an explicit split is recorded below. no suite is retired.

| original source/suite                                                                                          | destination and preserved boundary                                                                                                                                                                                                             | Task/fixture integration                                                                                                                           |
| -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `clientruntime/*_test.go`                                                                                      | `app/*_test.go`: manager leases/ownership, durable journal/events, ping, readiness, tracing; darwin journal file retains its platform constraint                                                                                               | routine and race package discovery; owner-lifecycle/observability selectors must include `app`                                                     |
| `projectpublisher/{worker,private,automatic_readiness}_test.go`                                                | same basenames under `app`: exact registration/run/target capture, private probes, cleanup, once-per-run readiness and accepted-result semantics                                                                                               | app-workflows, owner-lifecycle, invocation and race selectors must include `app`                                                                   |
| `projectpublisher/targets_test.go`, `publishertarget/*_test.go`                                                | `target/*_test.go`: immutable target identity, replacement at reused addresses, Docker/Compose placement and exact captures                                                                                                                    | routine/race plus existing `-tnl-compose-integration`; fixture path/depth corrected                                                                |
| `cmd/tnl/app_runtime_test.go`                                                                                  | `local/runtime_test.go`: real manager/journal/API fixture, scoped status and no unsolicited probing                                                                                                                                            | app-workflows/owner-lifecycle selectors add `local`                                                                                                |
| `cmd/tnl/app_runtime_invocation_test.go`                                                                       | `local/invocation_test.go`: same `TestInvocation*` assertions, real SQLite worker and native fixtures, allocation cleanup, limits, owner/config/server fences, lost acknowledgments                                                            | invocation/owner-lifecycle Tasks add `local`; existing isolated-publishing prerequisites remain                                                    |
| `cmd/tnl/app_workflows_tls_test.go`                                                                            | `local/mounts_test.go`: static mount address/CA/SNI and real enrolled preflight; calls canonical `PublishEnrolled` directly because the assertion is the target handshake                                                                      | app-workflows tier includes `local`; same signed fixture and TLS target                                                                            |
| `TestAppWorkflowRejectsStaleOwnerAfterOneAppRestart`                                                           | `local/owner_test.go`, same name and live-owner/configuration-conflict assertion                                                                                                                                                               | app-workflows selector adds `local`                                                                                                                |
| `TestNamedLeasePinsServerTeamConfigAndTargetAtOwnerBoundary`                                                   | command test retains selected server/team/config snapshot transfer; `local/named_test.go:TestNamedLeasePinsConfigurationDigestAtOwnerBoundary` retains actual lease target and server/team/config digest rejection using a serialized snapshot | command input suite plus local owner suite; no old owner capability is replayed                                                                    |
| command wait/crash workflow assertions                                                                         | remain in `cmd/tnl/app_workflows_test.go` with `app_observation_fixture_test.go`: real manager/journal/API, local-service filtering and stale-owner readiness invalidation                                                                     | existing command/app-workflows Task; fixture no longer reaches process-private fields                                                              |
| `cmd/tnl/publisher_selection_test.go`                                                                          | `invocation/identity_test.go`, same tests: exact saved-URL reservation/access and signed grant selection                                                                                                                                       | routine/app-workflows/native identity selectors add `invocation`                                                                                   |
| `cmd/tnl/publish_identity_test.go`                                                                             | `invocation/foreground_identity_test.go`, same signed-run/session-separation proof and identity reuse assertions                                                                                                                               | routine/native publishing tier includes `invocation`                                                                                               |
| `cmd/tnl/{alias_native,integration_urls,project_metadata_projection,preview,guest,publish_setup}_test.go`      | `invocation/{alias_identity,integrations,metadata,preview,guest,selection}_test.go`: same assertions; private helper names follow their defining owner                                                                                         | routine/alias/integration/native selectors add `invocation`; metadata's authority facts are in `fixtures_test.go`                                  |
| alias diagnostic and alias command preflight tests                                                             | remain command-owned; `AliasHostnamePolicy` supplies the exact selected facts to the canonical policy check before testing rendered diagnostics                                                                                                | existing command tier; no presentation assertions dropped                                                                                          |
| `client/service/private_target_validation_test.go`                                                             | `target/private_validation_test.go`, same declaration/trust-before-capture assertion                                                                                                                                                           | routine/race package discovery includes `target`                                                                                                   |
| `client/service/private_http_test.go`                                                                          | wire assertions in `target/private_http_test.go`; final installed-job assertion is `client/service/private_http_test.go:TestPrivateJobRejectsUncapturedTargetTLSName`                                                                          | both packages stay in routine/race discovery                                                                                                       |
| installed CLI/privilege/Ubuntu integration, foreground flag and retained-mode tests                            | remain command-owned and call canonical operation APIs; exact selection, scope, trust snapshots, private-result JSON and interrupted-install assertions retained                                                                               | existing Linux/systemd publisher-install tier and command tests; no host installation executed here                                                |
| toolbar Go/TS/browser tests                                                                                    | `toolbar/*`: Go embedding/injection, browser validator fixtures, DOM placement/evidence and CSP browser proof                                                                                                                                  | update root Vitest/typecheck/CSP selectors and bundle drift checks; toolbar TS project depth fixed                                                 |
| identity, group/runtime, managed/private, integration, target discovery/Kubernetes, deployment and demo suites | matching relative test filenames under the defining-owner destinations                                                                                                                                                                         | preserve existing opt-in flags, runtime/group/native/database/Kubernetes tiers and platform prerequisites; package lists change, assertions do not |

the following seven readiness regressions retain their exact names in
`app/automatic_readiness_test.go`:

- `TestAutomaticReadinessStopsAfterSuccessAndOnlyRearmsForNewRun`
- `TestAutomaticReadinessBudgetCancelsProbeWithoutStoppingPublication`
- `TestAutomaticReadinessReplacementJoinsOldRunBeforeCheckingNewRun`
- `TestAutomaticReadinessCancellationIsJoined`
- `TestAutomaticReadinessTargetChangeNeedsExplicitCheckAfterSuccess`
- `TestAutomaticReadinessAcceptedSuccessStopsAfterImmediateInvalidation`
- `TestAutomaticReadinessReplacementBeforeAcceptanceRejectsOldSuccess`

`Workers.checkService` still returns its deferred accepted observation result;
success is not reread from a subsequently invalidated journal. the move does not
rearm a completed automatic check or relax the retry budget/drain joins.

## public alias and consumer integration

`pkg/tnl.Publisher` directly aliases the relocated defining
`publisher/identity.Native`. all native source files, embedded methods, platform
credential ownership files and signed publishing fixtures moved; no methods were
removed and no internal compatibility package was added. cross-role proof types
are defined in `security/publisherproof` (retained package name
`publisheridentity`). the parent must still run the public Go API fixture against
the integrated tree, including exposed signature identities.

the parent's rewrite needs longest-prefix handling for `publisheridentity/native`
and `publisheridentity/credentialfile` before root `publisheridentity`, and for
the target declarations extracted from `projectpublisher`. `app` and `target`
are actual new package names; callers retaining old qualifiers need explicit
import aliases or qualifier renaming. all other moved packages retain their
original Go package names. shared paths follow the core move ledger, including
`client/project/meta`, `observability/inspection`, `transport/targettransport`,
and retained `clioutput`.

## validation and remaining integration

evidence below is from macOS and the uncommitted workstream on execution base
`bc1efd09`; it is not commit-qualified delivery evidence.

| actual command                                                                                                                                                  | result                                                                                                                   |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `mise exec -- go test ./internal/publisher/toolbar ./internal/publisher/target/discovery/rdsroots ./internal/publisher/demo ./internal/security/publisherproof` | passed all four packages                                                                                                 |
| `mise exec -- go test ./internal/publisher/target/discovery/rdsroots/...`                                                                                       | passed catalog tests; updater command compiled, no updater/network execution                                             |
| `mise exec -- pnpm exec tsc -p internal/publisher/toolbar/tsconfig.json --noEmit`                                                                               | passed                                                                                                                   |
| `mise exec -- go test ./internal/publisher/app ./internal/publisher/target ./internal/publisher/invocation ./internal/publisher/local`                          | initial intermediate run blocked by old shared/publisher import paths; superseded by the complete frozen-tree pass below |
| read-only `mise exec -- gofmt -l` on publisher/proof and owned command files                                                                                    | source parsed without syntax errors; listed formatting remains for the parent pass, so this is not a formatting pass     |
| `git diff --check`                                                                                                                                              | passed                                                                                                                   |
| old publisher-family source inventory                                                                                                                           | no files remain under any of the 22 moved old roots listed in the defining-owner table                                   |

### frozen-path extraction closure

after the parent's import sweep, the native owner enrollment branch exposed a
shadowed `identity` local: an authority `IdentityContext` hid the outer
`PublisherEnrollmentResult`. the authority result is now `currentIdentity`, so
`EnsurePrivateServiceOwner` assigns the defining publisher enrollment value to
the outer variable used by subsequent publication operations.

the remaining inspection/group command and test references now call the defining
`InspectionRoots`, `EnrollmentKeyInput`, and configured installation APIs. the
share-selection fixture constructs its target value directly instead of relying
on a helper moved with the metadata tests. no compatibility helper was restored
to commands.

`local/process_test.go` now exercises production `local.Serve`, including its real
listener, descriptor, manager, API, SQLite journal, and shutdown defers:

- `TestAppWorkflowProcessShutdownReleasesOwnershipAndPendingRegistration`:
  prepare a scoped app registration through HTTP; reject a competing owner;
  cancel and join shutdown; verify descriptor/listener removal, cleared
  registration and final `runtime.stopped`; restart with a new owner capability.
- `TestAppWorkflowProcessStartupFailureReleasesLockAndStopsManager`: force
  descriptor installation to fail after listener/manager construction, verify
  the manager's terminal journal state, then successfully restart against the
  same state/ownership lock.

these tests use the normal process constructor and no replacement publication
engine. private app preparation needs no external control service. the existing
keyring test backend isolates default macOS state protection.

the final deployment fixture lives in `deploy/publisher/fargate`. the embedded
instructions' reference link was moved by the global path sweep, so only the
manifest's `documentation_sha256` was stale. scoped generation refreshed that
hash from `37652430b6f57fb44ce14f8333ade7ac3f04b3ff6a5bf80b164aa1536f94e15c`
to `f4b5ca97f065fb4dca0e6db0f1eaf9ec76af4efa1e54cfe2ea1a583382f97362`.
comparison with the execution base confirms that this is the sole manifest
value change; template, parameter and storage-policy hashes are preserved.

| actual frozen-tree command                                                                                                       | result                                                                                                                                                    |
| -------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mise exec -- go generate ./internal/publisher/deployment`                                                                       | passed; only the owning deployment fixture generator ran, not global generation                                                                           |
| `mise exec -- go test ./internal/publisher/deployment`                                                                           | passed, including `TestGoldenAndReplicaStability`                                                                                                         |
| `mise exec -- go test ./cmd/tnl`                                                                                                 | passed after command namespace fixes                                                                                                                      |
| `mise exec -- go test -race -v ./internal/publisher/local -run='^TestAppWorkflowProcess' -count=1 -timeout=1m`                   | passed both production process-lifecycle tests                                                                                                            |
| `mise exec -- task go:test:app-workflows`                                                                                        | passed both Task commands; command/local workflow assertions and complete app/target/localapi/protocol/project suites ran with races                      |
| `mise exec -- go test -race ./internal/publisher/invocation -count=1 -timeout=2m`                                                | passed the complete invocation suite, including moved grant, metadata, preview, integration and guest assertions                                          |
| `mise exec -- go test -race ./internal/client/service -count=1 -timeout=3m`                                                      | passed the installed supervisor suite                                                                                                                     |
| `mise exec -- go test ./internal/publisher/... ./internal/client/service ./cmd/tnl`                                              | passed every requested package in one final combined run, including deployment, native identity, root serving, process construction and command consumers |
| `mise exec -- go vet ./internal/publisher/... ./internal/client/service ./cmd/tnl`                                               | passed                                                                                                                                                    |
| `mise exec -- go test ./internal/publisher/local ./internal/publisher/app -list='^Test(AppWorkflowProcess\|AutomaticReadiness)'` | discovered both new process tests and all seven unchanged automatic-readiness regressions                                                                 |
| `mise exec -- task --dry go:test:invocations`                                                                                    | confirmed canonical package paths and unchanged test-tier inputs; dry-run only, not counted as a test execution                                           |
| `mise exec -- go test ./tests/integration/connector -run='^$'`                                                                   | compile-only check passed; the earlier connector moved-test helper error no longer blocks compilation                                                     |

the actual `go:test:app-workflows` commands are:

```console
go test -race ./cmd/tnl ./internal/publisher/local ./internal/publisher/invocation -run='^Test(AppWorkflow|RuntimeStatus|HTTPRuntime|AppServiceSelection|Named|Status|Wait|Background|Configured|ConnectConfigured|ServiceShareSelection|Invocation|Enrolled|Install|SystemInstall|PrivateInstallation|ScopedPrivateInstall|ExplicitPublisherCannotInstall|InvalidConfiguredCA)' -count=1 -timeout=3m
go test -race ./internal/publisher/app ./internal/publisher/target ./internal/publisher/localapi ./internal/publisher/localapi/protocol ./internal/client/project -count=1 -timeout=3m
```

the first selector includes both new process names through `AppWorkflow`.
the current invocation-package test names do not match that workflow prefix;
the package compiled there, and its complete race suite ran separately above.
`go:test:invocations` selects registration/invocation, runtime-status and named
assertions in command/local packages, followed by complete app/target/localapi
and protocol suites. the existing `go:test:owner-lifecycle` Task is connector
focused; publisher process qualification is through `go:test:app-workflows`.

read-only `go list` checks verified both direct imports and transitive dependency
closure:

- serving `publisher` has no dependency on `publisher/app`, `publisher/local`,
  `publisher/invocation`, `publisher/setup` or `client/service`.
- `publisher/app` has no dependency on `client/service`, `publisher/local` or
  `publisher/invocation`.
- `publisher/target` has no dependency on `publisher/app`, `client/service`,
  `publisher/local` or `publisher/invocation`.
- `publisher/localapi` has no dependency on the local process, invocation
  composition, or installed supervisor.

the public alias implementation was not changed during this closure pass. the
parent reports `go:test:public-api` passed after its frozen import sweep; that
existing qualification is retained rather than reported as a new local run.

remaining parent integration operations:

1. complete the repository-wide generation/formatting and aggregate checks against
   the final combined source; focused formatting was applied only to owned
   publisher operation namespaces and touched command consumers in this pass.
2. finish generated/TS/browser path inventories and offline publisher deployment
   linting, then required Chromium, Linux/Compose/systemd/native and installed
   consumer tiers with their declared prerequisites. these are not established
   by the successful macOS Go runs.
3. handle the separate team/project/init command-boundary follow-up identified by
   the parent; it is not a remaining publisher namespace or compilation failure.

there are no unresolved publisher compile, focused-test or dependency-direction
failures from this closure pass. global generation, commits and pushes were not
run. SDK files, root manifests and final guidance remain with their assigned
owners. the main-repository papercut log records the non-import Compose/RDS path
gotcha.
