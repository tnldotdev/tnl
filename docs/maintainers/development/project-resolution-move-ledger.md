# project resolution move ledger

execution base: `bc1efd09c871124a62281d968c7cad2ba9913a7b`, branch
`0xcadams/role-organization`. these changes are in the uncommitted shared worktree.
this ledger records the shared-resolution follow-up to the publisher extraction;
its final destinations supersede the intermediate metadata locations in the
publisher move ledger.

## owners and source moves

| source                                                                                                                      | defining destination                                                                                               | retained boundary                                                                                                                                                                                                                                                                                                                      |
| --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cmd/tnl/config.go`: selection, state-backed loading, root selection, default service, server and team preference           | `internal/client/project/resolve/config.go`                                                                        | value-based `Options`; explicit config before environment before discovery; authored failure classification; salt read and database close before evaluation; canonical selected directory; sorted ambiguous-service diagnostic; explicit credentials cannot inherit a project server; project team applies only to the matching server |
| `cmd/tnl/generate.go`: portable generation operation                                                                        | `internal/client/project/meta/generate.go`                                                                         | canonical output root, source identity only for workloads/AWS, declaration and Python rendering, deployment bundle write/check, exact error reasons; returns the existing deployment manifest                                                                                                                                          |
| `cmd/tnl/project_metadata.go`, moved first to `internal/publisher/invocation/metadata.go`                                   | `internal/client/project/resolve/metadata.go`                                                                      | browser-safe metadata, identity/context caches, configured local hostnames, source-bound remote visitor projection, aliases, webhook metadata, path mounts and final validation                                                                                                                                                        |
| `cmd/tnl/publisher_selection.go`, moved first to `internal/publisher/invocation/selection.go`: hostname selection           | `internal/client/project/resolve/hostname.go`                                                                      | exact URL parsing, ready-domain selection, namespace shape, DNS bounds, generated names, member/shared scope and shared-host authorization                                                                                                                                                                                             |
| `cmd/tnl/integration_urls.go`, moved first to `internal/publisher/invocation/integrations.go`: integration origin selection | `internal/client/project/resolve/integrations.go`                                                                  | state-salted shared-project label and saved OAuth/webhook hostname reuse                                                                                                                                                                                                                                                               |
| `cmd/tnl/apply.go`: normalized declaration building                                                                         | `internal/client/project/resolve/declaration.go`                                                                   | sorted service/method/IP normalization, declarative cloud targets, public URL policy and limits, target trust snapshots, group restrictions and 512 KiB bound                                                                                                                                                                          |
| `internal/publisher/invocation/declaration.go`: duplicated local declaration building                                       | removed; `internal/publisher/invocation/service.go` calls `resolve.Declaration` for its one selected local service | local startup still captures only that service's target/trust; remote services remain declarative                                                                                                                                                                                                                                      |

`internal/client/project` remains the selected static evaluation owner and returns
`projectconfig.Project`. it does not import `resolve` or another operational child.
`internal/config` retains static types and validation. `resolve` imports shared
`client/team` facts/API, not publisher invocation or a command's private flags.
target discovery for declaration trust is supplied as a narrow function by the
caller; the shared declaration builder does not import publisher target startup.

`cmd/tnl/config.go` retains its flag application methods, command-context switch,
validation of CLI-only combinations, and small flag-to-value adapters. the new
operation returns `projectconfig.Project`; the existing command wrapper only adds
flag-application methods. `cmd/tnl/generate.go` retains argument mapping and the
same generated/current frame, publisher count, requested output path and footer.
`cmd/tnl/apply.go` retains authenticated mutation composition, workload binding,
connector scope persistence and presentation.

## caller adaptations

- `resolve.Server` replaces `resolveProjectServer`; `resolve.TeamForServer`
  replaces `projectTeamForServer`. callers are `cmd/tnl/{config,connect,status,share_service,publish_install}.go`.
- command project adapters call `resolve.Select`, `resolve.Load`,
  `resolve.LoadWithSalt` and `resolve.Root` using `projectOptions(flags)`.
  `resolve.DefaultService` owns the sorted ambiguity error used by `applyPublish`.
- `projectmeta.Generate(ctx, project, outputDir, check)` replaces inline artifact
  generation in `cmd/tnl/generate.go`. `runGenerate` still evaluates with zero salt
  before calling it; it opens no client state or telemetry.
- `resolve.NewMetadataResolver(database, project, authenticate)` replaces the
  publisher-owned metadata constructor. its authentication function takes context,
  borrowed client state and server, and returns the existing authenticated client.
  `cmd/tnl/share.go` closes over its command/input/diagnostic UI. invocation's
  `project.go`, `public.go`, `private.go` and `background.go` pass runtime auth.
- `MetadataResolver.Context` returns `*clientauth.Client` and `team.Context`;
  publication callers adapt the latter through `invocation.FromTeamContext`.
  the resolver borrows state and uses `team.NewSession(nil, ...)`, retaining the
  caller's database lifetime.
- `resolve.ConfiguredService` replaces `invocation.ConfiguredProjectService`.
  `resolve.PublishHostname` replaces `invocation.ResolvePublishHostname`; it takes
  `team.Context` directly. the supervisor fixture in
  `cmd/tnl/publish_install_integration_test.go` uses the defining shared operation.
- `resolve.IntegrationOrigin` replaces invocation's `projectIntegrationOrigin` in
  OAuth/webhook publication and metadata resolution.
- `resolve.Declaration` replaces command `projectDeclaration` and invocation's
  `localServiceDeclaration`. `cmd/tnl/apply.go` and
  `internal/publisher/invocation/service.go` supply their own target resolver;
  the latter also supplies the selected service name.

## retained assertions

all tests below are routine unless marked integration. assertions were moved to
the defining owner rather than replaced by tests of forwarding adapters.

| original path and assertion                                                                                                                                                               | destination path and assertion                                                                                            | retained proof                                                                                                                                                                  |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cmd/tnl/config_test.go`: `TestProjectServerSelection`                                                                                                                                    | `internal/client/project/resolve/config_test.go`: same name                                                               | full explicit/project/token precedence matrix and selection provenance                                                                                                          |
| `cmd/tnl/config_test.go`: `TestConfiguredProjectHostnameFixture`                                                                                                                          | `internal/client/project/resolve/config_test.go`: same name                                                               | exact managed-label and custom-domain member hostnames and HTTPS URLs                                                                                                           |
| `cmd/tnl/main_test.go`: `TestResolvePublishHostnameUsesNamespace`                                                                                                                         | `internal/client/project/resolve/hostname_test.go`: `TestProjectPublishHostnameUsesNamespace`                             | member namespace, shared-host rejection, generated two-word label and member scope                                                                                              |
| `cmd/tnl/publisher_selection_test.go`, intermediate `internal/publisher/invocation/selection_test.go`: `TestPublishHostnameScopeMatrix`                                                   | `internal/client/project/resolve/hostname_test.go`: `TestProjectPublishHostnameScopeMatrix`                               | managed/custom/member/shared scope, bare hostname and exact URL input                                                                                                           |
| same source: `TestManagedAndCustomDefaultURLShapes`                                                                                                                                       | same destination: `TestProjectManagedAndCustomDefaultURLShapes`                                                           | personal/organization, simple/generated managed modes, custom-domain namespace shapes and member-apex rejection                                                                 |
| same source: `TestExplicitHostnameUsesReadyDomainWhenDefaultIsPending`                                                                                                                    | same destination: `TestProjectExplicitHostnameUsesReadyDomainWhenDefaultIsPending`                                        | explicit ready domain wins over pending default; domain-not-ready reason, invalid/unavailable domain rejection, exact URL parsing                                               |
| `cmd/tnl/project_metadata_projection_test.go`, intermediate `internal/publisher/invocation/metadata_test.go`: `TestRemoteProjectMetadataUsesVisitorProjectionWithoutManagerConfiguration` | `internal/client/project/resolve/metadata_test.go`: `TestProjectMetadataUsesVisitorProjectionWithoutManagerConfiguration` | only source-bound visitor GET; actual protocol/port/exposure; no local target/trust/token leak; malformed endpoint rejection; 404 omission versus authorization failure         |
| `cmd/tnl/apply_test.go`: `TestApplyIgnoresPublisherInfrastructure`                                                                                                                        | `internal/client/project/resolve/declaration_test.go`: `TestProjectDeclarationIgnoresPublisherInfrastructure`             | AWS replica capacity cannot change the control declaration                                                                                                                      |
| `internal/publisher/invocation/fixtures_test.go`: `appliedTestContext`                                                                                                                    | `internal/client/project/resolve/declaration_test.go`: `appliedTestContext`                                               | the same team/membership/domain facts serve declaration and metadata assertions; the unused intermediate fixture file is removed                                                |
| same source: `TestApplyUsesPublicURLPresenceAndPreservesPolicyLimitsAndGrantIntent`                                                                                                       | same destination: `TestProjectDeclarationUsesPublicURLPresenceAndPreservesPolicyLimitsAndGrantIntent`                     | local/private/remote intent, HTTP readiness/path mounts, work/traffic limits, sorted IPs and absence of checkout/worktree data                                                  |
| same source: `TestApplyLocalDiscoveryNeedsNoRunningTarget`                                                                                                                                | same destination: `TestProjectDeclarationLocalDiscoveryNeedsNoRunningTarget`                                              | app/Compose/Docker declarations do not need running targets                                                                                                                     |
| `internal/publisher/invocation/selection_test.go`: visitor-access tests and `TestPublisherConfigPreservesEphemeralRouteChoice`                                                            | same path and names                                                                                                       | implicit IP suppression, explicit current-IP normalization/failure, ephemeral and concurrency propagation remain publication-owned                                              |
| `cmd/tnl/generate_test.go`: `TestGenerateTypesWithoutGitOriginOrRuntimeValues`, `TestGenerateOfflineAcrossWorktreesAndReadOnlyCheck`                                                      | same path and names                                                                                                       | offline state/telemetry isolation, equivalent worktree artifact bytes, no secret/local inputs, read-only check and file metadata, trackable outputs and custom output directory |
| `cmd/tnl/config_test.go`: project/command precedence and ambiguous-service assertions                                                                                                     | same path and names                                                                                                       | state-specific labels reach evaluated config and flags; sorted diagnostic and rendered service names; explicit CLI/environment precedence and cross-server team isolation       |
| `cmd/tnl/apply_workloads_test.go`: `TestApplyWorkloadBindingReuseAndCloudSelectors`                                                                                                       | same path and name; calls `resolve.Declaration`                                                                           | declarative cloud selectors, immutable GitHub binding reuse and original metadata failure cause/reason                                                                          |
| `cmd/tnl/publish_install_integration_test.go`: supervisor fixtures                                                                                                                        | same path and names; shared hostname call adapted                                                                         | integration tier and disposable-supervisor prerequisites remain with the parent-owned Task                                                                                      |

new boundary regression:
`internal/client/project/resolve/config_test.go::TestProjectRootUsesCanonicalSelectedDirectoryWithoutEvaluation`
proves that selecting through a directory symlink returns the real root without
executing TypeScript configuration.

## validation and remaining work

platform: darwin/arm64, Go 1.27.3 through mise. commands below test the dirty tree
above the recorded base; there is no new tested commit.

- passed: `mise exec -- task go:test:focused PACKAGES='./internal/client/project/resolve ./internal/publisher/invocation' RUN='Test(Project|Config|Generate|.*Server|.*Service.*)'`.
- passed: `mise exec -- task go:test:focused PACKAGES='./internal/client/project/resolve ./cmd/tnl' RUN='Test(Project|Config|Generate|.*Server|.*Service.*)'`.
  the resolver completed in 0.570s and the CLI in 10.187s, including the unchanged
  end-to-end generate assertions.
- compile-only attempts with `PACKAGES='./internal/client/project/resolve ./cmd/tnl' RUN='^$'`
  compiled the resolver but encountered the concurrent client/team migration in
  command callers and fixtures. those transient failures were resolved before the
  combined behavioral pass above.

the parent owns Task selectors, test harness discovery/shards, full generated
source verification, global formatting and broad qualification. routine Go
discovery already includes the new package through `./...`; explicit config,
app-workflow and metadata selectors need `internal/client/project/resolve` added
where the moved assertions were previously reached through command/invocation
packages, particularly `go:test:config-contracts` and `go:test:app-workflows`.
renamed assertions use the `TestProject` prefix and match the requested
focused selector. no external fixture assets or generated source bytes moved in
this follow-up. workload provider binding and the apply mutation workflow remain in
their existing command files; they were not part of the shared static declaration
and metadata extraction.
