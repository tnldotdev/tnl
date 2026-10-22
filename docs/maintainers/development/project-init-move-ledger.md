# project init move ledger

`internal/client/project/init` (`projectinit`) owns the complete project-init
operation: root and package-manager detection, planning, dependency installation,
safe source edits, Git ignore evaluation, artifact-generation sequencing, Python
dependency wiring, and JSONC declaration includes. `cmd/tnl/init.go` selects input,
supplies diagnostic presentation and generation, and renders operation facts.

This records the shared dirty role-organization worktree based on
`bc1efd09c871124a62281d968c7cad2ba9913a7b`, on macOS. Results qualify these
uncommitted files, not that commit's original tree or the final integrated tree.

## operation boundary

| old owner                                                                  | new owner                                                                                  | preserved responsibility                                                                                                                            |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cmd/tnl/init.go`: `initPlan`, `planInit`, config/framework source helpers | `internal/client/project/init/plan.go`: `Plan`, `NewPlan`, original private source helpers | read-only planning, exact config/dependency defaults, ambiguous detection, custom framework actions                                                 |
| `cmd/tnl/init.go`: install/edit/generate/type-wiring body                  | `internal/client/project/init/init.go`: `Plan.Apply`, `Options`, `Result`                  | install before source edits, generation before Python and JSONC wiring, original error/cancellation propagation and action order                    |
| `cmd/tnl/init.go`: package-manager command helpers, `runInitInstall`       | `internal/client/project/init/{plan,init}.go`: same private helpers                        | exact argv, cwd, inherited environment plus `NO_COLOR=1`, discarded subprocess output, no-install and unknown-manager recommendations               |
| `cmd/tnl/init_detection.go`                                                | `internal/client/project/init/detection.go`                                                | Git/workspace boundaries, project/config/package/framework detection, unchanged dependency list                                                     |
| `cmd/tnl/init_filesystem.go`                                               | `internal/client/project/init/filesystem.go`                                               | bounded reads, exclusive atomic create, recognized-content replacement, regular-file/mode checks, Git ignore edits                                  |
| `cmd/tnl/init_gitignore.go`                                                | `internal/client/project/init/gitignore.go`                                                | actual Git pattern evaluation, temporary bare repository fallback, ancestor/custom-rule diagnostics; `tnlLocalIgnoreRule` becomes `LocalIgnoreRule` |
| `cmd/tnl/init_server.go`                                                   | `internal/client/project/init/server.go`                                                   | recognized module/listener edits, custom-source refusal, framework/runtime distinction                                                              |
| `cmd/tnl/init_python.go`                                                   | `internal/client/project/init/python.go`                                                   | project-local editable uv dependency, no-install and missing-uv actions                                                                             |
| `cmd/tnl/project_types.go`                                                 | `internal/client/project/init/project_types.go`                                            | root-only entry, explicit referenced projects, JSONC trivia/CRLF preservation, inherited/default includes, symlink and bounds checks                |

`Plan` fields name project facts and planned source edits, including
`ConfigurationPath`, `NewConfiguration`, `MissingPackages`, `ServerSource`, and
`ServerReplacement`. `Result` records created configuration, installed packages,
ordered updated paths, declaration/Python paths, actions, and whether work changed
the project. The command retains frame state, labels, footer, and output writer.
The unused `scriptHint` field and its unreachable presentation branch are removed.
There are no production command wrappers for the moved helpers.

`NewPlan` accepts `func(error) string` only for recoverable detection actions. It
passes the original `failure.InitPackageManager` and `failure.InitFramework`
errors to the command's `presentFailure`. `Options.Generate` accepts only
`context.Context`, selected project root, and configuration path. The command
currently supplies its existing `runGenerate` with `.tnl/generated` and discarded
presentation. `cmd/tnl/generate.go` belongs to the separate generation/resolution
extraction; this slice does not move it. The parent can compose its shared
generation operation at this callback without introducing a command import.

The new production package imports project discovery, project metadata, failure
classification, HuJSON, and standard libraries. It does not import publisher
composition, the CLI renderer, client state, or credential ownership.

Every private helper below keeps its original name at the destination; none
remains in production command code:

| old file under `cmd/tnl/` | new file under `internal/client/project/init/` | exact helpers                                                                                                                                                                                                       |
| ------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `init.go`                 | `plan.go`                                      | `initConfigSource`, `frameworkConfigPaths`, `planFrameworkConfig`, `frameworkConfigSource`, `frameworkConfigAction`, `packageInstallCommand`, `commandForRecommendation`, `shellCommand`; private `packageDocument` |
| `init.go`                 | `init.go`                                      | `runInitInstall`; operation body becomes `Plan.Apply`                                                                                                                                                               |
| `init_detection.go`       | `detection.go`                                 | `initProjectRoot`, `pathInside`, `existingInitConfigs`, `detectPackageManager`, `packageWorkspaceBoundary`, `detectFramework`, `hasPackageDependency`, `initDependencies`, `packageTypeConfigExists`                |
| `init_filesystem.go`      | `filesystem.go`                                | `readInitFile`, `createInitFile`, `replaceRecognizedInitFile`, `ensureTnlGitignore`; `initReadLimit` unchanged                                                                                                      |
| `init_gitignore.go`       | `gitignore.go`                                 | `projectGitignoreActions`                                                                                                                                                                                           |
| `init_server.go`          | `server.go`                                    | `detectAPIServer`, `startsAPIServer`, `planAPIServer`, `apiServerEntry`, `isModuleEntrypoint`, `recognizedAPIServerSource`; `apiEntryInScript` unchanged                                                            |
| `init_python.go`          | `python.go`                                    | `wirePythonProject`                                                                                                                                                                                                 |
| `project_types.go`        | `project_types.go`                             | `wireProjectTypeIncludes`, `projectTypeIncludesAt`, `safeProjectTypeParents`, `appendJSONCValue`, `jsoncIndent`; private `projectTypeIncludeResult` and `projectTSConfig`                                           |

## moved assertions

All entries are routine Go tests. Names and subtest tables remain unchanged.
Paths in the first column are under `cmd/tnl/`; destinations are under
`internal/client/project/init/`.

| old file                       | test retained at destination                                        | new file                  | unique invariant                                                                                       |
| ------------------------------ | ------------------------------------------------------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------ |
| `init_plan_test.go`            | `TestInitPlansNextProjectWithoutRewritingExistingFrameworkConfig`   | `plan_test.go`            | exact missing dependency/app config and custom Next config action; planning writes nothing             |
| `init_plan_test.go`            | `TestPlanFrameworkConfigPreservesExistingConfig`                    | `plan_test.go`            | custom framework bytes are preserved                                                                   |
| `init_plan_test.go`            | `TestPlanFrameworkConfigPreservesMultipleConfigs`                   | `plan_test.go`            | multiple framework files produce action without edits                                                  |
| `init_plan_test.go`            | `TestInitCreatesAbsentKnownNextConfig`                              | `plan_test.go`            | absent recognized framework config is planned                                                          |
| `init_plan_test.go`            | `TestInitPlansGenericAppIntegration`                                | `plan_test.go`            | generic app registration instructions without inferred command/port                                    |
| `init_plan_test.go`            | `TestInitFrameworkWithoutDevScriptUsesAppStartup`                   | `plan_test.go`            | framework detection does not require a dev script                                                      |
| `init_server_test.go`          | `TestInitConnectsRecognizedAPIServerEntrypoints`                    | `server_test.go`          | Hono Node/Bun, Express, Fastify edits and repeat detection                                             |
| `init_server_test.go`          | `TestInitPreservesCustomAPIServerSource`                            | `server_test.go`          | custom listener source is not rewritten                                                                |
| `init_server_test.go`          | `TestInitDoesNotTurnANodeHonoExportIntoABunListener`                | `server_test.go`          | Node export does not imply a Bun runtime                                                               |
| `init_server_test.go`          | `TestInitViteOwnsHonoViteListener`                                  | `server_test.go`          | Vite owns its framework listener                                                                       |
| `init_package_manager_test.go` | `TestRunInitInstallPreservesCommandContextCancellation`             | `package_manager_test.go` | running installer retains cancellation cause; terminal assertion split below                           |
| `init_package_manager_test.go` | `TestInitDoesNotChooseAPackageManagerWhenLockfilesConflict`         | `package_manager_test.go` | conflicting lockfiles block automatic install                                                          |
| `init_package_manager_test.go` | `TestInitDetectsPackageManagerFromWorkspaceAncestor`                | `package_manager_test.go` | workspace manager discovery retains nested project root                                                |
| `init_filesystem_test.go`      | `TestProjectTypeIncludesUseReferencedProjectDirectories`            | `filesystem_test.go`      | solution root unchanged; explicit referenced leaf gets relative include                                |
| `init_filesystem_test.go`      | `TestProjectTypeIncludesPreserveConfiguration`                      | `filesystem_test.go`      | JSON/JSONC/duplicate-key handling and unrelated nested config preservation                             |
| `init_filesystem_test.go`      | `TestProjectTypeIncludeWiresRootWithoutNamedServices`               | `filesystem_test.go`      | includes are independent of configured service names                                                   |
| `init_filesystem_test.go`      | `TestProjectTypeIncludeActionDoesNotInferNestedServiceDirectory`    | `filesystem_test.go`      | absent root tsconfig yields root action without editing inferred directories                           |
| `init_filesystem_test.go`      | `TestInitGitignoreGroupsNewRuleAndPreservesExistingRules`           | `filesystem_test.go`      | marked broad-rule narrowing, custom rules, comments, mixed/CRLF endings and repeat behavior            |
| `init_gitignore_test.go`       | `TestInitGitignoreWithoutRepositoryAndWithNegations`                | `gitignore_test.go`       | Git negations evaluated without creating project Git state                                             |
| `project_types_test.go`        | `TestProjectTypeIncludesEditJSONCSyntaxWithoutRewritingOtherFields` | `project_types_test.go`   | comment/byte/mode preservation, includes/files/default/inheritance/duplicate handling and repeat mtime |
| `project_types_test.go`        | `TestProjectTypeIncludesRejectSymlinkFilesAndReferenceParents`      | `project_types_test.go`   | no edits through linked config files or reference parents                                              |

The old `projectConfiguration` parameter to type wiring contributed only `Root`.
The moved tests call that exact root-only operation; the helper no longer accepts
configuration services or a publisher/command composition type.

## command assertions retained

These remain in `cmd/tnl` because they exercise command presentation, input, or
composition with the real portable generator. The original 40 test names across
the init/type suites remain discoverable: 21 moved, 19 retained. One terminal
assertion now has an additional named command test.

| file                           | retained tests                                                                                                                                                                                                                                                                                                                  | boundary                                                                                                                   |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `init_presentation_test.go`    | `TestInitReportsManualActionForExistingFrameworkConfig`, `TestInitWiresProjectTypesIdempotently`, `TestInitAmbiguousFrameworkOutputNeedsAction`                                                                                                                                                                                 | action/state/footer output, preserved framework bytes, real repeated type wiring                                           |
| `init_presentation_test.go`    | `TestInitGenericShowsRegistrationStepsOnRepeat`, `TestInitFrameworkIntegrationDoesNotPromptForPort`, `TestInitPreservesAppScriptsAndDoesNotPromptForLifecycleSettings`, `TestInitIgnoresObsoleteCommandAndPortPromptAnswers`, `TestInitGenericRerunUpdatesUntouchedConfigWithPort`, `TestInitPreservesCustomizedGenericService` | unchanged input behavior, no inferred lifecycle settings, repeat and customized-config presentation                        |
| `init_server_test.go`          | `TestInitWritesHonoBunEntrypointWithoutAConfiguredPort`                                                                                                                                                                                                                                                                         | real command reports updated entrypoint, writes config without inferred command/port, repeat preserves source              |
| `init_package_manager_test.go` | `TestInitInstallsMissingPackageWithDetectedManager`                                                                                                                                                                                                                                                                             | actual manager argv/cwd and installed output, silent stderr                                                                |
| `init_package_manager_test.go` | new `TestRunInitInstallCancellationHasSuccessfulTerminalResult`                                                                                                                                                                                                                                                                 | original terminal-result assertion now consumes an operation-produced cancellation error; generation must not run          |
| `init_filesystem_test.go`      | `TestInitPreservesExistingStaticConfiguration`, `TestInitStaticProjectNeedsNoPackageManifestOrOrigin`, `TestInitWiresTypeIncludeForExistingProjectConfig`                                                                                                                                                                       | existing config plus actual generator composition, no manifest/origin requirement, types/ignore output                     |
| `init_gitignore_test.go`       | `TestInitGitignoreActualGitAndSourceState`, `TestInitGitignoreCustomRulesAreDiagnosedAndPreserved`, `TestInitGitignoreNestedProjectRoot`                                                                                                                                                                                        | command diagnostics plus actual Git/source-state capture and generated files remaining trackable                           |
| `init_python_test.go`          | `TestInitPythonFacadeIsProjectLocalAndNoInstallPreservesProject`                                                                                                                                                                                                                                                                | actual generated Python literal service types and project-local dependency action, nested root and no-install preservation |
| `project_types_test.go`        | `TestInitStaticGenerationNeedsNoExternalTooling`                                                                                                                                                                                                                                                                                | real static portable generation with an empty tool path and no JavaScript state                                            |

The nested Git test now obtains the ancestor-conflict diagnostic through
`runInit`, preserving its original `.gitignore:1` assertion at the command
boundary. Customized generic-config tests customize the actual generated source
instead of importing a production source-template helper back into commands.

## fixtures and helpers

| old location/helper                                                                                              | new location/helper                                                          | callers                                                                                 |
| ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `cmd/tnl/testdata/init/next/{package.json,pnpm-lock.yaml,next.config.ts}`                                        | `internal/client/project/init/testdata/next/` with identical filenames/bytes | owner and command tests                                                                 |
| `cmd/tnl/testdata/init/vite/{package.json,package-lock.json,vite.config.ts}`                                     | `internal/client/project/init/testdata/vite/` with identical filenames/bytes | owner and command tests                                                                 |
| `init_plan_test.go`: `copyInitFixture`, `genericInitFixture`                                                     | `internal/testutil/projectinit/fixture.go`: `CopyFixture`, `GenericFixture`  | thin test-only adapters in owner `fixtures_test.go` and command `init_fixtures_test.go` |
| `init_server_test.go`: `apiInitFixture`                                                                          | `internal/testutil/projectinit/fixture.go`: `APIFixture`                     | same test-only adapter files                                                            |
| command-private `planInit` test calls                                                                            | test-only `planInit` adapters to `NewPlan`                                   | owner adapter describes error causes; command adapter uses `presentFailure`             |
| `init_gitignore_test.go`: `initIgnoreGit`, `initIgnoreRepository`, `assertInitIgnored`, `writeInitIgnoreFixture` | retained in `cmd/tnl/init_gitignore_test.go`                                 | command Git/source-state and Python composition tests                                   |

Fixture copying takes an explicit directory from each caller, so it does not
depend on runtime source paths or a non-trimmed build. No generated source or
public wire fixtures move in this slice.

## added boundary regressions

| owner file           | new test                                                      | assertion                                                                                                                                                                                                                                  |
| -------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `init_test.go`       | `TestInitApplyOwnsInstallEditsGenerationAndTypeWiringOrder`   | subprocess install before source creation, generation after source edits and before Python/types, selected root/config/context, exact pnpm/uv argv/environment/cwd, no-install actions, ordered result paths and unchanged planned actions |
| `init_test.go`       | `TestInitApplyStopsBeforePythonAndTypesWhenGenerationFails`   | generation cause preserved, uv not invoked, tsconfig untouched                                                                                                                                                                             |
| `init_test.go`       | `TestInitDetectionDiagnosticsUseCallerActionsAndKeepReasons`  | both detection reason identities and caller-authored action bytes/order retained                                                                                                                                                           |
| `init_test.go`       | `TestInitApplyRefusesServerChangedAfterPlanning`              | concurrent custom server edit preserved; generator not invoked                                                                                                                                                                             |
| `filesystem_test.go` | `TestInitFileCreationDoesNotOverwriteExistingFilesOrSymlinks` | exclusive create preserves targets and cleans temporary files                                                                                                                                                                              |
| `filesystem_test.go` | `TestInitFileReplacementRejectsSymlinksAndPreservesMode`      | linked target untouched; regular replacement retains mode/content                                                                                                                                                                          |
| `filesystem_test.go` | `TestInitFileReadsAreBounded`                                 | original 1 MiB limit enforced                                                                                                                                                                                                              |
| `python_test.go`     | `TestInitPythonWithoutUvRecommendsProjectLocalDependency`     | missing uv yields exact editable project-local action without manifest edits                                                                                                                                                               |

## selectors and execution

All moved tests stay in the routine tier. `go:test` discovers the new package
through `./...`; no integration shard, tier flag, public Task target, or root Task
edit is needed. The existing focused Task accepts both owners:

```console
mise exec -- task go:test:focused PACKAGES='./internal/client/project/init ./cmd/tnl' RUN='Test(Init|ProjectType|RunInit|.*PackageManager)' FLAGS=''
```

That requested selector covers all original init/type tests except the two
`TestPlanFrameworkConfig*` tests. They remain named unchanged and run through:

```console
mise exec -- task go:test:focused PACKAGES='./internal/client/project/init' RUN='.' FLAGS=''
```

| check on the uncommitted macOS tree                                                                         | result                                                                                                                                                                                                                                                  |
| ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| requested combined focused Task, initial extraction                                                         | init owner passed; CLI build blocked by concurrent invocation/team extraction (`ReadyDomain`, `ReadyDomainForHostname`, `Session.authenticated`, `clientauth`)                                                                                          |
| requested combined focused Task after operation regressions                                                 | init owner passed; CLI still blocked by invocation's `Session.authenticated` and `clientauth` callers                                                                                                                                                   |
| requested combined focused Task after fixture/helper accounting                                             | init owner passed; invocation source compiled, but command tests still referenced the moved session's private `identity`, `authenticated`, and `store` fields in `connect_native_workflow_integration_test.go` and `connect_reload_integration_test.go` |
| owner-only full focused Task (`RUN='.'`)                                                                    | passed, including both unchanged `TestPlanFrameworkConfig*` assertions and all added operation regressions                                                                                                                                              |
| scoped `gofmt` on owned Go files                                                                            | completed                                                                                                                                                                                                                                               |
| `go list -f '{{join .Imports "\n"}}' ./internal/client/project/init`                                        | confirmed production imports are project/meta, failure, HuJSON, and standard libraries                                                                                                                                                                  |
| scoped Markdown `oxfmt --write` then `--check`                                                              | passed                                                                                                                                                                                                                                                  |
| scoped `git diff --check`                                                                                   | passed                                                                                                                                                                                                                                                  |
| `git ls-tree -r HEAD -- cmd/tnl/testdata/init` compared with `git hash-object` on all six new fixture paths | all six fixture blob hashes match exactly                                                                                                                                                                                                               |

A subsequent `mise exec -- go build -o /dev/null ./cmd/tnl` was also blocked by
concurrent unused invocation imports in `cmd/tnl/admin.go` and
`cmd/tnl/publisher_manage.go`. A final scoped `gofmt -l` reported no owned files.

The parent must rerun the combined focused command once concurrent callers
compile, then attach final integrated generation, formatting, and broader test
evidence. This slice does not claim blocked command tests passed, and it does not
run global generation/formatting or modify another extraction's callers.
