# tooling and assets move ledger

execution base: `bc1efd09`, branch `0xcadams/role-organization`, shared worktree
`/Users/chase/.worktree/tnl/role-organization`. this ledger records the tooling
workstream of the second PR. final root compilation, generation, integrated
validation, and delivery belong to the parent execution.

## public tasks and dispatch

All 142 baseline public Task entrypoints remain available. the new
`go:lint:harness` runs `go -C tools/testharness vet ./...` and is part of
`go:lint`. the root module's vet cannot cover this separate module.

| included implementation | public entrypoints                                                                                                         |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `tasks/local.yml`       | `dev`, every `local:*`; certificates remain internal                                                                       |
| `tasks/generate.yml`    | `generate`, `generate-check`, `format`, `format-check`, `go:generate`, `go:generate-check`, `go:format`, `go:format-check` |
| `tasks/go.yml`          | remaining `go:*` routine checks, focused selectors, fuzzing, public Go fixture, harness checks, and build                  |
| `tasks/integration.yml` | `go:test:integration` and every `go:test:integration:*`                                                                    |
| `tasks/load.yml`        | `go:test:load:{database,runtime}`, `go:bench:{plan,run,report}`                                                            |
| `tasks/javascript.yml`  | every `js:*` and `connect:*`                                                                                               |
| `tasks/python.yml`      | every `py:*`                                                                                                               |
| `tasks/packaging.yml`   | `package`, `installer:test`, every `release:*`                                                                             |
| `tasks/deployment.yml`  | every `deploy:*`                                                                                                           |

Root aliases contain only Task calls; each command body has one owner. every
include and task has explicit `dir: "{{.ROOT_DIR}}"`. included implementations
use absolute `:public:name` calls across files. normal namespace includes are
intentional: Task 3.53.1's flattened includes listed correctly but did not resolve
leading-colon calls. successful dry runs verify the final dispatch graph.

Public names, defaults, required inputs, tier flags, timeouts, Linux/macOS
preconditions, Node 24.20.0 prerequisite, kind selection, and build prerequisites
are preserved. the `default` implementation in the integration namespace also
has Task's ordinary `go:test:integration:default` alias.

Generation now follows the contract owner's required order: generate all seven
Go APIs with `scripts/generate/openapi.ts`, generate browser validators with
`scripts/generate/publisher-model.ts`, then run the remaining Go directives with
those two script patterns skipped. `GENERATED_PATHS` is one inventory shared by
the `HEAD` diff and untracked/unexpected-output check. it includes canonical
`pkg/api`, both generated databases, diagnostics, failure catalog, toolbar,
browser models, project keys/loader, SDK config, schema, public installer, all
four Fargate outputs, and the observability vocabulary. action bundles retain
their separate tracked and untracked check.

## complete script map

Each row includes its implementation and any colocated tests. no test body,
assertion, fixture expectation, version derivation, hash derivation, artifact
content, platform target, or legal-file requirement was removed.

| original path                       | destination                                    |
| ----------------------------------- | ---------------------------------------------- |
| `scripts/build-feedback-toolbar.ts` | `scripts/build/feedback-toolbar.ts`            |
| `scripts/clean-package.ts`          | `scripts/build/clean-package.ts`               |
| `scripts/filter-go-coverage.go`     | `scripts/development/filter-go-coverage.go`    |
| `scripts/render-local-capacity.ts`  | `scripts/development/render-local-capacity.ts` |
| `scripts/generate-installer.go`     | `scripts/installer/generate.go`                |
| `scripts/install.sh.in`             | `scripts/installer/install.sh.in`              |
| `scripts/install.test.ts`           | `scripts/installer/install.test.ts`            |
| `scripts/node-licenses.ts`          | `scripts/package/node-licenses.ts`             |
| `scripts/npm-artifacts.ts`          | `scripts/package/npm-artifacts.ts`             |
| `scripts/npm-artifacts.test.ts`     | `scripts/package/npm-artifacts.test.ts`        |
| `scripts/npm-consumer.ts`           | `scripts/package/npm-consumer.ts`              |
| `scripts/pack-python-wheels.ts`     | `scripts/package/pack-python-wheels.ts`        |
| `scripts/pack-tnl.ts`               | `scripts/package/pack-tnl.ts`                  |
| `scripts/python-package.ts`         | `scripts/package/python-package.ts`            |
| `scripts/python-package.test.ts`    | `scripts/package/python-package.test.ts`       |
| `scripts/python-version.ts`         | `scripts/package/python-version.ts`            |
| `scripts/python-version.test.ts`    | `scripts/package/python-version.test.ts`       |
| `scripts/validation.ts`             | `scripts/package/validation.ts`                |
| `scripts/verify-packages.ts`        | `scripts/package/verify-packages.ts`           |
| `scripts/verify-python-wheels.ts`   | `scripts/package/verify-python-wheels.ts`      |
| `scripts/verify-tnl-install.ts`     | `scripts/package/verify-tnl-install.ts`        |
| `scripts/publish-tnl-packages.ts`   | `scripts/release/publish-tnl-packages.ts`      |
| `scripts/release-check.ts`          | `scripts/release/release-check.ts`             |
| `scripts/release-check.test.ts`     | `scripts/release/release-check.test.ts`        |
| `scripts/release-version.ts`        | `scripts/release/release-version.ts`           |
| `scripts/release-version.test.ts`   | `scripts/release/release-version.test.ts`      |
| `scripts/update-homebrew.ts`        | `scripts/release/update-homebrew.ts`           |
| `deploy/tnl.rb.template`            | `scripts/package/homebrew/tnl.rb.template`     |

The sole root script exception is generated `scripts/install.sh`. it is an
externally downloaded installer; moving source ownership must not change its
public download path. the renderer still writes that exact output and its test
reads `../install.sh`. `internal/clioutput/generate.go` now calls the moved
renderer. the generated header changes only when the parent regenerates it.

The OpenAPI owner moved all `generate-*.ts` and `normalize-openapi-go.ts` into
`scripts/generate`; that owner's ledger is authoritative for those files. the
SDK owner moved `scripts/build-ts-bridges.ts` to `scripts/build/ts-bridges.ts`.
Neither set was edited here. shared validation imports now use
`../package/validation.ts` outside the package directory.

The packers/install verifiers follow
`packages/ts/src/internal/native/native-targets.ts`. source pack verification
copies `packages/ts/test/fixtures/connections/drizzle.config.ts`. the SDK owner
updated `npm-consumer.ts`'s browser input guard while this workstream moved it;
that edit is preserved. build/clean/license commands are recorded in the SDK
ledger. root `package.json` changes are confined to `scripts`; the OpenAPI
dependency and lockfile changes belong to its owner.

## complete deployment and fixture map

| original path                                                | destination                                                                    |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| `deploy/compose.yaml`                                        | `deploy/server/standalone/compose.yaml`                                        |
| `deploy/compose.split.yaml`                                  | `deploy/server/split/compose.yaml`                                             |
| `deploy/.env.example`                                        | `deploy/server/standalone/.env.example` and `deploy/server/split/.env.example` |
| `deploy/Caddyfile`                                           | `deploy/server/standalone/Caddyfile` and `deploy/server/split/Caddyfile`       |
| `deploy/compose-publisher/compose.yaml`                      | `deploy/publisher/compose/compose.yaml`                                        |
| `deploy/compose-publisher/.env.example`                      | `deploy/publisher/compose/.env.example`                                        |
| `deploy/compose-publisher/readme.md`                         | `deploy/publisher/compose/readme.md`                                           |
| `deploy/compose-publisher/test.Dockerfile`                   | `tests/integration/fixtures/publisher-install/test.Dockerfile`                 |
| `deploy/publishers/fargate.yaml`                             | `deploy/publisher/fargate/fargate.yaml`                                        |
| `deploy/publishers/fargate.parameters.example.json`          | `deploy/publisher/fargate/fargate.parameters.example.json`                     |
| `deploy/publishers/fargate.manifest.example.json`            | `deploy/publisher/fargate/fargate.manifest.example.json`                       |
| `deploy/publishers/fargate.storage-policy.json`              | `deploy/publisher/fargate/fargate.storage-policy.json`                         |
| `deploy/publishers/fargate.test.ts`                          | `deploy/publisher/fargate/fargate.test.ts`                                     |
| `deploy/publishers/replacement_integration_test.go`          | `deploy/publisher/fargate/replacement_integration_test.go`                     |
| `deploy/publishers/tsconfig.json`                            | `deploy/publisher/fargate/tsconfig.json`                                       |
| `deploy/publishers/readme.md`                                | `deploy/publisher/fargate/readme.md`                                           |
| `deploy/local/compose.yaml`                                  | `development/local/compose.yaml`                                               |
| `deploy/local/Caddyfile`                                     | `development/local/Caddyfile`                                                  |
| `deploy/local/dns.Dockerfile`                                | `development/local/dns.Dockerfile`                                             |
| `deploy/local/oidc.Dockerfile`                               | `development/local/oidc.Dockerfile`                                            |
| `deploy/local/oidc-admission.json`                           | `development/local/oidc-admission.json`                                        |
| `deploy/local/pebble-config.json`                            | `development/local/pebble-config.json`                                         |
| `deploy/local/pebble.minica.crt`                             | `development/local/pebble.minica.crt`                                          |
| `internal/tnldruntime/testdata/separated-load.compose.yaml`  | `tests/integration/fixtures/separated-stack/compose.yaml`                      |
| `internal/tnldruntime/testdata/runtime-load.Dockerfile`      | `tests/integration/fixtures/separated-stack/runtime-load.Dockerfile`           |
| `internal/tnldruntime/testdata/dns-integration.compose.yaml` | `tests/integration/fixtures/dns/compose.yaml`                                  |
| `internal/tnldruntime/testdata/compose-publisher/main.go`    | `tests/integration/fixtures/compose-publisher/main.go`                         |

The daemon fixture rows passed through `internal/daemon/testdata` during the Go
owner's move; the destinations above are final. their harness callers now use
these paths. Compose build contexts/mounts climb four levels from fixture units,
and two levels from `development/local`; local Dockerfile arguments use the new
repository-relative paths. runtime test binaries still build `internal/daemon`.
private daemon tests remain beside their implementation.

The standalone and split units each have their own environment, proxy config,
and readme. only topology-inapplicable environment examples were removed from
each unit. digest pins, actual runtime settings, private mounts, permissions,
direct migration versus pooled serving URLs, listener ports, health checks,
nonroot ownership, and keychain/state/reset behavior are preserved. publisher
Fargate template bytes and generated example/storage bytes moved unchanged.
the replacement test keeps `TestIntegrationPublisherIdentitySurvivesTaskStateDeletion`
and its PostgreSQL tier; its imports follow the actual Go owners.

New boundary readmes live beside both server templates, `development/local`, and
the integration fixture root. `.dockerignore` excludes the new contributor/test/
Task trees. the production `Dockerfile` still copies the same `cmd`, `internal`,
and `pkg` roots; `.goreleaser.yaml` still builds the same command roots and legal
files, so neither needs a path-only rewrite. no image pin or release setting was
changed. `.gitattributes`, `.oxfmtrc.json`, and `.oxlintrc.json` follow moved
generated assets.

## task selector closure

The actual implemented destinations in the Go, publisher, connector, and SDK
ledgers take precedence over the original plan's draft spellings. Task package
arguments follow `control/api/{public,authority}`, `control/state`,
`client/project`, `client/service`, `control/oidc`, `publisher/localapi/protocol`,
`publisher/target/{discovery,kubernetes}`, `transport/targettransport`,
`security/publisherproof`, `policy/publisherprovenance`, `ingress/clienthello`,
and the retained `internal/config` / `internal/clioutput` owners.

- `go:test:public-api` still compiles `pkg/tnl/testdata/publicapi` and is called by
  `go:test`, preserving #448's external Go consumer check.
- Connector subtree selectors include moved stream tests; owner-lifecycle still
  includes `Listener`. enrollment tests now select defining publisher identity
  plus credential-file and proof packages.
- Native owner integration and Drizzle select `tests/integration/connector`;
  the budget/shared-owner checks select `internal/connector`.
- App/config/invocation selectors include the newly extracted publisher local/
  invocation operations. target tests follow their extracted owner. server and
  observability checks include the four moved maintenance-worker assertions.
- Every baseline fuzz target is retained, including the nested wire trace-context
  target. parser targets follow ClientHello, PROXY v2, protocol inspection, and
  the retained output renderer.
- The three focused JavaScript selectors retain all 24 file arguments (9 tracing,
  10 connection, 5 framework); exact role paths match the SDK ledger.
- State/runtime/CLI shard inputs, stable whole-test hashing, and unsupported/
  empty-selector failures remain. runtime shards exclude only
  `WorkloadTransportLifecycle` and `PrivateDefaultLeaseCycles`; their dedicated
  real-clock Tasks keep their production socket proofs and budgets.

The harness now discovers and accounts for unsharded selectors too. both the
implicit shard and explicit `1/1` reject an empty top-level selection before
starting a container. single-shard subtest selectors pass through unchanged;
accounting is for their top-level parent, not proof that a named subtest ran.
multi-shard commands continue to reject subtest selectors and assign complete
top-level tests exactly once. new standalone harness regression coverage tests
implicit/explicit single-shard empty selection, default all-test selection, and
unchanged subtest commands with group/class alternatives and subtest exclusions.

### source selector accounting

The audit expanded 80 Task summaries and the database-load alias, then compared
each literal default `-run` / `-fuzz` expression with named Go source entrypoints
in its selected packages. these are source counts, not executed assertions or
build-constraint-aware discovery. subtest selectors count parents; `-skip` is
applied before counting. the default `go:test:focused` input for this audit was
`PACKAGES=./internal/publisher`.

| public task / selector family                                                                                                                                               | matching source entrypoints |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------: |
| `deploy:publishers:check`                                                                                                                                                   |                          10 |
| `go:test:app-workflows`                                                                                                                                                     |                          59 |
| `go:test:aws-bootstrap`                                                                                                                                                     |                          14 |
| `go:test:client-tracing`                                                                                                                                                    |                           8 |
| `go:test:config-contracts` / symlink snapshot                                                                                                                               |                           1 |
| `go:test:connections` / connection and native owner                                                                                                                         |                          15 |
| `go:test:connections:budget`                                                                                                                                                |                           1 |
| `go:test:database-native`                                                                                                                                                   |                          17 |
| `go:test:focused` / default expression                                                                                                                                      |                         165 |
| `go:test:ingress` / default expression                                                                                                                                      |                         240 |
| `go:test:integration:api`                                                                                                                                                   |                          31 |
| `go:test:integration:app-workflows`                                                                                                                                         |                           5 |
| `go:test:integration:auth`                                                                                                                                                  |                           1 |
| `go:test:integration:aws-bootstrap`                                                                                                                                         |                           2 |
| `go:test:integration:binary`                                                                                                                                                |                           5 |
| `go:test:integration:cli`                                                                                                                                                   |                          10 |
| `go:test:integration:company`                                                                                                                                               |                           7 |
| `go:test:integration:compose`                                                                                                                                               |                           1 |
| `go:test:integration:connections`                                                                                                                                           |                           1 |
| `go:test:integration`                                                                                                                                                       |                         339 |
| `go:test:integration:http-services`                                                                                                                                         |                           2 |
| `go:test:integration:ingress`                                                                                                                                               |                           6 |
| `go:test:integration:kubernetes`                                                                                                                                            |                           1 |
| `go:test:integration:live-authorization`                                                                                                                                    |                          10 |
| `go:test:integration:local-oidc`                                                                                                                                            |                           1 |
| `go:test:integration:owner-lifecycle`                                                                                                                                       |                           1 |
| `go:test:integration:private-claims`                                                                                                                                        |                           4 |
| `go:test:integration:private-services`                                                                                                                                      |                          37 |
| `go:test:integration:private-sshd`                                                                                                                                          |                           1 |
| `go:test:integration:private-topology`                                                                                                                                      |                           7 |
| `go:test:integration:publisher-egress`                                                                                                                                      |                           5 |
| `go:test:integration:publisher-groups`                                                                                                                                      |                           1 |
| `go:test:integration:publisher-observability`                                                                                                                               |                           2 |
| `go:test:integration:publisher-recovery`                                                                                                                                    |                           3 |
| `go:test:integration:publisher-replacement`                                                                                                                                 |                           1 |
| `go:test:integration:route53`                                                                                                                                               |                           1 |
| `go:test:integration:runtime`                                                                                                                                               |                          40 |
| `go:test:integration:runtime:leases`                                                                                                                                        |                           1 |
| `go:test:integration:runtime:shard` / after real-clock exclusions                                                                                                           |                          38 |
| `go:test:integration:runtime:workload`                                                                                                                                      |                           1 |
| `go:test:integration:service-access`                                                                                                                                        |                           7 |
| `go:test:integration:state-boundaries`                                                                                                                                      |                          10 |
| `go:test:integration:state-locks`                                                                                                                                           |                           4 |
| `go:test:integration:state:shard` / before shard selection                                                                                                                  |                         268 |
| `go:test:integration:tcp-clients` / PostgreSQL parents                                                                                                                      |                           4 |
| `go:test:integration:tcp-clients` / MySQL parents                                                                                                                           |                           2 |
| `go:test:integration:tcp-lifecycle`                                                                                                                                         |                           3 |
| `go:test:integration:vercel`                                                                                                                                                |                           1 |
| `go:test:integration:workload`                                                                                                                                              |                          12 |
| `go:test:integration:workload-http`                                                                                                                                         |                           3 |
| `go:test:integration:workload-runtime`                                                                                                                                      |                           2 |
| `go:test:invocations`                                                                                                                                                       |                          19 |
| `go:test:kubernetes`                                                                                                                                                        |                          28 |
| `go:test:live-authorization`                                                                                                                                                |                          19 |
| `go:test:owner-lifecycle`                                                                                                                                                   |                          33 |
| `go:test:publisher-groups` / CLI group assertions                                                                                                                           |                          11 |
| `go:test:publisher-provenance` / CLI deployment assertion                                                                                                                   |                           1 |
| `go:test:publisher-state` / state expression                                                                                                                                |                          20 |
| `go:test:publisher-state` / installed group                                                                                                                                 |                           4 |
| `go:test:target-discovery` / CLI discovery                                                                                                                                  |                           2 |
| `go:test:target-discovery:race` / CLI discovery                                                                                                                             |                           2 |
| `go:test:team-usage`                                                                                                                                                        |                           1 |
| `go:test:load:database`                                                                                                                                                     |                           6 |
| `go:test:fuzz` / `FuzzInspectClientHello`, `FuzzDecode`, `FuzzReadFrames`, `FuzzNormalizeTarget`, `FuzzSummaryFrames`, `FuzzCanonicalize`, `FuzzDomainPolicy`, `FuzzRender` |                      1 each |
| `go:test:fuzz:publisher-observability` / `FuzzWireTraceContext`                                                                                                             |                           1 |

Applying the unchanged FNV-1a whole-test hash to that source inventory gives state
shards `65 / 67 / 65 / 71`, runtime shards `11 / 8 / 9 / 10`, and CLI shards
`4 / 2 / 4`. every shard is nonempty, and both real-clock tests remain outside
runtime shards. the harness tests independently prove stable assignment, exact
once-only coverage, and flag/exclusion preservation using executable fixtures.

## workflow closure

Release workflows call the new package/release paths. framework matrices select
`packages/ts/test/frameworks/$FRAMEWORK.test.ts`. Compose validation selects each
server unit's environment and proxy file, plus `development/local/compose.yaml`.
the Go cache includes the new Taskfiles and separate harness dependency file.
all action pins, permissions, job timeouts, `persist-credentials: false`,
actionlint, and zizmor settings are retained.

## parent handoff and remaining integration

The follow-up allowed path-literal closure in publisher-owned fixture files.
those edits are complete and disjoint from the parent's Go import sweep:

| owner / file                                   | path closure and status                                                                                                                                                                                  |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| publisher `deployment/cmd/fixture/main.go`     | closed: `filepath.Join("..", "..", "..", "deploy", "publisher", "fargate", destination)` replaces the old `deploy/publishers` output; all four existing filenames retained                               |
| publisher `deployment/manifest_test.go`        | closed: golden reads climb three levels and select `deploy/publisher/fargate`; assertions and fixture bytes retained                                                                                     |
| publisher `deployment/instructions.md`         | closed: repository link selects `deploy/publisher/fargate/readme.md`                                                                                                                                     |
| publisher `target/compose_integration_test.go` | verified closed: fixture build target is `./tests/integration/fixtures/compose-publisher`                                                                                                                |
| `cmd/tnl/publish_install_integration_test.go`  | closed: Compose argument is `../../deploy/publisher/compose/compose.yaml`; surrounding concurrent implementation edits preserved                                                                         |
| development helper Go owners                   | core-agent moves now visible: `internal/devdns/**` to `internal/development/dns/**` and `internal/devoidc/**` to `internal/development/oidc/**`; Tasks and local/fixture Dockerfiles select those owners |
| moved OIDC mount integration test              | verified closed by the core agent: repository root climbs three levels and the Compose path is `development/local/compose.yaml`                                                                          |
| parent root/contributor/maintainer docs        | apply the complete script and asset maps above to live commands and links; retain historical baseline columns in the plan                                                                                |
| `docs/benchmarks/local-capacity.md`            | use `scripts/development/render-local-capacity.ts` for render and `--check`                                                                                                                              |
| `docs/maintainers/releasing.md`                | use `scripts/release/update-homebrew.ts`                                                                                                                                                                 |

The first source-selector audit found the development helpers at their old paths.
after the core agent's move became visible, a fresh audit found all 72 selectors
nonempty, including the one OIDC mount test. this is source/discovery closure;
the runtime integration tier remains a parent check. the CLI's default
`deploy/publishers/aws.json` is a path inside a user's project, not this
repository's reference-template directory; its public default must not be
rewritten merely to match this source move.

The frozen SDK handoffs were rechecked: all five focused selector changes, the
framework CI path, the Drizzle fixture path, and the capacity renderer's shared
validation import already match the requested destinations. package/release
callers retain the public `https://tnl.dev/install` endpoint and generated
`scripts/install.sh` output. the selected installer tests pass against that
anchored output; its source-provenance header awaits normal parent generation.

OpenAPI scripts already follow the relocated shared validation helper. publisher
generation directives already follow the new toolbar/browser builders. generated
installer/toolbar/model headers must be regenerated by the parent. SDK root
Vitest/TypeScript files and Python/action fixture imports remain their owners'
work. binary ClientHello fixture closure follows the Go owner's ledger; no
binary fixture was moved by this workstream.

## validation evidence

All results are against the uncommitted shared tree based on `bc1efd09` on macOS.
the parent must attach its final tested commit. tooling-owned file moves are
frozen before standalone harness execution. no root build, global formatter,
global generator, deployed workload, staging, commit, or push ran here.

| command / check                                                                                                                                                                                                                                                                                                                            | result                                                                                                                                                                                                                                                                         |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `mise exec -- task --list-all --json`, compared to `git show bc1efd09:Taskfile.yml`                                                                                                                                                                                                                                                        | passed again after the SDK freeze; all 142 baseline public names retained, 143 entries including harness vet; the ordinary integration `default` alias is also available                                                                                                       |
| `mise exec -- task --dry go:test generate-check format-check js:check go:test:integration:provider-http go:test:integration:runtime:shard go:test:integration:runtime:leases go:test:integration:runtime:workload SHARD=1/4`                                                                                                               | passed after replacing flattened includes; no test/build/generator command executed                                                                                                                                                                                            |
| `mise exec -- task --dry go:test generate-check go:lint go:test:owner-lifecycle go:test:publisher-identity go:test:fuzz js:test:client-tracing js:test:connections js:test:frameworks go:test:integration:connections go:test:integration:runtime:shard go:test:integration:runtime:leases go:test:integration:runtime:workload SHARD=1/4` | passed on the final path graph; generation ordering, cross-file aliases, listener/enrollment/fuzz selectors, SDK fixtures, native connector integration, and real-clock split all dispatch                                                                                     |
| final dispatch dry run above, with `deploy:publishers:check` added                                                                                                                                                                                                                                                                         | passed again after the SDK freeze; public aliases, moved SDK selectors, generation order, real-clock split, and offline template paths dispatch correctly                                                                                                                      |
| `mise exec -- task --dry go:test:integration:local-oidc local:down deploy:publishers:storage-check PREVIOUS=/tmp/tnl-previous.json NEXT=/tmp/tnl-next.json`                                                                                                                                                                                | passed after the core development move; OIDC, contributor Compose, and storage-check paths resolve through their public Tasks; no command body executed                                                                                                                        |
| `task --summary` inventory of 80 Go/deployment entrypoints plus load alias dry run; source-entrypoint accounting with `rg`                                                                                                                                                                                                                 | rerun after the SDK freeze and the core agent's development move: all 72 selectors nonempty; OIDC contributes one source entrypoint; no root Go code compiled; shard counts remain state `65/67/65/71`, runtime `11/8/9/10`, CLI `4/2/4`                                       |
| `mise exec -- pnpm exec tsc --project tsconfig.json`                                                                                                                                                                                                                                                                                       | passed after the SDK freeze; no-emit root TypeScript check reuses the existing SDK build                                                                                                                                                                                       |
| `mise exec -- pnpm exec tsc --project deploy/publisher/fargate/tsconfig.json`                                                                                                                                                                                                                                                              | passed; the moved deployment project's relative base configuration resolves                                                                                                                                                                                                    |
| `mise exec -- pnpm exec vitest run --project node scripts/installer scripts/package scripts/release scripts/generate deploy/publisher/fargate/fargate.test.ts`                                                                                                                                                                             | passed: 36 tests across 8 files; covers all seven script suites plus offline Fargate contracts                                                                                                                                                                                 |
| `mise exec -- node scripts/development/render-local-capacity.ts --check`                                                                                                                                                                                                                                                                   | passed; moved script/validation import resolves and existing benchmark figures match                                                                                                                                                                                           |
| `mise exec -- task go:lint:harness go:test:harness`                                                                                                                                                                                                                                                                                        | passed after tooling freeze; separate-module vet and race tests, including implicit/explicit single-shard nonempty accounting, default selection, and grouped/class/subtest pass-through; 6.405 seconds on the final harness code; follow-up rerun passed from Go's test cache |
| `git diff --check -- Taskfile.yml tasks scripts deploy development tests tools/testharness .github package.json .dockerignore .gitattributes .oxfmtrc.json .oxlintrc.json internal/clioutput/generate.go docs/maintainers/development/tooling-move-ledger.md`                                                                              | passed                                                                                                                                                                                                                                                                         |
| root generation, routine/race/integration, package snapshots, Linux install/DNS/Compose, Chromium, workflow lint                                                                                                                                                                                                                           | parent validation after global import integration; not claimed as passes                                                                                                                                                                                                       |
