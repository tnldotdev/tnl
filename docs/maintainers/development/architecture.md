# development architecture

Commands and process composition assemble reusable role operations. Shared client
state/configuration, generated contracts, test fixtures, and tooling have their
own owners below those operations. Use [contributing](../../../contributing.md)
for the current validation sequence and prerequisites.

## command, process, and shared code

| Owner                                                                                                                  | Responsibility                                                                                                                          |
| ---------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `cmd/{tnl,tnld,tnlbench}`                                                                                              | Input, dispatch, composition and output; no reusable publisher/connector engine                                                         |
| `internal/daemon`, `internal/daemon/config`                                                                            | Role construction, listeners, worker supervision, standalone adapters, bounded drain/join, and operational server settings              |
| `internal/client/{auth,authority,control,server}`                                                                      | Human session selection/refresh, generated API adapters, and selected server/state opening                                              |
| `internal/client/state`, `state/sqlite`, `internal/client/filelock`                                                    | SQLite/domain state, storage mechanics, and local ownership locks                                                                       |
| `internal/client/project`, `project/meta`, `project/sourcestate`, `project/githubmetadata`, `project/workloadmanifest` | Selected project evaluation, public metadata/declarations, source evidence, bounded GitHub metadata, and portable workload declarations |
| `internal/client/{service,webhooksource}`                                                                              | Installed job scheduling/registry and cached sender-source matching                                                                     |
| `internal/config`                                                                                                      | Static versioned project configuration, validation, schema and configuration key mapping                                                |
| `internal/clioutput`                                                                                                   | Deterministic ASCII CLI renderer, not `tnld` logs                                                                                       |
| `internal/{policy,security,naming,failure,observability}`                                                              | Focused validated values, proof/credential mechanics, names/IDs/ports, safe failures, and process-owned telemetry                       |
| `internal/{httpclient,httpjson,serviceapi,workerloop}`                                                                 | Shared bounded HTTP/service-authentication mechanics and worker lifecycle                                                               |
| `internal/development/{dns,oidc}`                                                                                      | Development-only DNS/OIDC processes and fixtures                                                                                        |

Static configuration is distinct from operational state. `internal/config`
defines the snake_case document and schema even when control validates apply.
`client/project` discovers/evaluates the selected source and captures provenance;
it does not start a local owner. `daemon/config` resolves `TNLD_*` role/environment
settings. Control state owns current authorization and placement, not the static
configuration package. Naming and policy values do not acquire process lifetime.

Go owns worktree label composition: project/primary-checkout name, optional linked
checkout directory, and a short client-state-salted ID; branch names do not enter
it. Config factories receive structured label pieces and the project path within
the worktree. Service names may shorten that label further. Portable declarations
do not capture allocated endpoints, filesystem roots, worktree labels, or secrets.

## sdk and browser boundary

TypeScript public entry files stay at `packages/ts/src/{index,index.browser,config,next,vite,workload}.ts`.
Private owners are `src/internal/publisher`, `connector`, `connector/workload`,
`project`, and `native`; tracing remains a shared leaf. Publisher preparation
does not pull native credentials into browser metadata. The browser root imports
only safe project/error/awaitable values. Vite and Next prepare/register only in
development, using the actual bound port; builds/previews stay inactive.

The public subpaths are the package root, `/config`, `/next`, `/vite`, and
Node-only `/workload`. Root import/require and browser import/require remain
supported as declared by `packages/ts/package.json`; config/framework exports
keep their declared ESM conditions. The connection bridge lazily loads
`dist/internal/connector/connection.cjs` while preserving the public `TnlError`
identity. ESM/CommonJS workload callers share one configuration singleton.
There is no `/server` or private IPC extension export.

Go validates ignored `.tnl/local/project.json`; the SDK validates the assignment
again. Metadata distinguishes public URL IDs from service IDs and keeps
allocated HTTP ports. `tnl generate` writes portable
`.tnl/generated/project.d.ts` and applicable workload/deployment artifacts for
source control. Runtime writes local values, not declarations. See
[portable generation](portable-generation.md).

Python remains flat under `packages/py`, with its locked `uv.lock`, public
modules, `py.typed`, ASGI lifetime, fork ownership, and native socket contract.
The action remains independently built under `connect`. Both consume the native
owners rather than defining alternate authentication or publication lifecycles.

## tests and fixtures

Colocate unit and white-box integration tests with their Go owner. Daemon
production-composition proofs stay in `internal/daemon`; a re-exec helper is not
automatically a black-box suite. Built-CLI connector proofs live in
`tests/integration/connector`. Shared subprocess/Compose assets live in
`tests/integration/fixtures/{compose-publisher,dns,publisher-install,separated-stack}`.
Keep local goldens/testdata with their parser or implementation and reusable
fixtures in focused test-only `internal/testutil` packages. Product code cannot
import test helpers.

SDK tests live in `packages/ts/test/{publisher,connector,project,frameworks,native,helpers,types,fixtures}`.
Positive and negative compiler cases remain in the package's explicit type-test
projects. Shared wire/hostname/project fixtures live in `api/fixtures`; local
registration goldens stay in `publisher/localapi/protocol/testdata`. Do not change
fixture bytes to hide a contract change. Preserve each unique assertion and its
tier/selector when moving suites.

`tools/testharness` is a separate Go module, not a product dependency. It owns
digest-pinned disposable PostgreSQL and stable whole-test shard selection.
Unsharded and explicit `1/1` selection must also account for a nonempty top-level
test set. A single-shard subtest selector passes through unchanged; top-level
accounting alone does not prove a requested subtest ran. Multi-shard selection
rejects subtests/unsupported selectors and assigns each complete top-level test
exactly once. Real-clock lease/workload proofs stay outside runtime shards.

## tasks, generators, and assets

`Taskfile.yml` is the public entrypoint. Included files in `tasks` own local,
generation, Go, integration, load, JavaScript/action, Python, packaging, and
deployment command bodies. Includes and tasks run at the repository root;
cross-file calls use absolute public Task names. Keep one command body per task
and CI on the same public interface. See the
[source/generator/output inventory](../../../contributing.md#edit-generated-sources).

Scripts are grouped under `scripts/{generate,build,package,release,installer,development}`.
`scripts/install.sh` is the generated, externally consumed root-path exception.
Go APIs generate before browser validators and the remaining Go directives.
Committed generated source is inventoried in `tasks/generate.yml`; action
bundles have their own drift check. SDK `dist` is disposable build output.

`development/local` owns contributor Compose/certificates/OIDC/Pebble, separate
from deployable `deploy/server/{standalone,split}` and
`deploy/publisher/{compose,fargate}` templates. `local:up`, `local:trust`, then
`local:login` retain their keychain and separate-state behavior. Down preserves
state; reset removes trust, containers, volumes, and `.local`. Hosted Fly
manifests and selected production digests belong to sibling `tnl.dev`.

## references

- [failure boundaries](errors.md), [metrics](metrics.md), [client tracing](client-tracing.md), [server readiness](server-readiness.md), and [client state](client-state.md)
- [domain plan](../domain-boundaries-plan.md) and [organization plan](../reorganization-plan.md)
