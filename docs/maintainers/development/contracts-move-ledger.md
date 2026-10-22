# contracts move ledger

The seven HTTP contracts now have serving-owned entrypoints and domain fragments.
The compatibility baseline is `bc1efd09`; the generated Go packages retain their
canonical import paths and package names. This ledger covers source organization
and standalone contract checks in the shared `0xcadams/role-organization` worktree.
Full generation and repository validation belong to the parent integration pass.

## sources and compatibility inventory

All paths are relative to the repository. Each entrypoint references `paths/`
and `schemas/` with standard file `$ref` and JSON pointers. Each schema has one
authoritative definition; the existing cross-contract references still select
control's public schemas. No shared schema package or compatibility facade was
introduced. Existing JSON wire fixtures remain at their original paths.

| baseline source                        | entrypoint                                          | retained Go package        | operations | schemas | required public Go types |
| -------------------------------------- | --------------------------------------------------- | -------------------------- | ---------: | ------: | -----------------------: |
| `api/control/v1/openapi.yaml`          | `api/control/public/v1/openapi.yaml`                | `pkg/api/controlv1`        |        137 |     219 |                      556 |
| `api/authority/v1/openapi.yaml`        | `api/control/authority/v1/openapi.yaml`             | `pkg/api/authorityv1`      |         64 |      73 |                      253 |
| `api/ingress/v1/openapi.yaml`          | `api/control/private/ingress/v1/openapi.yaml`       | `pkg/api/ingressv1`        |         19 |      38 |                      108 |
| `api/relay/v1/openapi.yaml`            | `api/control/private/relay/v1/openapi.yaml`         | `pkg/api/relayv1`          |         10 |      20 |                       63 |
| `api/public-url-usage/v1/openapi.yaml` | `api/integrations/public-url-usage/v1/openapi.yaml` | `pkg/api/publicurlusagev1` |          1 |      13 |                       35 |
| `api/publisher/v1/openapi.yaml`        | `api/publisher/browser/v1/openapi.yaml`             | `pkg/api/publisherv1`      |          7 |       5 |                       41 |
| `api/local-publisher/v1/openapi.yaml`  | `api/publisher/local/v1/openapi.yaml`               | `pkg/api/localpublisherv1` |         11 |      15 |                       66 |

The 249 operations retain their exact method, path, operation ID, request and
response fields, security settings, enum values, and generator annotations.
`api/fixtures/openapi-inventory/v1.json` records every operation, schema name,
required generated public type name, browser export name, and a canonical SHA-256
of each complete bundled contract. Its browser inventory has 48 exports, counting
the separate type and validator declarations.
`api/fixtures/openapi-inventory/public-types-v1.json` records the baseline's
exported Go type declarations, including fields and tags, and the browser model
bytes excluding its source-provenance comment. The fixtures were captured from
`bc1efd09`, before the source split; tests do not require that commit to be present
in a shallow checkout.

The first standalone comparison also loaded all seven original sources from
`git show bc1efd09:<path>` and compared their complete bundled objects to the
moved sources. That comparison passed before switching the retained test to the
captured fixture. This is source and inventory evidence, not regenerated-output
qualification.

## fragment ownership

- control public: discovery, public-urls, publish-runs, services, service-runs,
  publishers, publisher-groups, projects, connectors, workloads, browser-access,
  previews-and-shares, feedback, observations, admin, and common schemas.
- authority: login, sessions, teams, memberships, invites, domains, company,
  service, publisherauth, workload, and common schemas.
- ingress coordination: leases, certs, routing, admission, reporting, and common
  schemas.
- relay coordination: leases, certs, public-connections, private-connections,
  and common schemas.
- publisher browser: browser-access, feedback, and common values.
- local publisher: discovery, registration, invocations, observations, and common
  values.
- external usage receiver: reporting and common values.

`api/control/v1/applied-projects.md` moved to
`api/control/public/v1/applied-projects.md`, with its relative maintainer link
adjusted for the extra directory level.

## resolver and generation

`@apidevtools/json-schema-ref-parser` is now a direct, exact root development
dependency at `14.0.1`. That version already existed transitively in the lockfile;
the dependency change adds only the root importer. The established resolver owns
file loading and JSON-pointer lookup, with its HTTP resolver disabled. The named
component adapter preserves authored aliases and canonical component names while
flattening fragments. Duplicate YAML keys, missing references, duplicate operation
IDs, fragment-only cycles, and conflicting component names fail the build. Named
recursive schemas remain references.

The generator creates disposable bundles containing local named components.
Cross-contract references use canonical bundle filenames such as
`controlv1.yaml#/components/schemas/FeedbackID`; the four existing import mappings
still select `github.com/tnldotdev/tnl/pkg/api/controlv1`. The temporary directory
is removed on success or failure. Bundles are not committed generated output.

Run from the repository root through `mise exec --`:

```sh
node scripts/generate/openapi.ts
node scripts/generate/publisher-model.ts
go generate -skip 'scripts/generate/(openapi|publisher-model)\.ts' ./...
```

The first command generates `openapi.gen.go` in the seven existing `pkg/api/*`
directories in the table's dependency order: control, authority, ingress, relay,
usage receiver, browser publisher, local publisher. It also runs the existing Go
error-message normalizer where previously required. A package's `generate.go`
calls the same script with its canonical package name to generate just that
package, for example `node scripts/generate/openapi.ts localpublisherv1`.

The second command resolves the same graph, localizes control's named schemas for
typed-openapi, and generates `internal/publisher/browserapi/model.gen.ts`. Its
output must exist before the toolbar builder runs. The final command runs the
other Go directives without generating those contracts twice.

For external source consumers, this command only writes portable bundles and
does not run Go or browser generation:

```sh
node scripts/generate/openapi.ts --bundle-dir /absolute/output/directory
```

It writes `controlv1.yaml`, `authorityv1.yaml`, `ingressv1.yaml`, `relayv1.yaml`,
`publicurlusagev1.yaml`, `publisherv1.yaml`, and `localpublisherv1.yaml`. Their
cross-contract references work within that directory. Published website URLs
need their own explicit filename/reference projection if they retain the older
`openapi/<name>/v1/openapi.yaml` layout.

## other generator sources

| baseline script                            | current script                             | output/input owners                                                                                        |
| ------------------------------------------ | ------------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| `scripts/generate-config-types.ts`         | `scripts/generate/config-types.ts`         | reads `schema/v1.json` and `internal/client/project/keys.gen.json`; writes `packages/ts/src/config.gen.ts` |
| `scripts/generate-projectconfig-loader.ts` | `scripts/generate/projectconfig-loader.ts` | compiles `internal/client/project/loader.ts`; writes the neighboring `loader.mjs`                          |
| `scripts/generate-diagnostic-codes.ts`     | `scripts/generate/diagnostic-codes.ts`     | reads `internal/failure/diagnostic/catalog.json`; writes the neighboring `codes.gen.go`                    |
| `scripts/generate-publisher-model.ts`      | `scripts/generate/publisher-model.ts`      | reads the resolved browser/control graph; writes `internal/publisher/browserapi/model.gen.ts`              |
| `scripts/normalize-openapi-go.ts`          | `scripts/generate/normalize-openapi-go.ts` | normalizes the supplied generated Go file, called by the OpenAPI generator                                 |

The config and diagnostic generators use the tooling owner's relocated
`scripts/package/validation.ts`. Their generated headers name their new source
entrypoints. The loader and diagnostic generators follow the actual shared-tree
owners (`internal/client/project` and `internal/failure/diagnostic`).

## integration caller inventory

These caller updates are owned by the parent or the corresponding implementation
owner; they were identified by source search rather than assumed:

- `tasks/generate.yml`: the tooling owner has replaced the two broad `go generate`
  commands with the explicit three-command order above. Generated-path drift
  checks include all seven canonical outputs and the relocated browser/loader outputs.
- `internal/config/generate.go`: use `scripts/generate/config-types.ts` and format
  `internal/client/project/keys.gen.json` at its actual location.
- `internal/config/cmd/configgen/main.go:52`: the key-mapping writer still selects
  `internal/projectconfig/keys.gen.json`; update it to
  `internal/client/project/keys.gen.json` before running generation.
- `internal/failure/diagnostic/generate.go`: the implementation owner has updated
  the directive to `../../../scripts/generate/diagnostic-codes.ts`.
- `internal/client/project/typescript.go`: use
  `../../../scripts/generate/projectconfig-loader.ts` (the implementation owner
  has already updated this directive in the shared tree).
- `internal/publisher/browserapi/generate.go`: already points to
  `../../../scripts/generate/publisher-model.ts` in the shared tree.
- `internal/publisher/toolbar/api.ts` and
  `internal/publisher/localapi/readme.md`: update the source-contract references.
- root `AGENTS.md`, `contributing.md`, maintainer architecture, company-access,
  hosted-integration, publisher-provenance, and prerelease-review docs: replace
  live source references. The reorganization plan's baseline column is historical;
  its target table needs the newer public/private serving paths from this ledger.
- generated provenance comments in config, diagnostic, loader, and browser output
  are regenerated by their owning commands, not edited by hand.
- `.oxlintrc.json`: its generated-output ignores still name
  `internal/feedbacktoolbar/toolbar.js` and `internal/publisherapi/model.gen.ts`;
  update them to their moved owners. Workflow generation already uses the public
  Task; the release config has no contract-source reference.

The sibling `/Users/chase/git/tnldotdev/tnl.dev` was inspected read-only.
`scripts/sync-shared.ts:62-66` copies six sources through
`api/${name}/v1/openapi.yaml`; lines 103-125 also pass that old source pattern to
typed-openapi for control, authority, and usage models. Both loops need the new
entrypoint/bundle mapping. The hosted snapshots remain at
`apps/accounts/public/openapi/{control,authority,ingress,relay,public-url-usage,publisher}/v1/openapi.yaml`.
Do not copy only an entrypoint while omitting its referenced fragments, and do not
rename public hosted URLs merely because native source ownership changed.
Historical mentions in the sibling's `PAPERCUTS.md` and `POSSIBLE_FINDINGS.md`
were also found; they are not active loaders. No sibling files were modified.
The same sync script also reads `internal/diagnostic/catalog.json` at line 70 and
names that source in the generated header at line 79. Those references need
`internal/failure/diagnostic/catalog.json`; its hosted generated provenance header
will follow on the next sibling sync.

## standalone evidence and pending parent checks

On macOS with the pinned Node/pnpm versions, the following checks passed against
the uncommitted shared worktree based on `bc1efd09`:

```sh
mise exec -- pnpm install --frozen-lockfile --ignore-scripts
mise exec -- pnpm exec vitest run scripts/generate/openapi.test.ts --project node
mise exec -- pnpm exec tsc --project scripts/generate/tsconfig.json
mise exec -- pnpm exec oxlint --deny-warnings scripts/generate
```

The graph/inventory suite has 13 tests. It covers nested and URI-escaped file
references, escaped JSON pointers, reference siblings, named recursion, alias
preservation, missing files/pointers including unused schemas, duplicate YAML
keys/operation IDs, conflicting names, fragment cycles, and zero HTTP requests to
a listening local server. Inventory checks compare every operation and complete
contract hash, required generated public names and declarations, and browser
validator bytes. Vitest's existing Node project discovers the suite through its
normal `**/*.test.{ts,tsx}` pattern; `js:test` retains that discovery.
The export test also runs the bundle-only CLI twice, compares its bytes, and
reloads all seven exported documents to check portable cross-contract references.
Scoped oxfmt validation also passed for the 108 owned source, fragment, fixture,
and ledger files. The scoped Git whitespace check passed.

During the initial source-move pass, Go generation, browser model generation,
toolbar generation, whole-repository formatting/typechecking, Go tests, and
wire/consumer tests were left to parent integration. The follow-up below records
the actual regenerated-output review. No generated Go output was edited by hand,
staged, or committed.

## regenerated-output compatibility review

After the parent ran `task generate` on the role tree, review against `bc1efd09`
found only reordered `m.HandleFunc` calls in six generated files. All other bytes
were identical, including exported declarations, methods, fields, tags, enum
values, imports, request/response handling, and comments. Each file's complete
method/path/handler registration set also matched the baseline.

| package          | initial reordered lines, added/deleted | final generated-file diff |
| ---------------- | -------------------------------------: | ------------------------- |
| controlv1        |                                106/106 | byte-identical            |
| authorityv1      |                                  46/46 | byte-identical            |
| ingressv1        |                                  11/11 | byte-identical            |
| relayv1          |                                    6/6 | byte-identical            |
| publicurlusagev1 |                                    0/0 | byte-identical            |
| publisherv1      |                                    1/1 | byte-identical            |
| localpublisherv1 |                                    6/6 | byte-identical            |

The JSON encoding of temporary Go input bundles discarded the authored YAML path
order in oapi-codegen. Although the default HTTP mux chooses matches independently
of registration order, the public `ServeMux` interface permits custom routers to
observe that sequence. The generator now emits YAML for these temporary inputs,
preserving the original calls exactly. The portable bundle export and browser
generator retain their existing encodings. Only the seven API packages were
regenerated for this correction, using `node scripts/generate/openapi.ts`.

`public-types-v1.json` now also contains fixed SHA-256 goldens for all seven
registration sequences captured from `bc1efd09`. The new assertion failed on the
sorted control registrations before regeneration and passed after the generator
fix. The suite remains 13 tests. Its baseline names are provenance literals;
runtime assertions read the checked-in fixtures and source/generated files, with
no Git history, `HEAD`, clean-worktree, or base-branch requirement.

The complete bundled source hashes still match for all 249 operations and 383
schemas. All cross-contract references select existing control schemas, and the
four oapi-codegen import mappings retain
`github.com/tnldotdev/tnl/pkg/api/controlv1`: authority has 16 distinct references,
ingress 4, browser publisher 11, and local publisher 4. The other contracts have
no external schema references. A separate byte-for-byte comparison of each
regenerated Go file against `git show bc1efd09:<path>` passed for all seven files.

These follow-up commands passed on the uncommitted role tree:

```sh
mise exec -- node scripts/generate/openapi.ts
mise exec -- pnpm exec vitest run scripts/generate/openapi.test.ts --project node
mise exec -- task go:test:public-api
mise exec -- pnpm exec tsc --project scripts/generate/tsconfig.json
mise exec -- pnpm exec oxlint --deny-warnings scripts/generate
mise exec -- pnpm exec oxfmt --check scripts/generate/openapi.ts scripts/generate/openapi.test.ts api/fixtures/openapi-inventory/public-types-v1.json
```

The public API Task compiled the external consumer fixture successfully (Go
reported its cached result and no runtime tests). The follow-up did not run other
generation commands or change root dependency manifests.
