# portable project generation

`tnl generate` writes `.tnl/generated/project.d.ts` and applicable publisher AWS
artifacts. Commit this directory. `tnl generate --check` compares every owned
output without writing files; `tnl check` validates configuration and prints the
selected path. Both commands bypass client state and authentication.

Type-only projects and configured local publication need neither Git nor an
origin. AWS publisher and workload declarations require a real portable Git
origin because their manifests carry the source identity. Local publication
instead uses the canonical directory identity, which survives Git initialization
and origin changes. `--output-dir` is relative to the selected project root;
the declaration's type-only config import is relative to that output directory.
The artifact manifest owns the declaration hash as well as infrastructure files.
Writers reject symlink output paths and preserve unrelated files.

## declaration boundary

For TypeScript, the declaration registers
`typeof import("../../tnl.config.js").default` in the root SDK's
`TnlProjectConfig` interface. `TnlResolvedConfig`, `TnlProjectFromConfig`, and
`TnlServices` derive types from factory returns, preserving service unions and
optional properties across checkouts. `TnlConfigContext` always uses the broad
worktree type; it never depends on the generated registry. YAML/JSON produces
an exact static shape instead. Names, protocols, mounts, alias references, and
webhook paths/methods stay exact. Hostnames, ports, and exposure stay runtime
values with `string`, `number`, and `boolean` types.

A config with genuinely dynamic service names must declare its stable key set,
for example `TnlConfigForServices<"api" | "db">`. The generated declaration and
SDK service lookup report a stable-name diagnostic for `Record<string, ...>`.
Check declarations with TypeScript's `skipLibCheck: false` to surface that
generation diagnostic even before using an SDK service.

`TnlProtocolRegistry` defines browser-safe metadata for HTTP, PostgreSQL, MySQL,
TCP, and Kubernetes. `tnl.services.NAME` exposes the selected protocol,
hostname, allocated port, and current exposure; HTTP and Kubernetes also have an
HTTPS URL pattern. Missing runtime preparation raises a diagnostic. Browser
imports do not read local files. Ignored `.tnl/local/project.json` carries values
only, and the runtime writer never produces a declaration.

Local startup omits remote services that have no current visitor projection in
control, so an unapplied remote declaration does not block local listeners.
Applied remote endpoints still come from control; other lookup failures remain
errors.

`TnlConnectionRegistry` defines the server-only native connection result boundary.
PostgreSQL returns loopback `{host, port, ssl}` with the managed TLS server name.
MySQL returns the managed `host`, local `port`, a fresh mutable `ssl` object with
`verifyIdentity: true`, and mysql2's loopback `stream` factory. HTTP returns
`{url, fetch}` with an SDK-owned origin-restricted transport; TCP returns
`{host, port}`, and Kubernetes returns `{server, kubeconfig, context}`. Every
protocol requires the matching native binary on Node or Bun. The connector owns
admission for both public and private endpoints; no application client
certificate or key enters these snapshots. Omitting the optional `ssl.ca` uses
the driver's normal server roots. Await `tnl.connect(NAME)` to prepare one
service; synchronous reads require an already prepared owner. See the
[connection runtime](connection-runtime.md) for protocol and lifetime details.

## shared configuration shape

`internal/config` owns the static snake_case shape; the schema generator owns
`schema/v1.json`. The TypeScript generator and key mappings produce camelCase
SDK types from those sources. `projectconfig.Project.Declared` retains the
evaluated declarations before local Compose defaults are filled in.
`Project.StaticMap()` returns that validated snake_case shape for API mapping;
`Project.SourceIdentity(ctx)` separately supplies the project key, fingerprint,
and source label. API consumers should map these values into their owned models.

```yaml
version: 1
tnl:
  publishers:
    production:
      aws: { replicas: 2 }
  services:
    cluster:
      publisher: production
      protocol: kubernetes
      target: { type: eks, cluster: development, region: us-east-1 }
    db:
      publisher: production
      protocol: postgres
      target: { type: rds, cluster: orders, region: us-east-1, endpoint: writer }
  workloads:
    deploy:
      provider: github
      github:
        repository: company/project
        workflow: .github/workflows/deploy.yml
        ref: refs/heads/main
        events: [push, workflow_dispatch]
      services: [cluster, db]
      max_duration: 1h
```

`workloads.NAME.github` with `provider: github` optionally selects an environment and an exact
`reusable_workflow` (`owner/repository/.github/workflows/file@ref`). An omitted
repository is inferred from GitHub origin by the applying consumer, never by
type generation. Workflow paths and refs are exact; events are a declared enum;
service references must name existing keys. `max_duration`, when set, is
positive and at most six hours. omission means one hour;
`config.Workload.DurationLimit()` shares this default with consuming code without
filling in the declaration. visitor access grants do not imply workload authority.

`tnl generate` also writes `workloads.json` for any declared workloads. package
this nonsecret build manifest with a deployed application so its runtime can
select a saved workload without Git or evaluating TypeScript configuration.
see [workload sessions](workload-sessions.md) for provider acquisition and fields.

RDS selects exactly one `instance` or `cluster`; `endpoint` defaults to `writer`,
and `reader` is cluster-only. EKS and RDS selectors contain no discovered
addresses, CA snapshots, or application database secrets. Generated task roles
receive only resource-scoped `eks:DescribeCluster`, `rds:DescribeDBInstances`, or
`rds:DescribeDBClusters` for their declared resources, using `AWS::AccountId` and
the configured region. Identity-secret injection remains on the separate
execution role and existing bootstrap contract.

Control API/SQL mapping, publisher AWS discovery, GitHub Action execution, and
native SDK connections consume this foundation in their owning components.
Tunnel protocol version 1 remains the transport contract.

## init type includes

`tnl init` adds the generated declaration to ordinary JSON and JSONC tsconfig
files. It uses parsed syntax-tree offsets to retain existing comments, line
endings, compiler options, and reference lists. Referenced projects get includes
relative to their own config directory; a solution-only root keeps its empty
`files` list. With no explicit source list or inheritance, init retains the
default `**/*` source glob alongside the generated declaration. Repeated runs
leave already wired files byte-identical.

When an inherited include cannot be interpreted safely, or the selected config
is ambiguous or a symlink, init gives an exact include action. Static projects
without JavaScript tooling need no package manifest, TypeScript compiler, or
dependency installation to generate their declarations.
