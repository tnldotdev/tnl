# native kubernetes boundary

`protocol: kubernetes` uses the existing service publisher stream and
publisher connection slots. the publisher terminates managed visitor TLS,
authorizes the visitor, then verifies a separate HTTPS connection to the cluster.
tunnel protocol version 1 carries the same stream headers and bytes.

the visitor's Kubernetes `Authorization` header reaches the cluster unchanged.
public access uses a tnl client certificate; private access uses the authenticated
connector identity. browser sign-in redirects, tnl cookies, shares and feedback
endpoints do not handle Kubernetes requests. Kubernetes client-certificate
authentication needs opaque TCP when the original certificate must reach the
cluster.

an explicit cluster CA is pinned for the publisher's Kubernetes target transport;
it does not fall back to system WebPKI roots. a `target.tls` system-root selection
instead uses the target's own verified WebPKI hostname.

## prepare a context

the native connection result includes `protocol`, `namespace`, and `kubeconfig`
with `file`, `context`, `namespace`, `qualified`, and `files`. it contains paths and
connection metadata, not bearer tokens, certificate PEM or private keys.

`internal/connector/kubeconfig` exports the common local and session preparation boundary:

```go
plan, err := kubeconfig.PlanSession(runnerTemp, sessionID)
// handle err; runnerTemp is an absolute, non-symlink directory.
result, err := kubeconfig.PrepareConnection(ctx, plan, kubeconfig.Options{
    Owner: owner, // immutable control URL, team, source, and service IDs
    ProjectLabel: "shop",
    Service: "cluster",
    Namespace: "development",
    Server: serviceHTTPSOrigin, // or the private connector's loopback HTTPS origin
    TLSServerName: managedHostname,
    Helper: absoluteTnlExecutable,
}, kubeconfig.Profile{
    Owner: owner,
    StateDir: privateSessionStateDirectory,
    IdentityID: identityID,
    Public: public,
    Source: kubeconfig.Source{EKS: &kubeconfig.EKS{
        Cluster: "shop", Region: "us-east-1",
    }},
})
```

the session caller exports `result.File` as `KUBECONFIG`. this one-cluster file
selects `tnl:shop/cluster` as its current context. retain `plan` and `result` to
call `plan.CleanupSession(ctx, result)` with a live cleanup context; cleanup
retains a changed file. the session owner also owns its private state directory
and the returned profile path. profile state can serve several contexts, so its
lifetime belongs to that owner.

local `tnl connect` calls `PlanLocal(home, kubeconfigEnvironment)`. it writes to
the first nonempty selected path, keeps relative references in their original
files, and checks other selected files for collisions. it preserves the global
current context, unrelated entries, comments, and an owned namespace when no new
namespace is selected. a different immutable owner gets a deterministic qualified
name and a visible diagnostic. writes use a user-owned lock, private temporary
file, sync, and atomic replacement; aliases, YAML merge keys, duplicate keys and
symlink paths are rejected.

## compose client credentials

the generated kubeconfig uses one absolute `tnl connect kube-credential --profile
...` command with `client.authentication.k8s.io/v1` and `interactiveMode: Never`.
there are no static kubeconfig client-certificate fields: client-go would prefer
those fields and skip the plugin that supplies the cluster token.

`kubeconfig.Credential(ctx, profile, issueCertificate)` returns one official
`ExecCredential` containing the bearer token and, for public access, tnl client
certificate and key. expiry is the earlier certificate/token deadline. the CLI's
certificate callback uses the existing native enrollment and renewal boundary.
session integrations can supply `IssueCertificate` or protected
`Profile.Certificate` file references backed by their own certificate lifecycle.
profiles are immutable and content-addressed, so a failed kubeconfig write cannot
change a credential source already used by an existing context.

`Source` accepts exactly one of:

- `EKS`: invoke the standard runner's `aws eks get-token`; AWS's normal credential
  chain selects the runner role. preparation makes no AWS call.
- `TokenFile`: read a user-owned, mode-0600 bearer-token file on each helper run.
- `ConfigFile` plus `ExistingUser`: explicitly select a token/token-file or
  noninteractive exec user. relative paths retain that kubeconfig's base
  directory. an unselected exec entry is never executed. interactive-only,
  auth-provider, and client-certificate users are rejected.

local address targets use `--kube-token-file`, or both `--kube-user-config` and
`--kube-user`. `--namespace` selects the context namespace; `--kubeconfig` selects
the destination file. a configured EKS target supplies the cluster and region.

## connect publisher discovery and backend adapters

`kubernetes.ResolveEKS(ctx, discovery, region, cluster)` calls the narrow
`EKSDiscovery.DescribeEKS(context.Context, string, string)` publisher adapter. its
`DiscoveredCluster` contains `Endpoint` and base64 `CertificateAuthorityData`.
the result has a normalized `Address`, verified `TLS`, canonical CA-only `CAPEM`,
and a `privatetrust.Snapshot` in `Trust` for declaration/approval. it contains no
Kubernetes user credential. the discovery owner supplies the AWS describe adapter.

the generation-123 base accepts the config protocol but its serving OpenAPI enum
and control authorization still need the parent backend update. native adapters
can use `controlv1.ServiceProtocol("kubernetes")` until the generated named
constant exists. the parent also owns the SDK native-result consumer and CI
session/export hooks. those callers should reuse `PrepareConnection` rather than
reimplement kubeconfig or credential composition.

## request limits and qualification

every request checks current policy before forwarding, including upgrades.
the connection guard rechecks at half the last decision lifetime, capped at
30 seconds, and closes active watches and hijacked connections on denial or
expiry. transient authorization failures cannot extend the last confirmed
deadline. a normal request lasts at most two minutes, a long watch/log/upgrade
at most one hour, and request bodies at most 16 MiB. `publisher.KubernetesLimits`
allows narrower or explicit native stream durations (maximum 24 hours). the
existing run-wide HTTP request/concurrency budget applies to Kubernetes too.

request trace classification contains only bounded verb, API group, resource and
subresource labels. namespaces, object names, queries, commands, manifests,
credentials and response bodies are excluded. custom groups/resources become
`other`; labels are descriptive and never decide Kubernetes authorization.

```console
mise exec -- task go:test:kubernetes
mise exec -- task go:test:integration:kubernetes KIND=/absolute/path/to/kind
```

the opt-in target requires Docker, kubectl, and kind v0.30.0. it creates and removes
a fresh digest-pinned Kubernetes 1.34 cluster and digest-pinned BusyBox pod. the
qualified client was kubectl v1.36.1. both public certificate and private connector
admission exercise discovery/list, server-side apply, CRUD, rollout watch,
WebSocket exec, SPDY exec, logs-follow, attach, copy and active port-forwarding.
watch, exec, logs, attach and active port-forward connections close on revocation.
routine fixtures also check transparent WebSocket/SPDY upgrade bytes, target
certificate rejection, bounded long watches, safe kubeconfig updates and real
client-go v0.37.1 composed exec authentication.

these frontend proofs use current-policy callbacks. the complete control,
ingress, relay and connector topology still needs the parent's backend-adapter
qualification after the serving enum/schema integration lands.
