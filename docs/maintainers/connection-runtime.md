# native connection runtime

`await tnl.connect("database")` prepares native client access from Node or Bun.
the package root stays browser-safe and imports the Node implementation only on
that call. portable project declarations select exact service keys and protocol
results; allocated hostnames, ports, and exposure are runtime values.

```ts
import { tnl } from "@tnldotdev/tnl";

const database = await tnl.connect("database");
const credentials = {
  ...database,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
};
```

the application supplies SQL account settings. the result contains `host`,
`port`, and `ssl: {servername, rejectUnauthorized: true, ca?, cert?, key?}`.
private connections omit application client certificates; public connections
return a current native certificate snapshot. `ca` is omitted so the driver uses
its normal server roots. the client-certificate issuer is never a server root.
obtain another snapshot after its certificate expires.

HTTP returns `{url, fetch}`. its dedicated Undici dispatcher checks the managed
origin, uses current native mTLS material, limits active requests to 64, and
bounds requests and response bodies to 30 seconds or the credential deadline.
it preserves ordinary `Request`, body, `Response`, redirect, and cancellation
handling. redirects outside the managed origin fail. application `Authorization`
headers are passed through; tnl adds no application bearer token.

opaque TCP returns the loopback TLS helper's `{host, port}`. the helper owns
outer managed TLS, so applications must not add a second managed TLS layer.
Kubernetes returns `{server, kubeconfig, context}`. the native helper composes
the cluster bearer token and current tnl mTLS certificate into one exec
credential. local preparation uses `PlanLocal` without selecting a global
context; CI uses one private `PlanSession` file and returns it separately for
the action to export as `KUBECONFIG`. contexts use `tnl:shop/cluster` and the
existing ownership-based qualification rule.

## machine lifecycle, schema 1

these hidden commands always produce JSON. successful finite responses go to
stdout; authored machine errors go to stderr with a nonzero exit status. `tnl
version` and normal generated help retain their existing contracts.

```console
/absolute/tnl runtime connections capabilities
/absolute/tnl runtime connections context --directory /checkout/shop --ci migrate
/absolute/tnl runtime connections start --directory /checkout/shop --ci migrate --runner-temp /runner/temp
/absolute/tnl runtime connections status --handle /runner/temp/tnl-connections-.../handle.json
/absolute/tnl runtime connections stop --handle /runner/temp/tnl-connections-.../handle.json
```

`capabilities` returns `schema: 1`, the operation names, `workload_private`,
`opaque_private_preflight`, and
`team_names: "applied_binding"`. check this response before requesting an OIDC
assertion. this branch leaves `workload_private: false` until the separately
owned transport adapter is merged and installed at the factory below.

`context` evaluates configuration and source/worktree identity without opening
human client state. its nonsecret response contains:

```json
{
  "schema": 1,
  "directory": "/checkout/shop",
  "config_digest": "64 lowercase hex characters",
  "server": "https://control.example",
  "audience": "https://control.example",
  "team_id": "tm_...",
  "project_key": "project-...",
  "source_id": "source fingerprint",
  "worktree_key": "selected worktree key",
  "project_label": "shop",
  "ci": "migrate",
  "services": ["database"]
}
```

`--service NAME` may repeat to narrow the CI declaration; omission selects its
declared services. the fingerprint covers evaluated configuration, selected
server, Git source, and worktree. names such as `team: acme` use
`.tnl/generated/connections.json`, written after a successful administrator
`tnl apply`. commit this nonsecret binding alongside project declarations. it
binds server, configured team selector, exact team ID, project key, and source
fingerprint. it grants nothing; exchange still checks the saved policy. a
missing or mismatched binding fails before any JWT request. `--team-id` is an
explicit operator binding override. CI needs no human login or extra GitHub API
token to resolve its team.

`start` requires exactly this bounded JSON object on **stdin** for CI:

```ts
{ schema: 1, context, assertion: githubOIDCAssertion }
```

the parent recomputes the context and starts the same absolute executable as one
detached child. the child receives the request over a private pipe and creates
the ephemeral signing key in memory. assertion-request bearer environment
variables are removed; `RUNNER_TRACKING_ID` remains inherited. startup returns
only after selected native connections are ready. partial failure cancels and
joins earlier helpers and attempts workload revocation.

the success response is:

```ts
{
  schema: 1,
  state: "ready",
  pid: ownerPID,                 // observation only, never a cleanup capability
  expires_at: absoluteDeadline,
  public_runtime: browserSafeProjectRuntime,
  private_handle: absolutePrivateHandlePath,
  executable: exactAbsoluteBinaryPath,
  kubeconfig: privateSessionKubeconfigPath // present only for Kubernetes
}
```

the handle is mode 0600 in a mode-0700 owner directory under `RUNNER_TEMP`.
it contains a random IPC proof, loopback URL, project fingerprint, executable,
and deadline. it contains no JWT, workload credential, human credential, or TLS
key. the workload lease renews every 30 seconds within its fixed execution
deadline; failed renewal stops every helper. local SDK preparation uses an
existing human sign-in, prepares one owner for the project's managed services,
and stops it on app exit or its bounded parent/deadline check.

private listeners bind `127.0.0.1` at the allocated managed service port.
collision is an error; the owner never chooses a replacement port. HTTP and
database readiness performs verified native TLS negotiation without logging in
or issuing an SQL query. public native protocols connect directly; opaque TCP
uses the native outer-TLS helper.

## action consumer example

the next action owns GitHub token acquisition and environment-file writes. its
sequence is:

```ts
const capabilities = await nativeJSON(binary, ["runtime", "connections", "capabilities"]);
const context = await nativeJSON(binary, [
  "runtime",
  "connections",
  "context",
  "--directory",
  project,
  "--ci",
  policy,
]);
const assertion = await getIDToken(context.audience);
const started = await nativeJSON(
  binary,
  [
    "runtime",
    "connections",
    "start",
    "--directory",
    project,
    "--ci",
    policy,
    "--runner-temp",
    runnerTemp,
  ],
  { stdin: JSON.stringify({ schema: 1, context, assertion }) },
);

// save these exact nonsecret paths for post; never resolve PATH again.
saveState("binary", started.executable);
saveState("handle", started.private_handle);
exportVariable("TNL_PROJECT_RUNTIME", JSON.stringify(started.public_runtime));
exportVariable("TNL_CONNECTION_HANDLE", started.private_handle);
if (started.kubeconfig) exportVariable("KUBECONFIG", started.kubeconfig);

// post uses the original binary and private IPC, never a PID match.
await nativeJSON(savedBinary, ["runtime", "connections", "stop", "--handle", savedHandle]);
```

`nativeJSON` must bound stdout/stderr and time, pass stdin through a pipe, and
validate the response before narrowing its type. never log the start request or
private IPC payloads. the action exposes public runtime JSON and the private
handle path, without an application-environment mapping language.

## private IPC

the handle selects a numeric loopback HTTP origin. `Authorization: Bearer
<handle.key>` proves possession; browser origins are rejected. every request
contains `{schema: 1, directory, config_digest, service?}` and must match the
canonical selected project. requests, responses, headers, reads, and operations
are bounded. handle reads reject symlinks, wrong ownership, loose permissions,
and expiration. the Node SDK recomputes current project context through the
handle's exact executable before using it, including when an action prepared it.
`TNL_PROJECT_RUNTIME` never directs a file read.

| method | path                              | result                                             |
| ------ | --------------------------------- | -------------------------------------------------- |
| POST   | `/v1/connections/status`          | the nonsecret startup/status shape                 |
| POST   | `/v1/connections/connect`         | private current connection snapshot                |
| POST   | `/v1/connections/kube-credential` | composed Kubernetes exec credential                |
| POST   | `/v1/connections/stop`            | stop acknowledgement; CLI waits for joined cleanup |

only `connect` and `kube-credential` return native TLS material, on private IPC. snapshots
include `schema`, protocol, host, port, `expires_at`, protocol-specific fields,
and optional `ssl`. Kubernetes's helper is pinned to the same executable and
handle. stopping closes listeners and streams, joins connector workers, removes
the owned session kubeconfig, and revokes the workload. a nonsecret terminal
record preserves whether cleanup succeeded.

## transport merge and remaining qualification

`cmd/tnl/connections_backend.go` deliberately uses the factory
`newWorkloadConnectionControl`. after the transport commit is available, set it
to `tcpconnect.NewWorkloadControl`. its actual contract returns
`(tcpconnect.Control, error)` for `*workloadclient.Client`; `Config.IdentityID`
is empty for that subject. `ResolvePrivateService` supplies the approved run,
trust revision, protocol, and managed TLS endpoint. no human ID substitutes for
a workload. closing a service adapter releases only its own assignments; the
owner retains session renewal/revocation.

signed transport tip `7415424f` supplies that adapter. it also changes
`ClientTLSCertificate` to an opaque TLS signer and keeps certificates valid for
the fixed session window while checking the renewable lease at admission.
`workloadCredentialSnapshot(ctx, client, serviceID)` is the separate native-only
PEM snapshot factory. it must return a current exportable `tls.Certificate` with
the same workload key and service/session identity. this needs an upstream
native-only snapshot API or an owner-supplied ephemeral-key constructor; the
signed transport tip currently exposes neither. do not marshal an opaque signer
or substitute a second key. preparation checks exportability before reporting
ready, and all material still travels only over protected IPC.

the private workload native-process fixture and private Drizzle transport
variant require that merge. opaque private TCP also needs the transport owner's
verified probe installed as `preflightOpaqueConnection(ctx, tcpconnect.Config)`.
that capability remains false and preparation fails until the probe is
available; connector-path readiness alone cannot report complete native TLS
readiness. the existing helper verifies TLS before forwarding application bytes.

```console
mise exec -- task go:test:connections
mise exec -- task go:test:integration:connections
mise exec -- task js:check
```

the first target covers private IPC lifecycle and real native-process SDK HTTPS,
including mTLS, standard body/response behavior, cancellation, certificate
rotation, lost exchange response recovery, and revocation. it also checks the
Kubernetes SDK result, composed native exec credential, and session-file cleanup.
the integration target creates and removes digest-pinned disposable PostgreSQL
and runs actual Drizzle Kit migration through a public native TLS endpoint.
Drizzle Kit 0.31's synchronous CommonJS config loader uses an in-memory preload
in this fixture after awaiting `tnl.connect`; no credential-bearing config file
is generated. routine TypeScript tests check both public and private SQL option
shapes, malformed/expired snapshots, opaque TCP, and browser rejection.
