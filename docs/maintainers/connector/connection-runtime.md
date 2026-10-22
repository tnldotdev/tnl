# native connection runtime

`await tnl.connect("database")` prepares native client access from Node or Bun.
the package root stays browser-safe and imports the Node implementation only on
that call. portable project declarations select exact service keys and protocol
results; allocated hostnames, ports, and exposure are runtime values.

every protocol requires the matching native executable, including HTTP and
Kubernetes. deploy the platform package or Python wheel with the application;
a public endpoint does not select a direct-dial SDK path. configured local
publication uses a directory identity without Git; portable apply and generated
workload manifests retain their separate Git-source boundary.

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

the application supplies SQL account settings. every service uses an authenticated
loopback connector, including services with public endpoints. PostgreSQL settings
contain `host: "127.0.0.1"`, the actual listener `port`, and
`ssl: {servername, rejectUnauthorized: true, ca?}`. `ssl.servername` is the approved
managed hostname. no snapshot contains an application client certificate or key.
`ca` is normally omitted so the driver uses its normal server roots.

MySQL settings use mysql2's supported `host`, `port`, `ssl`, and `stream` options:
`host` is the managed hostname, `ssl.verifyIdentity` is `true`, and `stream()`
creates a fresh socket to the native loopback listener. mysql2 ignores
`ssl.servername`; giving it the loopback IP as `host` would lose hostname
verification. its `ssl` object is a fresh mutable copy because the driver writes
`rejectUnauthorized` during connection setup. a pool calls the stream factory
for each new connection. use the returned settings directly:

```ts
import mysql from "mysql2/promise";
import { tnl } from "@tnldotdev/tnl";

const database = await tnl.connect("database");
const pool = mysql.createPool({
  ...database,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});
```

`mysql` 2.18.1 is unsupported: it ignores these identity/stream options, has no
supported hostname-verification setting, and cannot authenticate with
`caching_sha2_password`. a legacy-auth account can make a query succeed while a
wrong-name certificate is accepted. do not treat that as compatible verified TLS.

pg's default `enableChannelBinding: false` works through publisher TLS termination.
turning it on selects SCRAM-PLUS when the target offers it and fails with SQLSTATE
`0A000`; the frontend and target certificates have different channel bindings.
Postgres.js 3.4.9 uses non-PLUS SCRAM and accepts the returned `host`, `port`, and
`ssl` directly. its application settings are ordinary `user`, `password`,
`database`, `max`, and `prepare` options. the accounts adapter's `max: 5` and
`prepare: false` need no `connection.channel_binding` parameter.

native PostgreSQL cancellation is unsupported; use provider `statement_timeout`
or explicitly authorized SQL cancellation. see the
[database cancellation boundary](../publisher/database-cancellation.md) for tested client
options, ownership proof, and the required follow-up design.

psql and psycopg/libpq use the managed `host`, loopback `hostaddr`, local port,
`sslmode=verify-full`, `channel_binding=disable`, and `gssencmode=disable`.
the last two options select supported SCRAM/TLS behavior across publisher TLS
termination; they do not turn off certificate or hostname verification. libpq
trust comes from `sslrootcert`, not a Python `SSLContext`. see the
[Python adapter instructions](../../../packages/py/connections.md#client-adapters)
for CA-file ownership and supported system-root versions.

HTTP returns `{url, fetch}`. its reusable Undici pool checks the managed
origin and dials the loopback listener with the managed TLS server name. eight
connections, a bounded pending-call budget, and four draining pool generations
bound local resources. caller cancellation controls streamed bodies without a
hidden 30-second total abort. redirects are manual, including same-origin
redirects; no body is replayed. application `Authorization`
headers are passed through; tnl adds no application bearer token.

the SDK calls its owned Undici fetch implementation on both Node and Bun.
Bun's global fetch ignores Undici dispatchers, so passing it a dispatcher would
not enforce the loopback dial boundary. the installed ESM/CommonJS fixture in
`packages/ts/test/connector/connection-installed.test.ts` runs actual Node and Bun processes and
checks managed Host/SNI, streamed uploads, manual redirects, and no request replay.
this resolves the targeted local Bun transport question; deployed provider
freeze/thaw remains a separate qualification.

opaque TCP returns the loopback TLS helper's `{host, port}`. the helper owns
outer managed TLS, so applications must not add a second managed TLS layer.
Kubernetes returns `{server, kubeconfig, context}`. the native helper composes
the cluster bearer token into an exec credential. its kubeconfig uses a loopback
`server` and managed `tls-server-name`. local preparation uses `PlanLocal` without selecting a global
context; CI uses one private `PlanSession` file and returns it separately for
the action to export as `KUBECONFIG`. contexts use `tnl:shop/cluster` and the
existing ownership-based qualification rule.

## ownership and authorization lifetimes

| scope                            | owner and deadline                                                                                                      |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| local publication                | one canonical project/client-state owner and evaluated configuration; app registrations and named leases keep it alive  |
| SDK connection process           | one verified human or workload identity/policy scope; selected services prepare independently                           |
| caller-prepared connection owner | the caller owns start and joined stop; `TNL_CONNECTION_HANDLE` retains its original fixed deadline                      |
| workload session                 | one key, exact service scope and fixed execution window; a renewable lease never extends that window                    |
| prepared snapshot                | one service adapter's transport identity and current authorization deadline; existing driver settings do not update     |
| admitted operation               | its original subject/session and exact run; bounded live decisions renew only within that original authorization window |

public HTTP responses and WebSocket upgrades retain live guards just as managed
HTTP and PostgreSQL streams do. guards recheck current access within 30 seconds
and fail closed at the last successful decision deadline during a control outage,
at most two minutes and never beyond an earlier credential/session/run deadline.
renewal can keep an authorized operation alive within its original scope; a fresh
session cannot extend that operation's original deadline. denied or failed
operations close without replay. pool reuse and stable listener ports do not
replace these checks.

## machine lifecycle, schema 1

these hidden commands always produce JSON. successful finite responses go to
stdout; authored machine errors go to stderr with a nonzero exit status. `tnl
version` and normal generated help retain their existing contracts.

```console
/absolute/tnl runtime connections capabilities
/absolute/tnl runtime connections context --directory /checkout/shop --workload migrate
/absolute/tnl runtime connections start --directory /checkout/shop --workload migrate --runner-temp /runner/temp
/absolute/tnl runtime connections status --handle /runner/temp/tnl-connections-.../handle.json
/absolute/tnl runtime connections read --handle /runner/temp/tnl-connections-.../handle.json --service database
/absolute/tnl runtime connections prepare --handle /runner/temp/tnl-connections-.../handle.json --service database
/absolute/tnl runtime connections stop --handle /runner/temp/tnl-connections-.../handle.json
```

`capabilities` returns `schema: 1`, the operation names, `workload_private`,
`opaque_private_preflight`, and
`team_names: "saved_policy"` and `workload_manifest: true`. both transport capabilities are true. check this
response before requesting an OIDC assertion.

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
  "workload": "migrate",
  "services": ["database"]
}
```

`--service NAME` may repeat to narrow the workload declaration; omission selects its
declared services. the fingerprint covers evaluated configuration, selected
server, Git source, and worktree. names such as `team: acme` use
`.tnl/generated/connections.json`, written after a successful administrator
`tnl apply`. commit this nonsecret binding alongside project declarations. it
binds server, configured team selector, exact team ID, project key, and source
fingerprint. it grants nothing; exchange still checks the saved policy. without
a matching binding, the exact configured team name remains a selector that
control resolves during exchange. `--team-id` is an explicit operator selector.
workloads need no human login or extra GitHub API token to resolve their team.
`--workload-manifest .tnl/generated/workloads.json` loads build-time context
directly without Git or project config evaluation; see [workload sessions](../control/workload-sessions.md).

`start` requires exactly this bounded JSON object on **stdin** for workloads:

```ts
{ schema: 1, context, assertion: providerOIDCAssertion }
```

the parent recomputes the context and starts the same absolute executable as one
detached child. the child receives the request over a private pipe and creates
the ephemeral signing key in memory. assertion-request bearer environment
variables are removed; `RUNNER_TRACKING_ID` remains inherited. startup returns
after identity, session, and owner IPC are ready for an SDK-owned process.
service listeners and verified preflight are lazy, selected by that service's
first explicit `prepare` operation. a service failure does not stop another prepared service.
caller-prepared CLI startup verifies its selected service set before reporting
ready, retaining the action and plain-client preparation contract.

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
deadline. data-plane admission fails closed after a failed renewal; an SDK-owned
process retains IPC so a fresh assertion can authorize future connections.
local human preparation uses an existing sign-in. SDK startup selects the
authorized service scope, then prepares only the awaited service. the process
stops on app exit or its parent check.

process-owned capabilities have a process-lifetime `ready.expires_at`, separate
from the current connection snapshot's authorization deadline. human renewal has
no one-hour owner cutoff. reusable workload providers can attach fresh verified
assertions and replace expired sessions for future accepts while keeping the
same listener. old streams retain their old subjects and deadlines.

TypeScript and Python recover an early owner death only after native's
`recover --handle` proves that its OS lifetime lock is released. IPC timeouts,
service denial, and malformed recovery replies do not authorize a second owner.
bounded caller-owned sessions still require joined cleanup after expiry.

synchronous handle reads cannot replace an expired owner: TypeScript reports
`sdk.connection_unprepared`, and Python reports `sdk.connection_expired`.
the implementer must await fresh settings and recreate any database pool or
connection that needs them. returned snapshots stay stable (mysql2 receives its
own mutable `ssl` copy); tnl does not
mutate old driver settings or replay SQL. this recovery applies only to
SDK-started owners. `TNL_CONNECTION_HANDLE` owners remain caller-owned and retain
their original fixed deadline, including workload sessions.

SDK-owned listeners bind an ephemeral port on `127.0.0.1`, so distinct verified
identities can coexist without sharing a capability. caller-prepared CLI owners
bind the allocated managed service port and report collisions. HTTP and
database readiness performs verified native TLS negotiation without logging in
or issuing an SQL query. opaque TCP uses the native outer-TLS helper. the service's
approved public setting, hostname, and port remain unchanged in browser-safe
metadata; private connection snapshots describe the local listener separately.

`read --handle FILE --service NAME` synchronously reads the current prepared
schema-1 wrapper through the existing owner's `prepared` IPC operation. it pairs
`public_runtime` with `connection` under the same owner's operation lock.
it reads existing local state only. it does not start an owner, session, listener,
provider acquisition, control request, or repair. an unprepared sibling fails;
awaiting the SDK handle sends `prepare` instead. only the
handle path and service name appear in argv; the capability stays in the private
handle and HTTP header. the operation is bounded to five seconds and expired
handles, owners, or snapshots fail with `TNL_CLIENT_CONNECTION_EXPIRED`. callers
must prepare again after expiration; a read never replaces the owner.

```json
{
  "schema": 1,
  "public_runtime": {
    "dev": false,
    "namespace": "production.shop.example",
    "services": {
      "database": {
        "protocol": "postgres",
        "namespace": "production.shop.example",
        "hostname": "database.production.shop.example",
        "port": 25443,
        "public": true
      }
    }
  },
  "connection": {
    "schema": 1,
    "protocol": "postgres",
    "host": "127.0.0.1",
    "port": 25443,
    "transport_id": "ctg_aaaaaaaaaaaaaaaaaaaaaa",
    "ssl": { "servername": "database.production.shop.example", "rejectUnauthorized": true },
    "expires_at": "2026-10-20T18:00:00Z"
  }
}
```

HTTP and Kubernetes snapshots add `url: "https://MANAGED_HOST:ALLOCATED_PORT"`.
Kubernetes also adds absolute `kubeconfig` and owned `context` values. opaque TCP
omits `ssl` and `url` because tnl owns its outer TLS. HTTP origin and local dial
address must be handled independently by the SDK dispatcher. the Kubernetes
client's `server` is the loopback HTTPS address from `host` and `port`, matching
the kubeconfig; its `tls-server-name` remains `ssl.servername`.

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
  "--workload",
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
    "--workload",
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

## private ipc

the handle selects a numeric loopback HTTP origin. `Authorization: Bearer
<handle.key>` proves possession; browser origins are rejected. every request
contains `{schema: 1, directory, config_digest, service?}` and must match the
canonical selected project. requests, responses, headers, reads, and operations
are bounded. handle reads reject symlinks, wrong ownership, loose permissions,
and expiration. Node and Python use their installed native binary to read the
existing owner's exact scope, including when an action prepared it. reads do not
recompute project context or resolve an executable from handle contents.
`TNL_PROJECT_RUNTIME` never directs a file read.

| method | path                              | result                                                    |
| ------ | --------------------------------- | --------------------------------------------------------- |
| POST   | `/v1/connections/status`          | the nonsecret startup/status shape                        |
| POST   | `/v1/connections/connect`         | private current connection snapshot                       |
| POST   | `/v1/connections/prepared`        | same-owner public metadata and private snapshot           |
| POST   | `/v1/connections/prepare`         | explicit service preparation and verified assertion reuse |
| POST   | `/v1/connections/kube-credential` | composed Kubernetes exec credential                       |
| POST   | `/v1/connections/stop`            | stop acknowledgement; CLI waits for joined cleanup        |
| POST   | `/v1/connections/attach`          | authenticated assertion attachment through authority      |

`connect` returns prepared connection options on private IPC. snapshots
include `schema`, protocol, host, port, `expires_at`, protocol-specific fields,
and optional `ssl`. Kubernetes's helper is pinned to the same executable and
handle. stopping closes listeners and streams, joins connector workers, removes
the owned session kubeconfig, and revokes the workload. a nonsecret terminal
record preserves whether cleanup succeeded.

async SDK calls use a bounded persistent authenticated loopback HTTP connection
after loading the mode-0600 handle from its mode-0700 owner directory. native
subprocesses remain responsible for startup, identity selection on a new
assertion, synchronous prepared-only reads, recovery proof, and joined stop.
each new adapter has a fresh opaque `transport_id`; HTTP pool selection includes
that ID even when the managed origin, local port, and TLS options stay unchanged.
retired pools drain their old responses and cannot receive a future request.

authority returns the verified `assertion_expires_at` for identity selection,
exchange, and attachment. SDKs cache only an exact assertion digest and its
control-confirmed binding/expiry, never decoded JWT claims. acquisition still
reads the current request or file every time. native reuse additionally requires
a live matching session and rechecks assertion policy and service access at most
30 seconds apart. explicit `attach` always goes through authority. cached
metadata is not a visitor grant; admission and active guards remain authoritative.

## native transport ownership and qualification

`cmd/tnl/connections_backend.go` uses `tcpconnect.NewWorkloadControl` with the
owner's `*workloadclient.Client`; `Config.IdentityID` is empty for that subject.
`ResolvePrivateService` supplies the approved run,
trust revision, protocol, and managed TLS endpoint. no human ID substitutes for
a workload. closing a service adapter releases only its own assignments; the
owner retains session renewal/revocation.

the native owner generates one ephemeral signing key per workload session for
exchange and connector proofs. current authorization retains the exact workload service set,
fixed execution deadline, and renewable lease. no human device represents a workload.

before returning its first prepared snapshot, the selected connector opens one authorized stream through its
existing ingress paths, verifies managed TLS with the approved protocol, and
closes it without sending application bytes. native HTTP, PostgreSQL, MySQL, and
Kubernetes keep their native TLS bytes for later local clients. a TLS
rejection fails only that service's preparation. Kubernetes defaults use control's saved `KubernetesAuth`
hint, including workload inventory, rather than unapplied local selectors.

```console
mise exec -- task go:test:connections
mise exec -- task go:test:integration:connections
mise exec -- task js:check
```

the first target covers private IPC lifecycle and real native-process connector
HTTPS, lost exchange response recovery, prepared reads, and revocation. it also
checks loopback Kubernetes server identity, native exec credentials, and
session-file cleanup.
the integration target creates and removes digest-pinned disposable PostgreSQL
and runs actual Drizzle Kit migrations for public and private managed endpoints.
the fixture packs matching native and launcher tarballs, installs them with pnpm,
and runs `pnpm exec drizzle-kit migrate` using an ordinary synchronous config
that spreads `tnl.connect("database")`. it verifies the created table through the
installed SDK and directly in PostgreSQL. the same installed-package path checks
HTTP managed origins and local Kubernetes settings. the SDK owner tests SQL option
shapes, malformed/expired snapshots, opaque TCP, and browser rejection.

`task go:test:integration:tcp-clients` also installs the packed SDK and matching
native binary in an isolated pnpm consumer, using Node 22.23.2. the disposable
TLS PostgreSQL and MySQL providers own real password authentication and SQL
queries. production ingress port selection and `publisher.ManagedStream` perform
native PostgreSQL/MySQL negotiation and independent frontend/target TLS. a real
connection owner serves prepared IPC to the installed binary; policy and placement
are fixture decisions, without a control service or deployed authority exchange.

the pinned installed-driver cases cover:

| client      | version | evidence                                                                                                                                                   |
| ----------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| pg          | 8.23.1  | ESM/CommonJS SDK, auth/query, Drizzle ORM, pool reuse and idle replacement, bad CA/name/password, opt-in PLUS rejection                                    |
| Postgres.js | 3.4.9   | ESM/CommonJS SDK, SCRAM auth/query with `max: 5, prepare: false`, Drizzle ORM, pool reuse and idle replacement, bad CA/name/password                       |
| mysql2      | 3.24.6  | ESM/CommonJS SDK, fresh `caching_sha2_password` full auth/query, Drizzle ORM, pool reuse and idle replacement, bad CA/name/password, frozen-ssl regression |
| mysql       | 2.18.1  | unsupported: modern auth rejection and wrong-name certificate acceptance with an isolated legacy-auth account                                              |
| Drizzle ORM | 0.45.4  | real queries through its pg, postgres-js, and mysql2 adapters                                                                                              |
| Drizzle Kit | 0.31.11 | separate connections target; synchronous ordinary config and verified migration, without a preload                                                         |

the TCP target retains real `psql` and `mysql` command checks from the digest-pinned
provider images through certificate and connector admission. these results qualify
the listed versions and paths; they do not establish compatibility for every SQL
driver, another runtime, or the accounts application's complete database workflow.

`task go:test:integration:vercel` qualifies the installed SDK in a real emitted
Vercel Node 24 function that starts its own packaged native owner. see
[local Vercel qualification](vercel-functions.md) for artifact checks, invocation
evidence, platform limits, and the separate deployed startup boundary.
