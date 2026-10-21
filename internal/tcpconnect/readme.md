# private connector boundary

`NewControl(client, profile, identityID)` adapts the authenticated control API
and protected client state to `Control`. `Serve` keeps two independent ingress
sessions and opens one admitted native TLS stream per loopback connection.
`Stream` uses the same transport and admission owner for one opaque stream,
without opening a listener. Its caller owns the stdin/stdout adaptation.
Callers provide the immutable service ID, protocol, approved `TrustRevision`
and control-owned `ManagedTLS` endpoint in `Config`.

## device and infrastructure trust

The adapter saves a pending device key before enrolling it. An enrollment
response must name the same identity and exact public key before its device ID
can be saved. Retrying enrollment uses the protected pending key.

Startup reserves one pair of ingress assignments. Each slot consumes its token
once; later refreshes reserve one assignment and exclude the sibling ingress,
including a pending sibling. Device-key possession authenticates that exact
short-lived session; the session nonce is infrastructure authentication, not
an application-stream credential. Ingress binds its observed source IP.

The adapter releases unused reservations, expired pending tokens and failed
trust lookups. Renewing one slot preserves its healthy sibling. Infrastructure
trust binds normal chain and hostname verification to the ingress process
lease. Target CA material is never an ingress or managed visitor trust anchor.

`Serve` closes the reservation owner when the runner ends. Each closed path
releases its exact session after joining its streams. A stream never changes
ingress paths after native TLS or an invalid admission response commits it.

## managed metadata and application bytes

Each local connection selects a current service/run, run number, protocol,
managed hostname/port and metadata revision. A revision, protocol or endpoint
mismatch ends `Serve` with `*MetadataReloadError` before opening an application
stream. The caller clears readiness, fetches current metadata, joins the old
runner and starts a new control adapter/listener. Queued or live connections
are closed, not replayed.

The connector compares ingress acceptance with its authenticated session's
identity, device and observed source. The publisher independently rechecks the
trusted admission against control before opening its configured target.
Connector admission never asks the application for a client certificate.

HTTP, PostgreSQL and MySQL clients use verified native server TLS through the
connector. Their instructions name the managed service hostname, not localhost or
the target certificate. Opaque applications use `ServiceTLS` as a verified TLS
helper. PostgreSQL retains `channel_binding=disable` across publisher TLS
termination. public and private managed endpoints use these same connector
assignments; the approved public setting and hostname are never rewritten.
`ServiceTLS` must verify the managed name without an application client certificate.
before reporting readiness, `Serve` opens one admitted stream and performs the
protocol's TLS negotiation without login or application bytes. both ingress
sessions must already be authenticated. a single stream never reloads metadata or reopens an
application connection. Both stream-copy directions and slot workers join on exit.

Publisher-to-target negotiation belongs to `internal/targettransport` and
`target.tls`. Omitting target TLS permits a plaintext backend while managed
visitor TLS remains mandatory. Shared HTTP framing, upgrade, streaming,
half-close and no-replay assertions live under `internal/httpstream`.
