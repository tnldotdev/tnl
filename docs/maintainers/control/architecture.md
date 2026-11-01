# control architecture

Control owns durable server state, current authorization, placement, certificate
work, and coordination. API names identify their callers; private ingress and
relay APIs are served by control. Only control and standalone receive PostgreSQL,
storage-key, DNS, ACME, mailer, and authority settings.

## implementation map

Paths below are relative to `internal/control`.

| Owner                                                       | Responsibility                                                                     |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `api/public`                                                | Public control handlers, authentication adapters, and safe HTTP problems           |
| `api/authority`                                             | Built-in identity/session/team/domain/company/workload authority                   |
| `api/private/{ingress,relay}`                               | Authenticated leases, routing, claims, admission, usage, and process coordination  |
| `api/serviceaccess`                                         | Signed-human exact-service management projection                                   |
| `state`, `state/controlstatedb`                             | Authoritative transactions and generated PostgreSQL access                         |
| `certificates`, `certificates/acme`, `certificates/visitor` | Durable issuance work, ACME adapter, and key-bound visitor certificate issuer      |
| `dns`                                                       | DNS authority, owned records/challenges, propagation, and cleanup                  |
| `oidc`, `proxy`, `storagekey`                               | Issuer proof, trusted public control proxy, and recoverable-secret encryption      |
| `email`, `usage`, `webhooks`                                | Leased mail delivery, usage finalization/delivery, bounded sender-feed catalog     |
| `maintenance`                                               | Bounded expiry, cleanup, routing retention, usage/audit and pool maintenance loops |

HTTP adapters depend on state/service operations and generated contracts. State
never imports handlers. Keep transaction bodies and lock scopes cohesive even
when declarations are separated by domain files. Ingress/relay depend on
coordination contracts, not `control/state`. `internal/daemon` constructs and
supervises control workers; maintenance operations do not import daemon startup.
Standalone adapters enforce the same identities, leases, and authorization as
split HTTP calls.

## database and schema boundary

PostgreSQL sources live in `state/migrations`, `state/queries`, and
`state/sqlc.yaml`; `state/generate.go` generates the committed `controlstatedb`
child. Edit those sources, not generated query code. The current baseline requires
a fresh database and coordinated stop/start of server roles. `tnld migrate` is
the only migration path and accepts `TNLD_DATABASE_DIRECT_URL`. Serving uses
pooled `TNLD_DATABASE_URL` and checks the exact embedded schema version and
baseline identity. Another version-1 database is not the same baseline. A path
move cannot change SQL, migration version, or baseline identity.

Transactions own current policy, complete run/assignment identity, idempotency,
capacity, and audit facts together. Routing revisions become visible in commit
order; cleanup cannot make a superseded projection current. Missing routing data
does not establish run closure. See [control-state invariants](control-state.md)
for lock order, reservations, retention, usage atomicity, and certificate states.

## policy and secrets

The authority API owns identities, sessions, teams, memberships, invitations,
domains, and current access decisions. OIDC proves identity; it does not grant
membership or publisher rights. Company eligibility, manual membership, team
role, issuer/session provenance, and recovery remain separate. Workload sessions
are key-bound visitor authority with exact saved service rights and a fixed
window; runtime assertions cannot apply configuration or create human sessions.

For public URL and public service HTTP, `state/visitor_tokens.go` turns one
authenticated source into a signed permission. Both resource kinds use
`control.visitor_identity_permission` and `control.visitor_grants`; browser,
share, device, and workload parents still bound their own lifetimes. HTTP client
certificates bind the same permission to the CSR key and certificate serial.
Refresh credentials are authority-facing; application requests carry only the
signed permission. `state/visitor_policy.go` returns a snapshot with its policy
revision, verification keys, IP filter, and workload leases. Fact mutations
advance policy revisions in the same transaction. Signing keys are prepared
before serving and ordinary rotation retains keys through issued deadlines.

Service browser sessions keep an encrypted refresh credential on their existing
session row. Renewal locks that row while the authority rotates the parent
control session, then checks that the returned access token belongs to the same
parent. The service, captured runs, and original browser deadline stay fixed.

`tnl share token create` exchanges its new share source at `/v1/visitor-tokens`
and prints a signed `Tnl-Visitor-Token` value. The public URL permission lasts at
most five minutes, capped by the share deadline; JSON `expires_at` reports that
permission deadline. `--expires-in` sets the underlying share lifetime.

Publisher grants bind one saved public URL or authorized namespace. Enrollment
is explicit and one-use; signing keys remain with the publisher. Control checks
grant, current team access, and URL state at run creation and heartbeat. Purposes
`app`, `alias`, `demo`, `oauth`, and `webhooks` are immutable saved URL facts.
Hostnames follow control's namespace/domain policy. Certificate plans are exact
for saved-URL grants or narrow approved namespace plans, with publisher-private
keys and DNS-01 automation. services keep separate IDs, hostnames, ports,
certificate plans, and grants; they do not borrow a public URL record.

Control encrypts recoverable values and IP-policy/request digests using the
storage key. Guest trials reserve their namespace transactionally and retain a
keyed issuing-IP digest, never the address; the credential lasts 72 hours.
Ingress receives only the purpose-specific public URL verifier over authenticated
coordination. PostgreSQL routing events contain hashed prefixes, not raw CIDRs
or that verifier. An IP match is only a filter, never visitor credentials. Usage
network estimates are a separate nonauthorizing sketch. Ingress/relay never hold
the storage key. Relay transport private keys are retrievable only under the
current relay lease and remain in memory there.

The public control backend accepts only configured proxy peers, an overwritten
client-IP header, `X-Forwarded-Proto: https`, and the configured external host.
Forwarded host/port never choose the origin. Split private control HTTPS uses
its own required static certificate/key and cluster-authenticated listener;
public proxy or ACME settings cannot supply them. Standalone keeps private
coordination in-process.

`TNLD_SERVER_DOMAIN` selects infrastructure independently of
`TNLD_MANAGED_DOMAIN`. Public URL DNS points to ingress. Managed endpoint DNS
selects loopback for private reachability and ingress only after port inventory
and ready-publisher checks for public endpoint access. Returning to private denies
cached public DNS at admission. DNS work retains captured domain ownership
through issuance and cleanup after a move.

## deeper references

- [applied projects](applied-projects.md): revisions, groups, local identity, endpoint ownership, and durable restoration
- [services](services.md): run preparation, claims, admission, grants, and publisher/connector handoffs
- [human authentication](oidc.md), [company access](company-access.md), and [workload sessions](workload-sessions.md)
- [hosted integration](hosted-integration.md), [signed-human service access](service-access.md), and [website usage](team-usage.md)
- [HTTP contract map](../architecture.md#own-each-http-surface) and [server readiness](../development/server-readiness.md)
