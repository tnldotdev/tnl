# applied project boundaries

Browser-safe public metadata identifies public URLs and managed HTTP services
separately. Managed HTTP entries carry `private_service_id`, hostname, and the
allocated port; they never borrow a `public_url_id`. Generated `.tnl/local/project.json`
URLs retain that port, including after publisher namespace renames. Private
targets and trust material remain outside browser metadata.

## managed endpoint ownership

named groups reserve a durable namespace beneath the selected team's existing
namespace. the readable project label is captured from the Git source and config
directory at first apply; checkout paths and branch names do not rename it.
services receive stable endpoint hostnames and durable per-ingress-pool ports.
`publishers.NAME.domain` selects the ready domain and `public: true` declares
direct reachability; omission keeps the endpoint connector-only. neither setting
replaces visitor authorization or creates a public URL record.

`tnl publisher rename OLD NEW` changes only the configuration selector, retaining
the group ID, namespaces, service IDs, grants and port claims. update the Git
publisher key and its service references before the next apply. historical names
remain permanently tied to the same group ID. control resolves those selectors
for portable credentials and provisioning; exported display names do not grant
authority. verification uses `/v1/publisher-groups/verify` and never rotates a
running task's lease. unchanged publications keep their runs and certificates.

`tnl publisher namespace rename GROUP LABEL` explicitly changes the managed DNS
namespace beneath the existing project label and domain. for example:

```console
tnl status --scope=server
tnl publisher namespace rename live primary --expected-revision 4 --request-id namespace-primary-1
```

reuse the exact revision, request ID and arguments after a lost reply. the POST
`/v1/projects/{project_key}/publisher-groups/{group_name}/namespace/rename` stores
the encrypted original response in the mutation transaction; changing input
with the same key conflicts, and a stale revision cannot overwrite newer state.

namespace rename retains group/service IDs, visitor grants, ports and replica
signing identities. it closes old managed service runs, invalidates their
publication grants, and creates replacement assignments with the new certificate
plan. publishers reconcile DNS and real certificates through the existing
workers. `target.tls` still controls the independent publisher-to-target hop.
source-bound service lookups and refreshed client profiles return the new
hostname. separately declared public URL hostnames keep their own scope.

old namespace claims remain retired until the actual certificate lifetime,
unresolved issuance (including uncertain finalization), DNS cleanup and the
seven-day quarantine all permit reuse. historical selectors cannot transfer to
another group even after that DNS scope becomes reusable.

moving a service to another group preserves its ID, visitor grants and port,
but changes its hostname and certificate scope. the apply transaction revokes
the previous group's publishers. a live namespace cannot be adopted by another
project; retired namespaces can be reused after the actual certificate lifetime,
outstanding issuance, DNS removal and quarantine have completed.

`TNLD_SERVICE_PORT_RANGES` declares the ingress pool's ports or inclusive ranges,
such as `20000-20100,25443`. allocation and inventory changes serialize with each
other. removing a held or quarantined port fails instead of renumbering clients.

connector admissions carry the authenticated visitor/session binding to the
publisher and require only server-authenticated native TLS. direct admissions
start without an identity and wait for ingress capacity promotion before target
bytes. HTTP accepts current browser, managed share/token, or optional
service-scoped client-certificate authentication; other direct protocols require
the service-scoped client certificate.
ingress selects direct traffic by the trusted destination port before inspecting
any TLS bytes, including PostgreSQL and server-first MySQL negotiation.

the certificate and DNS workers serve public URLs and managed services through
their existing owners. service DNS uses exact records with separate ownership
markers: loopback for connector-only endpoints and ingress for public endpoints.
each publisher keeps an independent key/cache for its narrow group certificate.
issuance retains its original domain for cleanup after an endpoint moves.

Project configuration in Git declares services and their publisher groups.
`tnl apply` sends a normalized revision to control. Enrolled group members pull
only the assignments for their group and acknowledge the revision and health.
Infrastructure runs those members; control does not provision their machines.
Hosted and self-hosted control use this same boundary.

```text
Git project configuration
          |
       tnl apply
          v
control: applied revision, groups, assignments, status, audit
          ^
          | pull + acknowledge with enrolled group identity
          |
tnl publisher serve --group production ---> assigned private targets
```

## declare a group

```ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  publishers: {
    production: { description: "publishers in the production network" },
  },
  services: {
    web: { publicURL: {} },
    api: {
      name: "internal-api",
      publisher: "production",
      target: { type: "address", address: "https://api.internal:8443", tls: {} },
      access: { team: true },
    },
  },
});
```

Each `publishers.NAME` value accepts optional `description`, `domain`, and
`public` settings. Cloud capacity and host provisioning belong to infrastructure.
`local` is reserved and cannot be declared. Services default to the built-in
`local` publisher; an explicit `publisher` must select a declared group. Named
groups require reachable address targets, not app, Docker, or Compose discovery
on the applying machine.

For `local`, `publicURL` is opt-in per service (`public_url` in static
configuration). Root public URL settings supply defaults only to explicit
blocks. Named groups always use managed services: the group's `public` setting
alone controls direct reachability. A named HTTP service's `publicURL` block may
narrow IP access and set HTTP request limits; it cannot create a second public
URL, select another hostname/domain, enable anonymous access, or change the
allocated port. Ephemeral and public-URL traffic-limit overrides are rejected.
HTTP request budgets are shared across the run's public and connector requests.

The protocol defaults to `http`. `name` overrides the saved service name and
`access: {team: true}` declares a team access grant. `tcp` is opaque; `mysql` and
`postgres` select database negotiation. See [private services](private-services.md)
for HTTP credentials, target TLS, and native-client boundaries.

## apply evaluated declarations

```console
tnl config check
tnl apply
tnl status --scope=server
```

`internal/projectconfig.SourceIdentity` derives the project key and full source
fingerprint from the normalized Git origin and the configuration file's
repository-relative path. Branches, local checkout paths, and client-state
salts do not change that identity. Control rejects a key with a different full
fingerprint. This identifies the configuration source, not a signed Git commit;
applying a branch's evaluated configuration is an explicit operator action.

`cmd/tnl/apply.go` sends evaluated service declarations and captured trust
snapshots, never executable TypeScript or a remote dependency on a local CA
path. `internal/controlstate/applied_project*.go` stores the encrypted normalized
configuration, hash, revision, saved services, grants, and group assignments in
PostgreSQL. An expected revision protects concurrent updates; a stale apply
fails instead of overwriting a newer revision.

Local app discovery stays local. An applied local service descriptor does not
contain a discovered container address or a running app's listener. Framework
startup through `pnpm dev` registers the actual bound listener with the local
publisher, without applying remote changes. Root OAuth and webhook declarations
are retained in the normalized document, hash, revision, and manager status.
Their existing local runtime maintains stable project integration URLs while
development tunnels run; applying the declarations neither allocates those URLs
nor makes them production group assignments.

Moving a private service between `local` and a named group retires its old
resources, closes their publish runs, and revokes their publisher and visitor
grants in the apply transaction. A named group receives a new shared service ID;
moving back to `local` defers new per-worktree IDs until runtime realization.
Moving between named groups keeps the saved service ID and replaces publisher
grants for the new group, while changing its hostname to the new namespace.

## enroll and reconcile members

`tnl publisher enroll --group NAME` issues a group bootstrap key. A task runs:

```console
tnl publisher serve --server CONTROL_URL --project-key PROJECT_KEY --group production --state-dir /state --instance replica-1
```

Supply the key through `TNL_GROUP_ENROLL_KEY` or `--enroll-key -` on first
enrollment. Each replica needs an independent private state directory and
signing identity. The task does not need a person's control session. The CLI
defaults to a one-member key with a 600-second lifetime. `--members` accepts
1–256 and `--expires-in` accepts whole-second durations from `1m` to `24h`,
matching control's limits, with at most 256 active members across an applied
project's groups. Enrollment capacity and key expiry are distinct from runtime
capacity and the enrolled member's lifetime.

The publisher generates and retains its signing key. Control stores the public
key and exact project/group membership. Explicit signed runtime start and renewal
acquire short-lived group leases; those leases authorize assignment reads and
acknowledgements for that group only. Assignment responses include exact service IDs and grants,
the applied revision/hash, and approved trust revisions. A member cannot use a
group lease to read another group's targets or publish another service.

`internal/grouppublisher` owns polling and revision reconciliation.
`cmd/tnl/publisher_group.go` and `internal/publisherjob/group.go` adapt each
assignment into the managed-service publication lifecycle. Removed or changed
assignments cancel their old workers before replacement. Acknowledgement binds
the exact current revision and configuration hash; stale acknowledgements fail.
Server status reports observed revision, health, and lease expiry. An observed
revision means the member reconciled it, not that a visitor successfully used
the target. Named groups use publisher pools for public and private services.
Each member retains its own identity, grants, runs, and connection assignments;
control selects ready runs without combining their credentials. No separate
pool or replica property belongs in project configuration.

An operator can provision one portable group identity with `tnl publisher
provision --group NAME --instance replica-1 --output-file FILE`. The bounded,
private JSON binds the signing key to the exact control URL, team, project,
group, member, and instance. `publisher serve --identity-file FILE`, or the
ECS-injected `TNL_GROUP_IDENTITY`, restores it into fresh protected client state
after proving the key and current membership to control. Replacement uses no
person session or enrollment and consumes no new member allowance. Invalid,
mismatched, or revoked identity input fails without bootstrap fallback.

after a selector rename, the original exported file works with either the new
selector or a historical selector returned by control. repeated provision of the
same group and instance exports the saved replica key. durable group filenames
use immutable group/publisher IDs; a public catalog pins the replica independently
of runtime SQLite. a task directory containing multiple matching project/instance
references requires an explicit portable identity rather than scanning secrets
by name. imports update the typed member document and its sealed-key context in
one SQLite transaction and reject replacement identities or signing keys.

## recover publisher certificates

remote runtimes also maintain one [control-observed egress record](publisher-egress.md)
per replica, refreshed by their existing lease loop. server status retains its
last address and timestamps after stop or lease expiry. provisioning and identity
verification do not record the operator's address.

the [Fargate template](../../deploy/publishers/readme.md) mounts a replica-private
EFS access point at `/identity` and keeps runtime SQLite and its wrapping key in
task-local `/state`. Secrets Manager supplies the initial signing identity.
`publisher serve --identity-dir /identity` selects the durable directory; local
development defaults to `identities` beneath its normal state directory.

`internal/clientstate` owns the same filesystem certificate cache in both cases.
each private record contains its exact control/team/publisher scope, approved
plan, pending key/CSR, staged/current material, issuance IDs and renewal times.
atomic replacement and file/directory sync precede external issuance or install.
runtime SQLite is not the owner of these keys, so replacing its wrapping key
does not lose certificate state. control stores no copy of publisher TLS keys.

the group publisher holds a writer lock in its durable directory for its entire
lifetime. certificate transactions also serialize on that filesystem rather
than task-local locks. all writers use the same replica-private mount; EFS uses
NFSv4 advisory locking. invalid scope, unsafe permissions and replaced directories
fail at the filesystem owner. retryable write/sync errors block new external work
while a valid installed certificate can continue through renewal retries.

control records permanently when a replica first submits issuance work. after
that point, startup without recoverable durable material fails
instead of silently generating replacement keys. a recovered CSR finds its
original order across publish-run replacement and compatible sibling services,
but only for the same publisher, account, domain and exact certificate plan.
each new run still acknowledges its own installation and audit event.

each single-replica service owns a different member; infrastructure constrains
replacement without a rolling surge. never share a member secret across
independent replicas. runtime SQLite WAL remains on a SQLite-suitable local
filesystem. an exported signing identity alone does not recover the publisher's
TLS keys after issuance has started; preserve the complete identity directory.

## preserve authority and audit

Control owns member scopes, assignment grants, revocation, desired revision,
and current authorization decisions. Removing a group revokes its enrollments,
member identities, and service grants. Revoking a member invalidates its leases
and exact publication grants; stopping its infrastructure alone does not revoke
the identity. Applied-project changes and group membership changes enter the
service audit history with their actor and revision context. Visitor lifecycle
events retain their exact service/run and trusted source attribution, without
application credentials or payloads.

The control OpenAPI contract owns these operations; PostgreSQL queries and
migrations under `internal/controlstate` own durable state. Include applied
project, group-scope, stale acknowledgement, revocation, and audit tests in
`task go:test:integration`. The focused `private-services` target selects these
boundaries against disposable PostgreSQL. Infrastructure contract checks and
offline CloudFormation schema validation live beside the publisher template:
`task deploy:publishers:check`. `task go:test:integration:publisher-replacement`
checks real control signing, complete task-state deletion and restoration,
stable membership, key mismatch, and revocation with disposable PostgreSQL.
`task go:test:publisher-state` covers filesystem durability and writer ownership.
the Linux CLI replacement workflow deletes task-local state during pending
issuance and again after installation, then checks the same issuance and real
visitor traffic using its preserved identity directory. its local CA replaces
the external issuance boundary; offline tests do not qualify live EFS mounts.
