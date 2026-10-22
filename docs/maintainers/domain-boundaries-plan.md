# domain boundaries plan

Make internal state and authorization boundaries explicit before moving packages.
This is the execution plan for the first of two requested PRs. It covers the
complete domain cleanup; the second PR follows the
[role organization plan](https://md.cormo-turtle.ts.net/.worktree/tnl/role-organization/docs/maintainers/reorganization-plan.md).

Status: first-PR domain implementation delivered in
[PR #448](https://github.com/tnldotdev/tnl/pull/448). The CI follow-up merges current
main and adapts its socket-reservation fixtures to the validated port inventory.
The execution record and ledger below identify completed local checks and the
remaining CI qualification. Role organization remains the second PR's work.

## execution anchor and delivery

| Item                    | Execution anchor                                                                                                 |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Implementation baseline | `5203676605d98999cfc012ec20fa857fa0271db9`                                                                       |
| Main merged for CI      | `3a4ede1e252185ba485e7bab4724d88eef64236a`, including #446 and #447                                              |
| Landed rewrite          | PR #442 at `48a2b8e5`; its tree matches `331def37`                                                               |
| Superseded checkpoints  | Earlier checkpoints prefixed `45c`, `b371`, and `e423` are stale; they are not execution or validation baselines |
| First PR                | [#448](https://github.com/tnldotdev/tnl/pull/448), `0xcadams/domain-boundaries`; implementation `bc1efd09`       |
| Second PR               | `0xcadams/role-organization`, initially based on `0xcadams/domain-boundaries`                                    |
| CI follow-up directory  | `/Users/chase/.worktree/tnl/domain-boundaries-ci`                                                                |

The requested outcome is two implemented, validated PRs. Put both plans in the
repository with the first PR so reviewers can see the complete sequence. The
first PR owns domain changes and their regression coverage. The second owns the
role layout, source and generator moves, and updated contributor guidance. Review
the second PR against the first branch while stacked; after the first lands,
update its base and verify the resulting diff again.

Use semantic commit messages and PR titles, such as `refactor: make internal
domain boundaries explicit` and `refactor: organize implementation by role`.
Update the ledgers in the PR that supplies the evidence. Opening a PR, running a
check, or writing this plan does not establish that an acceptance criterion passed.

## compatibility boundary

Preserve the behavior of valid inputs and every existing external contract:

- Keep exported Go import paths, names, signatures, field types, and assignability.
  In particular, all seven existing `pkg/api/*` packages stay canonical, and
  `pkg/tnl` and `pkg/protocol/tunnelv1` retain their public contracts. The newest
  public Go compatibility rule supersedes earlier proposals to break those paths.
- Keep HTTP paths, methods, status codes, authentication, problem codes, JSON
  field names, omission rules, enum strings, frame bytes, and size limits.
- Keep PostgreSQL and SQLite encodings, stored JSON, schema versions, baseline
  identities, and existing queries' transaction and lock boundaries. This work
  adds no schema migration and changes no fresh-database baseline.
- Keep token derivation, HMAC purpose strings, signing inputs, canonicalization,
  hash inputs, cache keys, local identity derivation, and idempotency keys.
- Keep CLI commands, flags, defaults, diagnostics, output streams, human frames,
  JSON and NDJSON, SDK exports, configuration keys, and package artifacts.
- Keep retry budgets, admission deadlines, cancellation, drain/join ordering,
  ownership locks, visitor-byte retry boundaries, and fixed workload expiry.

Two deliberate corrections belong in the first PR: reject malformed or
contradictory input at the earliest owned boundary, and handle typed-nil values
without panicking or accepting a credential. Record each correction and its
lowest sufficient regression assertion. Do not describe these as byte-for-byte
behavior preservation for invalid input. Keep the established safe diagnostic
classification and external error envelope.

## implementation method

For each section, inventory the current owner and callers before editing. Use
existing types and validators where they already express the boundary. For
example, certificate issuance already has separate `ACMEOrderState`,
`ACMEAuthorizationState`, and `RelayCertificateOrderState` types; finish their
conversions and use rather than adding parallel state vocabularies.

Follow this sequence for each domain:

1. Identify untrusted input, persisted representation, validated internal value,
   and the operation that may change it.
2. Introduce or complete the internal constructor, parser, closed variant, or
   state transition. Name the role and scope it represents.
3. Decode and validate once at the boundary. Pass the owned result to internal
   callers; convert explicitly when entering generated API or database code.
4. Remove duplicated validation and unrestricted internal construction only when
   all callers use the owned boundary.
5. Preserve meaningful assertions while adapting fixtures. Add regression
   coverage for a newly enforced invariant or corrected failure.
6. Record the implementation and validation evidence before marking the scope
   complete. Carry the ownership decision into the second PR's package moves.

Avoid a generic state, credential, subject, revision, or parser package that
accepts every role's values. A new type earns its place by preventing a specific
mix-up, controlling construction, or making a transition exhaustive. Internal
types can be private or have private fields; exported DTOs remain compatible.

## protocols, persisted states, and revisions

### protocol values and validated variants

Inventory protocol selection in configuration, applied assignments, local owner
requests, private metadata, target setup, and managed forwarding. Distinguish the
service protocol (`http`, `tcp`, `postgres`, `mysql`, and any existing
Kubernetes-specific form) from the publisher connection transport (QUIC or
TLS/TCP with yamux), HTTP versions, and tunnel frame kinds.

- Parse each external selector into its owning internal type. Apply existing
  defaults at the same point; an empty defaultable protocol and an unknown
  protocol are different inputs.
- Validate combinations such as protocol, target TLS, target discovery, managed
  endpoint, and access mode before starting work or allocating resources.
- Keep `pkg/protocol/tunnelv1` as the handwritten wire source. Retain its exported
  message structs and framing functions. Build validated internal views of
  messages where consumers need a closed variant.
- Require exactly the fields belonging to the selected message, peer, stream,
  or admission variant. Reject missing, contradictory, cross-kind, or trailing
  data through the existing contract boundary.
- Preserve golden JSON and framed-wire fixtures, invalid fixtures, bounds tests,
  fuzzing, and shared QUIC/TLS behavior coverage. Do not introduce a second
  tunnel JSON Schema or tests that compare two copied schemas.

### private and certificate state machines

Cover private service runs and preparations, assignment claims, connector
sessions, publisher installation, certificate plans and orders, DNS challenge
work, cleanup, and terminal states. Use separate types for different machines
even when they persist the same word, such as `ready` or `failed`.

- Document legal transitions and the operation that owns each transition.
  Prepared, active, routable, healthy, draining, expired, and closed are separate
  facts; use the existing machine's actual vocabulary at storage boundaries.
- Parse stored strings when constructing the internal state. Unknown values
  must fail closed rather than selecting a default transition.
- Keep preparation expiry, publisher expiry, certificate expiry, assignment
  credential expiry, and cleanup eligibility distinct.
- Preserve claim idempotency, committed-response-loss recovery, exact request
  digests, capacity release, and cleanup after interrupted certificate work.
- Keep certificate availability separate from publisher installation. Keep DNS
  presentation, validation, cleanup intent, cleanup completion, and installation
  separate, including failure that still requires cleanup.

### revisions and counters

Inventory policy revision, public URL mutation revision, assignment revision,
lease revision, trust revision, applied configuration revision, alias or receiver
selection revision, and local mutation counters. Publish run numbers remain run
numbers in public terminology.

Use domain-specific internal values or references where mixing counters would
otherwise compile. Keep generated field types unchanged and perform checked
signed/unsigned conversions at adapters. Validate positive, zero, overflow, and
stale values according to each existing contract. Equality of revision alone is
never equality of a run, assignment, lease, or selection.

## certificate subjects, company types, and recovery

### certificate and visitor subjects

Audit `certificateidentity`, `visitorcert`, `visitorsubject`, `httpsubject`,
`privatetrust`, and their control, connector, and publisher callers.

- Distinguish certificate plan identity, a certificate's authenticated subject,
  human visitor identity, workload visitor identity, publisher identity, and
  accepted transport peer. An arbitrary parsed certificate is not an authorized
  subject.
- Use explicit constructors and exhaustive internal subject variants. Reject
  mixed human/workload fields, missing IDs, wrong issuer or audience, wrong key
  binding, and an unsupported identity extension at the boundary that knows it.
- Keep exact hostname and one-label wildcard rules, approved SAN types, key
  requirements, challenge method, plan scope, and cache key unchanged.
- Preserve certificate parsing and signature causes for internal classification;
  keep diagnostics safe and avoid exposing certificate material or credentials.
- Ensure independently parsed certificate chains and keys match the approved
  plan and CSR. Never trust caller-populated `tls.Certificate.Leaf` as proof.

### company identity and authorization

Inventory company connection state, issuer/session provenance, eligibility,
managed subject status, manual membership, contractor exceptions, tnl team role,
publisher ownership, setup, activation, and recovery. Keep these separate from
each other and from ordinary OIDC proof of identity.

- Replace internal string/bool combinations with types that name the actual
  decision. A verified company subject does not itself create membership or
  grant a tnl role.
- Carry validated issuer, connection, subject, team, and session provenance
  together. Recheck current company and membership state at authorization.
- Model setup and recovery stages explicitly. Bind activation and recovery
  results to the original operation, connection, subject, expiry, and one-use
  secret or digest; preserve replay rejection and existing recovery authority.
- Keep offboarding, disabled-subject denial, expiration, reactivation, and
  contractor handling as separate transitions. Recovery cannot revive a revoked
  subject or broaden publisher ownership.
- Preserve transaction locks, audit records, persisted values, and every existing
  authorization check. Check stale completion and concurrent setup/recovery at
  the smallest real database boundary where they matter.

## requested and resolved native scopes

### scope ownership

Separate a caller's requested service, namespace, group, server, team, or
invocation from the resolved native scope that can authorize work. Cover
`connectionruntime`, `privateprotocol`, `localpublisher`, `publisheridentity`,
`publisherprovision`, `publisherjob`, `workloadclient`, and command composition.

- A requested selector contains intent. It cannot carry a resolved credential or
  assert ownership merely by setting an ID.
- A resolved scope binds the normalized server, selected team, exact service or
  namespace, identity/key/grant, and applicable project or invocation identity.
  Construct it only after validation and current authorization.
- Keep configured local identity separate from portable Git source identity.
  Resolve from the already evaluated project snapshot; do not evaluate config
  again during trust capture, owner lookup, or registration.
- Preserve explicit selection precedence, invalid explicit-file failure, and
  server/team conflicts. Setup remains explicit; an app call cannot silently
  install a grant or broaden a namespace scope.
- Pass the smallest resolved capability to each worker. Keep control sessions,
  signing keys, and owner credentials native and out of app/browser metadata.

### capabilities and enrollment

Model owner, service-registration, and invocation-registration capabilities as
distinct internal cases. Bind them to their exact owner/process and registration
or invocation; prevent using a service capability for an unrelated service or an
ad-hoc invocation.

Separate enrollment request, issued one-use enrollment, installed signing
identity, scoped grant, and usable runtime credential. Bind enrollment completion
to its original scope and key. Preserve bootstrap secret consumption, credential
file encodings and permissions, idempotency inputs, interrupted-install cleanup,
and revocation. Cancellation and late completion cannot publish a credential into
a replacement owner's state.

### device login stages

Make requested, pending approval, issued, consumed, denied, expired, and canceled
device operations explicit where those stages exist. A poll result must carry
only the data valid for its stage. Keep human control sessions, enrolled devices,
workload sessions, and publisher enrollment separate.

Preserve polling intervals, expiry, one-time consumption, browser approval, and
session rotation. If cancellation happens after issuance, finish the existing
owned cleanup; reject late results instead of installing them into a new login
or connection owner. Keep safe authored failure classification.

### feedback state and author identity

Give report, reply/event, thread status, and verified author their owned internal
types. Validate evidence and source state at the existing submission boundary.
Keep the first report immutable, follow-up events ordered, status open/resolved
with existing reopen behavior, and pins optional when an element changes.

The server derives verified author identity and its name snapshot from current
authentication. A client-supplied name or browser subject cannot construct that
authority. Preserve access checks, evidence bounds, stored encodings, feedback
API shapes, and the distinction between source matching and Git branch/staging.

## bound runs, assignments, and transport peers

### bound runs and managed credentials

Create internal bound-run values after successful preparation or authorization.
A public run binds public URL ID, run ID, run number, token, certificate plan,
and expiry. A private run binds private service ID, private run ID, run number,
approved endpoint/trust, token, and expiry. Keep the two variants distinct;
neither is a partially filled version of the other.

Use explicit managed HTTP credential variants for the existing browser, share,
token, and client-certificate mechanisms. Parse the request and TLS identity into
one validated credential at the request boundary. Preserve valid credential
selection precedence, header/cookie stripping, HTTP status/HTML negotiation,
Host/SNI checks, and service/run/source binding. Reject malformed combinations
before target access and keep credentials out of inspection and logs.

Bind cached and live decisions to the exact credential digest, subject, service,
run, source, and decision revision. A replacement credential can authorize a
future request; it cannot silently replace the live guard's original authority.

### assignment references

Replace repeated loose internal parameter bundles with public/private assignment
references that include the complete identity needed for stale-state checks:

- owning public URL or private service and run;
- publish run number or private run number;
- publisher connection ID, slot, and assignment revision;
- relay service ID and, where claimed, relay process/run/lease identity.

Validate complete references at construction. Compare all relevant identity
fields, not just an ID or a revision. Keep public exported reference structs and
wire fields compatible; adapters may construct stricter internal values.

### relay lifetime and forwarding variants

Separate the relay service's stable address, one relay process lifetime, its
current lease, one publisher connection claim, and one visitor stream. Renewal
can extend a current process lease without changing a routing projection's copied
deadline. A copied deadline is neither a replacement identity nor proof that a
relay's current lease has expired. The relay remains responsible for checking its
current lease and exact claim before stream acceptance.

Represent public forwarding, connector-admitted private forwarding, and direct
managed forwarding as separate internal variants. Each carries only its
authenticated admission fields. Preserve the exported frame shape and enforce
its existing exclusive fields before converting it.

An accepted peer is the result of completed authentication and validated session
acceptance, not any TLS connection or caller-provided subject. Bind connector
session acceptance to the expected service/session/subject, ingress-observed
source, expiry, and key proof. Bind visitor acceptance to that session and the
exact claim before inner TLS or target dialing.

Preserve all data-path invariants: visitor TLS ends at the publisher, ingress
creates PROXY v2 metadata once, relay preserves it, stream capacity releases once,
and no visitor byte is retried after the first byte sent to a relay. Cover
server-first protocols, half-closes, denial, lost responses, and current but full
relay admission without conflating new-stream capacity with existing promotion.

## inventory, cloud metadata, and target plans

### bounded inventory and projections

Inventory local/native service lookup, private service inventories, applied
publisher assignments, selected cloud metadata, and deployment manifests.

- Give internal inventory entries a validated identity and protocol. Distinguish
  absence, an empty result, an unavailable lookup, and a denied lookup.
- Keep inventories bounded and authorization-filtered. Validate the whole result
  before publishing a new snapshot; do not retain a partially decoded entry.
- Use keyed internal projections when ownership is by service or publisher name.
  Reject duplicate keys, unknown references, and conflicting owners. Preserve
  existing serialized order and omission behavior at output adapters.
- In YAML generation, locate and update the intended key and object path. Avoid
  positional or text-replacement edits that can change another resource after
  reordering. Keep emitted CloudFormation resources, parameters, hashes, logical
  IDs, and golden artifacts equivalent.

### cloud metadata and private target plans

Separate raw AWS/provider responses from validated EKS/RDS target identity,
endpoint, region, account/resource selector, CA trust, and freshness. Keep signed
deployment provenance distinct from independently verified discovery. A tag,
hostname, or supplied metadata document does not become authority by itself.

Build a private target plan only after protocol, selected endpoint, approved trust
revision, authentication mode, and discovery constraints are validated. Keep
target TLS separate from managed visitor TLS and connector authentication.
Preserve PostgreSQL SSLRequest, MySQL server-first negotiation, Kubernetes
credentials, CA revision checks, metadata freshness limits, and selected target
identity. Endpoint refresh applies to new connections; it never replays an
admitted visitor.

### job status

Distinguish requested job, prepared job, running publication, observed health,
retryable failure, draining, and completed cleanup according to each existing
worker's machine. Keep applied revision, acknowledged assignment, local runtime
stage, readiness, and terminal result separate. A status projection reports
observed facts; it cannot manufacture an active lease or authorized target.

Preserve bounded retries, exact idempotency keys, shutdown joins, and late-result
rejection. Publish related metadata and transport identity together so prepared
reads cannot mix revisions or wait on an unrelated sibling's preparation.

## exact current state and readiness

At the execution baseline, `clientruntime.Manager.Current` combined registration
checks with `run == 0` meaning any run. The implementation now separates
`CurrentRegistration`, exact nonzero `CurrentRun`, and the locked `ServiceForRun`
read. `Current` retains exact-run semantics for its existing name. The required
boundary is:

- A registration-current operation checks exact service, registration ID,
  target, owner liveness, and registration lease without claiming a run match.
- An exact-run-current operation requires that registration and its exact,
  nonzero run number. Zero is invalid for the exact operation.

Migrate callers according to their real intent. Keep any externally visible
status or readiness shape unchanged. Reuse the same locked state checks when an
observation is accepted; a check before a concurrent replacement is not proof
that the result still belongs to the current run.

Preserve `projectpublisher.checkService`'s accepted-result semantics. It reports
whether this probe's ready observation was accepted for the captured
registration, target, run, and readiness path. Reading a later snapshot is not an
equivalent return value. Target freshness is checked before observation acceptance.

Automatic readiness keeps one budget per run:

- Start once when that run becomes routable. Repeated ready events do not restart
  the checker.
- Keep the existing two-minute budget, including delays and in-flight probes;
  preserve the five-second probe deadline and 500-millisecond to two-second
  backoff.
- Stop on accepted success, budget exhaustion, replacement, drain, or shutdown.
  Cancellation joins the checker before run cleanup.
- A target change invalidates its observation. An active checker may retry in
  its remaining budget; a finished checker receives no new automatic budget.
- Explicit `tnl wait` can check again. A failed readiness check leaves publication
  running. Ad-hoc readiness remains run routability rather than an app GET probe.

Cover stale registration/run/target/path observations, success followed by target
change, repeated ready events, and cancellation with deterministic gates where
possible. Preserve the existing accepted-result proof rather than replacing it
with a broad snapshot assertion.

## oauth routing and listener ownership

Carry initiating public URL/run, destination app tunnel/run, integration URL,
alias selection, and receiver selection as distinct internal references.

- OAuth state remains a bounded, expiring, single-use digest. Keep existing HMAC
  purposes, suffix lengths, expiry, PKCE/app ownership, and callback paths.
- An alias-origin callback returns to its initiating alias hostname and run.
  Validate the final single-use return hop as well as the callback lookup; a
  handoff cannot redirect it to a replacement alias or another worktree.
- Preserve host-only cookies, allocated ports, exact escaped paths, methods,
  webhook source policies, selected receiver claims, and fanout behavior.
- Keep app, integration, alias, connector, and prepared-listener ownership
  distinct. A listener binding is acknowledged after bind, including port 0;
  it is not provisioning or readiness.
- Listener replacement cancels and joins the previous publication. Unregister,
  owner exit, expired renewal, and failed acknowledgment retain their existing
  cleanup ownership. Workers hold hostname locks through drain and join.
- Preserve native connection-owner sibling isolation, joined ASGI cleanup, and
  the boundary between preparing a service and opening its visitor stream.

Keep OAuth state, codes, request bodies, signing keys, and application credentials
out of snapshots, events, diagrams, inspection, and failure text.

## bounded output and small correctness repairs

### all three subprocess buffers

Remove unrestricted embedded `bytes.Buffer` operations from the three bounded
subprocess outputs: `publishertarget.boundedBuffer`,
`sourcestate.boundedOutput`, and `kubeconfig.limitedOutput`. Private storage plus
the needed explicit methods must make every write path honor its bound; promoted
`ReadFrom` or `WriteString` must not bypass `Write` through interface dispatch.

Preserve each existing size, overflow result, subprocess cancellation, and safe
diagnostic. Check exactly-at-limit, over-limit, multiple writes, and `io.Copy` or
the actual subprocess path. Keep Git hashing read-only and Docker/exec stderr
out of returned diagnostics. A shared helper is justified only if it preserves
these distinct failure contracts.

The TypeScript config loader's separate `projectconfig.boundedOutput` deliberately
drains excess output and records overflow. Preserve that behavior: changing it to
an early-error writer can block the child process. Include it in the inventory
so a mechanical buffer cleanup cannot silently change its semantics.

### nil safety and csr errors

Audit typed-nil private/public keys, signers, certificate/CSR parse results,
optional subjects, credential providers, callbacks, and error wrappers at the
boundaries changed here. A non-nil interface can hold a nil pointer. Validate the
concrete value before dereference or method calls; malformed values must return
the existing safe failure rather than panic or authorize.

Handle CSR parsing, signature validation, public-key extraction, and certificate
matching as explicit stages. Preserve the underlying cause where callers need
`errors.Is`/`errors.As` classification. Report an authored CSR failure without
raw certificate input, provider text, or credentials.

### standard helpers and parser state

Use the pinned Go version's `errors.AsType` where it makes an existing type
extraction clearer. Preserve wrapped-cause behavior, typed-nil handling, and any
custom `As` semantics; this is not a new error taxonomy.

Use `slices.Clone` or `maps.Clone` for actual ownership copies, preserving nil
versus empty encoding and copying nested mutable data when required. A shallow
clone cannot establish ownership of keys, byte slices, maps, or pointer fields
inside an entry. Clone before canonical sorting if the caller owns the input.

Make parser state local to one parse or an explicitly owned incremental parser.
Audit framed messages, ClientHello/protocol inspection, subject extensions,
configuration, and kubeconfig conversions that this work touches. Bound reads,
validate lengths before slicing, reset reused state, and publish the parsed value
only after full validation. Unknown, truncated, duplicate, or trailing input must
not leave a partially valid prior value available to callers.

For publisher-side PostgreSQL/MySQL/Redis summaries, keep parser stages and
pending-operation attribution explicit and bounded. Losing framing or attribution
disables observation for that visitor without changing forwarding success. Keep
authenticated MySQL capability selection separate from parser progress. Preserve
safe counts/status fields and exclude SQL, arguments, application bodies, and
credentials from inspection records.

### workload expiry

Keep the initial workload session window immutable. Assertion refresh, connector
renewal, HTTP certificate renewal, transport reconnection, and cached authorization
cannot extend it. Every derived expiry is bounded by the original session and any
earlier credential, run, certificate, or decision deadline. Late acquisition or
renewal results cannot replace a newer subject or resurrect an expired owner.

Use deterministic clocks for local deadline assertions and retain the real
transport integration proof across production lease cycles. Distinguish a denied
assertion, unavailable issuer, malformed response, and expired fixed session.

### benchmark directions and atomic aggregates

Validate downstream, upstream, and bidirectional intent before starting benchmark
workers. Use an internal direction type so unknown input cannot fall through as
downstream. Preserve string values, report JSON, per-direction stream counts,
rate units, byte accounting, time windows, and command defaults.

Keep concurrently updated counters race-safe and load values when snapshotting;
never copy a live atomic value or its owner. Validate an aggregate or histogram
merge completely before mutating the destination, including layout, cumulative
counts, bounds, overflow, and finite nonnegative measurements. A failed merge
must leave the destination unchanged. Preserve exact joined totals and upload/
download attribution with local fixtures; no deployed benchmark is needed to
prove these invariants.

## validation sequence

Run commands from the repository root through `mise exec --`, using pinned
dependencies. First use the focused existing Task for the domain being edited.
Then run routine checks once for the complete first PR. The
[role organization plan](https://md.cormo-turtle.ts.net/.worktree/tnl/role-organization/docs/maintainers/reorganization-plan.md)
defines the stack-wide source inventory and coverage-preservation ledger.

```console
mise exec -- task generate
mise exec -- task format
mise exec -- task format-check
mise exec -- task go:test
mise exec -- task go:lint
mise exec -- task js:check
mise exec -- task py:check
mise exec -- task connect:check
mise exec -- task workflows:lint
mise exec -- task go:vulncheck
mise exec -- task go:test:race
mise exec -- task go:test:harness
mise exec -- task go:test:integration
mise exec -- task build
```

`go:test` runs `go test ./...` and the public Go consumer fixture through
`go:test:public-api`. `go:lint` includes `go vet ./...` and staticcheck; do not
repeat those direct commands as additional evidence. `js:check` builds once,
then reuses the build for typechecks, tests, lint, formatting, and packing.
`py:check` includes Ruff, mypy, real-native pytest, and source packaging checks.
If an aggregate Task already ran a listed check on the same final tree, record
that invocation instead of rerunning it. Repeat checks only for a later change,
a failure, or an unresolved boundary.

Run `mise exec -- task generate-check` against the intended committed generated
tree before shipping. It regenerates and compares generated paths to `HEAD`; it
is mutating and intentional uncommitted generated changes appear as drift. A
failure caused by comparison with old `HEAD` is not evidence of generator
nondeterminism, and generated files must never be hand-edited to make it pass.

### focused boundary evidence

| Scope                                                     | Existing Tasks to select as applicable                                                                                                                                                  |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Native selection, enrollment, login, and owner cleanup    | `go:test:auth`, `go:test:config-contracts`, `go:test:connections`, `go:test:owner-lifecycle`, `go:test:invocations`, `go:test:app-workflows`                                            |
| Public and managed admission, credentials, streaming      | `go:test:live-authorization`, `go:test:http-streaming`, `go:test:database-native`, `go:test:ingress`, `go:test:relay`                                                                   |
| Group, target, Kubernetes, and durable identity           | `go:test:publisher-groups`, `go:test:publisher-state`, `go:test:target-discovery`, `go:test:kubernetes`, `deploy:publishers:check`                                                      |
| Company, recovery, revisions, and transaction boundaries  | `go:test:integration:company`, `go:test:integration:state-boundaries`, `go:test:integration:state-locks`, `go:test:integration:publisher-recovery`                                      |
| Claims, assignments, managed services, and live decisions | `go:test:integration:private-claims`, `go:test:integration:tcp-lifecycle`, `go:test:integration:http-services`, `go:test:integration:live-authorization`, `go:test:integration:ingress` |
| Workload fixed expiry and subject binding                 | `go:test:integration:workload`, `go:test:integration:provider-http`, `go:test:integration:runtime:workload`                                                                             |
| SDK, action, toolbar, and installed native consumers      | `js:test:connections`, `js:test:frameworks`, `js:test:browser`, `py:check`, `connect:check`, `go:test:integration:tcp-clients`                                                          |
| Parser, framing, and byte ownership                       | `go:test:fuzz`, the owning package's routine assertions, and the relevant transport integration Task                                                                                    |

Focused Tasks supplement unique boundaries; they need not repeat every assertion
already executed by an aggregate. Use `go:test:focused` for an assertion without
a dedicated Task, keeping the assertion's original tier. Pass Go test inputs with
`-tnl-*` flags; keep environment variables for orchestration/resource limits.

Integration Tasks own digest-pinned disposable PostgreSQL through
`tools/testharness`. Docker and Pebble are prerequisites. Linux-only CLI, binary,
app-workflow, and cross-team publisher-group proofs require an isolated Linux
runner; record them as pending until that environment has actually passed.
System OpenSSH, kind/kubectl, Node 24 Vercel artifacts, Chromium, and installed
database drivers remain explicit prerequisites of their respective Tasks.
Routine Go tests do not establish these integration or platform boundaries.

Use existing state/runtime/CLI shards for complete broad coverage, preserving
whole-test discovery and separate real-clock lease/workload proofs. Record shard
inputs and results. Large local load sweeps and deployed benchmarks remain
explicit opt-in work with their existing server/workload approval rules.

## first-pr execution record

Implementation commit `bc1efd09c871124a62281d968c7cad2ba9913a7b` delivered the
domain boundaries in [PR #448](https://github.com/tnldotdev/tnl/pull/448), based on
`5203676605d98999cfc012ec20fa857fa0271db9`. The CI follow-up merges main at
`3a4ede1e252185ba485e7bab4724d88eef64236a`. It preserves main's reserved-listener
handoff in ingress and uses `Inventory.Ranges()` in the new standalone and split
socket-reservation tests. The validation results distinguish implementation
qualification from the checks rerun on this merged tree.

### implemented domain boundaries

- **Protocols, state, revisions, and certificate subjects (d01-d04):** owned
  protocol/inspection values, private lifecycle and assignment states, checked
  run/assignment bindings, and revision overflow checks are in place. Certificate
  work and DNS dispatch use explicit public/private subjects.
  `private_runs_boundaries_test.go` covers lifecycle, assignment identity, stored
  metadata, public projection, and credential hash vectors.
  `certificate_work_subject_test.go` covers subject selection, revision bounds,
  and DNS dispatch; certificate and DNS worker subject tests cover their callers.
  `internal/controlstate/queries/dns_challenges.sql` owns the new
  `GetDNSChallengeSubject` query, and sqlc regenerated its committed database
  implementation and querier. This is a query-source change, not a migration.
- **Company decisions and recovery (d05):** admission mode, connection state,
  request history, and owner decision have independent types.
  `UpdateCompanyMembershipDecision` accepts `CompanyMembershipDecision`;
  `RecoverCompanyOwner` is a separate authorized operation. The old boolean-mode
  state adapter is deleted and its callers use the explicit operations. The
  authority HTTP operation remains compatible. `TestCompanyAdmissionDomainsAndDecisionRetries`
  and `TestIntegrationCompanyAdmissionOwnerRetryRechecksEligibility` cover retry,
  current eligibility, and decision boundaries, alongside company integration.
- **Native scopes and enrollment (d06-d07):** transaction-resolved publisher
  scopes have exclusive saved-URL, private-service, or namespace targets. Native
  workers own copied scalar scope and URL snapshots. Local capabilities retain
  their exact owner/service/invocation boundary. Enrollment uses explicit pending
  enrollment, recorded result, installed identity, and selection storage APIs.
  All callers moved to those APIs; the overloaded signing-identity enrollment
  adapter in `internal/clientstate/private_state.go` is deleted. Tests cover
  exclusive resolved targets, independent worker scopes, a key persisted before
  one-use redemption, retry without another grant, recorded-result recovery,
  promotion rollback, and protected job documents.
- **Device and feedback state (d08-d09):** device stages validate exclusive
  payloads and clear exchange material on transitions. Atomic cancellation is
  covered in real PostgreSQL. Feedback uses owned thread/event types and an
  authorized actor with independent permissions; combined browser/share access
  retains the verified account author. Stage, resolve/reopen/resume, concurrent
  cursor, and verified-author assertions passed in the recorded scopes.
- **Bound runs, credentials, assignments, and peers (d10-d12):**
  `publicRunAuthority` binds setup identity, token, team, and certificate plan.
  Managed run tokens and assignment seeds are distinct from public publish-run
  tokens. Managed HTTP credentials have exclusive parsed payloads. Full
  assignment references, claimed relay identity, stream lifetime, forwarding
  variants, and accepted peer checks are used by their production callers.
  Tests cover changed/missing claim fields, pending-open cancellation, admitted
  drain, release exactly once, one forwarding responder, and rejection before
  visitor bytes. Managed visitor normalization covers values, pointers, and
  typed nil after TLS. Public native method signatures remain compatible through
  the narrow managed-control boundary; typed lifecycle calls use
  `ManagedRunControl` with exact service scope.
- **Metadata, inventory, cloud selectors, target plans, and jobs (d13-d14):**
  private metadata decoding now returns an error through every saved-service,
  publisher, local/applied lookup, visitor selection, and reconciliation caller.
  `checkedPrivateMetadata` and `checkedPrivateServiceRecord` replace silent
  decoding. `TestIntegrationPrivateMetadataCorruptionRollsBackCallers` checks
  safe errors and rollback of configuration, grants, runs, routing, and audit;
  valid absent/null trust and valid TLS metadata retain their existing behavior.
  Port inventory validates before publishing its projection. Cloud selectors
  share validation across configuration, assignment, discovery, and generated
  schema; YAML projection is keyed and strict while preserving presence and
  precedence. Private target plans validate trust before resolution/publication,
  and job status rejects unknown observed or stored values while retaining its
  stored strings.
- **Readiness, OAuth, and listeners (d15-d17):** registration-current and
  exact-run-current checks are separate; live service/run reads happen together
  under the manager lock. `checkService` returns this probe's accepted result,
  preserving once-per-run budget completion even after immediate invalidation.
  New deterministic tests cover old-success rejection and success followed by
  target replacement. OAuth scope, redirect origin, and callback destination are
  named values with exact state-digest coverage. Listener generation ownership
  retains cancellation, replacement, and joined cleanup.
- **Buffers, nil safety, errors, clones, and parsers (d18-d20):** all three
  subprocess buffers use private storage and bounded writes. Docker, Git, and
  credential exec tests exercise `io.Copy` and real subprocess paths. The config
  loader keeps its separate drain-on-overflow behavior. Typed-nil key, managed
  visitor, diagnostic, and failure cases are handled safely; CSR failures retain
  owned classification. `AsType` conversions and ownership clones preserve cause
  and snapshot boundaries. MySQL/Redis parser progress and protocol selection
  are explicit, bounded, and covered by body-free summary tests.
- **Workload and benchmark correctness (d21-d22):** workload session updates
  preserve immutable identity, copied metadata, provider execution, and a
  nonextending expiry boundary. Benchmark direction and per-stream wire
  direction are validated separately; aggregate merge validates before mutation
  and owns copied slices. `TestSessionUpdatesShareImmutableAndNarrowingBoundary`,
  `TestBandwidthModesAndStreamWireDirections`, and
  `TestVisitorMergeIsAtomicAndOwnsSlices` cover those boundaries.
- **Compatibility (d23):** all seven `pkg/api/*` import paths and public Go
  signatures remain intact. `go:test:public-api` compiles the external consumer
  under `pkg/tnl/testdata/publicapi`. HTTP/tunnel sources, PostgreSQL/SQLite
  migrations, and baseline identities are unchanged. Hash-vector assertions
  preserve managed credential, private run, and assignment derivation bytes.
  Stored defaults, encodings, CLI behavior, and SDK exports remain compatible.

### intentional corrections and resolved regressions

- Invalid RDS resource/endpoint combinations are rejected by shared selector
  validation before discovery. The writer default is unchanged. Generated schema
  constraints come from the same source; `schema/v1.json` was regenerated.
- Strict YAML rejects wrong scalar/collection types rather than coercing them.
  `TestTNLDYAMLRejectsWrongScalarAndCollectionTypes` and
  `TestTNLDYAMLPresenceDefaultsAndPrecedence` distinguish malformed input from
  existing defaults, explicit emptiness, and environment precedence.
- Typed-nil values return safe errors or the intended empty observation instead
  of dereferencing nil. Promoted `bytes.Buffer` methods can no longer bypass the
  three subprocess bounds. Corrupt persisted metadata now fails at its checked
  boundary and rolls back the calling transaction.
- The managed HTTP opaque-token regression is resolved at the canonical
  server-side boundary as well as the typed client path. `ManagedHTTPRun.valid`
  uses `ParseManagedRunToken` for the existing unprefixed random secret; it no
  longer interprets that secret as a public publish-run token. Padded,
  noncanonical, wrong-domain, or public tokens remain rejected. Token bytes,
  stored digests, assignment derivation, and defaults did not change.
  `TestManagedHTTPRunCredentialBoundary`, `TestManagedHTTPCredentialHashVectors`,
  and real managed HTTP/TLS integration cover the correction.
- The broad integration run exposed one stale test fixture in
  `TestIntegrationPublisherRuntimeHTTPObservation`: its managed-token method
  signature masked the embedded real client's production path. The fixture now
  stubs the typed health-heartbeat operation, has compile-time method checks,
  and invokes `ManagedRunControl().HeartbeatPrivateServiceRunHealth`. The same
  test then passed against real PostgreSQL with `-race`. This is a corrected
  production-path fixture, not a weakened assertion or a token-format change.

### validation results

These IDs are the validation references in the scope ledger. All commands use
`mise exec --` from the repository root. A scoped pass does not imply an
unrecorded aggregate or platform run passed.

- **v01 — passed:** `task generate` and `task format`. Source-owned SQL and
  configuration schema outputs were regenerated and formatted.
- **v02 — passed:** full `task go:test` and `task go:build`, including the public
  API consumer fixture. `go:test` includes `go test ./...` and
  `go:test:public-api`; these are not separate claims of repeated suite runs.
- **v03 — passed:** `task go:lint` (`go vet` plus staticcheck),
  `task go:vulncheck` with no called vulnerabilities, and `task workflows:lint`.
- **v04 — passed:** `task js:check`; 272 tests in 34 files, with its build,
  typecheck, lint, formatting, and source-package checks.
- **v05 — passed:** `task py:check`; 127 passed and one skipped, plus Ruff,
  mypy, and package checks. The skipped test remains a skip.
- **v06 — passed:** scoped race runs for the changed boundaries, followed by
  the complete routine race suite in v12.
- **v07 — passed:** multiple real-PostgreSQL auth, feedback, device, company,
  publisher, and private-metadata scopes, including metadata rollback through
  all callers and company decision retries.
- **v08 — passed:** full control-state integration. State, transaction, and
  generated-query assertions completed against disposable PostgreSQL.
- **v09 — passed:** private claims and TCP lifecycle integration, plus split and
  standalone private topology with managed TLS and QUIC. These cover actual
  transport/claim paths rather than only unit adapters.
- **v10 — executed with one corrected fixture failure:** full
  `task go:test:integration` ran all configured packages. The other packages,
  including state and runtime, passed; control API had the single
  `TestIntegrationPublisherRuntimeHTTPObservation` fixture failure described
  above. Do not record this invocation as an all-green aggregate.
- **v11 — passed after fixture correction:** the same publisher runtime HTTP
  observation test, selected through the PostgreSQL integration harness with
  `-race`. This closes that failure without claiming another full aggregate run.
- **v12 — passed:** full `task go:test:race`, covering every routine Go package.
  Repeated successfully on the CI follow-up tree after merging main.
- **v13 — passed:** `task go:test:harness`, including its separate module's
  race-enabled tests; repeated successfully after merging main.
- **v14 — passed:** `task generate-check` against committed generated files and
  `task format-check` on the CI follow-up tree. Generation produced no drift.
- **v15 — passed:** after merging main, `task go:test:focused
PACKAGES='./internal/tnldruntime' RUN='^$'`, full `task go:test`, and
  `task go:lint`. `task go:test:integration:runtime
RUN='^TestIntegration(PrivateRuntimeReserves.*|StandalonePublishReservesSockets|SplitPublishReservesSockets)$'`
  passed all four reservation tests, including control subtests, with `-race`
  and disposable PostgreSQL.
- **v16 — pending:** GitHub checks for the updated PR head. Earlier CI merge
  checks could not compile new main fixtures that ranged over `tcpport.Inventory`;
  v15 verifies the corrected callers. Additional platform, action, browser, fuzz,
  and release-artifact checks are separate from the recorded local results.

## scope and progress ledger

Rows d01-d23 are complete for implementation commit `bc1efd09`, with
source/assertion evidence above and validation references below. The final rows
record local qualification, PR delivery, and the remaining updated-head CI checks.

| ID  | Scope                                                               | Implementation evidence                                     | Validation evidence                            | Status                    |
| --- | ------------------------------------------------------------------- | ----------------------------------------------------------- | ---------------------------------------------- | ------------------------- |
| d01 | Protocol selectors and validated wire variants                      | Owned protocol and inspection values                        | v02                                            | complete                  |
| d02 | Private run, claim, certificate, and DNS states                     | Lifecycle states and checked subject dispatch               | v02, v07-v09                                   | complete                  |
| d03 | Revisions, counters, and checked adapters                           | Run/assignment bindings and overflow rejection              | v02, v08                                       | complete                  |
| d04 | Certificate and visitor subject ownership                           | Subject constructors, SQL source, generated query           | v01-v02, v07-v09                               | complete                  |
| d05 | Company types, setup, offboarding, and recovery                     | Typed decisions; boolean-mode state adapter deleted         | v02, v07-v08                                   | complete                  |
| d06 | Requested/resolved native scopes                                    | Authorized exclusive scopes and owned snapshots             | v02, v07                                       | complete                  |
| d07 | Capabilities, enrollment, and credential installation               | Explicit storage APIs; enrollment adapter deleted           | v02, v07                                       | complete                  |
| d08 | Device stages, cancellation, and late issuance                      | Exclusive stages and atomic cancellation                    | v02, v07-v08                                   | complete                  |
| d09 | Feedback states, evidence, and verified authors                     | Authorized actor and typed thread/event states              | v02, v07-v08                                   | complete                  |
| d10 | Bound runs and managed HTTP credential variants                     | Bound authority, typed tokens, canonical server validation  | v02, v07, v09, v11                             | complete                  |
| d11 | Assignment references and relay lifetime                            | Complete claim identity and owned stream lifetime           | v02, v06, v09                                  | complete                  |
| d12 | Forwarding variants and accepted transport peers                    | Exclusive dispatch, accepted peer, release-once checks      | v02, v06, v09                                  | complete                  |
| d13 | Bounded inventory, cloud metadata, and keyed YAML projections       | All metadata callers checked; shared selector/schema rules  | v01-v02, v07-v08                               | complete                  |
| d14 | Private target plans and job status                                 | Validated plans and closed status values                    | v02                                            | complete                  |
| d15 | Exact current checks and accepted readiness results                 | Registration/run split and locked live read                 | v02                                            | complete                  |
| d16 | Once-per-run readiness budget and joins                             | Accepted success, stale result, replacement/join assertions | v02                                            | complete                  |
| d17 | OAuth/alias routing and listener ownership                          | Named callback boundaries and listener generations          | v02, v04-v05                                   | complete                  |
| d18 | Three bounded subprocess buffers and config-loader drain            | Private buffers; copy/subprocess assertions; drain retained | v02                                            | complete                  |
| d19 | Typed-nil safety and CSR error causes                               | Nil-safe keys/visitors/errors and CSR classification        | v02                                            | complete                  |
| d20 | `AsType`, ownership clones, and parser state                        | Cause/snapshot ownership and bounded parser progress        | v02                                            | complete                  |
| d21 | Nonextending workload expiry                                        | Immutable/narrowing session update boundary                 | v02, v10                                       | complete                  |
| d22 | Benchmark direction and atomic aggregate correctness                | Direction validation and atomic owned merge                 | v02                                            | complete                  |
| d23 | Public compatibility, wire/stored fixtures, and unchanged baselines | External Go consumer, hash vectors, unchanged migrations    | v01-v02, v04-v05, v07-v09                      | complete                  |
| d24 | Routine, integration, platform, and packaging checks                | Local checks complete; updated-head CI outstanding          | v12-v15 passed; v16 pending; v10 not all-green | pending CI                |
| d25 | First PR review and handoff to the stacked second PR                | Implementation committed; #448 open; CI follow-up isolated  | `bc1efd09`, #448; merged main `3a4ede1e`       | ready for stacked handoff |

## first pr completion gate

The domain implementation is complete through d23 and delivered in #448. Full
routine race, harness, generated-drift, formatting, and focused reservation
results are recorded above. Confirm updated-head CI before completing d24. The
broad integration invocation and its successful corrected-test rerun remain
separate results; they are not rewritten as a second all-green aggregate.

Before opening or updating the PR, review the full branch diff against the
recorded baseline, including generated output and fixtures. Carry forward the
coverage ledger and exact validated commit into the role-organization branch.
The second PR begins from that result. Its organization, coverage-move, and
delivery ledgers remain pending; completed domain work does not complete those
moves.
