# package reorganization and go type-safety plan

## purpose

Make the Go codebase easier to understand, harder to misuse, and easier to change
while preserving the functionality of tnl.

This work reorganizes packages around the components that own behavior, clarifies
dependencies between those components, and applies idiomatic, type-safe Go
practices where they provide a concrete benefit.

The intended result is a codebase where an implementer can readily answer:

- Which component owns this operation?
- Which facts have already been validated?
- Which state can change concurrently?
- Which transaction or process owns this work?
- Which package owns this domain concept?
- Which boundary converts it into an API, database, configuration, or output
  representation?
- Which tests establish that the behavior is still correct?

Package count, abstraction count, and the number of primitive types replaced are
not measures of success. Clear ownership, preserved behavior, and useful
compiler-enforced distinctions are.

## starting point

The initial stack builds on [PR #274](https://github.com/tnldotdev/tnl/pull/274),
which adds public TCP readiness checks and publisher-replacement retry behavior.

The planning baseline is commit `2f5d2cca260e5a05cd0de27f6a63b07c6712504f`.

Treat this as a historical starting point. Before beginning a PR, identify the
actual current stack base and account for changes that have landed since this
plan was written.

The scope includes:

- all handwritten Go code under `cmd`, `internal`, and `pkg`;
- handwritten adapters around generated Go models and queries;
- Go generators and scripts;
- the separate Go modules used by the test harness and inspection oracle;
- affected documentation, fixtures, generation configuration, and verification
  targets.

Generated sources remain owned by their authoritative inputs.

## how to use this plan

This is an evolving handoff to the agents implementing the work. It states goals,
important boundaries, and thematic PR scopes. It does not prescribe every package
name, constructor, interface, or file move.

Each implementing agent is responsible for investigating the current code and
choosing a design that satisfies its PR's goals.

The agent should:

- trace the affected operation through its inputs, domain behavior, storage or
  transport, and output;
- identify the existing owner of each invariant;
- preserve relevant tests and the behavior they establish;
- choose package boundaries from real dependencies and lifetimes;
- keep related refactors together;
- document any dependency that makes the planned boundary inappropriate;
- update this plan to reflect the architecture that actually ships.

The agent may revise a PR's scope, split a goal, combine closely related goals, or
change sequencing when the dependency graph justifies it. Preserve the stable
task identifiers so the history remains understandable.

When revising the plan, record the reason and the resulting ownership boundary.
The document should describe the next useful work rather than defend an earlier
design.

## behavior-preservation contract

This is intended to ship as pure refactoring.

Preserve the product's accepted inputs, externally observable behavior, stored
state, and operating characteristics. A change that intentionally modifies those
belongs in separately scoped work with its own explanation.

### public and machine contracts

Preserve:

- public Go import paths, exported signatures, constructible structures, fields,
  and relevant method sets;
- HTTP paths, methods, headers, status codes, problem codes, and authentication
  behavior;
- tunnel protocol versions, message shapes, numeric widths, validation behavior,
  and framed bytes;
- local publisher API and native bootstrap contracts used by the TypeScript and
  Python bindings;
- CLI flags, configuration selection, human output, JSON, NDJSON, raw output,
  and stdout/stderr ownership;
- project configuration formats and generated browser metadata;
- fixture formats consumed by several languages.

Equivalent decoded values are not always sufficient. Preserve encoded bytes where
they are used as identities, fingerprints, digests, or golden expectations.

### defaults and validation

Preserve:

- omitted, null, empty, explicit false, and explicit zero distinctions;
- inheritance and normalization rules;
- existing zero-value and nil semantics;
- accepted identifier forms at each particular boundary;
- validation order where it affects diagnostics or side effects;
- existing errors, retry classifications, and cause identities.

A constructor or shared validator must enforce the rules of the boundary it
serves. Introducing a stronger type must not silently narrow an existing public
contract.

### persistence and coordination

Preserve:

- database filenames, schemas, migration histories, stored values, and
  nullability;
- lock names, hashes, credential formats, encryption contexts, and
  state-directory identities;
- canonical request hashes and retry-stable credential derivation;
- transaction atomicity, lock ordering, isolation, and unrelated-work concurrency;
- lease, revision, process-run, registration, and claim fencing;
- event ordering, retention, cursor representation, and restart continuity.

Old and new processes sharing supported state must continue to coordinate
correctly.

### lifecycle and visitor behavior

Preserve:

- ownership of listeners, sessions, workers, and cleanup;
- cancellation and join ordering;
- admission and drain behavior;
- retry timing and idempotency boundaries;
- public readiness meaning;
- transport fallback and recovery;
- byte accounting, inspection limits, and half-closes;
- the visitor retry boundary.

A failed visitor connection is never replayed after the first visitor byte reaches
a relay.

### trust boundaries

Preserve the provenance of trusted facts and the scope of credentials.

Control remains the only role with PostgreSQL, storage keys, and control-owned
provider credentials. Ingress and relay retain their existing fail-closed lease
behavior. Browser sign-in, preview access, publisher authentication, visitor IP
policy, and feedback authorship remain distinct decisions.

## desired organization

The package structure should communicate a small number of recognizable ownership
boundaries.

### client

Client-owned code includes:

- local publisher process orchestration;
- application preparation and registration;
- local publisher API serving and scopes;
- publish-run lifecycle;
- visitor TLS termination and local forwarding;
- project discovery and effective configuration;
- client authentication and state;
- aliases, OAuth callbacks, and webhook integration URLs.

### control

Control-owned code includes:

- public control and authority APIs;
- private APIs served to ingress and relay;
- durable authority and publication operations;
- placement and routing-table publication;
- preview access and feedback;
- certificate and DNS work;
- usage aggregation and delivery;
- invitation email delivery.

The private ingress and relay API servers belong to control's serving boundary
even though their callers are ingress and relay.

### ingress and relay

These remain recognizable, independent runtime components.

Ingress owns visitor inspection, policy, admission, connected-relay selection,
and one-time forwarding.

Relay owns authenticated publisher connections, exact assignment claims, visitor
stream admission, and forwarding to locally connected publishers.

### transport

Shared transport mechanisms have focused ownership for multiplexing, handshakes,
framing adapters, trusted connection metadata, and duplex copying.

Preserve the distinction between transport mechanisms and the domain operations
that use them.

### process composition

Process composition owns concrete construction, worker supervision, startup,
readiness, partial-startup cleanup, and shutdown.

Commands adapt user input and present results. Components own the lifecycle they
implement.

### shared domain concepts and infrastructure

Concepts used across several components should have small, dependency-light
owners.

Examples include publication identity, service protocol, hostname rules,
credentials, traffic-limit values, and inspection outcomes.

Infrastructure helpers remain focused on mechanisms such as bounded JSON, file
locking, SQLite setup, and worker scheduling.

Choose the actual directory layout from the dependency graph. Grouping directories
may organize packages without introducing a package façade or additional runtime
layer.

## go design goals

Apply the following principles throughout the affected components.

### domain-specific values

Use distinct named types where interchangeable primitives create a realistic risk
of confusion.

Priorities include resource IDs, run numbers, revisions, cursors, connection slots,
ports, rates, capacities, statuses, and fixed configuration choices.

Types should follow domain ownership. Their conversion to wire and database forms
should happen at explicit boundaries.

### methods and construction

Put behavior on a value when the value owns that behavior.

Use constructors, validation, and unexported operational fields where they make an
invariant reliable. Separate validated operational values from input and output
structures when that improves the boundary.

Preserve useful existing zero values. Resource-owning types should have clearly
understood construction and lifecycle requirements.

### interfaces and method sets

Define interfaces around the operations a consumer needs.

Keep concrete construction in composition code. Important implementations should
have compile-time assertions at locations that preserve dependency direction.

Choose pointer and value receivers intentionally. Account for mutation,
synchronization, copying, and optional interfaces exposed by wrappers.

### generics and closed variants

Use generics for genuinely shared typed mechanics with a clear constraint.

Use sealed interfaces when modeling a real closed set of domain variants and when
doing so prevents contradictory states.

Existing effective patterns should remain effective. Simplification may be the
right result.

### nil and error contracts

Make successful error returns, optional dependencies, and interface boundaries
unambiguous.

Preserve sentinel identity, wrapped causes, classification, retry behavior,
diagnostics, and safe output.

Characterize existing nil behavior before changing it. A newly discovered
typed-nil bug or changed zero-value behavior should be explicitly classified as a
functionality change rather than hidden inside a refactor.

### state and ownership

Make coordinated state transitions and ownership transfers clear.

Types can establish local facts. Current authorization, lease validity, and
concurrent database state still require runtime checks at their owning boundaries.

Respect deliberate sharing and dynamic resolution. Strengthening an ownership
model must preserve the behavior of supported callers.

## shipping structure

Ship the work through thematically consistent PRs. A PR may be large when its
changes establish one coherent boundary and can be reviewed as one architectural
change.

The first refactor PR should target the current branch corresponding to PR #274.
Later dependent PRs should target their immediate predecessor. Each diff should
contain only its own thematic work.

The sequence below is a starting order, not a fixed dependency chain. Reevaluate
it after each substantial boundary change.

R01 is in progress; the remaining tasks are planned. Update each task's status,
PR link, actual base, and resulting ownership as work proceeds.

| task | theme                                                |
| ---- | ---------------------------------------------------- |
| R01  | local publisher process ownership                    |
| R02  | client and project package organization              |
| R03  | control and daemon package organization              |
| R04  | transport and protocol ownership                     |
| R05  | shared domain values                                 |
| R06  | configuration and resolved choices                   |
| R07  | control transactional state ownership                |
| R08  | client persistence and coordination ownership        |
| R09  | publisher and visitor-path state models              |
| R10  | registration, readiness, and integration lifecycles  |
| R11  | authority, preview access, and feedback facts        |
| R12  | inspection observations and protocol-specific models |
| R13  | durable work, usage, and observability contracts     |
| R14  | remaining interfaces, errors, and Go contracts       |
| R15  | CLI, benchmark, and tooling completion               |

### r01 — local publisher process ownership

**Status:** in progress, implementation extracted and local validation passed;
Linux binary integration awaits PR CI.

**Actual base:** `0xcadams/public-tcp-readiness` at
`2f5d2cca260e5a05cd0de27f6a63b07c6712504f` ([PR #274](https://github.com/tnldotdev/tnl/pull/274)).

**Implementation boundary:** `internal/localpublisher` composes the project
publisher process and local HTTP API. `internal/clientruntime` continues to own
registration leases, observations, probes, and the journal; `internal/publisher`
and `internal/adhoc` continue to own publish runs and visitor handling. runtime
commands pass plain options, while command adapters own interactive authentication
and terminal rendering.

The dependency investigation required extracting publication setup, project
metadata resolution, team/domain selection, dynamic Docker targets, preview
association, inspection adapters, and integration worker coordination alongside
the runtime. commands reuse this behavior through client-facing operations rather
than providing the runtime's preparation or publishing implementations. R02
should separate these reusable helpers from process composition and simplify the
command-side compatibility projections according to their actual consumers.

Local API, scope, external publisher, descriptor cleanup, Docker resolver, and
publication policy tests move to the component. CLI bootstrap, status, wait,
watch, and login presentation assertions remain at the command boundary. a new
partial-startup test checks descriptor cleanup and listener release.

Local validation passed generation and generated-drift checks, formatting, lint,
routine Go/TypeScript/Python tests, Go race tests, PostgreSQL-backed integration,
the development publisher image and scoped Compose app integration, and builds.
The existing Linux binary integration workflow covers SDK bootstrap and shared
app/named publisher lifecycles.

**Goal:** make the local publisher process an explicit client component rather than
an implementation distributed through CLI command code.

The component should own application preparation, registration, local API serving,
scope enforcement, publication coordination, readiness observations, and shutdown.
CLI commands should construct and invoke that component through clear options.

The agent should choose extraction boundaries that preserve the existing division
between registration management and publish-run behavior.

Completion should make it possible to follow the local publisher's lifetime
independently of CLI flags or presentation code.

Preserve:

- preparation versus registration acknowledgement;
- owner lifetime versus request lifetime;
- app, named-service, and ad-hoc distinctions;
- scoped credentials and project checks;
- external publisher PID-namespace behavior;
- replacement, cancellation, join, and endpoint cleanup ordering.

Retain the existing local API, SDK bootstrap, publisher restart, and scope tests
at their resulting owners.

### r02 — client and project package organization

**Goal:** make client-owned behavior discoverable as a coherent part of the
repository.

Organize project discovery, effective configuration, authentication, state,
publication, ad-hoc publication, and integration URL coordination beneath
understandable client boundaries.

Clarify the difference between:

- configuration input;
- a selected and resolved project;
- a running local publisher;
- an app-owned listener;
- a publish run;
- saved local state.

Use the package organization to communicate those responsibilities while retaining
cohesive implementations.

Preserve project discovery and server-selection precedence, worktree identity,
metadata generation, dynamic target resolution, and current public import paths.

Update affected imports, generation paths, embedded assets, fixture consumers,
documentation, and test targets as part of the same ownership move.

### r03 — control and daemon package organization

**Goal:** make control-owned serving and durable operations distinct from daemon
composition and stateless roles.

Organize the control API, authority API, private ingress/relay API servers, durable
state, and control workers around their actual owner.

Make daemon composition the clear location for concrete dependencies, role
startup, worker supervision, readiness, and shutdown.

Standalone should continue composing the same role boundaries through the same
private service logic.

Preserve:

- control-only database and provider credentials;
- direct and HTTP private API equivalence;
- API surface routing and authentication;
- optional capability behavior;
- partial-startup cleanup;
- worker supervision and shutdown ordering.

Directory changes should make the existing architecture visible before deeper
transactional decomposition.

### r04 — transport and protocol ownership

**Goal:** make transport mechanisms and authenticated tunnel behavior easy to
locate and reason about.

Clarify ownership of multiplexed sessions, transport connectors, tunnel handshakes,
stream setup, PROXY metadata, and duplex copying.

Improve typed shared mechanics where they reduce duplication without changing
public protocol structures or wire behavior.

Preserve:

- public tunnel protocol source APIs and golden bytes;
- QUIC and TLS/yamux contracts;
- stream acceptance before metadata and visitor bytes;
- deadlines, cancellation, resets, and error normalization;
- half-closes and two-direction completion;
- bounded transport cleanup and socket release.

Review optional method sets deliberately. Additional promoted methods can change
copy dispatch, observation, budgeting, or UDP behavior even when required
interfaces still compile.

### r05 — shared domain values

**Goal:** establish clear ownership and useful compiler-enforced distinctions for
values crossing component boundaries.

Prioritize identities, run numbers, revisions, cursors, slots, ports, rates, and
domain choices that are currently easy to interchange.

Use existing owning packages where possible. Create shared leaf packages when
several architectural roles need the same concept.

Boundary adapters should make conversion and validation explicit. Preserve the
differing identifier rules of configuration, application-generated resources,
HTTP APIs, and the tunnel protocol.

Completion should reduce same-type argument ambiguity and unchecked conversions
while preserving:

- public Go source compatibility;
- wire and storage representations;
- canonicalization and accepted ranges;
- omission and zero semantics;
- hashes, fingerprints, and credential derivation.

Apply types through meaningful consumers rather than merely defining unused
wrappers.

### r06 — configuration and resolved choices

**Goal:** distinguish configuration input from validated operational choices.

Make fixed choices such as publisher selection, target selection, service
protocol, visitor TLS behavior, and inspection modes explicit.

Clarify how project defaults and service overrides become an effective
configuration, then a resolved target or publication plan.

Preserve:

- JSON, YAML, and TypeScript configuration behavior;
- strict parsing and custom scalars;
- omission, explicit values, inheritance, and normalization;
- app-reported versus named targets;
- public metadata and generated declarations;
- dynamic Docker and mounted-service resolution.

Treat reflected schema names, generated TypeScript definitions, and
configuration-key mappings as compatibility surfaces.

Completion should let runtime code rely on a well-defined resolved choice without
changing what users can configure.

### r07 — control transactional state ownership

**Goal:** make complete control operations and their transaction boundaries easier
to follow.

Organize durable authority, publication, placement, routing, collaboration, and
work-state operations according to their transactional commitments.

The agent should preserve a cohesive transactional owner wherever an operation
spans several concepts. Smaller packages are useful only when they clarify
ownership without fragmenting atomic work.

Preserve:

- transaction-time authorization rechecks;
- authority mutations and publication closure;
- reservation accounting and placement capacity;
- exact assignment and lease fencing;
- recovery behavior;
- routing publication as the final transaction phase;
- routing-clock and retention semantics;
- public TCP port allocation;
- relevant database triggers and persisted projections.

Concurrency is part of correctness: conflicting work must still block
appropriately, and unrelated work must still progress.

Keep the pool, migrations, generated-query ownership, and connection purposes
understandable.

### r08 — client persistence and coordination ownership

**Goal:** make local persistence and ownership boundaries clear without changing
saved state.

Clarify responsibilities for server profiles, sessions, certificates,
installation identity, publication records, aliases, webhook ownership, OAuth
callbacks, inspection retention, telemetry, and locks.

The agent should retain shared transactions and stable coordination identities
where several local processes depend on them.

Preserve:

- `client-v2.db` and its supported schema;
- migration and initialization behavior;
- keychain and other platform-specific secret protection;
- lock names, paths, hashes, and ownership checks;
- worktree salt and saved hostname identity;
- snapshot and event consistency;
- certificate restart behavior;
- terminal retention and cleanup.

Package moves must preserve platform-specific test setup and environment
isolation. Existing white-box assertions should move with the behavior they
establish.

### r09 — publisher and visitor-path state models

**Goal:** make connection state, admission, and ownership transfers harder to
represent incorrectly.

Strengthen the publisher's assignment and connection lifecycle, relay connection
registry, ingress forwarding stages, and visitor-serving ownership.

Use local types and transition methods where they establish useful facts, such as
a serving connection owning its session or a committed stream retaining its exact
cleanup responsibility.

Preserve:

- validation of all replacement assignments before mutation;
- assignment identity independent of reported lifecycle state;
- initial two-connection readiness and subsequent one-connection service;
- transport preference and fallback behavior;
- no reconnection of an obsolete claimed assignment;
- denied-visitor handling;
- separate challenge capacity;
- no replay after the visitor retry boundary;
- drain and immediate-failure behavior.

Keep time-dependent validity and concurrent-state checks at their existing runtime
boundaries.

### r10 — registration, readiness, and integration lifecycles

**Goal:** make the local registration and integration URL lifecycle explicit.

Clarify registration identity, owner liveness, publication identity, readiness
observations, integration election, and handoff.

Preserve preparation, registration, routability, and readiness as separate facts.
Preserve fencing against replaced registrations, publish runs, targets, and
readiness configurations.

Retain PR #274's public TCP readiness behavior:

- public-path probing remains separate from private-target preflight;
- probes remain bounded and credential-free;
- protocol-specific checks retain their current meaning;
- failed readiness leaves publication running;
- wait performs fresh, identity-fenced checks;
- ordinary status reads observations;
- selected-publisher probes execute from the owning publisher environment.

Preserve integration URL election-lock identities, readiness clearing, revision
changes, join-before-release, OAuth origin binding, and alias/webhook selection
behavior.

### r11 — authority, preview access, and feedback facts

**Goal:** make the provenance and lifetime of authorization facts clear.

Improve models for identities, memberships, publication scope, credentials,
preview inclusion, shares, browser sessions, and feedback actors.

Use distinct types or closed variants where they prevent different authorization
paths from being accidentally treated as equivalent.

Preserve:

- API authorization followed by transaction-time rechecks;
- current membership and policy revision checks;
- saved-URL, ephemeral, guest, and publish-run credential scope;
- captured share scope and revocation;
- browser sign-in separate from preview access;
- host-bound, expiring, single-use handoffs;
- publisher-provided visitor facts separate from control-verified authorship;
- immutable first reports and ordered feedback history;
- demo-specific retention and cleanup.

The result should make trusted facts easier to audit without introducing a generic
authorization flag that erases their source.

### r12 — inspection observations and protocol-specific models

**Goal:** represent completed observations according to their actual protocol and
evidence.

Clarify HTTP, PostgreSQL, and MySQL observation models, their conversion to local
storage, and their presentation.

Use closed variants or validated values where current structures allow
contradictory combinations.

Preserve:

- observed execution and outcome attribution;
- exact HTTP status and database error fields;
- summary versus detailed capture;
- statement truncation and payload bounds;
- credential exclusion;
- parser disablement and unsupported-protocol behavior;
- nonblocking observation;
- inspection retention and byte accounting;
- existing CLI and storage shapes.

Retain protocol parser, frame-boundary, EOF, fragmentation, and oracle assertions
at their owning package. Test-only decoder dependencies remain outside product
dependencies.

### r13 — durable work, usage, and observability contracts

**Goal:** make work claims, progress, completion, retry, and measurement facts
explicit.

Improve the domain values and consumer boundaries used by certificate work, DNS
reconciliation, invitation email, usage aggregation, delivery, and metrics.

Preserve the different lifecycles of these workflows.

Important commitments include:

- exact work owner, epoch, revision, and lease checks;
- challenge-routing acknowledgement barriers;
- public URL versus relay certificate installation behavior;
- DNS verification separate from provider acknowledgement;
- custom-domain release barriers;
- durable change receipts and foreign-record preservation;
- invitation creation and email enqueue atomicity;
- at-least-once email behavior;
- usage replay, coverage, aggregation, finalization, and guest accounting;
- per-item delivery acceptance, retry, and rejection;
- bounded metric labels and existing metric meaning.

Keep external effects, stored work, and stale-work protection distinguishable.
Reuse shared mechanics only where their semantics genuinely match.

### r14 — remaining interfaces, errors, and go contracts

**Goal:** complete the cross-cutting Go cleanup within the resulting ownership
boundaries.

Review remaining large interfaces, repeated capability assertions, receiver
choices, interface-valued returns, and error adapters.

Make important implementations explicit through compile-time assertions. Keep
interfaces consumer-owned and construction concrete.

Preserve:

- sentinel and wrapped-cause identity;
- retry policy and cancellation causes;
- API and CLI classification;
- authored safe output;
- expected shutdown behavior;
- optional dependencies and existing nil semantics;
- synchronization and copying requirements.

Use constrained generics where they improve reuse and compile-time safety. Retain
dynamic types where the boundary genuinely handles dynamic data.

Record discovered behavior-changing defects separately. Completing this PR means
the remaining contracts are clearer, not that every type follows one mechanical
pattern.

### r15 — cli, benchmark, and tooling completion

**Goal:** carry the new ownership and domain vocabulary through the remaining
entry points, reporting, and development tools.

Complete command adaptation and presentation boundaries. Improve fixed workload,
direction, scenario, and measurement choices where primitive values obscure their
meaning.

Preserve:

- command flags and environment precedence;
- human, JSON, NDJSON, and raw output;
- telemetry payloads, identities, and durable outbox behavior;
- benchmark plans, approval semantics, workloads, and result formats;
- explicit test tiers and fixture inputs;
- disposable infrastructure ownership;
- nested-module dependency isolation;
- generator and coverage-tool behavior.

Ensure the repository's normal commands and CI still exercise the reorganized
packages. The result should be one understandable codebase rather than a product
refactor with stale tooling around it.

## verification goals

Each PR is responsible for preserving the behavior it moves or changes.

Establish a baseline against the actual stack base. Distinguish inherited failures
from regressions and report the evidence accurately.

Use existing tests wherever they already establish the relevant invariant. Add
meaningful coverage for newly explicit boundaries, conversions, or ownership
guarantees.

Preserve unique assertions when moving tests, including tests that rely on
unexported implementation details. Test relocation must not silently weaken
coverage.

The required root checks include:

```sh
mise exec -- go test ./...
mise exec -- go vet ./...
```

Use the repository's normal formatting, static analysis, race, generation, build,
and integration targets as appropriate to the changed boundary.

### compatibility evidence

Verification should establish, where relevant:

- unchanged public source APIs and method sets;
- unchanged golden JSON and framed bytes;
- unchanged configuration and generated metadata;
- continued reading and coordination of existing local state;
- unchanged canonical identities and fingerprints;
- preserved error identities and classifications;
- equivalent direct and HTTP adapters;
- stale-work rejection;
- correct cancellation, drain, cleanup, and join ordering;
- both conflicting-work blocking and unrelated-work progress;
- public readiness and publisher-restart behavior from PR #274.

### verification ownership

Package moves must carry their verification references with them.

Account for:

- Task targets with explicit package selectors;
- generated-drift paths;
- relative generator working directories;
- embedded files;
- TypeScript and Python fixture consumers;
- tagged tests;
- Darwin keychain setup and CLI environment isolation;
- Linux-only binary tests;
- Docker image source-copy boundaries.

Root Go checks do not traverse nested Go modules. The test harness and inspection
oracle require their own applicable checks, including their existing tagged
integration paths.

Generation checks are state-changing and compare tracked generated paths against
`HEAD`. Use them with an understanding of intentional generated changes.

Keep infrastructure-backed verification within the repository's existing
test-tier and disposable-resource boundaries.

## completion criteria

The work is complete when:

- major components and their lifetimes have obvious owners;
- commands primarily adapt inputs and present results;
- control transaction boundaries remain cohesive and understandable;
- shared concepts have clear dependency-light ownership;
- operational values distinguish important domain facts;
- interfaces describe actual consumer needs;
- state transitions and cleanup ownership are easier to follow;
- public, wire, storage, configuration, and output contracts remain compatible;
- generation, builds, fixtures, and CI reflect the new organization;
- relevant tests retain their assertions and pass on the supported environments;
- maintainer documentation describes the architecture that shipped.

The final summary should explain the resulting ownership, the concrete misuse
prevented by types, the verification performed, and any remaining coupling worth
future work.

## keeping the plan current

For each task, maintain:

- status;
- PR link;
- actual dependency or stack base;
- the boundary that shipped;
- important deviations and their rationale;
- remaining follow-up goals.

Use these statuses:

- **planned** — goals are defined and implementation has not started;
- **in progress** — an agent is actively implementing the task;
- **blocked** — a specific dependency prevents progress;
- **complete** — the goals and applicable verification are satisfied;
- **superseded** — another recorded task or decision now owns the goal.

Update architectural descriptions when ownership changes. Keep completed task
summaries short and preserve the reasoning behind consequential decisions.

Useful decisions to record include:

- where shared publication concepts ended up;
- which control operations remain together because of transaction coupling;
- how local publisher composition is separated from commands;
- how configuration input differs from resolved operational values;
- which variants became closed domain models;
- which apparent cleanup opportunities were retained because of compatibility;
- which discovered defects were moved to separate functionality work.

**The plan should evolve with evidence. Its lasting commitments are clear
ownership, useful type safety, coherent PRs, and unchanged product behavior.**
