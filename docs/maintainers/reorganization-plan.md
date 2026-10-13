# go ownership and type-safety work

Make the Go codebase easier to understand, harder to misuse, and easier to change
while preserving what tnl does. this document records our goals, what we have
learned, and the next useful change. update it as the work reveals better
boundaries.

## goals

- Make client, control, ingress, relay, and transport ownership clear. private
  ingress and relay APIs served by control belong to control's serving boundary.
- Keep commands focused on input and presentation. process composition owns
  construction, supervision, startup, partial-startup cleanup, and shutdown.
- Keep complete operations and their transactions cohesive, including operations
  spanning authority, publication, placement, routing, or collaboration.
- Give shared domain concepts small, dependency-light owners. choose package
  boundaries from actual dependencies and lifetimes.
- Use types to distinguish values that are realistically easy to confuse: IDs,
  publish run numbers, revisions, cursors, slots, ports, rates, and fixed choices.
- Make configuration input, resolved choices, validated facts, and live state
  distinguishable where that prevents misuse.
- Simplify the code needed to follow an operation. share owned types directly;
  separate representations should serve a real input, output, storage, or trust
  boundary.

The scope includes handwritten Go under `cmd`, `internal`, and `pkg`, adapters
around generated code, generators, separate tooling modules, and their affected
documentation, fixtures, and checks. package count, abstraction count, and the
number of primitive types replaced are not measures of success.

## design principles

Put behavior on the value or component that owns it. constructors, validation,
and private operational fields should establish useful invariants while retaining
supported zero values and deliberate sharing.

Define interfaces around what a consumer needs. keep construction concrete and
use compile-time assertions where they clarify an important implementation.
Choose pointer and value receivers deliberately, accounting for mutation,
synchronization, copying, and optional methods exposed by wrappers.

Use generics for genuinely shared typed mechanics and closed variants when they
prevent contradictory states. apply stronger types through real consumers;
unused wrappers and parallel models do not improve the boundary.

Types can establish local facts. current authorization, lease validity, and
concurrent state still require checks at their owning runtime boundaries.

## compatibility requirements

This is refactoring work. keep discovered functionality fixes separately scoped,
including typed-nil bugs and changes to zero-value behavior.

Preserve:

- Public Go import paths, signatures, constructible structures, fields, and method
  sets. optional methods can affect copying, observation, and budgeting even when
  required interfaces still compile.
- HTTP, tunnel, local publisher, and SDK bootstrap contracts; golden bytes;
  configuration formats and generated metadata; CLI flags, output formats, and
  stdout/stderr ownership.
- Omitted, null, empty, false, and zero distinctions; inheritance, normalization,
  accepted ranges and identifier forms; validation order and reload boundaries.
- Database filenames, schemas and migrations; keyring identities; lock and
  descriptor paths; salts, hashes, fingerprints, credentials, and coordination
  identities. preserve encoded bytes used as identities, not only decoded values.
- Transaction atomicity, lock ordering, isolation, authorization rechecks,
  reservation accounting, routing publication order, and unrelated-work progress.
- Registration, assignment, lease, revision, process-run, and work-claim fencing;
  event ordering, retention, cursor continuity, recovery, and retry boundaries.
- Listener, session, worker, and cleanup ownership; cancellation, drain, join,
  half-close, transport fallback, admission, and byte-accounting behavior.
- Error and wrapped-cause identities, classification, retry policy, cancellation
  causes, expected shutdown, and authored safe output.
- Trust and credential scopes. control owns PostgreSQL and control-only secrets;
  ingress and relay fail closed on expired leases. browser sign-in, preview
  access, visitor policy, and verified feedback authorship remain distinct facts.
- Protocol-specific inspection attribution, fields, capture bounds, nonblocking
  observation, credential exclusion, and retention. durable work, usage, metrics,
  telemetry, and benchmarks keep their existing meanings and external effects.

Preparation, registration, routability, and readiness remain separate facts.
Readiness checks use the public visitor path, remain bounded and credential-free,
and reject stale observations. a failed check leaves publication running; wait
checks freshly and ordinary status reads observations. dynamic target resolution
retains owner context, cache expiration, and stale-target rejection.

Ingress never replays a visitor connection after the first visitor byte reaches a
relay. external processes sharing supported state must continue to coordinate
correctly through refactors.

The [architecture guide](architecture.md), [control-state notes](control-state.md),
and [failure boundaries](errors.md) describe the detailed commitments of each
component. use them when investigating a change.

## how we proceed

For each change:

1. Trace a concrete problem through its consumers, state, lifetime, and outputs.
2. Choose a complete change that clarifies ownership or prevents a real misuse.
   explain the purpose of each new package, interface, type, and conversion.
3. Implement it with the existing invariants and their tests intact. move the
   implementation with its owner and keep adapters focused on actual boundaries.
4. Verify the affected contracts and review the resulting complexity, including
   added forwarding code and duplicate representations.
5. Record the decision, resulting boundary, and verification. choose the next step
   from what remains difficult to understand or easy to misuse.

Keep one next step here. revise it when investigation changes the problem or the
appropriate boundary. keep decision records short and put shipped architecture
in the architecture guide.

## current findings

[PR #276](https://github.com/tnldotdev/tnl/pull/276) extracts the local publisher
process into `internal/localpublisher`. registration leases, probes, and the
journal remain owned by `internal/clientruntime`; publish-run and visitor behavior
remain owned by `internal/publisher` and `internal/adhoc`.

The extraction also introduced an exported forwarding layer in
`internal/localpublisher/api.go` and retained command-side copies of publication,
team, and settings models. some values now travel through conversion round trips
without establishing a new invariant or crossing a distinct representation
boundary. this scaffolding added complexity beyond the ownership move.

The package also contains reusable project and publication operations. their
eventual owners should follow their consumers and dependencies as we investigate
them.

## next step

Simplify the boundary of the local publisher extraction.

Inspect the exported API and its command consumers, especially publication setup,
team context, metadata resolution, and settings adaptation. reuse owned types
directly where the representations mean the same thing. remove unnecessary
forwarders, duplicate models, and unused exports; retain conversions that serve
real parser, wire, storage, or trust boundaries.

The result should keep the publisher lifecycle traceable outside command code,
reduce the code needed to follow shared operations, and preserve the contracts
established by the existing tests. after verification, reassess the remaining
coupling before choosing further work.

## decisions made

- Replace the predefined PR sequence with goals and an evidence-driven working
  process. choose scope and order from the code as we learn.
- Address the unnecessary scaffolding in the local publisher extraction before
  choosing broader package moves.

## verification

Establish the actual current base and distinguish inherited failures from
regressions. reuse existing coverage and add tests at the lowest sufficient layer
for an untested boundary. preserve unique assertions, including white-box tests,
when moving behavior.

Use the [contributor validation sequence](../../contributing.md#check-your-change)
and the Task targets appropriate to the change. root Go checks do not traverse
the separate tooling modules. race, platform-specific, tagged, and integration
checks remain necessary where they establish the affected boundary.

Package moves carry their Task selectors, generator paths, embedded assets,
relative fixture paths, cross-language consumers, Docker build inputs, and
platform-specific setup. edit authoritative inputs and regenerate committed
outputs. `generate-check` regenerates files and compares generated paths with
`HEAD`; account for intentional generated changes.

Keep infrastructure-backed checks within the existing test-tier, disposable
resource, and benchmark approval boundaries. record the concrete verification
performed with each change.
