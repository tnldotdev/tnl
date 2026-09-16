---
name: tnl-release-smoke
description: Use when qualifying a tnl release candidate against staging, recording live release smoke evidence, or deciding whether a stable v* release may be cut.
compatibility: opencode
metadata:
  project: tnl
  environment: staging
---

# tnl release smoke qualification

Qualify one published tnl release candidate against the deployed staging
environment before promoting its exact commit to a stable release. This skill
owns live staging evidence. The `tnl-release` skill owns version assessment,
local validation, signing, tagging, and publication.

## Release contract

- A release candidate may be published before live qualification. Describe it
  as unqualified until this suite passes.
- A stable release requires a published release candidate with the same base
  version and the exact commit that will receive the stable tag.
- Do not put the stable tag on a later commit, including a documentation-only
  commit. Publish and qualify another release candidate instead.
- Qualify the published client and immutable server image, not locally built
  substitutes. Instrumented binaries may isolate a transport or failure mode,
  but cannot replace the released-client scenarios.
- A stable version is not qualified when a mandatory result is `fail`,
  `blocked`, or `not run`. Do not convert missing evidence into a pass.
- Production deployment is a separate decision and approval. Stable
  qualification never authorizes a production mutation.

## Safety rules

- Operate only on the designated staging deployment and dedicated smoke-test
  identities, projects, routes, and local services.
- Read the deployed configuration before testing. Do not infer topology,
  addresses, packet-I/O mode, or image identity from repository intent.
- Obtain explicit approval before restarting a server role, changing network
  policy, expiring a lease, draining a relay, exercising rollback, changing
  authentication state shared with a person, or touching a staging database.
- Never execute the Fly benchmark from this skill.
- Never print access tokens, refresh tokens, login secrets, cluster secrets,
  storage keys, database URLs, hosted secrets, or DNS credentials.
- Capture the existing route inventory before testing. Never update or delete a
  route that the suite did not create.
- Use unique route names and an isolated client state directory. Keep the
  durable route ID created by the suite in the evidence record.
- Define recovery and cleanup before each disruptive test. Stop if the observed
  topology or failure boundary differs from the plan.

## Candidate record

Record these values before testing:

| Field         | Required evidence                                                     |
| ------------- | --------------------------------------------------------------------- |
| Candidate     | Signed RC tag and GitHub release URL                                  |
| Source        | Full commit SHA, reachable from `origin/main`                         |
| Client        | `tnl version` from a fresh registry or archive installation           |
| npm           | Launcher version, four exact native dependencies, and `next` dist-tag |
| Server        | Signed GHCR index digest from `tnld-image-digest.txt`                 |
| Deployment    | Deployment-repository commit and staging release ID                   |
| Runtime       | Actual platform image digest and `tnld version`                       |
| Configuration | Relevant non-secret settings, including QUIC packet-I/O mode          |
| Time          | UTC start and finish timestamps                                       |
| Operator      | Identity performing approved disruptive actions                       |

Verify the release workflow, artifact signatures, npm packages, public exports,
and image signature as required by `tnl-release`. Deploy the RC image by digest.
Do not continue while repository intent, platform state, and the candidate
record disagree.

## Determine topology

Inspect the running `tnld` roles and process configuration.

- `standalone`: one deployed process composes control, ingress, and two logical
  relay services. Run the common suite. Mark the split suite `not applicable:
standalone topology`.
- `split`: independently deployed control, ingress, and relay roles, with at
  least two distinct relay service IDs and stable relay addresses. Run the
  common suite and every split test.
- `split and replicated`: a split deployment with multiple processes for at
  least one role. Also run the applicable replica tests.

An incomplete or unhealthy intended split deployment is `blocked`, not
standalone and not `not applicable`.

## Evidence rules

For every scenario, record the command or procedure, expected result, observed
result, UTC timestamps, relevant route and process IDs, and links or paths to
sanitized output. Use exactly one status:

- `pass`: the stated pass criteria were observed against this candidate.
- `fail`: behavior contradicted the criteria.
- `blocked`: prerequisites or safe control of the scenario were unavailable.
- `not run`: the scenario was applicable but was not attempted.
- `not applicable`: only for a documented topology condition or an untriggered
  change-specific test.

Local and CI integration tests are supporting evidence, not live staging
evidence. State clearly when a disposable probe differs from the released
client.

## Common staging suite

These checks are mandatory for stable qualification in both standalone and
split staging.

| ID  | Scenario                     | Pass criteria                                                                                                                                                                                                                                                                                     |
| --- | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C01 | Candidate identity           | The released client reports the RC version and commit. The deployed server is the signed digest in the candidate record. The staging configuration matches the intended non-secret settings.                                                                                                      |
| C02 | Service readiness            | Public control `/v1/health` and `/v1/ready` pass. Every process's private `/health` and `/ready` pass. Required certificates, leases, and routing state are current.                                                                                                                              |
| C03 | Fresh authentication         | A dedicated isolated state directory completes the hosted browser or device login and performs an authenticated read. No pre-existing saved session is reused.                                                                                                                                    |
| C04 | Session lifecycle            | A real access-token refresh succeeds, logout revokes the session, and the revoked credential cannot perform another authenticated operation. Use a staging-supported short session rather than editing stored credentials.                                                                        |
| C05 | Ephemeral route              | Create an ephemeral public route, wait for `ready`, visit it, stop gracefully, and verify that route listing and public access no longer expose it.                                                                                                                                               |
| C06 | Durable route                | Create a dedicated durable route, visit it, stop, and confirm the route remains enabled. Republish the same hostname, verify the route ID is unchanged and the route version increases, visit it, then delete only that test route.                                                               |
| C07 | Direct QUIC                  | The released client reaches `ready` without a fallback event and carries visitor traffic. A disposable exact-commit probe with TLS/TCP disabled must also reach `ready` and carry traffic, proving QUIC independently.                                                                            |
| C08 | Network fallback             | With UDP packets to the assigned relay silently dropped or delayed, the released client emits the TLS/TCP fallback event, reaches `ready`, and carries traffic. An immediate connector error is useful diagnostic evidence but does not satisfy this network-blackhole test.                      |
| C09 | Idle path                    | A QUIC publisher carries traffic, remains otherwise idle for at least 105 seconds, then carries traffic again without a fallback event or route-session replacement.                                                                                                                              |
| C10 | Traffic behavior             | Over the public route, complete at least 32 concurrent requests, integrity-check uploads and downloads of at least 1 MiB, complete a WebSocket round trip, and receive separated chunks from a streaming response.                                                                                |
| C11 | Vite development             | Install the published npm client in a disposable Vite fixture, run it through `tnl dev`, verify public loading and HMR, then verify child failure/restart behavior and route cleanup.                                                                                                             |
| C12 | Next.js development          | Install the published npm client in a disposable Next.js fixture, run it through `tnl dev`, verify public loading and development refresh, then verify child failure/restart behavior and route cleanup.                                                                                          |
| C13 | IP policy                    | Verify default current-IP access, explicit allowed prefixes, denial from a genuinely independent source address, the aggregate denial warning, and an intentional switch to public access.                                                                                                        |
| C14 | Hosted authorization         | Using dedicated identities or memberships, verify allowed route create, update, session, and delete operations and rejected cross-team, removed-member, or suspended-member mutations.                                                                                                            |
| C15 | Publisher recovery           | Interrupt publisher network connectivity while keeping the publisher process alive. Existing connections may fail, but publisher connections replenish, visitor traffic recovers, and the route ID and active route version remain unchanged.                                                     |
| C16 | Server recovery and draining | During an active streamed visitor response, gracefully restart the staging server role or standalone process. The stream completes within the configured drain window or closes at its documented deadline, is never replayed, and new traffic succeeds after readiness returns.                  |
| C17 | Operations and usage         | Authorized administration reads succeed, private metrics reflect the exercised routes, denials, connections, streams, and bytes, and the configured route-usage receiver records the test route's revisioned bucket without source addresses.                                                     |
| C18 | Rollback                     | Exercise the documented rollback to the previous verified image and return to the candidate. Both directions regain readiness and pass a test route. For a schema change, use a reviewed backup/restore procedure in an isolated staging copy; never start the old binary against the new schema. |

Use visitor clients with automatic retries disabled when testing retry boundaries
or side effects. A failed visitor connection is acceptable where documented; a
duplicated request is not.

## Conditional split suite

Run this section only when the deployed staging topology is actually split.
Every applicable result is mandatory for stable qualification.

| ID  | Scenario                     | Pass criteria                                                                                                                                                                                                                                                                                                                               |
| --- | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| S01 | Role readiness and placement | Every control, ingress, and relay process passes private readiness. A test route has two ready publisher connections placed on two distinct relay services and connected relay processes before becoming routable.                                                                                                                          |
| S02 | Both relay services          | Exercise QUIC and TLS/TCP connectivity for each relay service. Use controlled placement, drain, or loss so evidence identifies the service carrying each test instead of inferring it from one successful request.                                                                                                                          |
| S03 | Relay loss and replenishment | Stop one connected relay process. After failure detection, new visitors succeed through the surviving relay service. Restore the process and verify a new process run ID, a current relay lease revision, a replacement connection assignment, two ready publisher connections, and no route-version change. Repeat for each relay service. |
| S04 | Relay drain                  | Start a long-running stream through an identified relay, drain that exact process, and verify new work avoids it while the admitted stream can finish until the deadline. Any stream still active at the deadline closes, and the acknowledged process does not register again without a restart.                                           |
| S05 | Brief control outage         | Stop control for less than the observed ingress and relay lease lifetime. Existing data-plane traffic continues. Restart control and verify the same ingress and relay process identities renew current leases and traffic remains available after the original lease deadline.                                                             |
| S06 | Lease expiration             | In an approved window, interrupt private control connectivity past lease expiration. Affected ingress and relay processes become unready and reject new work that requires a current lease. Restore connectivity and verify recovery uses current process run IDs and lease revisions; stale operations remain rejected.                    |
| S07 | Ingress restart              | Restart ingress while publishers remain connected. It becomes ready only after obtaining a current lease, certificate state, listener, and routing table. New visitors then succeed without changing publisher placement or route version.                                                                                                  |
| S08 | Retry boundary               | Send a uniquely identified side-effecting request with visitor retries disabled, then terminate its selected relay after the first visitor byte crosses the retry boundary. The request may fail, but the target records it at most once and ingress does not replay it through another relay.                                              |
| S09 | Trust boundaries             | Public networks cannot reach private control or internal relay addresses. Missing or incorrect cluster authentication is rejected. Relay transport certificates verify their exact relay addresses. Ingress and relays do not receive PostgreSQL, storage-key, hosted-authority, DNS-provider, ACME-account, or administrator credentials.  |

Do not require an established visitor connection to migrate between relays.
tnl never replays a live visitor connection after the retry boundary.

## Conditional replica suite

Run each check only when that role has multiple deployed processes.

| ID  | Scenario                 | Pass criteria                                                                                                                                                                                                                       |
| --- | ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R01 | Replicated control       | Remove one control process. Public control requests and ingress/relay lease renewal continue through another process sharing PostgreSQL. Restore it and verify readiness without duplicate durable work.                            |
| R02 | Replicated ingress       | Remove one ingress process. The health-aware ingress address sends new visitors to a ready process, and routing-table revisions converge after restoration.                                                                         |
| R03 | Replicated relay service | Remove the connected relay process from a service that has another process. The publisher reconnects through the same stable relay address to a new connected relay process while placement remains on two distinct relay services. |

## Change-triggered checks

Review the candidate diff and mark each item pass or `not applicable` with the
reason. These checks supplement rather than replace the common suite.

- Schema or migration changes require migration rehearsal, backup restoration,
  fail-closed old/new schema checks, and the schema-changing rollback procedure.
- ACME, certificate, or DNS changes require fresh control, relay, and route
  issuance as applicable, renewal or persisted-order recovery, DNS cleanup, and
  exact-hostname verification.
- Authentication or authority changes require invitation, role change,
  membership removal, suspension, token replay, and current-authorization tests
  affected by the diff.
- Lease, placement, routing, drain, or stale-state changes require the relevant
  split and replica disruptions even if the normal staging topology would not
  exercise the changed behavior. Use an isolated split environment when needed.
- Tunnel, QUIC, TLS/TCP, forwarding, or stream-copy changes require a sustained
  soak with connection churn, concurrent streams, and file-descriptor and memory
  observation.
- Route-usage changes require rejection, retry, redelivery, revision ordering,
  and idempotency checks against a staging receiver.
- Packaging or launcher changes require fresh npm and pnpm installs, all public
  imports, framework fixtures, archive equality, executable permissions, legal
  files, and confirmation that no `tnld` executable is installed by npm.

## Cleanup gate

Before declaring qualification:

1. Stop every test publisher and local service.
2. Verify all ephemeral routes disappeared and delete only the dedicated durable
   route created by the suite.
3. Restore network policy, role counts, image digest, packet-I/O configuration,
   drain state, lease connectivity, and authentication settings.
4. Verify all applicable public and private readiness probes again.
5. Compare the final route inventory with the baseline and explain every
   remaining difference.
6. Revoke test sessions and remove temporary identities or memberships through
   their supported lifecycle when the scenario created them.
7. Preserve sanitized evidence and remove temporary probe binaries, processes,
   state directories, and configuration.

Cleanup failure makes qualification `blocked` until staging is restored.

## Qualification report

Use this structure:

```markdown
### Candidate

- RC tag:
- Commit:
- Client version:
- Image index digest:
- Runtime image digest:
- Deployment commit/release:
- Topology:
- Started/finished UTC:

### Results

| ID  | Status | Evidence | Notes |
| --- | ------ | -------- | ----- |
| C01 | pass   | ...      | ...   |

### Change-Triggered Results

| Area | Status | Evidence | Reason |
| ---- | ------ | -------- | ------ |

### Cleanup

- Final health:
- Route inventory:
- Restored configuration:
- Remaining differences:

### Decision

- qualified / not qualified
- blocking IDs:
- residual topology limitations:
```

Declare `qualified` only when every common check, every topology-applicable
split or replica check, every triggered check, and cleanup passed.

## Stable promotion handoff

Give the completed report to `tnl-release`. Before showing stable tag commands,
that skill must verify that the stable tag will point to the report's exact
commit and that no shipped source, generated output, packaging, configuration,
or documentation changed after the qualified RC.

After stable publication, verify the stable archives, signatures, provenance,
container, npm `latest` packages, public exports, and Homebrew formula. Install
the stable client and binaries and confirm their version and commit. These
post-publication checks verify stable packaging; they do not retroactively fix
an unqualified candidate.
