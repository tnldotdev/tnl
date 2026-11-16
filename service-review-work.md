# work from the service review

This is what needs doing after the review. No code has changed for this
follow-up yet.

- [Review guide](https://md.cormo-turtle.ts.net/.worktree/tnl/public-url-guarantees-audit-9fb7a7c1/public-url-guarantees.md):
  what we decided, how the old and new systems differ, and the open choices.
- [Evidence](https://md.cormo-turtle.ts.net/.worktree/tnl/public-url-guarantees-audit-9fb7a7c1/public-url-guarantees-evidence.md):
  the original 422 checks and their code/test references.
- Updated November 16, 2026.

We settled **27 product entries; 82 remain open**. The broad test run finished
with **31 of 36 lanes passing and 26 distinct test cases failing**. Several
failures were in setup or cleanup, so that is not a count of production bugs.

## work list

All items are **not started**. Update their status as work lands and add the PR,
tested commit, commands, and results. A passing rerun alone does not explain a
previous failure.

| Item                                                      | Work                                                                                            | Depends on                                                |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| [W01](#w01-request-body-idle-timeout)                     | Add the request-body idle timeout and fix its enforcement                                       | W06 config rules                                          |
| [W02](#w02-configurable-control-outage-tolerance)         | Let existing traffic continue through a control outage for a configurable time                  | Find and align the deadlines along the traffic path       |
| [W03](#w03-one-bounded-shutdown-budget)                   | Make shutdown use one budget and return promptly                                                | Investigate the cleanup failures in W09                   |
| [W04](#w04-simple-synchronous-webhook-fanout)             | Keep webhook fanout simple and make failures clear                                              | Keep selected delivery for callbacks needing one response |
| [W05](#w05-feedback-sign-in-and-default-on-telemetry)     | Require feedback sign-in; default telemetry on with opt-out                                     | Check every client and SDK entry point                    |
| [W06](#w06-configuration-replacement-and-conflict-checks) | Replace configuration rather than merge it; reject stale edits                                  | Config/API/client changes                                 |
| [W07](#w07-reviewer-continuity-readiness-and-aliases)     | Keep reviewers working across restarts; recheck replacement apps; keep alias selection explicit | W02 outage rules; W05 feedback sign-in                    |
| [W08](#w08-other-fixes-and-open-questions)                | Fix the other bugs and explain the surprises we chose to keep                                   | Some rows still need a decision                           |
| [W09](#w09-failing-tests)                                 | Explain and fix each of the 26 failed cases                                                     | Original logs below                                       |
| [W10](#w10-docs-and-final-checks)                         | Update public docs, fill test gaps, and rerun checks on the final commit                        | W01–W09                                                   |

## w01: request-body idle timeout

Add `http.requestBodyIdleTimeout`, default `"30s"`. Reset it when more request
body bytes arrive. A progressing upload can take longer than 30 seconds. Once
the upload finishes, this timer must not limit the response or WebSocket.

The current code intends a 30-second total upload limit. It also accidentally
clears the deadline on first HTTP/1 admission. Fix both together.

**Where:** config and generated types; HTTP settings sent to the publisher;
`internal/transport/httpstream`; `internal/publisher/service`.
**Refs:** P33, C20, G054, G247.

**Done when:**

- [ ] Omission uses 30 seconds; overrides reach the real serving path.
- [ ] A stalled upload times out, including the first HTTP/1 request.
- [ ] A progressing upload runs longer than 30 seconds and succeeds.
- [ ] One timed-out HTTP/2 request does not cancel its siblings.
- [ ] Trailers, early responses, cancellation, and unread-body cleanup still work.
- [ ] Long responses and supported upgrades are unaffected after upload finishes.
- [ ] Generated config/types and public docs include the setting.

Work out how to handle a slow target that makes the publisher pause reads.
That must not be mistaken for the client stalling. Also settle validation for
zero, negative, and excessive durations. No extra total-upload-time setting.

## w02: configurable control-outage tolerance

Add one setting on control or standalone:

```yaml
version: 1
tnld:
  control_outage_tolerance: 5m
```

Also support `TNLD_CONTROL_OUTAGE_TOLERANCE=5m` and
`--control-outage-tolerance=5m`. Default to five minutes. Control sends the
deadlines to the other components; apps do not choose their own allowance.

Count from the **last successful confirmation**, not the first failed refresh.
Failures must not restart the clock. Earlier credential, certificate, service,
workload, or guest expiry still wins.

The tradeoff: existing traffic can survive a longer outage, but a revocation
that cannot reach the publisher can take the remaining allowance to take effect.
Five minutes is the product choice, not a benchmark result.

### what the code does now

| Dependency                       | Current timing                                                             |
| -------------------------------- | -------------------------------------------------------------------------- |
| Publisher's cached access policy | Expires after 10 seconds; refresh every 2 seconds                          |
| Ingress's cached routing data    | Expires after at most 10 seconds; refresh roughly every second             |
| Ingress and relay process leases | 30-second defaults; renew every 10 seconds                                 |
| Publisher run                    | Initial two minutes; heartbeat extends expiry to at least 45 seconds ahead |
| Ordinary visitor token           | Up to five minutes, but still needs current access policy                  |

So today a full control outage can stop traffic within the remaining part of
**roughly ten seconds**, including active requests. Raising only the token
lifetime or one heartbeat timeout will not fix that.

**Where:** daemon config; control state/APIs; ingress; relay; publisher policy
and service; connector code that uses the same deadlines.
**Refs:** P26, C04/C06/C26/C34, G044/G104/G138/G242.

**Done when:**

- [ ] Config file, flag, environment variable, default, and validation agree.
- [ ] List every deadline that can stop traffic and align the serving allowance.
- [ ] Keep frequent refresh and fast detection of dead connections. Do not make
      failure detection wait five minutes.
- [ ] Real traffic continues inside the chosen window during an outage, then
      stops at the applicable deadline. Test public and connector paths separately.
- [ ] Revocation takes effect when learned; earlier expiry always wins.
- [ ] Slow replies, retries, clock differences, and reconnects cannot extend
      expired permission or revive an old request.
- [ ] Recovery before expiry preserves working traffic; recovery after expiry
      requires fresh permission.
- [ ] Guest time limits and short workload/provider-proof expiries still apply.
- [ ] Small deterministic tests cover expiry; a real outage test checks the
      components together.

Still to settle: accepted duration range and how changing the setting affects
already-issued deadlines. Reducing it cannot notify an unreachable publisher.
New login, publication, or setup that needs control can still be unavailable.

## w03: one bounded shutdown budget

Use one overall budget, default 10 seconds:

1. Stop accepting new work.
2. Let existing requests finish within the remaining time.
3. At expiry, force-close owned connections and finish local cleanup.
4. Return a timeout if graceful shutdown failed. Say when remote cleanup could
   not be confirmed.

Do not give each phase a fresh budget or add a long remote-cleanup wait.
Second Ctrl-C forces CLI exit.

tnl's own workers must stop and be joined. An SDK cannot forcibly terminate
application handlers that ignore cancellation, so it must not wait forever for
them or claim they all returned.

**Where:** publisher/connector process owners, transport cleanup, installed jobs,
CLI signal handling, Go/TS/Python SDKs. Keep server-role drain settings distinct
where they serve a different purpose.
**Refs:** P39/P78/P79, C22–C25, G061/G228–G229/G257/G360/G366/G370/G389.

**Done when:**

- [ ] All phases use the original remaining budget.
- [ ] Closing I/O unblocks tnl's workers; none are left running after return.
- [ ] Graceful completion delivers the accepted response bytes and trailers.
- [ ] Forced closure and timeout are reported honestly.
- [ ] Unavailable remote cleanup does not hang shutdown or become false success.
- [ ] Independent operation and cleanup errors survive cancellation races.
- [ ] CLI interrupt escalation and SDK close have deterministic tests.

The current cleanup failures in W09 need diagnosis, not blanket suppression as
“expected cancellation.”

## w04: simple synchronous webhook fanout

Keep the current basic model. For each incoming request:

1. Check endpoint, method, and source before reading the body.
2. Find the eligible worktrees.
3. Attempt each once, even if another fails.
4. Return success only when all required recipients acknowledge.
5. Report failures by endpoint/worktree without logging request secrets.

Let the provider retry. A later attempt can repeat delivery to a worktree that
already succeeded; apps need duplicate protection. Some providers do not retry,
so this does not guarantee eventual delivery.

Keep selected delivery for verification challenges or callbacks that need one
app response. Keep the provider-specific defaults unless a concrete callback
needs correction. Do not arbitrarily pick between disagreeing responses.

**Where:** publisher integrations, local recipient selection, config, diagnostics,
and public integration docs.
**Refs:** P66–P68, C29, G095–G101/G295/G299/G309–G315/G321–G322.

**Done when:**

- [ ] All recipients are attempted despite sibling failures.
- [ ] Results and diagnostics match actual acknowledgments.
- [ ] No hidden delivery retry or transport body replay occurs.
- [ ] Selected delivery still handles response-dependent callbacks.
- [ ] Body/signature inputs, source checks, limits, and recipient replacement
      checks still work.
- [ ] Docs explain duplicate delivery and local-only worktree coordination.

**Not doing now:** SQLite outbox, background delivery, remembered successes
between requests, deduplication, or delivery backoff. Active provider-IP refresh
is the separate open choice P70.

## w05: feedback sign-in and default-on telemetry

**Feedback:** require sign-in to leave feedback. Anonymous feedback is deferred.
Keep preview access checks and verified authorship; signing in is not permission
to visit every preview.

**Telemetry:** MUST default on and MUST be opt-out. An explicit opt-out must
survive restart/install and must not be reset by another publication.

**Where:** control feedback state/API, browser/toolbar, CLI and SDKs, telemetry
preferences/outbox, installed jobs.
**Refs:** P52/P102, C03/C28/C30/C33, G085–G087/G282–G284/G355–G356/G384.

**Done when:**

- [ ] Browser, CLI, and API feedback submissions require authenticated identity
      and current access. Team-only restrictions are not weakened.
- [ ] Existing anonymous settings have a clear handling path; historical author
      records are left intact.
- [ ] Fresh state defaults telemetry on across CLI, SDK, framework, demo, and
      installed paths.
- [ ] Explicit opt-out persists, prevents new product events, and stays
      independent between publications.
- [ ] Existing field filtering and bounded delivery still work. Operational logs
      remain separate from product telemetry.
- [ ] Public docs and generated contracts match.

## w06: configuration replacement and conflict checks

Configuration edits replace the whole configuration. Omitted settings return
to defaults; do not merge old settings back in.

Separately, normal writes should reject stale edits. Replacing everything does
not mean silently overwriting a newer edit.

The current API distinguishes omitting the whole configuration from supplying
a replacement. Its conflict check is optional, and target trust revision does
not cover every policy change.

**Where:** config/project resolution, control config state/API, CLI/management
clients, generated models.
**Refs:** P09/P10, C10/C35, G008/G160/G324/G401–G402/G416–G417.

**Done when:**

- [ ] Config edits clearly mean replacement; metadata-only calls remain distinct.
- [ ] Omitted access/timeout settings use documented defaults.
- [ ] Normal writes check the current full-configuration fingerprint.
- [ ] Stale writes fail without partial changes; unconditional writes are explicit.
- [ ] CLI, APIs, generated types, and docs agree.

Still open: revision checks for DELETE and the live-edit rules in P08.

## w07: reviewer continuity, readiness, and aliases

Keep reviewers working across normal app restarts without reopening the share
or signing in again. Obtain current permission for the new run; do not reuse
expired permission.

Readiness remains a startup check, not continuous monitoring. A detected
replacement app gets a fresh check, even at the same address.

An alias shows its selected app or fails. A healthy different branch is not a
substitute. Alias access remains separate from the app's own share/access rules.

**Where:** publisher app/readiness/httpaccess, browser/share state, aliases.
**Refs:** P17/P18/P43/P45/P47/P60/P62; G068/G070/G078/G080–G081/G086/
G090–G091/G273/G278–G280/G284/G302–G304/G338–G339/G418.

**Done when:**

- [ ] A real signed-in reviewer visits, survives an ordinary restart, and leaves
      feedback without manual sign-in/share redemption.
- [ ] Expiry, revocation, and loss of the share creator's permission still deny
      access within the applicable outage bounds.
- [ ] Shares keep their captured service set. Live app changes are not described
      as frozen snapshots.
- [ ] Replacement triggers a fresh bounded check; an old result cannot mark the
      new app Ready. Checks stop after success.
- [ ] A stopped selected alias fails even when another branch works.
- [ ] Status/docs explain last successful check and independent alias access.

W05 supplies feedback sign-in; W02 supplies outage bounds. OAuth callback
restart behavior is different and is covered by W08.

## w08: other fixes and open questions

| Work                               | Done when                                                                                                                                                                                       | State / refs                                                 |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| Close retry after suspension       | A valid exact retry confirms an already-closed run without reopening it or touching its replacement. Wrong credentials still fail.                                                              | Fix; C24/G165. P13's broader suspension policy remains open. |
| Outage error responses             | Known temporary dependency failure returns 503; invalid credentials get the appropriate 401/403; unexpected faults remain 500. Test each rather than remapping every backend error.             | Decided; P26/C34/G138.                                       |
| OAuth final redirect               | Ordinary worktree callbacks check the exact initiating run, as aliases do. A replacement cannot receive the code. Preserve callback bytes and the app's own OAuth validation.                   | Decided; P64/C28/G093/G305–G308.                             |
| Guest time accounting              | Show/explain remaining versus already-issued/held allowance. Do not promise immediate stop-time refunds. Larger outage tolerance must not extend fixed guest expiry or permit overlapping runs. | Decided; P87/C06/C21/G107/G128.                              |
| Certificate polling before RetryAt | Settle whether RetryAt is a minimum or hint, then test/change the actual poll loop. Early polling is not proof of early CA issuance.                                                            | Needs decision; P96/C15/G190.                                |
| Other pending choices              | Review integration conversion, ingress startup waiting, eight-candidate search, IP-list size, active provider-IP refresh, retained certificate work, and expiring IP/name rules.                | P07/P16/P25/P36/P70/P97/P104–P105 remain open.               |

Keep a focused regression and results for each fix. The earlier cancellation-first
TLS fix remains withdrawn: it could hide an authority failure.

## w09: failing tests

Explain each F01–F26 below, then fix the cause. Separate fixture defects, setup
failures, cleanup reporting, timing, and production behavior.

**Where:** connector stream/recovery and fixtures; publisher invocation enrollment
fixtures; daemon runtime/cleanup tests.

**Done when:**

- [ ] Every F ID has a cause and links to the original failure.
- [ ] Focused reproduction uses the normal Task commands and existing bounds.
      Record intermittent non-reproduction rather than calling it fixed.
- [ ] Fixes retain the behavior being checked. Do not raise timeouts, drop cases,
      or hide independent cleanup errors to make the run pass.
- [ ] Focused checks pass, followed by the affected full lanes on the new commit.

## w10: docs and final checks

Update public docs in the companion repository under
`apps/accounts/src/content/docs/` as behavior lands.

Cover the new settings, full config replacement, shutdown budget, feedback
sign-in, opt-out telemetry, webhook retry duplication, and restart behavior.
Also explain the accepted surprises:

- Path mounts use the hosting hostname's visitor policy.
- A custom target CA adds to system roots; it is not pinning.
- Shares follow live services; aliases have independent access.
- Integration coordination is local to shared client state, not cross-machine.
- Stopping/removing an installed job does not revoke every credential copy.
- Guest allowance can include time already issued but not yet expired.
- Name/domain reuse can wait for DNS/certificate cleanup or expiry; member labels
  have no promised automatic reuse date.

**Refs:** P37/P38/P43/P62/P66/P77/P82/P87/P98/P106, plus W01–W09.

### tests still missing

| Test                                  | What it needs to exercise                                                                                                  | Refs / scope                     |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| Public Vite/Next hot reload           | Real framework edit and update through the actual public endpoint, not local sockets or fake Ready responses               | Required by P77                  |
| Two runs, held visitors, and audits   | Select both through the same ingress, hold real TLS traffic, reject overflow, finish both, correlate their audit histories | G039; pieces exist separately    |
| Replacement checks and browser review | Real readiness proof during replacement; sign-in/share/feedback/restart/creator-revocation flow                            | W05/W07                          |
| Competing transport claims            | Real QUIC/TCP candidates reaching the durable claim operation                                                              | G154                             |
| Certificate install retry             | First installation timestamp survives acknowledgment retry                                                                 | G183                             |
| Temporary-service DNS expiry          | Real managed expiry creates claimable DNS-removal work                                                                     | G200/C27                         |
| Certificate creation failures         | Actual creation with wrong/expired permission, maintenance rules, retries, and audit rollback                              | G207                             |
| Access update rollback                | Actual access change and policy invalidation roll back together                                                            | G271/C08                         |
| Ordinary-member publication           | Built CLI publishes its own app while broad inventory is denied                                                            | G357; P42 remains pending        |
| Public workload renewals/outage       | Original public stream survives permitted renewals/outage and stops at its earliest actual expiry                          | W02; broader P93 remains pending |
| Role/read-race/input limits           | Missing security-sensitive cases at their real owning operations                                                           | G415/G419/G420                   |
| Crash-time temporary URL continuity   | Real owner crash and restart, if we choose to promise the same temporary URL                                               | Conditional on P04               |

### final check list

- [ ] Close out W09 failures and run the affected full suites.
- [ ] Run normal format/lint/build/generation/Go/race/JS/Python/Action and
      integration Tasks on the changed commit. Generation checks rewrite generated
      files, so run them before freezing the source for the final sweep.
- [ ] Account for Linux-only tests, external tiers, build exclusions, and helpers.
- [ ] Run companion-repository checks against the matching native source.
- [ ] Check CI on the final commits.
- [ ] Keep matched performance comparison separate, or say it was not run.
      No throughput/latency/memory/recovery SLO was set in this review.
- [ ] Record commit, PR, commands, receipts, and every remaining failure/skip.

## round-7 test results

The run covered **November 16, 2026, 17:28:31–18:55:15 UTC**, about 87 minutes.
All 36 receipts report unchanged source at
`accc5407913e3a4ba8d5e009dc3c364d0c449481`.
The old comparison baseline is `9fb7a7c1fefcc81a71c9a01bf25243f161743c34`.

Receipt/log names below are relative to:

```text
/private/var/folders/2p/lmllwl2s77g7x1lc8w45_vp40000gn/T/opencode/
```

| File                                                    | Contents                 |
| ------------------------------------------------------- | ------------------------ |
| `service-publication-restoration-checks-7-results.json` | All lane results         |
| `service-publication-restoration-checks-7-source.json`  | Frozen file hashes       |
| `service-publication-restoration-checks-runner.py`      | Runner and lane commands |
| `service-publication-restoration-checks-<lane>-7.json`  | Individual receipt       |
| `service-publication-restoration-checks-<lane>-7.log`   | Individual output        |

These are local files. Attach relevant receipts/excerpts to the fix PRs so the
evidence does not depend on this machine's temporary directory.

| Result | Lanes                                                                                                                                                                    | Count |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----- |
| Passed | `format`, `lint`, `go-build`, `go-vulnerabilities`, `test-harness`, `generation-tooling`, `generation`, `javascript`, `python`, `connect-action`, `fuzz`                 | 11    |
| Passed | `state-1-of-4`, `state-2-of-4`, `state-3-of-4`, `state-4-of-4`, `api`                                                                                                    | 5     |
| Passed | `runtime-1-of-4`, `runtime-3-of-4`, `runtime-4-of-4`, `runtime-leases`, `runtime-workload`                                                                               | 5     |
| Passed | `connector-direct`, `connections`, `local-database`, `owner-lifecycle`, `tcp-clients`, `management-sdk`, `service-access`, `compose-targets`, `publisher-install`, `dns` | 10    |
| Failed | `go-routine`, `go-race`, `runtime-2-of-4`, `runtime-closure`, `connector-rebinding`                                                                                      | 5     |

Each failed Task returned 201. The logs show test/setup/cleanup failures, not a
build failure or panic. No race-detector warning was found in the failed logs.

## round-7 failure inventory

**26 distinct failed cases:** 22 in both routine and race runs, one additional
race-run case, and three integration cases. Parent failures are not counted
again.

### f01–f22: routine and race

Logs: `service-publication-restoration-checks-go-routine-7.log` and
`service-publication-restoration-checks-go-race-7.log`.
Commands: `mise exec -- task go:test` and
`mise exec -- task go:test:race`.

F01–F20 are in `internal/connector/stream`.

| ID  | Exact test/subtest                                                                            | Failure                                                                                                                                                          |
| --- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| F01 | `TestConnectorFixtureRebindCancellationOrigin/canceled_valid`                                 | `peer_fixture_test.go:401`: fixture returns unavailable/authority denial instead of the cancellation cause.                                                      |
| F02 | `TestConnectorFixtureRebindCancellationOrigin/deadline_valid`                                 | Same assertion for the deadline cause.                                                                                                                           |
| F03 | `TestConnectorFixtureRebindCancellationOrigin/owned_stop_valid`                               | Same assertion for the owner's stop cause.                                                                                                                       |
| F04 | `TestConnectorInitialActivationRetriesKeepOperationAndFreshHelloSeparate/quic/hello`          | `peer_initial_activation_test.go:15`: ends before readiness after lost hello reply; QUIC closed/unavailable. Cleanup at `connect_test.go:250` repeats the error. |
| F05 | `TestConnectorInitialActivationRetriesKeepOperationAndFreshHelloSeparate/quic/activation`     | Same startup failure after lost activation reply; cleanup also fails.                                                                                            |
| F06 | `TestConnectorLegHelloNormalEndRequiresPreCloseEvidence/already_ended`                        | `peer_pair_test.go:1110`: wrong retry decision after normal session end; alternate transport never connects.                                                     |
| F07 | `TestConnectorLegActivationNormalEndRequiresCompleteResult/already_ended`                     | `peer_pair_test.go:1152`: wrong decision after the activation session ends.                                                                                      |
| F08 | `TestConnectorReconnectRetainsOperationAcrossLostHelloAndActivationReplies/quic`              | `peer_reconnect_test.go:196`: uncertain replies strand the retained connection.                                                                                  |
| F09 | `TestConnectorRecoveryCancellationOrigin/stopped_local_guard/ready_recovery/canceled`         | `peer_recovery_retry_test.go:639,659`: replaces cancellation with unavailable and wrongly reports the local stop as an owner cleanup failure.                    |
| F10 | `TestConnectorRecoveryCancellationOrigin/stopped_local_guard/ready_recovery/deadline`         | Same two assertions; expected deadline exceeded.                                                                                                                 |
| F11 | `TestConnectorRecoveryCancellationOrigin/stopped_local_guard/ready_recovery/owned_cause`      | Same two assertions; expected the exact owner-stop cause.                                                                                                        |
| F12 | `TestConnectorRecoveryCancellationOrigin/stopped_local_guard/inspection_recovery/canceled`    | Same two assertions; expected cancellation.                                                                                                                      |
| F13 | `TestConnectorRecoveryCancellationOrigin/stopped_local_guard/inspection_recovery/deadline`    | Same two assertions; expected deadline exceeded.                                                                                                                 |
| F14 | `TestConnectorRecoveryCancellationOrigin/stopped_local_guard/inspection_recovery/owned_cause` | Same two assertions; expected the exact owner-stop cause.                                                                                                        |
| F15 | `TestConnectorRecoveryCancellationOrigin/stopped_local_guard/new_inspect_phase/canceled`      | Same two assertions; expected cancellation.                                                                                                                      |
| F16 | `TestConnectorRecoveryCancellationOrigin/stopped_local_guard/new_inspect_phase/deadline`      | Same two assertions; expected deadline exceeded.                                                                                                                 |
| F17 | `TestConnectorRecoveryCancellationOrigin/stopped_local_guard/new_inspect_phase/owned_cause`   | Same two assertions; expected the exact owner-stop cause.                                                                                                        |
| F18 | `TestConnectorRecoveryCancellationOrigin/stopped_local_guard/existing_phase_call/canceled`    | Same two assertions; expected cancellation.                                                                                                                      |
| F19 | `TestConnectorRecoveryCancellationOrigin/stopped_local_guard/existing_phase_call/deadline`    | Same two assertions; expected deadline exceeded.                                                                                                                 |
| F20 | `TestConnectorRecoveryCancellationOrigin/stopped_local_guard/existing_phase_call/owned_cause` | Same two assertions; expected the exact owner-stop cause.                                                                                                        |

F21–F22 are in `internal/publisher/invocation`.

| ID  | Exact test                                                   | Failure                                                                                   |
| --- | ------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| F21 | `TestForegroundEphemeralSelectionAllocatesFreshLifetimes`    | `identity_test.go:240`: “redemption changed its issued key or used management authority.” |
| F22 | `TestForegroundTemporarySelectionUsesTheRealMemberNamespace` | Same combined enrollment-redemption assertion.                                            |

That assertion checks the issued key and absence of management authorization.
The message does not say which condition failed; it is not enough to conclude
that a credential leaked.

### f23: additional race-run failure

| ID  | Exact test/subtest                                             | Failure                                                                                                                 |
| --- | -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| F23 | `TestConnectorRevokedSessionStopsOnlyItsActiveStreams/tls-tcp` | `internal/connector/stream`, `connect_test.go:250`: cleanup returns “service: authenticated connection is unavailable.” |

Log: `service-publication-restoration-checks-go-race-7.log:33–35`.
This is an assertion failure in the race-enabled run, not a reported data race.

### f24–f26: integration failures

All three are in `internal/daemon`.

| ID  | Exact test/subtest                                                                                       | Failure                                                                                                                                                                                   |
| --- | -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| F24 | `TestIntegrationStandalonePrivateTwoIngressTwoRelayLifecycle/tls-tcp`                                    | `runtime-2-of-4`, `runtime_harness_test.go:74`: publisher cleanup reports two deadline-exceeded errors.                                                                                   |
| F25 | `TestIntegrationWorkloadTransportClosure/tls-tcp/lease-expiry`                                           | `runtime-closure`, `workload_transport_integration_test.go:189`: HTTP 403 “workload session does not currently authorize this service” while opening paths, before checking expiry.       |
| F26 | `TestIntegrationConnectorRebindingRetainsApplicationAndTarget/standalone=true/tcp=false/both-connectors` | `connector-rebinding`, `connector_carrier_integration_test.go:356`: cleanup returns unavailable, repeated cancellation, and hello-response deadline errors. `tcp=false` is the QUIC case. |

- **F24:** QUIC sibling passed. This failure is in cleanup, not evidence that
  delivered requests failed.
- **F25:** parent cleanup also fails at
  `workload_transport_integration_test.go:485` for the PostgreSQL publisher:
  stream not bound to the current claimed connection, stale visitor policy,
  closed TCP connection, repeated TLS closeNotify errors, and cancellation.
  QUIC revocation/expiry and TLS/TCP revocation passed.
- **F26:** the binding-deadline dump at
  `connector_rebinding_integration_test.go:310` is a diagnostic, not another
  failed assertion. Retained PostgreSQL transaction siblings passed.

Commands:

```sh
mise exec -- task go:test:integration:runtime:shard SHARD=2/4
mise exec -- task go:test:integration:runtime:workload:closure
mise exec -- task go:test:integration:connector-rebinding
```

Logs:

- `service-publication-restoration-checks-runtime-2-of-4-7.log:225–237`
- `service-publication-restoration-checks-runtime-closure-7.log:53–81`
- `service-publication-restoration-checks-connector-rebinding-7.log:495–511,561–581`

## skipped tests and checks still to run

| Test / area                                                          | What is missing                                                                                                                                     |
| -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TestIntegrationConnectorDirectSourceRebinding`                      | Skipped in connector-direct and connector-rebinding: real multi-source loopback sockets require Linux.                                              |
| `TestIntegrationConnectorSourceRebindingRetainsApplicationAndTarget` | Skipped in connector-rebinding: requires the Linux fixture.                                                                                         |
| `TestIntegrationRoute53StagingACME`                                  | Skipped in API lane: requires the separate external Route 53 tier.                                                                                  |
| `TestIntegrationPublisherInstallIdentity`                            | Intentionally skipped helper. The real `TestIntegrationPublisherInstallLifecycle` passed, including Linux/container installation and reboot checks. |
| Other Linux workflows                                                | Account for separately selected CLI/identity/binary/sshd/deployment-database tests. Running some Linux containers does not cover them all.          |
| Browser/framework/package matrices                                   | Expanded matrices and public-endpoint HMR remain separate from the passing JavaScript lane.                                                         |
| Companion repository                                                 | Full matching checks for tnl.dev PR #327 remain pending.                                                                                            |
| Performance comparison / final CI                                    | Neither established by this local sweep. Check native PR #761 and companion PR #327 on their final commits.                                         |

Routine Go output is not verbose, and build tags can omit tests without a skip
line. This lists the skips seen in the logs and known remaining work, not every
test that did not execute.
