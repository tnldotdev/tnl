# team and project move ledger

## team

`internal/client/team` now owns authenticated team sessions, membership selection,
ready-domain selection, namespace facts, and the domain-claim polling operation.
Commands still choose arguments, polling budgets, authentication prompts, browser
openers, and human/JSON presentation.

### implementation and api

| Original owner                                                                                                                 | Destination                       | Boundary                                                                                                                                        |
| ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `cmd/tnl/team_session.go` session construction, lifetime, and membership selectors                                             | `internal/client/team/session.go` | `Open(ctx, Options)`, `NewSession(database, store, authenticated, identity, Options)`, and `Session` accessors/selection methods                |
| Duplicate session and membership selectors in `internal/publisher/invocation/context.go`                                       | `internal/client/team/session.go` | One implementation of explicit, project, saved, configured-default, and personal-team selection                                                 |
| Domain readiness and namespace selection in `internal/publisher/invocation/selection.go`; domain lookup in `cmd/tnl/domain.go` | `internal/client/team/context.go` | `NewContext`, `Context.Team`, `Membership`, `Domains`, `Mode`, `Namespace`, `ReadyDomain`, `Domain`, `FindDomain`, and `ReadyDomainForHostname` |
| `cmd/tnl/domain.go` domain-claim wait loop                                                                                     | `internal/client/team/domain.go`  | `ClaimAndWaitForDomainRecords` accepts `DomainClaimAPI` and caller-selected `DomainClaimWait`                                                   |
| `internal/publisher/invocation/guest.go` signed-in-command guard                                                               | `internal/client/auth/guest.go`   | `clientauth.RequireSignInOutsideDemo`; credentials and refresh remain owned by client auth/state                                                |

`Options` carries `ServerURL`, `StateDir`, `AccessToken`, `ProjectTeam`,
`SelectedTeam`, `Diagnostics`, `AuthenticationPrompt`, `OpenURL`, and optional
`HTTPClient`. It does not depend on command flags. `Open` owns its database and
closes it on construction failures; `Session.Close` returns the database close
error. `NewSession` accepts already-loaded authentication and identity facts;
passing a nil database keeps its lifetime with the caller.

`Session` exposes `Database`, `Store`, `Authenticated`, `Identity`, `ProjectTeam`,
`SelectedTeam`, `InitialTeam`, `Current`, `CurrentWithDomains`,
`CurrentMembership`, and `ResolveMembership`. `Current` does not read domains.
One-command overrides do not write the saved team; default selection still writes
it and preserves state errors. Team IDs precede matching display names, ambiguous
name diagnostics retain membership order, and project-team failures retain the
override guidance. Authority/control clients and their page/cursor behavior are
unchanged.

`cmd/tnl/team_session.go` is now the flag and authentication-UI composition seam.
There is no command-private session/context alias. Publication inputs retain
`invocation.TeamSelection`; `FromTeamContext` and `TeamSelection.Context` convert
values at that boundary. `client/team` does not import publisher code.

### caller inventory

Production command callers use the shared session/context directly:

```text
cmd/tnl/admin.go
cmd/tnl/audit.go
cmd/tnl/auth_browser.go
cmd/tnl/bootstrap.go
cmd/tnl/connect.go
cmd/tnl/domain.go
cmd/tnl/feedback.go
cmd/tnl/group_identity.go
cmd/tnl/private_publisher_identity.go
cmd/tnl/publisher_group.go
cmd/tnl/publisher_group_rename.go
cmd/tnl/publisher_manage.go
cmd/tnl/publisher_namespace_rename.go
cmd/tnl/share.go
cmd/tnl/share_invite.go
cmd/tnl/share_service.go
cmd/tnl/status.go
cmd/tnl/team.go
cmd/tnl/team_feedback.go
cmd/tnl/team_session.go
cmd/tnl/url.go
cmd/tnl/url_access.go
cmd/tnl/url_available.go
cmd/tnl/url_visitor_selection.go
```

Publication consumers and their selection conversion boundary:

```text
internal/publisher/invocation/background.go
internal/publisher/invocation/context.go
internal/publisher/invocation/guest.go
internal/publisher/invocation/private_publication.go
internal/publisher/invocation/publication.go
internal/publisher/invocation/selection.go
internal/publisher/invocation/service.go
```

The project-resolve work independently adopts `team.Context` and `NewSession` in
`internal/client/project/resolve`, including `cmd/tnl/apply.go`; its implementation
and test moves are recorded by that owner.

Narrow command test callers now construct shared values or use session accessors:

```text
cmd/tnl/app_workflows_test.go
cmd/tnl/connect_native_workflow_integration_test.go
cmd/tnl/connect_reload_integration_test.go
cmd/tnl/connect_ssh_workflow_integration_test.go
cmd/tnl/domain_test.go
cmd/tnl/group_detached_workflow_integration_test.go
cmd/tnl/group_identity_workflow_integration_test.go
cmd/tnl/group_workflow_integration_test.go
cmd/tnl/named_workflow_integration_test.go
cmd/tnl/publish_install_integration_test.go
cmd/tnl/publisher_background_test.go
cmd/tnl/publisher_file_workflow_integration_test.go
cmd/tnl/publisher_groups_integration_test.go
cmd/tnl/share_service_test.go
cmd/tnl/share_test.go
```

### preserved and added coverage

| Original suite/assertion                                              | Destination/assertion                                                                                                                                                | Tier and invariant                                                                                                                                                                                                                                                       |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `cmd/tnl/team_session_test.go:TestTeamSelectionDoesNotRequireDomains` | `internal/client/team/session_test.go:TestTeamSelectionDoesNotRequireDomains`                                                                                        | Routine; stale saved selection repair, explicit selection over a stale project team, no implicit domain request, domain-service errors, unchanged saved selection, and missing/ambiguous diagnostic reasons                                                              |
| `cmd/tnl/team_session_test.go:TestConfiguredInitialTeamSelection`     | `internal/client/team/session_test.go:TestTeamConfiguredInitialSelection`                                                                                            | Routine; configured initial team and saved-selection precedence; renamed to remain in the requested focused selector                                                                                                                                                     |
| `cmd/tnl/domain_test.go:TestDomainClaimWaitsForRecordsOnly`           | `internal/client/team/domain_test.go:TestDomainClaimWaitsForRecordsOnly`                                                                                             | Routine; one claim, exact polling/read counts, immediate/delayed records, and failed responses                                                                                                                                                                           |
| `cmd/tnl/domain_test.go:TestDomainClaimWaitTimeoutAndReadErrors`      | `internal/client/team/domain_test.go:TestDomainClaimWaitTimeoutAndReadErrors`                                                                                        | Routine; timeout before/after reads, read errors, parent cancellation, and cancellation during a read                                                                                                                                                                    |
| Rendering assertions formerly mixed into the two domain-wait tests    | `cmd/tnl/domain_test.go:TestDomainClaimResultPresentation`, `TestDomainClaimTimeoutPresentation`                                                                     | Routine; DNS record/failed-state output and saved-claim timeout instructions remain at the command boundary                                                                                                                                                              |
| Existing domain presentation/status/required-record tests             | `cmd/tnl/domain_test.go`, retained names                                                                                                                             | Routine; claim/status actions, selected-domain lookup, server/team follow-up, and both required DNS records                                                                                                                                                              |
| New session boundary coverage                                         | `internal/client/team/session_test.go:TestTeamMembershipPriorityAndDiagnostics`, `TestTeamSessionOpenAndLifetime`, `TestTeamSessionRejectsGuestBeforeAuthentication` | Routine; ID/name and project/saved precedence, exact diagnostic content, unavailable-state errors, explicit authenticated HTTP requests, domain reads only on request, discovery-mode namespace facts, owned/borrowed close, and guest restriction before authentication |
| New shared-domain boundary coverage                                   | `internal/client/team/context_test.go:TestDomainSelectionKeepsReadinessAndHostnameBoundaries`                                                                        | Routine; readiness diagnostics, pending-domain status lookup, longest ready suffix, and DNS label boundaries                                                                                                                                                             |

No fixture or Task/shard changes are needed. Tests remain package-local and are
discovered by routine Go tests and the focused Task.

### validation

Executed on darwin in the uncommitted `0xcadams/role-organization` worktree:

```console
mise exec -- task go:test:focused PACKAGES='./internal/client/team ./cmd/tnl' RUN='Test(Team|Domain|Project.*Team|.*Membership)'
```

Result: passed once; `internal/client/team` completed in 1.980s and `cmd/tnl` in
1.775s. This compiled the narrow command callers and ran the requested routine
selector. No generation, global formatting, commits, or staging were performed
by this boundary work. Full-tree and opt-in integration qualification remain with
the parent; no unresolved team-boundary compile or focused-test failure remains.
