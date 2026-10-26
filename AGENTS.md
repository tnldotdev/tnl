# writing and documentation

Write for a developer trying to do something or understand a specific boundary.
Lead with the result, show a command or example when useful, then link to more
detail. The [readme](readme.md) is the model for public introductions.

Use everyday words unless a technical term makes an important distinction;
explain the term when the reader needs it. Name the component doing the work and
qualify claims:

- Write “Start your app normally to give it an HTTPS URL,” not “Leverage tnl’s
  seamless workflow to expose your application.”
- Write “Ingress may try another connected relay before sending the first visitor
  byte,” not “Traffic is intelligently rerouted.”
- Write “By default, visitors need a current sign-in, share link, or token,”
  not “Your app is completely private.”

Keep the voice lowercase, spare, concrete, practical, and understated. Avoid
hype and unnecessary jargon. Start public guides with what the reader can do;
in maintainer docs, explain the relevant boundary. In diagnostics, say what
failed and what to do next. Follow the CLI output rules below for presentation.

Use lowercase documentation filenames and headings. Write `url` in lowercase
in branded headings and page titles; use the canonical `public URL` in prose.
Write code-comment prose in lowercase too, preserving the exact case of
identifiers and literal values. Keep `AGENTS.md` and `SKILL.md` uppercase for
agent discovery.

Public product, client, and operator docs live in the sibling `../tnl.dev`
repository, under `apps/accounts/src/content/docs/`. The repository README and
npm package README link there. Keep contributor, maintainer, and benchmark docs
with this code. Update the relevant docs alongside behavior changes.

Write maintainer docs only for reasons, rules, or setup that are hard to find in
code or tests. Keep them short and plain, link to the source, and put work logs
and check results in the PR.

# canonical terms

Use these terms consistently in code, APIs, CLI help, and documentation. Write
the product and binaries as lowercase `tnl` and `tnld` in prose; preserve case
in identifiers such as `TNLD_*` environment variables. Do not introduce old
names such as _route_ for a saved public URL, _gateway_ for a relay, or _link_
for a publisher connection. Never introduce `Core` as a tnl architectural term;
name the specific role or API instead. Reserve `generation` for internal
mutation counters; public URL counters are publish run numbers.

## system and roles

| Term                   | Definition                                                                                                                                         |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **tnl server**         | The complete deployed system, including control, ingress, relays, and PostgreSQL.                                                                  |
| **`tnld` process**     | One running daemon process configured with a server role.                                                                                          |
| **control**            | A stateful `tnld` role that stores runtime state in PostgreSQL and manages placement, certificates, administration, and coordination.              |
| **control service**    | All interchangeable control processes sharing PostgreSQL.                                                                                          |
| **ingress**            | A stateless `tnld` role that accepts visitor connections, applies public URL policy, selects a connected relay, and forwards each connection once. |
| **ingress service**    | The replicated ingress processes behind one health-aware public address.                                                                           |
| **relay**              | A stateless `tnld` role that maintains publisher connections and carries visitor streams from ingress to publishers.                               |
| **relay service**      | Interchangeable relay processes behind one stable relay address and sharing one intended failure boundary.                                         |
| **relay process**      | One running `tnld` process configured with the relay role and belonging to a relay service.                                                        |
| **standalone**         | A `tnld` role that composes control, ingress, and two logical relay services in one process against PostgreSQL.                                    |
| **control API**        | The server HTTP API used by clients and administrators.                                                                                            |
| **authority API**      | The HTTP API that manages identities, teams, memberships, invitations, domains, authentication, and current authorization decisions.               |
| **built-in authority** | The authority API served by control or standalone for login, sessions, teams, memberships, invitations, and domains.                               |

## people and local processes

| Term              | Definition                                                                                  |
| ----------------- | ------------------------------------------------------------------------------------------- |
| **identity**      | A person or administrator known to one tnl server.                                          |
| **implementer**   | The person or AI coding agent working in the project directory.                             |
| **reviewer**      | A person using a share to visit a preview and optionally leave feedback.                    |
| **publisher**     | A native `tnl` process serving public URLs or services through assigned relays.             |
| **visitor**       | A browser or native client connecting to a public URL or service.                           |
| **local service** | An application listener reached by the publisher.                                           |
| **target**        | The destination the publisher dials, with protocol-specific target trust.                   |
| **tunnel**        | One registered app service's publication, or a `tnl publish` invocation, and its lifecycle. |

## projects and client state

| Term                        | Definition                                                                                                                  |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **project**                 | The directory selected from where the command runs, project configuration, and Git worktree.                                |
| **preview**                 | Control's saved group of public URLs for one project directory, reused across app restarts.                                 |
| **app registration**        | A bound listener reported by an SDK and kept current only while its application owner is running.                           |
| **local publisher process** | The native `tnl` process that owns publications for one canonical project, worktree, and client state directory.            |
| **project service**         | A named local service in project configuration, with optional settings that override project defaults.                      |
| **project configuration**   | The selected `tnl.yml`, `tnl.yaml`, `tnl.json`, or `tnl.config.ts` file and its validated settings.                         |
| **project metadata**        | Generated, browser-safe hostname and project-service information used by framework integrations during development.         |
| **client state**            | Local data saved by `tnl`, including sessions, certificates, project records, and locks.                                    |
| **local event cursor**      | A position in the app runtime's local event history; pass it to `tnl watch --after` to resume.                              |
| **worktree label**          | A DNS-safe label derived from the project, checkout directory, and client state for use in default public URL hostnames.    |
| **path mount**              | Serving one configured local service beneath a path on another service's public URL; the hostname's visitor policy applies. |

## services

Use **service** for a saved application service and **service run** for one active
publication of it. A **publisher group** assigns services to enrolled publisher
identities. Keep the group name, group ID, service name, service ID, and publisher
identity ID distinct. A **service endpoint** contains its visitor hostname, port,
and reachability; **service target TLS** describes publisher-to-target trust.
Reachability (public or connector-only) and visitor access rules are independent.
Services and public URLs have separate records, credentials, and lifecycles.

## addresses and dns

| Term                       | Definition                                                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **hostname**               | A complete DNS name exposed by tnl.                                                                                 |
| **control URL**            | The normalized HTTPS origin clients use to reach the control API.                                                   |
| **server domain**          | The infrastructure DNS suffix from which control, ingress, and relay hostnames are derived.                         |
| **control hostname**       | The public hostname clients use to reach the control API over HTTPS.                                                |
| **ingress address**        | The public, health-aware address that sends visitor connections to ingress processes.                               |
| **public URL DNS**         | DNS records that send public URL hostnames to the ingress address.                                                  |
| **relay address**          | The stable public hostname and port a publisher uses to establish a publisher connection through one relay service. |
| **internal relay address** | The internal hostname and port ingress uses to forward visitor connections to a relay.                              |

## public urls and publish runs

| Term                             | Definition                                                                                                  |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| **public URL**                   | The saved mapping from a public hostname to a target, policy, and state.                                    |
| **integration URL**              | A project-level public URL for OAuth callbacks or declared webhooks.                                        |
| **integration URL publisher**    | The elected publisher worker inside a running `tnl` process that serves one integration URL.                |
| **OAuth callback URL**           | The project's opt-in integration URL registered with OAuth providers for authorization-code callbacks.      |
| **webhook endpoint**             | A declared exact path, method set, and source policy on a project's webhook integration URL.                |
| **publish run**                  | One active publication of a public URL, including its number and publisher connections.                     |
| **publish run number**           | An ever-increasing number for one public URL; each new publish run receives the next number.                |
| **ephemeral public URL**         | A public URL removed after its tunnel stops instead of remaining available for a later publish run.         |
| **enabled**                      | A saved public URL that has not been suspended or deleted.                                                  |
| **routable**                     | A publish run with its certificate and enough ready publisher connections to receive visitors.              |
| **visitor TLS**                  | The visitor's TLS connection. It passes through ingress and relay and ends at the publisher.                |
| **public URL certificate**       | The publicly trusted certificate the publisher uses to terminate visitor TLS for a public URL hostname.     |
| **certificate plan**             | The hostnames, cache scope, and challenge method approved for a public URL certificate.                     |
| **certificate issuance**         | One attempt to obtain and install a public URL certificate for a publish run's certificate plan.            |
| **IP policy**                    | An optional filter on visitor source addresses, in addition to a public URL's access setting.               |
| **ingress routing table**        | Short-lived routing information control sends to ingress, including public URL policy and connected relays. |
| **policy revision**              | The authority policy version recorded when a public URL operation is authorized.                            |
| **public URL mutation revision** | An ever-increasing counter changed whenever editable public URL state changes.                              |

## preview sharing and feedback

| Term                       | Definition                                                                                                            |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| **share**                  | Expiring, revocable access to the public URL IDs captured from a preview when the share is created.                   |
| **share link**             | The URL containing the secret a reviewer uses to access the public URLs included in a share.                          |
| **team access grant**      | An opt-in setting on one preview that lets current team members sign in and visit its included public URLs.           |
| **browser access session** | Browser sign-in state used to issue and renew host-bound visitor tokens.                                              |
| **feedback thread**        | A durable conversation containing an immutable first report and ordered follow-up events.                             |
| **report**                 | The reviewer's immutable first submission in a feedback thread, including its submitted evidence and source state.    |
| **verified author**        | An account identity and name snapshot derived by control from an authenticated browser or CLI session.                |
| **evidence**               | Bounded, reviewed context submitted with a report, such as element HTML, actions, and failed requests.                |
| **pin**                    | A feedback thread's on-page reference to an element; if the element changes, the thread remains in the feedback list. |
| **feedback toolbar**       | The development-only browser interface for leaving and reading feedback.                                              |
| **source state**           | The recorded Git HEAD, project-relative path, and changed-file blob IDs; branch and staging do not affect matching.   |

Feedback is `open` until someone with preview access resolves it. They can
reopen it later; replies, updates, and status changes remain in its history.
Implementers and reviewers use the same feedback toolbar. Use **feedback list**,
not _inbox_, for the collection of threads.

## publisher connections

| Term                                | Definition                                                                                         |
| ----------------------------------- | -------------------------------------------------------------------------------------------------- |
| **publisher connection**            | A long-lived multiplexed connection from a publisher to a relay.                                   |
| **publisher connection ID**         | The unique identifier for one publisher connection from creation through close.                    |
| **connection slot**                 | One of the two publisher connections maintained by a publish run.                                  |
| **connection assignment**           | Control's instruction assigning a connection slot to a particular relay service and relay address. |
| **connection assignment revision**  | An ever-increasing number changed whenever control replaces the assignment for a connection slot.  |
| **assigned relay**                  | The relay service selected by control for a connection assignment.                                 |
| **connected relay**                 | The specific relay process that claimed and holds a publisher connection for a publish run.        |
| **ready publisher connection**      | An authenticated, current publisher connection that can carry visitor streams.                     |
| **publisher connection credential** | A secret that lets one publisher establish one assigned publisher connection.                      |
| **transport**                       | The mechanism carrying a publisher connection: QUIC or TLS/TCP with yamux.                         |
| **publish run token**               | A credential authorizing the publisher to update one publish run.                                  |
| **publisher identity**              | A native publisher's signed identity, independent of a person's control session.                   |
| **publisher grant**                 | Revocable permission for one saved public URL, service, or authorized public URL namespace.        |
| **publisher enrollment key**        | A one-use bootstrap secret for installing a publisher identity's signing key.                      |
| **publisher credential file**       | A private, portable JSON file containing one publisher identity's key and exact grant.             |

## visitor connections

A visitor token proves permission; it does not reserve stream capacity. SNI selects
a hostname; it does not identify or authorize a visitor.

Control owns visitor permission decisions. Serving processes verify signed
decisions against current local policy state; they do not duplicate control's
membership or grant rules.

| Term                        | Definition                                                                                                                                                                    |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **visitor connection**      | One public TCP connection from a visitor to a public URL hostname.                                                                                                            |
| **visitor connection ID**   | The unique identifier used to correlate one visitor connection across ingress, relay, and publisher.                                                                          |
| **visitor stream**          | One multiplexed stream that carries a visitor connection through a relay to the publisher and back.                                                                           |
| **visitor token**           | A control-signed credential authorizing a visitor to access one public URL or service; serving processes verify its scope, expiry, binding, and current policy state locally. |
| **stream reservation**      | One connection's held slot in a bounded control allocation, bound to its resource, run, visitor, and exact ingress process lease; it grants capacity, not visitor permission. |
| **visitor policy revision** | A resource's current visitor permission version; distinct from management policy, routing revisions, and run numbers.                                                         |
| **internal forwarding**     | Sending a visitor connection from ingress to a connected relay over an authenticated internal connection.                                                                     |
| **retry boundary**          | The first visitor byte sent to a relay. Ingress may try another relay before this point but never afterward.                                                                  |
| **PROXY v2 metadata**       | The original visitor source and destination information created once by ingress and preserved to the publisher.                                                               |

## process coordination

| Term                                | Definition                                                                                                             |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| **ingress lease**                   | Control's time-limited permission for an ingress process to serve visitor traffic and use the ingress routing table.   |
| **relay lease**                     | Control's time-limited permission for a relay process to accept connection assignments and publisher connections.      |
| **visitor policy lease**            | Control's time-limited confirmation of the policy and revocation state a process may use when checking visitor access. |
| **lease renewal**                   | A periodic request that extends control's confirmation of a process or its authorized local state.                     |
| **lease expiration**                | The deadline after which the lease no longer permits serving or trusting the state it covers.                          |
| **lease revision**                  | An ever-increasing number that distinguishes a current lease from an older lease for the same owner and scope.         |
| **process run ID**                  | A unique identifier generated each time an ingress or relay process starts.                                            |
| **stale-state checks**              | Checks that reject an old publish run, replaced connection assignment, expired lease, or restarted process.            |
| **placement**                       | Control's choice of different relay services for a publish run's connection slots.                                     |
| **draining**                        | A process state that rejects new work while allowing existing connections to finish until a deadline.                  |
| **connection capacity**             | The number of publisher connections a relay is configured to support.                                                  |
| **stream capacity**                 | The number of concurrent visitor streams a relay is configured to support.                                             |
| **recovery episode**                | The time from an unexpected publisher connection loss until a visitor again receives a publisher byte.                 |
| **public URL recovery observation** | Control's recorded measurement that closes one recovery episode.                                                       |

## internal security

| Term                            | Definition                                                                                                                   |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **cluster authentication**      | Authentication with a shared secret for private communication among control, ingress, and relays in one deployment.          |
| **cluster secret**              | The current secret configured as `TNLD_CLUSTER_SECRET`; split ingress and relay processes use it to authenticate to control. |
| **website credential**          | The secret the website sends to control for identity and invitation requests.                                                |
| **webhook credential**          | The separate secret control sends to a mailer for invitation emails.                                                         |
| **storage key**                 | The symmetric key available only to control and standalone for encrypting recoverable secrets in PostgreSQL.                 |
| **control session**             | A login session that can be revoked and has an access token and refresh token.                                               |
| **access token**                | A short-lived credential that authorizes control API and authority API requests for a control session.                       |
| **refresh token**               | A longer-lived credential used to rotate a control session's access and refresh tokens.                                      |
| **ingress identity**            | The configured ingress process identity bound to ingress leases and internal-forwarding sessions.                            |
| **relay identity**              | The configured relay process identity bound to relay leases and publisher connection claims.                                 |
| **relay transport certificate** | The exact-hostname WebPKI certificate shared by a relay service and managed by control.                                      |
| **relay transport TLS**         | Server-authenticated TLS on a relay address using the relay transport certificate.                                           |

## teams and domains

| Term                    | Definition                                                                                                      |
| ----------------------- | --------------------------------------------------------------------------------------------------------------- |
| **team**                | The stored ownership and authorization boundary for domains and public URLs.                                    |
| **team name**           | A stable, server-unique lowercase DNS label that selects a team in project configuration and the CLI.           |
| **personal team**       | The permanent, single-owner team created for each identity.                                                     |
| **organization team**   | A team created for collaboration among multiple identities.                                                     |
| **membership**          | The relationship between an identity and a team, including team role and immutable member slug.                 |
| **invitation**          | A time-limited offer to create a membership with a reserved member slug and initial team role.                  |
| **member slug**         | A team-unique, immutable DNS label chosen or derived when a membership is created and used with custom domains. |
| **managed label**       | A server-generated, immutable DNS label used with the managed domain.                                           |
| **namespace**           | A complete hostname built from a membership and domain.                                                         |
| **managed domain**      | A server-controlled domain beneath which namespaces are generated.                                              |
| **custom domain**       | A domain added by a team and assigned exclusively to it after DNS authority verification.                       |
| **team domain**         | A managed domain or custom domain available to one team.                                                        |
| **default domain**      | The ready team domain used when a command does not select another domain.                                       |
| **DNS authority**       | State control uses to manage public URL DNS beneath one custom domain.                                          |
| **shared public URL**   | A team-owned public URL outside individual namespaces.                                                          |
| **public URL scope**    | Whether a public URL belongs to one membership or to the team collectively.                                     |
| **maintenance control** | An administrator-controlled gate for public URL creation, publish run creation, or certificate issuance.        |

## machine field names

| Concept                         | Field                                                |
| ------------------------------- | ---------------------------------------------------- |
| Public URL ID                   | `public_url_id`                                      |
| Preview ID                      | `preview_id`                                         |
| Share ID                        | `share_id`                                           |
| Feedback ID                     | `feedback_id`                                        |
| Publish run ID                  | `publish_run_id`                                     |
| Publish run number              | `publish_run_number`                                 |
| Publish run token               | `publish_run_token`                                  |
| Service ID                      | `service_id`                                         |
| Service run ID                  | `service_run_id`                                     |
| Service run number              | `run_number` (`service_run_number` in mixed records) |
| Service run token               | `run_token`                                          |
| Policy revision                 | `policy_revision`                                    |
| Public URL mutation revision    | `public_url_mutation_revision`                       |
| Publisher connection ID         | `publisher_connection_id`                            |
| Connection slot                 | `connection_slot`                                    |
| Connection assignment revision  | `connection_assignment_revision`                     |
| Publisher connection credential | `publisher_connection_credential`                    |
| Visitor connection ID           | `visitor_connection_id`                              |
| Visitor token                   | `visitor_token`                                      |
| Stream reservation ID           | `reservation_id`                                     |
| Stream capacity allocation ID   | `allocation_id`                                      |
| Visitor policy revision         | `visitor_policy_revision`                            |
| Ingress identity                | `ingress_id`                                         |
| Ingress process run ID          | `ingress_run_id`                                     |
| Ingress lease revision          | `ingress_lease_revision`                             |
| Relay service identity          | `relay_service_id`                                   |
| Relay identity                  | `relay_id`                                           |
| Relay process run ID            | `relay_run_id`                                       |
| Relay lease revision            | `relay_lease_revision`                               |
| Lease expiration                | `lease_expires_at`                                   |
| Relay address                   | `relay_address`                                      |
| Internal relay address          | `internal_relay_address`                             |
| Ingress routing-table revision  | `routing_table_revision`                             |
| Recovery episode ID             | `recovery_episode_id`                                |
| DNS authority reference         | `dns_authority_reference`                            |
| Transport                       | `transport`                                          |
| Cluster secret                  | `cluster_secret`                                     |

# cli human output

In introductory diagrams and user-facing CLI output, label the local process
`tnl`. Use **publisher** when its architectural or protocol role matters; do
not rename machine fields such as `publisher_connection_id`.

Human-readable `tnl` output, including diagnostics, uses the shared ASCII
diagram renderer. The renderer and its tests define layout, width, wrapping,
escaping, and frame syntax. Command handlers provide semantic content only;
they must not construct borders, rails, padding, or connectors.

Frames follow this general form:

```text
+--[ <command> ]-- <state> -------------------------------+
|                                                         |
|  diagram or structured details                          |
|                                                         |
+-- <optional action, hint, or diagnostic code> -----------+
```

- Use short, lowercase, concrete states and ASCII-only frame syntax. Use `v` for healthy flow and `x` for the exact failure boundary.
- Keep human output deterministic and at most 72 columns. Do not truncate meaningful values or emit ANSI control sequences.
- Keep JSON and NDJSON contracts unchanged. `tnl version` and one-time credentials remain exact raw values; generated help remains unframed.
- Finite results go to stdout; prompts, lifecycle output, warnings, and errors go to stderr. Applications own their terminal output.
- Render errors once at the top level through the same renderer. Preserve stable diagnostic codes, help URLs, HTTP behavior, and HTML negotiation.
- `tnl publish` uses the tunnel presentation; app-led observations use `tnl status`, `tnl wait`, and `tnl watch`.
- Do not use the diagram renderer for `tnld`. Its commands retain exact raw values, silent successes, and compact one-line operational logs and errors.
- Never include secrets in diagrams or logs.

# codebase and contracts

`cmd/tnl` is the client CLI, `cmd/tnld` is the server process, and
`cmd/tnlbench` is the benchmark driver. Product releases contain `tnl` and
`tnld`. Follow [contributor architecture](docs/maintainers/architecture.md)
for runtime invariants, trust boundaries, and package/API ownership. Put
operational procedures and current capability limits in
[self-hosting](https://tnl.dev/docs/self-hosting).

- HTTP OpenAPI contracts under `api/{control,publisher,integrations}` generate one Go package per contract under the matching `pkg/api` serving-owner path. Edit their `paths/` and `schemas/` fragments and generator configuration, then regenerate. The local publisher contract is native app/CLI registration; the browser contract also generates validators in `internal/publisher/browserapi`. Reference control schemas for identical wire shapes. Shared components, if needed, contain only byte-identical referenced schemas and generate no Go package.
- `pkg/protocol/tunnelv1` is handwritten and is the sole tunnel protocol source of truth. Do not add standalone tunnel JSON Schemas or schema-parity tests; use golden JSON and framed-wire fixtures, invalid fixtures, bounds tests, fuzzing, and shared transport behavior tests.
- PostgreSQL sources are `internal/control/state/{migrations,queries,sqlc.yaml}`; their committed output is `internal/control/state/controlstatedb`. SQLite sources are `internal/client/state/{migrations,queries,sqlc.yaml}`; their output is `internal/client/state/clientstatedb`. Edit sources and generator configuration, not generated Go files. `task generate` orders Go API generation, browser validators, then the remaining Go directives; `task format` formats the resulting tree.
- `tnld migrate` is the only migration path and accepts only `TNLD_DATABASE_DIRECT_URL`. Serving control and standalone processes accept only pooled `TNLD_DATABASE_URL` and require the exact schema version and baseline identity. The new baseline requires a fresh PostgreSQL database and a coordinated stop/start of all server roles. Client state starts fresh in `v1.db`; do not import older SQLite or publisher credentials.

## place implementation with its owner

Start with an operation-focused file in the package that owns the behavior.
Create a package only for a concrete lifecycle or authority boundary with a useful
consumer. Explain its owner, allowed dependency direction, and why the existing
owner cannot be reused. File size or a new directory name is not an ownership
reason. Move supporting types, fixtures, assertions, and callers with the real
implementation.

| Tree                                                                | Responsibility                                                                                                                                                      |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cmd/{tnl,tnld,tnlbench}`                                           | Flags, process composition, and presentation; reusable operations live below commands                                                                               |
| `internal/publisher`                                                | Publication runtime; children own app state, local process/API, invocation operations, identity, groups, targets, and browser assets                                |
| `internal/connector`                                                | Visitor-side selection, native owner and connection operations; `stream`, `runtime`, `workload`, and `kubeconfig` own their narrower lifetimes                      |
| `internal/control`                                                  | Serving APIs, PostgreSQL state, authorization, certificates, DNS, OIDC, delivery, and maintenance                                                                   |
| `internal/{ingress,relay,daemon}`                                   | Visitor acceptance, publisher streams, and server process composition, respectively                                                                                 |
| `internal/client`                                                   | Shared auth/state/team selection, project evaluation/resolution/init/generation, and installed service jobs                                                         |
| `internal/config`                                                   | Static project configuration types, validation, and schema; `client/project` evaluates selected configuration, `daemon/config` resolves operational server settings |
| `internal/{transport,policy,security,naming,failure,observability}` | Focused mechanics and validated shared values; no command or daemon startup                                                                                         |
| `packages/{ts,py}`, `connect`                                       | SDK bindings and the independently built GitHub Action                                                                                                              |
| `tasks`, `scripts`, `development`, `deploy`, `tests/integration`    | Task implementations, owned tooling, contributor stack, deployment templates, and black-box suites/fixtures                                                         |

Commands compose operations, operations compose owned runtimes/state, and those
owners depend on focused shared leaves and public contracts. Directory nesting
does not make a parent a shared helper: a child must not import a parent
orchestrator for convenience. Put a validated value or consumer-owned interface
at the smallest boundary, or compose it above both users. For example,
`publisher/local` composes `app`, `localapi`, and `invocation`; `localapi` does not
call back into the process owner. Connector `stream` does not import connector
root operations. Control state never imports HTTP handlers; ingress and relay
never import control state.

Classify by lifecycle and authority, not executable: `tnl publish` is publisher
work, `tnl connect` is connector work, `tnl apply` sends a control mutation, and
`tnld` composes server roles. A single native process may compose both publisher
and connector without merging their capabilities. The public SDK exposes a
prepared publisher identity without its internal control client or signing key.

Use these practical boundaries when placing a change:

| Change                                 | Owner and boundary                                                                                                                                                                               |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Replace an app registration            | `internal/publisher/app` cancels and joins the old publication before replacement; `publisher/local` composes the process and API                                                                |
| Renew a native connection owner        | `internal/connector/runtime` owns the renewal loop and fixed-expiry fence; connector operations provide the backend and join its work                                                            |
| Authorize certificate issuance         | `internal/control/state` checks the current run, publisher grant, and certificate plan; certificate workers execute approved work                                                                |
| Retry a visitor connection             | `internal/ingress` chooses another eligible relay only before sending the first visitor byte                                                                                                     |
| Claim a publisher connection           | `internal/relay` owns local reservation, current lease/claim validation, connected-session lifetime, and release; control state authorizes the durable claim                                     |
| Change multiplexed stream mechanics    | `internal/transport/muxsession` owns QUIC/yamux mechanics without placement or visitor policy                                                                                                    |
| Persist protected certificate material | `internal/client/state` owns keys, pending CSRs, locks, and atomic persistence; publisher TLS files use the private identity directory, while service-client keys use the local secret protector |
| Change project configuration syntax    | `internal/config` owns types and validation; `client/project` evaluates the selected source and `client/project/resolve` combines it with selected state/server/team facts                       |
| Change CLI framing                     | `internal/clioutput` owns frame syntax, wrapping, width, and escaping; commands supply semantic facts                                                                                            |

Shared client operations are implemented, not command-private helpers:
`client/team` owns session/team/domain selection, `client/project/resolve` owns
declarations and browser-safe metadata resolution, `client/project/init` owns
planning/install/edit sequencing, and `client/project/meta` owns portable artifact
generation. Commands supply arguments, prompts, browser opening, and presentation.
Process owners such as `publisher/local`, connector owner operations, and
`daemon` own startup, supervision, bounded drain, cancellation, and joins. A
presentation callback does not transfer that lifetime to a command.

Keep one authority for each wire shape and validated domain value. Reuse the
defining source or a genuinely identical shared wire schema; do not copy models,
policy checks, or lifecycle engines to avoid an import. Move the implementation
and its support together instead of leaving forwarding facades. Before combining
or retiring suites, preserve every unique assertion at the lowest sufficient
owner and retain its Task selector, tier, fixtures, and execution evidence.

# development workflow

When adding or changing errors, follow [failure boundaries](docs/maintainers/development/errors.md).

- Open a PR for every change.
- Use semantic `type: summary` messages for every commit in a PR and for the PR title, such as `feat: ...`, `fix: ...`, `docs: ...`, `refactor: ...`, or `chore: ...`.
- Use the versions in `mise.toml`. Bootstrap with `mise trust`, `mise install`, then `mise exec -- pnpm install --frozen-lockfile` and `mise exec -- uv sync --frozen --project packages/py`; run repository commands from the root through `mise exec --`.
- Follow [contributing.md](contributing.md) for the validation sequence, generated-source ownership, local stack, and test-tier prerequisites.
- `task generate-check` regenerates files before comparing generated paths to `HEAD`; it is not read-only. `task format-check` is read-only.
- Task targets are the public test interface; use `go:test:integration:*` and `go:test:load:*`, and have CI call the same targets.
- Use `-tnl-*` flags for Go test selection and inputs. Never introduce `TNL_TEST_*` environment variables.
- Keep routine tests safe by default; opt-in tests must explicitly require their test tier.
- PostgreSQL-backed targets must create, use, and remove digest-pinned disposable PostgreSQL themselves.
- Use environment variables only for Task/Compose orchestration and resource limits; pass test-binary settings as flags.
- Package `test` and `typecheck` scripts build explicitly; `*:run` variants reuse an existing build.
- Author Node tooling and npm runtime code in TypeScript. Keep strict compiler and lint checks enabled; validate external data before narrowing it. The embedded project-config loader JavaScript is generated from `internal/client/project/loader.ts`. See the source/generator/output table in [contributing](contributing.md#edit-generated-sources); disposable SDK `dist` output is separate from committed generated source.
- Author the Python ASGI binding in `packages/py`, use the committed `uv.lock`, and run its Ruff, mypy, and pytest Task targets. Keep the app-owned native socket protocol shared with TypeScript and avoid storing ad-hoc credentials in snapshots or errors.

# tests and benchmarks

- Routine tests cover deterministic invariants without external infrastructure.
- Integration tests use the smallest real setup needed to verify a boundary.
- Runtime tests use one separated local topology and default to small smoke workloads.
- Large load and fault sweeps and deployed benchmarks are explicit opt-in runs.
- Local and deployed benchmarks share publisher, visitor, and measurement implementations.
- Add coverage at the lowest sufficient layer; migrate unique assertions before retiring overlapping tests.
- Colocate Go unit and white-box integration tests with their implementation, including daemon composition proofs. Put built-CLI black-box suites in `tests/integration/<boundary>` and shared subprocess/Compose assets in `tests/integration/fixtures`. Keep package-local `testdata` with its owner and shared helpers in test-only `internal/testutil` children. SDK suites and fixtures live under `packages/ts/test`; Python remains under `packages/py`.

# operational safety and releases

- The local stack order is `task local:up`, `task local:trust`, then `task local:login`. `local:trust` modifies the macOS login keychain; `local:down` preserves state, while `local:reset` removes trust, containers, volumes, and `.local`.
- When AWS SSO expires, prefer `mise exec -- aws sso login --profile <profile> --no-browser --use-device-code`. If terminal output is buffered while the command polls, run it in the background with a private temporary log outside the repo and promptly give the user the prefilled `.../#/device?user_code=...` URL printed by AWS CLI. After approval, verify with `mise exec -- aws sts get-caller-identity --profile <profile>`; do not store the code in the repo or bypass authentication.
- Never execute a deployed benchmark without explicit approval for its server and workload. Planning is read-only, but execution requires an explicit control URL, `BENCH_SUITE`, and `BENCH_APPROVED=1` and creates public URLs on the selected server. Explicit continuing approval covers retries of the same plan during one debugging session; ask again if the server, suite, or workload overrides change.
- For release/version/tag work, load and follow `.agents/skills/tnl-release/SKILL.md`; do not duplicate or improvise its approval gates.
- Keep GitHub Actions SHA-pinned with explicit permissions, timeouts, and `persist-credentials: false`; retain `actionlint` and `zizmor` checks.
- CI publishes release artifacts and images but does not deploy production. Production Compose images must remain digest-pinned.
- Release archives, native npm packages, and platform Python wheels must retain all required dependency license and legal files; see [contributing.md](contributing.md).
