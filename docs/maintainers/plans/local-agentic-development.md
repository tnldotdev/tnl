# local agentic development

Audience: tnl maintainers. This is product direction, not a description of
shipped behavior. Current behavior is marked below.

## the goal

Run `tnl dev` in several Git worktrees and get distinct, stable HTTPS addresses
without assigning ports or preview IDs. A developer or local coding agent
should be able to find what is running, wait for it to work, and stop only what
it owns. **Serving the wrong worktree is worse than failing to start.**

The first step is local coordination. Hosted dashboards, CI, remote agents,
guest review, and cross-machine continuation can follow without becoming
prerequisites for local development.

## what works today

- Next.js and Vite register the listener they actually open, including port
  fallback. A forced-port mismatch remains an error. Node and Bun API servers
  can register their listener through the package integration. Other commands
  with hard-coded ports do not gain automatic fallback.
- Project metadata gives each service a browser-safe URL. It is an address
  snapshot, not proof that the application is ready. Framework integrations
  remain inactive during production builds and previews.
- A framework can discover its project-service socket when its configuration
  loads, even if it is not a `tnl dev` child. It does not keep polling for a
  socket or retroactively attach to an already-running arbitrary application.
- Different project services have separate sockets and locks. A second
  `tnl dev` for the same project service currently fails instead of returning
  the running service.
- Worktree labels keep default hostnames stable for the same path and client
  state. Moving the worktree or changing installations can change the name.
  `tnl status --all --output=json` reports local tunnels and stale records.

Build on those capabilities. Do not add another port allocator, status store,
or browser-visible operational metadata.

## close the local coordination loop

**Start and stop.** Repeated or concurrent requests for one project service
should discover the same running service and URL. Report changed commands,
targets, or access settings instead of silently accepting them. A managed
service is started and stopped by tnl; an attached local service remains
running when publication stops. Ownership-aware cleanup must not kill another
worktree's process or trust a stale process ID or port.

**Readiness.** Report distinct observations: process started, listener found,
local HTTP responding, and public URL serving. A TCP listener is not an HTTP
readiness check; an HTTP response is not proof that the whole application
works. Use bounded, conservative probes and allow stricter project settings
without requiring every app to expose a custom health endpoint.

**Discovery.** Provide versioned machine-readable lifecycle events without
mixing them into application output. An agent should find the correct project
and service, wait for a stated condition, inspect a failure, and request a
safe stop. Build the human inventory on `tnl status`, grouped by project,
worktree, and service. Keep process IDs, local paths, attribution, and tokens
out of browser-safe project metadata.

**Multiple services.** Start or attach the intended services together and
show which one blocks readiness. A frontend should discover its own worktree's
API through `tnl.services`; a stopped API must not silently fall back to a
different worktree. tnl owns publication and addresses, not an application's
build graph, database, or third-party credentials.

## keep identity and access clear

The project, project service, worktree, and team remain different identities.
Branch names and agent-run labels are useful context, not unique ownership.
An agent acts on behalf of the developer rather than joining the team as a
new identity. Keep the current-IP development default and explicit public
access opt-in. Network access policy is not application authentication.

A public URL is durable even when its tunnel stops. Later work can recognize
an authorized project on another machine and resume the address when the
match is unambiguous. Otherwise require an explicit choice. Do not replace
an active publisher, merge unrelated worktrees, or promise a seamless transfer
of live visitor connections.

Review links and narrower agent capabilities are later extensions. Preserve
publisher-side visitor TLS termination, credentials in the smallest role that
needs them, and the current private development socket as an implementation
detail rather than a public agent API.

## how to stage the work

1. Make repeated start, structured events, readiness observations,
   ownership-aware stop, and worktree-aware status one reliable local loop.
2. Coordinate multiple project services and keep same-worktree addresses
   consistent.
3. Add secure sharing and portable continuation after the local loop works.

The first stage is done when several worktrees can run concurrently without
editing ports or hostnames; a repeated start returns the running service;
an agent can wait for HTTP and public URL readiness without scraping logs;
and stopping one service never affects another worktree or an attached local
service. Existing port fallback, HMR, stable naming, JSON/NDJSON contracts,
and unchanged child output must continue to work.

Exact commands, local state representation, and event transport belong to an
implementation design. This direction does not turn tnl into a general
process orchestrator or browser test runner.
