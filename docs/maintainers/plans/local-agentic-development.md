# local agentic development

Audience: tnl maintainers. This is not user documentation.

Status: product problem statement and direction. Current capabilities below are
grounded in the implementation and tests; desired outcomes are not a description
of shipped behavior.

## north star

Every worktree gets stable, working HTTPS addresses automatically, and tnl knows
what is running across all of them.

After initial authentication and project setup, creating another worktree should
require zero additional networking configuration. Developers and local coding
agents should not assign ports, invent preview identifiers, maintain per-worktree
URLs, or reconcile process state by hand.

The normal entry point remains `tnl dev`. A developer runs the application, gets
its addresses, and works. An agent can discover those same addresses and their
state without scraping terminal output.

## problem

Local development increasingly means several versions of an application running
at once. A developer may review one change while multiple coding agents implement
others in separate Git worktrees. Browser agents exercise those applications, and
humans take over work without necessarily restarting its services.

This makes familiar development friction much more consequential:

- A preferred port belongs to another worktree.
- An agent starts a second copy of an already-running service.
- A browser opens the right-looking URL but sees the wrong worktree.
- A frontend calls the API belonging to another change.
- A service accepts TCP connections before it can answer HTTP requests.
- Restarting an agent loses the address or the knowledge of what it started.
- Nobody can tell which services are running, which are stale, and which are safe
  to stop.

tnl already provides much of the networking and framework integration needed to
solve this. The remaining problem is coordination: making startup, discovery,
readiness, inspection, and cleanup one dependable workflow across concurrent
worktrees.

**Serving the wrong worktree is a worse failure than failing to start.**

## primary user and scope

The primary user is a developer working locally, with agents acting on their
behalf. The first-class workflow is several local worktrees, each containing one
or more project services.

Use the existing project, project-service, worktree, client-state, and tunnel
model. A worktree can contain multiple projects; those projects must remain
distinct when grouping related work across checkouts. A branch name is useful
context, but is not a unique project or worktree identity.

Zero configuration means no repeated setup for each worktree or agent. Initial
authentication, framework integration, and project-specific service definitions
may still be necessary. Infer conventional setups where reliable, preserve
explicit project settings, and report ambiguity rather than silently starting
the wrong application.

The local experience should work with both a hosted and a self-hosted tnl server.
CI, remote coding agents, and PR integrations are subsequent uses of the same
capabilities, rather than prerequisites for local value.

## what already works

### framework listener discovery and port fallback

The Next.js and Vite integrations register the listener the framework actually
bound, rather than assuming its preferred port:

- Next.js uses its post-bind `__NEXT_PRIVATE_ORIGIN` and validates consistency
  with the reported `PORT`.
- Vite registers `httpServer.address()` after its `listen()` completes.
- Both have real framework tests showing that an occupied preferred port results
  in registration of the fallback listener.
- Explicitly forcing a port retains an exact-port contract. A different reported
  port produces a target-mismatch diagnostic.
- Loopback and wildcard listeners are supported without forcing a different
  framework host binding.

Automatic port fallback is therefore an existing capability to preserve and
integrate into the wider workflow. tnl does not need a competing port allocator
for these frameworks. Arbitrary commands with hard-coded ports do not gain the
same discovery guarantee automatically.

### host configuration, hmr, and service addresses

Next.js receives the assigned hostname in `allowedDevOrigins`; Vite receives it
in `allowedHosts`. Tests exercise host/origin restrictions, development assets,
and real HMR updates.

Generated `.tnl/project.json` and `.tnl/project.d.ts` already describe project
services. The integrations expose browser-safe, read-only runtime metadata:

```ts
import { tnl } from "@tnldotdev/tnl";

const apiURL = tnl?.services.api.url;
```

This is already a foundation for same-worktree service discovery. It is a
snapshot of addresses, not evidence that those services are running or healthy.
`runningUnderTnlDev` describes the integration context, not readiness.

The integrations preserve normal development without a tunnel, can inject
generated metadata without contacting tnl, and remain inactive during production
builds and Vite preview. Tunnel options belong in project configuration rather
than separate framework-plugin settings.

### independent processes and concurrent services

A framework does not have to be a child of `tnl dev`. With generated project
metadata, it can discover the matching private project-service socket when its
configuration loads. This supports starting tnl and the framework in separate
terminals, with tnl available before framework discovery.

Discovery happens at configuration load; the integration does not keep looking
for a socket afterward. This is not general late attachment to an arbitrary
already-running application. `tnl publish` can forward an existing target, but
cannot retroactively inject framework metadata.

Different services have separate sockets and locks and can run concurrently.
Duplicate `tnl dev` invocations for the same project service currently fail with
an already-running error.

### stable local naming and status

Default non-ephemeral hostnames use worktree labels, with a service prefix where
applicable. A label combines the worktree directory name with a hash of its
absolute root using private client-state salt. It is stable for the same root
and client state and distinguishes different worktrees. Changing commits or a
branch name alone does not change that input.

Durable routes already support reuse across publishing runs. Moving the
worktree or changing installations can change the generated hostname; portable
continuation is a separate gap.

`tnl status --all --output=json` already reports tunnels across local projects,
including project, service, process ID, URL, target, and lifecycle state where
available. Local heartbeats identify stale records. The opportunity is to extend
this inventory into a coordinated workflow, not introduce a second status store.

## desired experience and remaining gaps

### stable addresses without manual identity

Restarting an application, agent, terminal session, or machine should preserve
the address of the same project service. Adding another worktree should assign
different addresses automatically. Adding a service should not rename existing
services.

Developers should not configure a preview ID. Identity should remain separate
from a readable display name, branch, or agent-run label. Existing local naming
already meets much of the restart requirement; stronger continuity must build on
it without unexpectedly renaming existing routes.

The longer-term expectation is the same URL when work moves to another machine
under the same authorized ownership and domain. Recognize continuation
automatically when unambiguous. When two checkouts cannot be distinguished
reliably, an explicit resume action is preferable to guessing. Never silently
replace an active publisher or merge independent worktrees.

A stable URL is a durable address, not a promise that the application continues
running after the developer closes the laptop. Session cleanup and release of
the address are different operations.

### idempotent start, discovery, and stop

A human or agent requesting an already-running project service should discover
its current state and URL. Concurrent requests should converge on one intended
publisher and service instead of launching duplicates. Changed command, target,
or access settings must be surfaced rather than silently ignored or applied to
someone else's running process.

Support both lifecycle relationships:

- **Managed:** tnl starts the service and owns its shutdown.
- **Attached:** publication uses a separately managed service; stopping
  publication leaves that service running.

An agent ending its task should not accidentally terminate services still being
used by a human or another agent. Intentional stop and ownership transfer need
clear semantics. Stale status must not authorize killing a different process
that happens to reuse an old process ID or port.

Extend existing locks, registration, and process cleanup. The current private
development socket is an integration detail, not a supported agent API.

### readiness that browser agents can trust

Framework registration proves where the listener is; the current local target
check proves TCP reachability. Neither establishes application-level HTTP
readiness. Route readiness is another distinct fact.

Humans and agents need to distinguish:

- The process is starting.
- Its actual listener is known.
- The application is responding to HTTP.
- The public route can reach that application.
- A previously usable service has become unavailable.

Use framework signals and conservative HTTP checks by default. An application
that requires login, or an API with no handler at `/`, must not require a custom
health endpoint just to use tnl. Allow optional readiness settings for projects
with stricter requirements. Bound checks and avoid side-effecting probes.

Expose what was actually verified. An HTTP response is not proof that checkout,
login, or every dependency works. Browser assertions and business correctness
remain the responsibility of browser agents and application tests.

### one coherent multi-service project

Project configuration and runtime service URLs already exist, but development
commands select one service at a time. Multiple configured services currently
require an explicit selection.

The desired workflow starts or attaches to the intended set of services and
reports their collective state without per-worktree networking setup. A human
or browser agent can tell which service is blocking readiness and inspect it
individually.

Build on `tnl.services` so the frontend discovers the API for its own project and
worktree. Keep address snapshots consistent with effective service assignments,
and keep availability separate from address discovery. Never silently fall back
to another worktree's service because the intended one is stopped.

tnl owns publication, address discovery, and the associated lifecycle. Existing
package scripts and task runners can continue to manage complex build graphs,
databases, and dependencies. Arbitrary application URLs, CORS policy, and
third-party credentials cannot be safely rewritten by inference alone.

### an agent interface and a useful human inventory

Agents need structured development lifecycle information as well as the
existing JSON status snapshot. `tnl dev` currently emits human lifecycle output
while preserving child stdout and stderr.

Provide a versioned machine interface that leaves application output intact.
It should let an agent discover the correct project and service, wait for a
specific readiness condition, inspect a failure, and request an ownership-aware
stop. Preserve existing JSON and NDJSON contracts as this interface evolves.

Build on `tnl status` for a human view grouped by project, worktree, and service.
Show addresses, observed readiness, managed/attached ownership, and stale state.
Distinguish related worktrees from unrelated projects rather than treating every
local tunnel as one environment.

Keep operational metadata separate from browser-safe project metadata. Process
identifiers, local paths, agent attribution, and credentials do not belong in
the application's browser bundle.

## ownership, access, and handoff

### agents act on behalf of the developer

The team remains the ownership and authorization boundary. Personal work
defaults to the personal team; an organization project can select its team once
and inherit that choice in subsequent worktrees.

A local coding agent is a delegated process, not a new team member or account.
The developer remains the accountable identity. Optional task or agent-run
labels are attribution, not proof of authenticated identity.

Project-scoped capabilities may later narrow what an agent can manage, but
creating credentials manually must not become part of each local task. Keep
control credentials out of framework children and browser metadata. The current
integration boundary is not a sandbox against an agent with the developer's
full operating-system access.

### safe development first, easy sharing next

Retain the current-IP default for local development and the explicit public
opt-in. Network access policy is not application authentication, and a browser
on a different network may need additional access.

Secure, expiring review links should make later collaboration possible without
asking designers or customers for IP addresses or making them team members.
Review access should be changeable without restarting the application. Preserve
publisher-side route TLS termination when designing HTTP review access.

Guest review is a subsequent product capability, not a prerequisite for solving
local concurrent development.

### continuity before seamless cutover

Preserve the URL when an agent stops and a human or another agent resumes the
work. Brief interruption is acceptable initially; accidental takeover or a
different address is not.

Do not require overlapping route sessions or migration of live visitor
connections for the initial experience. A later seamless handoff must respect
route versions, explicit ownership, and the existing retry boundary.

## hosted and self-hosted scope

Local discovery, port fallback, stable local naming, lifecycle coordination,
service metadata, and machine-readable status should provide the same developer
experience against hosted and self-hosted servers.

A hosted provider can subsequently add account-backed cross-machine discovery,
review links, and remote-agent integrations. Those may require authority and
control API changes. Self-hosting continues to require its existing operator
setup; zero per-worktree configuration does not mean zero server infrastructure.

A GitHub App, CI workflow, remote dashboard, or new server-side preview object
must not be required to get the local benefit. External integrations should
consume supported lifecycle and status interfaces.

## observable success criteria

These are product acceptance scenarios, including existing behavior that must
continue to work:

1. **Concurrent worktrees:** several agents run the same integrated application
   in different worktrees without editing ports, hostnames, or networking config.
   Every URL reaches the intended worktree.
2. **Occupied preferred port:** Next.js or Vite chooses another port and tnl
   publishes that registered listener. An explicit forced-port mismatch remains
   an actionable failure.
3. **Repeated start:** two callers requesting the same running service discover
   one service and its URL rather than creating a second process or receiving
   only a lock error.
4. **Browser-agent handoff:** an agent obtains the URL and readiness observations
   through a machine interface, with no log scraping or fixed sleep. Application
   and tunnel failures are distinguishable.
5. **Multi-service isolation:** the frontend discovers its own worktree's API.
   Stopping that API shows it as unavailable rather than routing to another
   worktree.
6. **Restart and human handoff:** the application and publisher can stop and
   restart under the same ownership without changing URLs or requiring an agent
   account. Existing active publishers are not silently replaced.
7. **Managed versus attached cleanup:** stopping a managed service cleans up its
   owned processes; stopping publication for an attached service leaves the
   external process running. Neither affects another worktree.
8. **Crash recovery:** abandoned runs become visibly stale and can be recovered
   without deleting durable addresses or acting on unrelated processes.
9. **One local inventory:** the developer can inspect all relevant worktrees,
   their services, URLs, and observed state through human and machine interfaces.
10. **Portable continuation:** in a subsequent increment, an authorized move to
    another machine can retain the URL. Ambiguous continuation is explicit and
    does not claim another active environment.

## sequence and boundaries

First, complete the local coordination loop: idempotent startup, structured
development events, HTTP and route readiness observations, ownership-aware
cleanup, and a worktree-aware view built on local status. Preserve the existing
fallback-port, HMR, stable-naming, and metadata behavior.

Next, make multi-service coordination and same-worktree address consistency
routine, then add secure sharing and portable continuation. Consider narrower
agent capabilities as the lifecycle interface develops.

Remote workload federation, hosted dashboards, quotas, and seamless publisher
cutover follow demonstrated demand. They should not shape the first local
workflow around CI or force a new preview-management concept on developers.

This direction does not turn tnl into a general process orchestrator, browser
test runner, arbitrary network tunnel, or hosted application platform. Preserve
loopback HTTP targets, publisher-held route TLS keys, safe exposure defaults,
development-only framework behavior, and unchanged child output.

Exact command additions, persistent identity representation, lifecycle event
transport, and any new server records belong in a subsequent implementation
design. The product requirement is automatic, reliable coordination using the
smallest extension of the existing model.

## implementation evidence

- **Next.js listener, origins, runtime, and HMR:**
  [implementation](../../../packages/tnl/src/next.ts) and
  [tests](../../../packages/tnl/next.test.ts), including
  `registers the actual fallback port selected by Next.js`.
- **Vite listener, host filtering, runtime, and HMR:**
  [implementation](../../../packages/tnl/src/vite.ts) and
  [tests](../../../packages/tnl/vite.test.ts), including
  `registers the actual next port selected by Vite`.
- **Metadata and independent socket discovery:**
  [development integration](../../../packages/tnl/src/internal/dev.ts),
  [integration protocol tests](../../../packages/tnl/internal-dev.test.ts), and
  [browser runtime tests](../../../packages/tnl/runtime.test.ts).
- **Integration setup and current limits:**
  [package guide](https://md.cormo-turtle.ts.net/git/tnldotdev/tnl/packages/tnl/readme.md).
- **Duplicate services and exact target registration:**
  [bootstrap tests](../../../cmd/tnl/dev_bootstrap_test.go), particularly
  `TestDevBootstrapTimesOutAndClosesIdempotently` and
  `TestDevBootstrapReturnsTargetMismatchDiagnostic`.
- **Naming and service selection:**
  [worktree labels](../../../internal/projectconfig/worktree.go),
  [label tests](../../../internal/projectconfig/worktree_test.go), and
  [CLI configuration](../../../cmd/tnl/config.go).
- **Current development lifecycle and TCP startup checks:**
  [development command](../../../cmd/tnl/dev.go) and
  [local proxy](../../../internal/localproxy/proxy.go).
- **Existing machine-readable local inventory:**
  [status command](../../../cmd/tnl/status.go),
  [status tests](../../../cmd/tnl/status_test.go), and
  [local tunnel state](../../../internal/clientstate/tunnels.go).
