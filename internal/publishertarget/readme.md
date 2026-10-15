# container targets and compose owners

`publishertarget.Resolver` discovers a private target without changing its saved
public URL, registration, or publish run. host owners use a single local
published TCP binding. compose owners use one address on the host-selected,
worktree-labelled private network. discovery runs again for each capture.

```sh
mise exec -- go test -race ./internal/publishertarget ./internal/localpublisher ./internal/projectpublisher
mise exec -- go test ./internal/tnldruntime -run '^TestComposeIntegrationOwnerTargets$' -count=1 -timeout=5m -args -tnl-compose-integration
```

The Compose test creates and removes only randomly named test-owned projects,
networks, and volumes. Its images are digest-pinned. It runs real HTTP and Redis
targets, recreates a container, checks two real Git worktrees and scoped
app capabilities, and restarts the private owner. It does not exercise a public
URL or claim that a private-target probe proves public readiness.

## discovery boundary

- only a local Docker unix socket is accepted; remote contexts, including TCP
  loopback daemon endpoints, are rejected before container discovery.
- Compose selection supplies an explicit project directory, configuration file,
  project, and service. exactly one full running container ID must match all
  Compose labels and `tnl.worktree`. one-off containers and replicas are rejected.
- Docker selection accepts an exact name or full ID, never an ID prefix. the
  selected container must be running and have the current `tnl.worktree` label.
- host bindings must resolve to one loopback address and port. network targets
  must share the exact selected network ID with the current publisher container.
- app listeners supply only a port and HTTP scheme. only a configured app-to-
  Compose-service mapping determines the container; listener hostnames, process
  IDs, and application directories cannot select another container.

`projectpublisher.TargetBinding` captures address, immutable container identity,
and a local revision. a replacement that reuses the same address still invalidates
a readiness observation. call `Current` after a public check before accepting
its result. already-admitted streams retain their captured target.

## owner transport

The host installs placement metadata with `docker compose exec`, then uses an
exec-backed loopback bridge for the same owner's API. the owner credential stays
in the container. bridge app and invocation capabilities are scoped locally;
the exec helper obtains the matching capability inside the container on each
request. HTTP and TCP CLI leases use that same owner and manager.

The container uses `publishertarget.Socket` for Docker discovery, so its image
does not need a Docker CLI. the socket is an explicit publisher mount; apps have
only their own read-only descriptor volume and `TNL_APP_ENDPOINT`. the publisher
needs separate writable named volumes for its state and each app descriptor.
descriptor readers must be able to read the publisher-owned mode-0600 files.

`ComposeSetup.Validate` verifies host-selected identity, a non-published API
port, and exactly one worktree-labelled local bridge network. `ComposeBoundary`
checks the exact HTTP authority and current container-network membership before
the existing capability middleware runs. app descriptor rotation is atomic and
checks all volume consumers before writing any capability.

## parent integration points

The owned CLI files install `runtimeTargetResolver` and `runtimeOwnerTransport`.
The following small boundaries are outside this unit's file ownership:

1. Add `Project` and `File` to `config.AppPublisher` and expose the configured
   app-to-Compose-service mapping. install `runtimeComposeApps` to return
   `map[string]localpublisher.ComposeApp`, with each configured descriptor path
   and exact Compose service. empty app mappings are valid for database-only
   projects.
2. Dispatch hidden `runtime compose-proxy`, `runtime compose-request`, and
   `runtime compose-configure` to `runRuntimeComposeProxy`,
   `runRuntimeComposeRequest`, and `runRuntimeComposeConfigure`. the request and
   configure commands read stdin; request writes its JSON reply to stdout.
3. Add `runtime serve --compose`. call `runtimePrepareComposePlacement` before
   generating metadata or creating the manager; use its `Listen`, `Handler`,
   and `PublishApps` helpers. validate the configured port against the selected
   listener. keep Compose owners alive while idle and leave `Manager.Alive` nil:
   application and CLI process IDs belong to different PID namespaces. leases
   and owner IDs provide the fencing.
4. Install `runtimeRestoreHostWorktree`. the project-config implementation must
   restore `Worktree.primaryRoot` and `Worktree.labelParts` from the validated
   host worktree and primary-root metadata. copying only the public JSON fields
   loses the service-hostname label parts. do not recompute the label with container state.
5. In app preparation, select the capability's configured service using the
   owner's project directory, rather than resolving an app-container directory
   in the owner's filesystem. preserve the app's raw listener in registration
   lease comparisons; `runtimeTargetBinding` maps its port onto the configured
   Compose service for publication.
6. The publisher forwarding boundary needs a per-request/per-new-connection
   target callback. use `runtimeTargetBinding(...).Capture`; invalidate current
   readiness through its `Changed` callback. fresh public checks capture before
   probing and call `Current` before accepting observations. do not replace the
   registration or restart a publish run for a container address change.
7. SDK/private-protocol descriptor validation must accept the exact declared
   Compose app authority for a mounted app descriptor. host owner discovery
   stays numeric loopback; mounted descriptors remain app-scoped. the existing
   `privateprotocol.ValidateEndpoint` currently rejects all non-loopback URLs.
8. Add `go:test:integration:compose` with the opt-in test command above. the
   native owner/server integration should then exercise public readiness and
   saved URL/run preservation through the same callback boundary.

OAuth, webhook, and alias companions remain on the common owner's existing
integration lifecycle hook; these placement helpers do not create a separate
app-only manager or reject those integration declarations.
