# publisher targets

this package resolves the address a publisher dials. for a host-side Docker or
Compose target, it also captures the container's full ID. if Docker replaces a
container but reuses its port, the new ID invalidates the old readiness result.
existing streams keep their captured target; new requests use a fresh capture.

start with [targets.go](targets.go) for `TargetSnapshot` and `TargetBinding`, or
[binding.go](binding.go) for app-reported listeners.

## container lookup

[resolve.go](resolve.go) and [docker.go](docker.go) require:

- a local Docker Unix socket.
- one running container with the current `tnl.worktree` label. Docker names or
  full IDs must match exactly; Compose also checks the selected directory, file,
  project, and service, and rejects replicas and one-off containers.
- one unambiguous published TCP address. loopback bindings work directly;
  wildcard bindings are dialed through loopback.

with Docker and Compose available, run the disposable HTTP/TCP target check from
the repository root. it also replaces a container to check readiness invalidation:

```sh
mise exec -- task go:test:integration:compose
```
