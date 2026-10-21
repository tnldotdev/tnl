# container targets

`publishertarget.Resolver` discovers a private target for a host-side publisher
without changing its saved public URL or publish run. it captures the current
container ID with its published loopback port. replacement invalidates an old
readiness observation, even if Docker reuses the same address.

```sh
mise exec -- go test -race ./internal/publishertarget ./internal/projectpublisher
mise exec -- task go:test:integration:compose
```

the opt-in Compose test starts disposable digest-pinned HTTP and Redis targets,
checks their actual loopback bindings, and replaces the HTTP container. public
URL forwarding from a manually run Docker publisher is covered by the Linux
binary integration tier.

## discovery boundary

- only a local Docker unix socket is accepted; remote contexts are rejected.
- Compose selection supplies an explicit project directory, file, project,
  service, and worktree label. one full running container ID must match those
  values. replicas and one-off containers are rejected.
- Docker selection accepts an exact container name or full ID, never an ID
  prefix. the container must be running with the current worktree label.
- selected ports must have one published loopback binding. no container's
  reported hostname, label prefix, or unrelated network selects the target.

`projectpublisher.TargetBinding` captures the address and immutable container
identity for each new request or connection. admission rechecks the current
capture; already admitted work retains its target and is not replayed.
