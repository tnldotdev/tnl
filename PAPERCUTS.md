# Papercuts

- Adding a project tunnel setting requires updating `internal/config/cmd/configgen/main.go` as well as `config.Tunnel`: the handwritten tunnel schema overrides reflected struct tags, so generation can silently omit a new field from JSON Schema and TypeScript declarations.
- The shared publisher smoke initially passed `t.TempDir()` directly to client state; Linux creates that directory with permissions broader than the required 0700. Passing a new child directory lets client state create it with its normal private permissions.
- `task lint` ran staticcheck while the JavaScript typecheck build removed `packages/tnl/dist`, causing Go's `./...` directory walk to fail intermittently. Root lint/test/build tasks now run their Go and JavaScript stages sequentially.
- The Linux race smoke exposed a runner polling race after the successful coordinator closed HTTP but before the race runtime exited. Polling external-fault requests only for an external-fault scenario avoids mistaking that shutdown interval for workload failure.
