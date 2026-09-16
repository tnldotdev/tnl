# Papercuts

- `task go:test-integration` intermittently failed while starting `TestIntegrationRelayDrainPreservesActiveVisitorStream` because the certificate worker lost its ACME work lease; three immediate isolated race-detector reruns passed, suggesting a startup timing flake.
- A rolling standalone deployment can delay the new ingress lease past its first usage tick; rejected idle watermarks must be regenerated or the process retries a pre-registration timestamp forever.
- The Linux binary split-publish check intermittently outlived QUIC's 30-second default idle timeout during certificate provisioning because publisher connections sent no keepalives, closing both sessions before readiness.
- An externally terminated `task go:test-integration-dns-linux` invocation left its disposable PostgreSQL container and network behind despite the shell cleanup trap; interrupted runs need an explicit Docker cleanup check.
- `TestControllerInstallsCertificateBeforeReady` observed the certificate callback before the controller recorded its validity, so the race suite could assert readiness before the controller goroutine completed the transition.
- `flyctl` is configured in the `tnl.dev` mise environment but not `tnl`, so staging deploy commands launched from the product repository need the `tnl.dev` tool environment explicitly.
- A QUIC listener test closed the client before the server's `Accept` completed and could hang until the Go test timeout under race instrumentation; synchronize acceptance before closing either side.
- `task format-check` reports unchanged `cmd/tnlbench/plan.go` from `goimports -l`, so a clean wording-only change cannot pass the repository formatting check without touching unrelated benchmark code.
- A fresh Git worktree has no ignored `node_modules`, so `task generate` fails loading `json-schema-to-typescript` until the lockfile dependencies are installed in that worktree.
