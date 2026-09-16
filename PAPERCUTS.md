# Papercuts

- `task go:test-integration` intermittently failed while starting `TestIntegrationRelayDrainPreservesActiveVisitorStream` because the certificate worker lost its ACME work lease; three immediate isolated race-detector reruns passed, suggesting a startup timing flake.
- A rolling standalone deployment can delay the new ingress lease past its first usage tick; rejected idle watermarks must be regenerated or the process retries a pre-registration timestamp forever.
- The Linux binary split-publish check intermittently outlived QUIC's 30-second default idle timeout during certificate provisioning because publisher connections sent no keepalives, closing both sessions before readiness.
- An externally terminated `task go:test-integration-dns-linux` invocation left its disposable PostgreSQL container and network behind despite the shell cleanup trap; interrupted runs need an explicit Docker cleanup check.
- `TestControllerInstallsCertificateBeforeReady` observed the certificate callback before the controller recorded its validity, so the race suite could assert readiness before the controller goroutine completed the transition.
