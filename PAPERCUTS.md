# Papercuts

- `task go:test-integration` intermittently failed while starting `TestIntegrationRelayDrainPreservesActiveVisitorStream` because the certificate worker lost its ACME work lease; three immediate isolated race-detector reruns passed, suggesting a startup timing flake.
- A rolling standalone deployment can delay the new ingress lease past its first usage tick; rejected idle watermarks must be regenerated or the process retries a pre-registration timestamp forever.
