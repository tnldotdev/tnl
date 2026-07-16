# Papercuts

- `task go:test-integration` intermittently failed while starting `TestIntegrationRelayDrainPreservesActiveVisitorStream` because the certificate worker lost its ACME work lease; three immediate isolated race-detector reruns passed, suggesting a startup timing flake.
