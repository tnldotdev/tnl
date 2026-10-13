---
name: tnl-release-check
description: Use when discovering test fixtures with the tnl CLI or running mutating release checks against staging, production, or a self-hosted server.
compatibility: opencode
---

# check a deployed release

Use the Go `staging:check:smoke` task with an explicitly selected control URL,
dedicated test team, released `tnl` binary, expected version and commit, and a
private login-token file. See [deployed server checks](../../../docs/maintainers/release-checks.md).

1. Confirm the deployed image digest and source commit independently of the
   client binary. Use a test identity in a dedicated organization team, not a
   personal team. Check that the team's managed domain is ready; select a ready
   custom domain only if shared-hostname coverage is needed.
2. Run the smoke check with the selected deployment:

   ```console
   mise exec -- task staging:check:smoke SERVER=<control-url> TEAM=<team-id> \
     TNL_BINARY=<absolute-path> VERSION=<version> REVISION=<commit> \
     TOKEN_FILE=<absolute-path>
   ```

   The task creates public URLs and publish runs. Pass `CUSTOM_DOMAIN=<domain>` for shared URL
   coverage. Use `staging:check:full` for both transports and the four supported
   TCP protocols when Docker is available.

3. Confirm cleanup and inspect the dedicated team's URL list if a run was
   interrupted. Remove only run-owned URLs. Check production with its own
   server, team, token, and binary after promotion. Stop if the deployed
   revision changes during a check.

Obtain separate approval for deployed benchmarks; staging checks do not invoke
`tnlbench`. Keep release-signing approvals in `tnl-release`.
