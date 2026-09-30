---
name: tnl-release-check
description: Use when checking a published tnl release against staging, production, or a self-hosted server before or after deployment.
compatibility: opencode
---

# check a deployed release

Use the same `release:check:plan` and `release:check:run` tasks for every server.
They run a small functional check with the released `tnl` binary, not a load
benchmark. Follow [deployed release checks](../../../docs/maintainers/release-checks.md).

1. Confirm the signed release version and deployed image digest first. Obtain
   the exact control URL, dedicated team ID, ready claimed domain, private saved
   login directory, and released `tnl` binary. Do not use a personal team or
   default client state. Ask for missing fixtures rather than guessing them.
2. Preview the selected server and fixture:

   ```console
   mise exec -- task release:check:plan SERVER=<url> TEAM=<id> \
     STATE_DIR=<absolute-path> TNL_BINARY=<absolute-path> VERSION=<version> \
     CLAIMED_DOMAIN=<domain>
   ```

   Review the read-only target, then run `release:check:run` with the same
   values. A run creates at most three public URLs and four publish runs in the
   selected test team.

3. Require staging to pass before production promotion. Run the same scope on
   production after deployment. On failure, inspect only the dedicated team's
   release-check public URLs; never delete an unrelated URL or change domain
   delegation. Report both server results and the selected release version.

For self-hosted servers without a claimed domain, omit `CLAIMED_DOMAIN` and
report that shared custom URL coverage was omitted. Keep all release-signing
approvals in `tnl-release` and obtain separate approval for deployed benchmarks.
