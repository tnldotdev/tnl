---
name: tnl-release-check
description: Use when discovering test fixtures with the tnl CLI or running mutating release checks against staging, production, or a self-hosted server.
compatibility: opencode
---

# check a deployed release

Use the same `release:check:plan` and `release:check:run` tasks for every server.
They run a small functional check with the released `tnl` binary, not a load
benchmark. Follow [deployed release checks](../../../docs/maintainers/release-checks.md).

1. Confirm the signed release version and deployed image digest. Use that
   release's `tnl` binary with an explicit `--server` and `--state-dir`. Run
   `tnl team list` and `tnl team current` to find the saved login and record the
   original team ID. `tnl domain list` shows only the selected team's domains;
   select a different team with `tnl team use` if needed. Authentication may
   refresh local client state, so these CLI commands are not read-only.
2. Use a dedicated test team. If only a personal team exists, create an
   organization team with `tnl team create` and confirm its managed domain is
   ready before checking public URLs. An existing saved login may be used with
   that team; prefer a separate identity and state directory when available.
   Do not claim an unprovided domain or change DNS delegation. Without a ready
   claimed domain, run the managed-only checks and report that the shared custom
   URL was not tested.
3. Preview the selected server and fixture:

   ```console
   mise exec -- task release:check:plan SERVER=<url> TEAM=<id> \
     STATE_DIR=<absolute-path> TNL_BINARY=<absolute-path> VERSION=<version> \
     CLAIMED_DOMAIN=<domain>
   ```

   `release:check:plan` is read-only. `release:check:run` is **not**: it creates
   up to three public URLs and four publish runs in the test team. Review the
   plan before running with the same values.

4. After each run, select the test team if necessary and check `tnl url list`
   for leftovers. Delete only a test-owned public URL ID if cleanup failed.
   Restore the original team selection with `tnl team use <original-team-id>`
   for that server, including after a failed run.
5. Require staging to pass before production promotion and check production
   after deployment. Report the version, both results, and any omitted
   claimed-domain coverage. A managed-only run does not qualify shared custom
   public URLs.

Omit `CLAIMED_DOMAIN` for managed-only checks. Keep release-signing approvals
in `tnl-release` and obtain separate approval for deployed benchmarks.
