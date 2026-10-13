# check a deployed server

Run a small Go check after a staging deploy. The runner publishes from this
machine, visits the public URL through ingress and a relay, then removes the
test-owned public URLs. It checks the released `tnl` binary against the expected
version and commit before publishing. Use a dedicated organization test team
with a ready managed domain, an identity in that team, and a server-specific
login token. The server must have its public HTTP and TCP ports reachable from
the runner.

```console
SERVER=https://control.tnl.wtf TEAM=team_... TNL_BINARY=/private/releases/tnl \
  VERSION=0.1.0-rc.36 REVISION=<deployed-commit> \
  TOKEN_FILE=/private/tnl-staging-token mise exec -- task staging:check:smoke
```

The token file is read by the Go test; its contents are not passed on the
command line. Smoke checks an HTTP visitor and a small `tnl` CLI flow:
generated ephemeral URL, saved URL republish, hostname and publish run number.
The CLI check verifies that the service received its unique nonce and the
visitor's hostname. Pass `CUSTOM_DOMAIN=checks.example.com` to also visit a
team-shared ephemeral public URL on an already-ready custom domain; that check
requires an owner or administrator membership in the test team.

Run `task staging:check:full` with the same inputs for both QUIC and TLS/TCP
publisher connections and real PostgreSQL, MySQL, Redis, and SSH visitors. The
TCP checks start and remove their own digest-pinned disposable local servers
through `tools/testharness`; Docker must be available. This is a functional
check, not a benchmark. The server does not currently expose MongoDB public
URLs. Project readiness, IP policy, OAuth callbacks, and webhooks still rely on
local integration coverage; do not describe this deployed suite as covering
those boundaries yet.

The tasks run only when explicitly selected; routine `go test ./...` skips the
deployed tests. Use the same smoke task with a production control URL, binary,
revision, and dedicated production test team after promotion. The Task target
does not determine what revision the server deployed: compare the expected
revision with the deployment image digest and stop if the deploy changed while
the check was running. CI must enforce that comparison when deployment jobs
and this runner share a branch.

The runner uses private temporary state and unique hostnames. On failure it
stops any started publisher, lists the selected team's public URLs, and removes
only its recorded IDs or exact run-label hostnames. It reports unexpected
ephemeral leftovers as failures. If the process is killed before cleanup, list
the test team's URLs and remove only the URLs identified by the reported run
label; do not guess IDs or change DNS delegation.
