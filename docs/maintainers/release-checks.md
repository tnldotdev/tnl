# check a deployed release

After publishing a release, run the small functional check on staging before
production promotion and again on production after deployment. The test starts
a local HTTP service, publishes a generated ephemeral public URL, republishes
one saved URL with a higher publish run number, and visits a team-shared custom
hostname under an already-ready claimed domain. It verifies public HTTPS and
the local service response; it does not create domains or run a load workload.

Sign in to each server with a dedicated test identity and private client state
directory. That identity needs an admin or owner membership in a test team with
a ready claimed domain. Reuse that team and domain, not a personal team or a
domain overlapping the server's managed deployment domain. Use the verified
`tnl` executable extracted from the signed release archive.

```console
SERVER=https://control.tnl.wtf TEAM=team_... STATE_DIR=/private/tnl-staging \
  TNL_BINARY=/private/releases/tnl VERSION=0.1.0-rc.36 \
  CLAIMED_DOMAIN=checks.example.com mise exec -- task release:check:plan
```

`plan` makes no server request. With the same inputs, run
`release:check:run` after reviewing the target; use the matching production
identity and `https://control.tnl.dev` after promotion. A self-hosted server
can omit `CLAIMED_DOMAIN`, with shared-hostname coverage visibly omitted.

The runner stops each publisher to remove ephemeral public URLs and deletes
the saved public URL using its ID from `tnl status --output=json`. It reports
the URLs and any failures to stdout/stderr. If it is killed before graceful
cleanup, inspect `tnl url list` in the dedicated team and remove only the
test-owned hostname; do not guess an ID or change DNS delegation.
