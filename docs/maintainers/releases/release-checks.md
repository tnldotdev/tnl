# check a deployed release

After publishing a release, run the small functional check on staging before
production promotion and again on production after deployment. The test starts
a local HTTP service, publishes a generated ephemeral public URL, republishes
one saved URL with a higher publish run number, and visits a team-shared custom
hostname under an already-ready custom domain. It verifies public HTTPS and
the local service response; it does not create domains or run a load workload.

Use the verified `tnl` executable from the signed release. Run `tnl team list`
and `tnl team current` with an explicit `--server` and `--state-dir` to inspect
the saved login and record the original team ID. `tnl domain list` shows the
selected team's domains. If needed, use `tnl team create` to make a dedicated
test team; it selects that team in local client state. An existing saved login
may be used with a test team. Do not publish under a personal team. The full
check needs an admin or owner membership and a ready custom domain outside
the server's managed domain.

```console
SERVER=https://control.tnl.wtf TEAM=team_... STATE_DIR=/private/tnl-staging \
  TNL_BINARY=/private/releases/tnl VERSION=0.1.0-rc.36 \
  CUSTOM_DOMAIN=checks.example.com mise exec -- task release:check:plan
```

`plan` makes no server request. `run` is not read-only: it creates up to three
public URLs and four publish runs in the test team. Review the plan, then run
`release:check:run` with the same inputs. After deployment, use that server's
control URL and its own test team. If no custom domain is ready, omit
`CUSTOM_DOMAIN` and report that shared-hostname coverage was not exercised.

The runner stops each publisher to remove ephemeral public URLs and deletes
the saved public URL using its ID from `tnl status --output=json`. It reports
the URLs and any failures to stdout/stderr. If it is killed before graceful
cleanup, inspect `tnl url list` in the dedicated team and remove only the
test-owned hostname; do not guess an ID or change DNS delegation. Select the
original team again with `tnl team use <original-team-id>` after each run, even
on failure. CLI discovery may refresh the saved login and team selection;
do not describe those commands as read-only.
