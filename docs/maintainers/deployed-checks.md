# deployed checks

use the smoke check to publish one test-owned HTTP public URL and verify a
visitor using a dedicated organization test team:

```console
mise exec -- task staging:check:smoke SERVER=https://control.example.test \
  TEAM=team_test TNL_BINARY=/absolute/path/to/tnl VERSION=v1.2.3 \
  REVISION=<deployed-commit> TOKEN_FILE=/absolute/path/to/private-token
```

the token file must be private (mode 0600). the binary must match the expected
version and revision. the selected identity must belong to the specified team;
the check will not fall back to a personal team. it uses isolated client state,
one ephemeral public URL at a time, and removes test-owned URLs after checking.

`staging:check:full` also exercises the CLI, both publisher transports, and
real PostgreSQL, MySQL, Redis, and SSH clients against disposable local
targets. it requires Docker. both tasks select the `deployed` test tier
explicitly; routine `go test`
skips these tests. neither task runs a benchmark. for release qualification,
see [release checks](release-checks.md).
