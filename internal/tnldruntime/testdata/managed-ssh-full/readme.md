# full managed ssh proof

From the repository root, run:

```console
mise exec -- sh internal/tnldruntime/testdata/managed-ssh-full/run.sh
```

The runner builds the production Linux `tnl`, the runtime test binary, and the
pinned Pebble version. Docker Compose creates a private network, digest-pinned
disposable PostgreSQL, and a root Linux account fixture with
`no-new-privileges`. It removes the containers, database, network, and temporary
binaries when finished. It needs Docker Compose and the Go version in
`mise.toml`; it can run from macOS without changing host accounts or trust.

`TestIntegrationFullManagedSSH` reuses the separated runtime fixture: real
PostgreSQL-backed control, ingress, two relay services, and ACME TLS-ALPN
issuance through Pebble. Each transport (QUIC and TLS/TCP) runs the public
`tnl ssh USER@HOST` command, including system OpenSSH, the production hidden
TLS ProxyCommand, a saved login in isolated client state, and a control-issued
visitor certificate. Linux loads the private CA bundle through `SSL_CERT_FILE`.
Container-only hostname entries and byte-preserving loopback proxies expose the
fixture addresses; the public-port proxy supplies trusted PROXY v2 metadata.

The proof requires an explicit account grant even for the URL owner, checks the
production child’s uid, gid, supplementary groups, and home, and rejects a
different host-allowed account through real control authorization. It holds a
command and public `-L` forward open, revokes the grant through control, then
requires the CLI, user-owned command, and forwarded backend to close before the
last successful authorization deadline. A new command must also fail afterward.
The serving publisher remains root. Host installation and service-manager
behavior belong to the lower CLI installation tests.

For a parent Task runner supplying its own disposable Linux fixture, the test
binary accepts:

```console
/fixture/tnldruntime.test -test.run='^TestIntegrationFullManagedSSH$' \
  -test.v -test.timeout=5m -tnl-test-tier=integration \
  -tnl-test-postgres-url='postgres://postgres:fixture@postgres:5432/postgres?sslmode=disable' \
  -tnl-test-managed-ssh-root-user=tnl-ssh-test \
  -tnl-test-managed-ssh-other-user=tnl-ssh-other \
  -tnl-test-managed-ssh-binary=/fixture/tnl
```

The test requires `/run/tnl-managedssh-fixture`, real/effective uid zero,
`NoNewPrivs: 1`, two existing distinct nonroot accounts, Pebble on `PATH`, and
loopback TCP port 443. Without the tier and dependency flags, it skips.
