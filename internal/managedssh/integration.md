# managed ssh publisher integration

`managedssh.New` builds a root-service SSH runtime for one job. `ServeConn`
owns an already authenticated visitor connection and joins its sessions and
forwarding children before returning. It does not listen on a public socket or
perform visitor TLS itself.

```go
server, err := managedssh.New(managedssh.Config{
    HostKey: signer,
    Users: job.SSHUsers,
    Authorize: authorizeSSHUser,
})
// handle err before accepting visitors.
err = server.ServeConn(ctx, securedVisitor, managedssh.Identity{
    IdentityID: authenticatedIdentityID,
    PublicURLID: job.PublicURLID,
})
```

## caller boundary

The publisher must finish visitor mTLS and obtain a current control decision
before constructing `Identity`. An SSH username never establishes an identity.
The `Authorize` callback receives that trusted identity, the exact SSH username,
and a context derived from the `ServeConn` context. The caller can carry its
validated certificate and publish-run authorization scope in that context.
The callback must honor context cancellation. Wrap an explicit denial with
`livevisitor.ErrDenied`; other errors retain their transient meaning.

Return a `Decision` with matching `IdentityID`, `PublicURLID`, and `SSHUser`,
and a future `ValidUntil`. The host job allowlist and the current named,
non-root host account are checked independently before every callback. The
runtime uses SSH's `none` authentication method inside
the authenticated TLS connection; passwords and SSH user keys do not grant
access. It refreshes successful decisions every 30 seconds by default, sooner
for a short decision. Explicit denial, removal of the host account, or expiry
closes the connection. A transient failure retains existing work only until
the last successful deadline, bounded to two minutes. While a decision is
unknown or refreshing, new channels and new session commands are rejected.
Cancellation closes the visitor connection and joins child work.

Only session channels and `direct-tcpip` channels are accepted. The latter
covers OpenSSH local (`-L`) and dynamic (`-D`) forwarding. Its destination is
dialed in a separate dropped-user child. Reverse, agent, Unix-socket, and X11
forwarding are rejected. Client environment requests are rejected. PTY sizes
and terminal modes, shell requests, raw command strings, RFC 4254 signals,
and the `sftp` subsystem are supported. Terminal modes are installed before
the shell starts. Signals are delivered by the dropped-user child, and a
signal termination is reported with SSH's `exit-signal` request. The default
active channel limit is 32; configuration may select at most 256.

## installed child dispatch

Dispatch the hidden `runtime ssh-child` command directly to
`managedssh.RunChild(ctx)` before opening client state, starting services, or
initializing normal CLI output. Its stdout is session or SFTP data, and its
private status channel is fd 4. Return success when `RunChild` succeeds; the
session's exit code is already carried separately on fd 4. A different hidden
command can be selected through `Runner.Args`.

`GenerateHostKey` returns an ed25519 private PEM and its authorized-key public
line. `ParseHostKey` reads the private PEM. Keep the private value in
`Job.SSHHostKey`; bind only the public key to the saved public URL.

## publisher job boundary

`publisherjob.publicationConfig` binds the protected host key to the saved
URL's registered public key and builds `publisher.SSHConfig`. The publisher
requires current certificate authorization before passing the TLS connection
to this runtime. An SSH job has no target or target TLS options. `Job` JSON includes
the private key for the existing encrypted whole-job snapshot, so CLI and API
adapters must continue selecting approved fields rather than serializing jobs.

Publisher mTLS dispatch and the control-client adapter live in
`internal/publisher/managed_ssh.go`; the CLI owns hidden child dispatch. Routine tests
inject a same-uid child privately. The opt-in disposable Linux test exercises
the production child entry point, real root-to-user credential changes,
and the root serving process's unchanged credentials.
See [the child boundary](runtime.md) for account, descriptor, environment, and
process-group behavior, including the direct-setuid/PAM distinction.

## isolated root verification

Compile the package's Linux test binary outside the checkout, then build the
account fixture from its digest-pinned project base image. Set `GOARCH` to the
Docker host's architecture, and use an absolute path for the mounted binary:

```sh
mise exec -- env GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c \
  -o "$TMPDIR/managedssh-root.test" ./internal/managedssh
mise exec -- docker build -f internal/managedssh/testdata/root.Dockerfile \
  -t tnl-managedssh-root-test internal/managedssh/testdata
image=$(mise exec -- docker image inspect tnl-managedssh-root-test --format '{{.Id}}')
mise exec -- docker run --rm --network none --security-opt=no-new-privileges \
  --pids-limit=128 --memory=512m \
  --mount "type=bind,source=$TMPDIR/managedssh-root.test,target=/managedssh.test,readonly" \
  "$image"
```

Only the readonly test binary is mounted. The fixture creates and removes its
accounts inside the disposable container. Its test entry point explicitly
selects the integration tier and named fixture user; the test refuses to run
without the container marker and `NoNewPrivileges`. No host account, service,
signing key, client state, or Docker socket is shared with the container.
