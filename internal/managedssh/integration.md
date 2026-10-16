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
The callback must honor context cancellation.

Return a `Decision` with matching `IdentityID`, `PublicURLID`, and `SSHUser`,
and a future `ValidUntil`. The host job allowlist is checked independently
before the callback. The runtime uses SSH's `none` authentication method inside
the authenticated TLS connection; passwords and SSH user keys do not grant
access. It refreshes successful decisions every 30 seconds by default and
closes on denial, callback failure, or the last decision's expiry. Cancellation
closes the visitor connection and joins child work.

Only session channels and `direct-tcpip` channels are accepted. The latter
covers OpenSSH local (`-L`) and dynamic (`-D`) forwarding. Its destination is
dialed in a separate dropped-user child. Reverse, agent, Unix-socket, and X11
forwarding are rejected. Client environment requests are rejected. PTY sizes,
shell requests, raw command strings, and the `sftp` subsystem are supported;
terminal mode negotiation and SSH signal requests are not implemented yet.

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

## publisher job handoff

`publisherjob.Engine.ConfigureSSH func(Job, *publisher.Config) error` receives
the validated job and its protected host key before publication. SSH jobs fail
closed without this hook. The hook must attach the managed SSH publisher
handler; an SSH job has no target or target TLS options. `Job` JSON includes
the private key for the existing encrypted whole-job snapshot, so CLI and API
adapters must continue selecting approved fields rather than serializing jobs.

This rough pass supplies the runtime and job hook. Publisher mTLS dispatch,
control-client adaptation, public host-key binding, hidden CLI dispatch, and
replacement of the old raw SSH publisher path belong to the integrating
caller. Real root-to-user credential changes still need isolated Linux
integration coverage; routine tests inject the same-uid child privately.
See [the child boundary](runtime.md) for account, descriptor, environment, and
process-group behavior, including the direct-setuid/PAM distinction.
