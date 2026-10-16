# live visitor permissions

`Group.Acquire` checks a permission before admitting a connection and shares
checks across active connections with the same `Key`. The key includes the
public URL ID, publish run ID and number, trusted original source IP, certificate
SHA-256 digest, and SSH account when applicable. Source ports are excluded.
Create a group per publish run; never use a database or URL-only decision for an
SSH account.

The checker must call current authority directly and obey context cancellation.
Return `Decision{Allowed: false}, nil` or `ErrDenied` for a definite denial. Other
errors represent an unknown result: new sessions fail closed, while existing
sessions keep only their last successful `ValidUntil`. An allowed decision needs
a nonzero hard deadline. The group bounds it to two minutes from the start of
the check and rejects an identity change on an established proof.

An active proof refreshes every 30 seconds, or earlier for a short deadline.
Refresh requests have a five-second timeout. A separate timer closes the lease
at its hard deadline even if the checker is still blocked. No commands, startup
fields, or visitor traffic are replayed during a check.

## connection ownership

Bound concurrent calls with the existing connection limit. A successful acquire
returns a `Lease`; close both visitor and backend sockets when `Lease.Done()`
closes, and call `Lease.Close()` when forwarding finishes. Releasing the last
lease cancels and joins its checker and removes the proof. `Group.Close()`
cancels and joins all active checkers and rejects future acquires. The checker
must not leave detached work after returning.

Database forwarding uses `publisher.RevalidateVisitorCertificate`, supplied by
`LiveVisitorCertificateAuthorization` when the control client exposes
`AuthorizeVisitorCertificateDecision`. This bypasses the new-connection positive
cache. The certificate deadline also bounds the returned permission. Anonymous
database visitors use the same hook with no peer certificate, so current IP
policy and publish-run checks still apply. Each visitor owns a joined socket
closer, and pending checks share the application's existing concurrency bound.

## managed ssh takeover

The managed SSH runtime can use the same group with a fresh `AuthorizeSSHVisitor`
callback. Set `Key.SSHUser` to the exact requested account and map the returned
identity and deadline to `Decision`. Keep transient control errors distinct from
an explicit denial; the group must never call the positive certificate cache.
Cancel and join the connection owner on run shutdown, and close the whole SSH
connection and backend when its lease ends.

The native publisher signing adapter currently exposes only the error-returning
certificate authorizer through `publisheridentity/native.RunControl`. Expose or
forward `AuthorizeVisitorCertificateDecision` there so app-owned publishers can
select the live hook automatically. The old raw SSH branch in
`publisher.PublicURLServer.handleVisitorHeaderContext` still rejects pending SSH
streams; the managed runtime must replace that branch when it takes ownership.
Ingress already sends restricted SSH streams through bounded pending capacity.

## focused checks

```console
mise exec -- go test -race ./internal/livevisitor ./internal/publisher ./internal/ingress
mise exec -- task go:test:integration RUN='^TestIntegrationSplitDatabaseLiveVisitorRevocation$'
```

The integration target creates digest-pinned disposable PostgreSQL. The new split
test establishes a real idle PostgreSQL connection, revokes an identity grant or
replaces an anonymous visitor's allowed source IP through control, and observes
socket closure without sending another query.
