# webhook development plan

Audience: tnl maintainers. **Planned; implementation has not started.**

Make local webhook development part of `tnl dev`: set up endpoints, keep a
durable delivery history, inspect old requests, and replay them after a
restart. Start with Stripe, GitHub, and Resend. Provider tools remain the way
to generate new events.

## what the developer does

Configure named webhooks on a project service, each with a provider, callback
path, events, and a signing-secret environment variable. A service inherits
project defaults unless it supplies its own map; an empty map disables the
inherited webhooks. Require unique names, paths, and secret variables within
the effective service. Resolve project, worktree, and service through the
existing project configuration rather than a new identity system.

`tnl dev` prepares the endpoints, adds signing secrets only to the local
service process, and activates delivery when the local service and public
URL can serve it. It records matching deliveries on the developer's machine.
History persists when endpoints and tunnels stop.

| Command                          | Purpose                                                                     |
| -------------------------------- | --------------------------------------------------------------------------- |
| `tnl webhook list`               | Find deliveries by project, service, webhook, event, result, or time        |
| `tnl webhook inspect <delivery>` | See status, timing, capture completeness, and optionally body or headers    |
| `tnl webhook replay <delivery>`  | Send saved bytes to a selected running local service with a fresh signature |
| `tnl webhook status`             | See endpoint state, cleanup work, and retained history                      |
| `tnl webhook cleanup` / `prune`  | Retry owned endpoint cleanup / remove old local history                     |

Commands default to the current project and worktree. A related-worktree
search must use the Git common directory and the project's relative location
to avoid joining separate projects in a monorepo. List results remain useful
without a running service. Human output uses the shared renderer; finite
results go to stdout, lifecycle output and errors to stderr. Keep JSON for
finite results and NDJSON for follow mode.

## own the lifecycle in the client

Keep orchestration, capture, storage, and replay local. The existing
`clientstate` database stores endpoint ownership and delivery history;
`localproxy` observes configured webhook paths without changing forwarded
bytes. A small provider-neutral manager owns operation ordering and cleanup;
provider adapters own API calls, event identification, and replay signatures.
Use existing publisher events and the private development socket for active
status and replay work. It is not a public extension API.

On startup, validate configuration and provider authentication before creating
remote resources. Record creation intent, use an inactive endpoint where
possible, and activate only after publication is ready. Stripe and Resend may
need a staging callback followed by disable and update; GitHub supports
inactive creation. Record enough ownership to recover if the process stops
between remote creation and saving the endpoint ID.

On shutdown, stop new replay work, disable and remove owned endpoints, stop
publishing and the managed local service, then flush capture writes. Use
bounded cleanup independent of a canceled command. Failed cleanup leaves
an ownership record for `cleanup` or the next session to retry. Verify scope
before touching any remote endpoint.

A restricted public URL must allow the provider's webhook source ranges
without silently making the whole hostname public. Resolve and validate
ranges before creating endpoints; explain that this remains a hostname-wide
IP policy.

## keep captured data local and bounded

Store queryable delivery metadata separately from protected request and
response content. Preserve exact request-body bytes for replay. Do not retain
unneeded authorization, cookie, or original signature headers; require an
explicit option to display sensitive content. Limit capture size, in-memory
queues, and retention. An oversized request should still reach the local
service, with its history marked incomplete and not replayable.

Use the existing `clientstate` protection backend rather than inventing
another one. Its current macOS backend uses Keychain-backed encryption; the
current non-macOS backend stores plaintext. Portable encrypted storage is a
follow-up, not a claim this plan can make today. Start with 30 days and
100 MiB of history per project/worktree; evict oldest deliveries when either
limit is reached. Report capture failures instead of silently losing history.

Replay selects an active destination, preserves the captured payload and
provider event identity, and signs with that destination's current secret.
It does not follow redirects or reuse old forwarding and transport headers.
Replaying into another worktree requires explicit destination selection.
Application-level event deduplication still applies.

## build and verify in stages

1. Add validated configuration and durable, project-scoped history.
2. Implement one provider end to end, including interrupted creation,
   activation rollback, and cleanup. Add the other providers through the
   same narrow contracts.
3. Capture requests without changing forwarding or streaming behavior; add
   inspection, local replay, and the shared CLI output.
4. Document provider authentication, retention, cleanup, replay, and
   worktree scope on tnl.dev.

The acceptance case is straightforward: receive a webhook, stop `tnl dev`,
restart with fresh endpoints and secrets, find the old delivery, replay it
successfully, and inspect both results. Tests must also cover byte-preserving
capture, incomplete payloads, ownership isolation, signing, redaction,
retention, and failed cleanup. Follow the repository's
[validation sequence](../../../contributing.md#check-your-change).
