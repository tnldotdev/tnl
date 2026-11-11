# local publisher api

SDKs use this loopback HTTP API to tell `tnl` where an app is listening. The same
API gives the CLI status, events, and readiness checks. One local publisher
process serves each canonical project directory and client-state root.

## registering an app

The SDK runs `tnl runtime endpoint --directory <project> --service <name>` to
discover or start that process. The response includes its address and a token
limited to the selected app service. Then:

```text
SDK                              local publisher
 |-- prepare -------------------------->|
 |<-- registration + public URL --------|
 |                                      |
 |  app opens its listener              |
 |-- register actual target ----------->|
 |-- renew same registration + target ->|  repeat while running
 |                                      |
 |-- unregister ----------------------->|
 |<-- stopped and worker exited --------|
```

Register a new target when the app replaces its listener. The publisher stops
and joins the old worker before starting its replacement. Renewals keep the
20-second registration lease alive. After a `401` or
`runtime.registration_stale`, discover the endpoint, prepare, and register again.

The process keeps one evaluated configuration. If reuse returns
`TNL_CLIENT_APP_CONFIGURATION_CONFLICT`, stop and restart the project's apps and
named local publishers so they all use the new configuration.

## publishing an application resource

Use `tnl runtime endpoint --directory <project> --invocation-id <id>` for each
publication handle. This capability cannot prepare configured apps or rebind
publisher-group services. Post to `/v1/publications` after the listener is bound:

```json
{
  "version": 1,
  "invocation_id": "ivk_0123456789ABCDEFGHIJKL",
  "owner": "0123456789abcdef0123456789abcdef",
  "pid": 123,
  "target": "http://127.0.0.1:3000",
  "server_url": "https://control.example",
  "auth": { "source": "private identity-source handoff" },
  "resource_id": "url_0123456789ABCDEFGHIJKL"
}
```

Select `resource_id` or `allocate: {namespace: "member.example"}`, never both.
The authority checks the exact resource or namespace before accepting the
registration. New allocations default to restricted visitor access; anonymous
access must be explicitly requested and authorized. The native API accepts only
the bound target: SDK listener and handler ownership stays with the SDK.

The reply contains `registration`, `public_url_id`, `hostname`, and `public_url`.
It means the resource was selected and registration accepted, not that a
certificate or relay is ready. Poll scoped `/v1/status` or `/v1/events` and use
`routable` for traffic readiness. `ready` records a separate application probe;
these handles do not start an automatic probe. Auth never enters the journal.

Repeat `/v1/publications` with the same public request fields and a current auth
proof to refresh the identity source and renew the existing registration without
allocating again. `/v1/renew` renews only the local registration lease; it does not
hand over new auth. Unregister the returned registration using
`/v1/unregister`. Unregister drains and joins only that publication, then cleans
its temporary allocation. A cleanup failure retains the registration for another
unregister attempt. A successful retry is acknowledged without returning the
repaired cleanup error. An independent publication failure remains in status and
events, and close returns `runtime.publication_failed` after releasing the cleaned
registration; this is separate from `runtime.cleanup_failed`, which needs another
cleanup attempt. Release `/v1/capability` with `DELETE` once cleanup finishes
so a long-lived publisher does not retain closed handles. Application-owned
listeners remain open; SDK-owned listeners close only after native drain/join.

## where to change it

- [server.go](server.go) handles HTTP requests and capability scopes.
  [protocol/endpoint.go](protocol/endpoint.go) handles private discovery files,
  authentication, and loopback-only requests; browser `Origin` headers are rejected.
- [local/runtime.go](../local/runtime.go) owns process startup and shutdown.
  [app/manager.go](../app/manager.go) owns registrations and their leases.
- [The OpenAPI contract](../../../contracts/publisher/local/v1/openapi.yaml) defines
  request and response fields. Edit it rather than the generated Go types, then
  regenerate from the repository root:

```sh
mise exec -- task generate
```
