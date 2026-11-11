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
