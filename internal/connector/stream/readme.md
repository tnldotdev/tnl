# connector streams

this package carries service traffic from a local client to a publisher through
two relay paths. `Serve` accepts connections on a loopback listener; `Stream`
carries one TCP stream supplied by its caller.

control selects the service run and authorizes the relay pair. before `Serve`
reports readiness, both relay paths and the encrypted QUIC session to the
publisher must be ready:

```text
tnl                   relays                 publisher
 |-- connect both ----->|                        |
 |<======== encrypted session via relays =======>|
 |                     |                        |
 |-- signed opening + service stream ---------->|
 |<--------------- application bytes ---------->|
```

switching relay paths keeps the same session and service stream. a failed
application stream is closed, never replayed against another target.

## where to start

- [connect.go](connect.go): `Serve`, `Stream`, and their required `Config`.
  callers supply the approved service ID, protocol, endpoint, and TLS settings.
- [control.go](control.go) and [workload_control.go](workload_control.go):
  control API adapters for signed-in people and workload sessions.
- [peer_connection.go](peer_connection.go): preparation, renewal, and shutdown.
  background workers prepare signed openings; a new local connection consumes
  one without calling control or signing another request.
- [connector_prepared.go](connector_prepared.go): one stream's admission, copying,
  and cleanup. TCP gets a TLS wrapper here; HTTP and database clients negotiate
  their own service TLS.

`MetadataReloadError` means the approved service metadata changed. the caller
must fetch fresh metadata and restart the connector after the old one exits.
existing connections close rather than moving to the new endpoint. target TLS
is a separate publisher-to-target connection owned by
[targettransport](../../transport/targettransport/).
