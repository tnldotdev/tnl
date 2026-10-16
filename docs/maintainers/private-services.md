# private service boundaries

use `protocol: tcp` to define a team-scoped service for `tnl connect`. the
validated project service key becomes its saved name; set `private.name` only
when a different team-unique saved name is needed. the name is never a public
URL or hostname. the connector gets an infrastructure session credential
through the authenticated control API for an exact service ID. ingress
authenticates the outer TLS mux session once and binds its identity, selected
service and source IP observed on that connection. this does not authorize
visitor streams. the session credential is claimed once; the connector must
not send an IP address or use untrusted SNI to select the service. there is no
per-service DNS, WebPKI
issuance or listening port. HTTP still uses public URLs; native SSH retains its
assigned port and browser-approved attempt flow.

```yaml
version: 1
tnl:
  team: shop
  services:
    orders:
      protocol: tcp
      target:
        type: compose
        service: db
        port: 5432
        tls:
          mode: postgres
          server_name: db.internal
          ca_file: certs/ca.pem
```

this service is saved as `orders`. to use `database` instead, add
`private: {name: database}` under `services.orders`. a project-level `tunnel`
can set public URL defaults for HTTP and SSH services in the same project;
private TCP services do not inherit its domain, access rules or limits, and
cannot set a per-service `tunnel`.

omit `tls` for opaque bytes to the target. `direct` verifies a target that
starts TLS immediately; `postgres` and `mysql` explicitly negotiate target
TLS before verification. none of these modes changes the visitor-side
protocol. do not pass a private service through public URL certificate, DNS,
inspection or public hostname selection code.

control reserves a run ID, run number and short-lived nonce under an exact
publisher grant. the publisher generates a fresh per-run Ed25519 TLS key and
signs the team ID, service ID, run ID, run number, grant ID, enrolled signing
key ID, idempotency key, nonce and proposed TLS public key with its enrolled
publisher identity key. control verifies that signature against the current
enrolled public key under the run lock. a retry must use the same preparation,
signature and TLS public key; it can rotate only the run token. control stores
the TLS public key and the identity signature, never the TLS private key.
the publisher alone holds that private key and discards it when the run ends.

for **each visitor stream**, the connector requests a new one-use ticket through
the authenticated control API, passing its claimed mux session ID. control
copies the identity and ingress-observed source IP from that session, checks
current service/run/grants, and binds the ticket to those values. the stream
opens with a fresh ticket and nonce. ingress checks its current lease, the
already authenticated mux session, the exact service/run, and the same trusted
source IP; it atomically consumes the ticket before forwarding. a claimed
ticket cannot be used on a different session, observed source IP or stream.
hosts sharing one public IP still rely on the session credential and one-use
ticket. `tnl connect` cannot reuse the mux session's credential in place of a
per-stream ticket.

the connector and publisher then establish TLS 1.3 across that forwarded
stream. the publisher's per-run self-signed certificate uses its locally held
key; the connector pins its public key to the value control returned with the
ticket. no public CA or per-service certificate is involved. inside that TLS
session, the publisher signs the service ID, run ID, run number, ticket, fresh
visitor nonce, claimed connector session ID, identity, trusted source IP and
visitor connection ID before application bytes. the connector compares the
accepted session, identity and source with the ticket response and verifies
the publisher's signature. a proof from another live stream fails verification
even if it reuses the same TLS run key. ingress forwards the **digest** of the
consumed ticket in `PrivateStreamHeader`, not the raw ticket. the publisher
computes `PrivateChallengeFromHeader` with the digest and trusted stream
identity; the connector computes `PrivateChallenge(entry, accepted)` with its
ticket and `PrivateVisitorAccepted`. both produce the same digest.
ingress and relays carry encrypted bytes but never receive the signing key.
`pkg/protocol/tunnelv1` owns the session, per-stream entry and proof frames.

private service visitor policy consists of current owner/admin access or an
exact team/identity grant; there is no separate private-service IP allowlist.
the visitor inventory lists saved services with current grants even while the
publisher is offline. run ID and number appear only when a run and both
publisher connections are ready. inventory alone never permits a connection;
each ticket still needs a ready run and two ready slots at issuance.
the source IP binding on each ticket limits replay across hosts, but does not
grant access. invitations are bound to a verified email and become exact
identity grants, not team memberships. publisher grants similarly select one
private service ID and cannot authorize a public URL. a closed or replaced run
invalidates assignments and tickets. publish a tombstone for a disabled
service or closed run; ingress uses only projections from a current lease and
never receives publisher TLS private keys.

the SQL baseline, HTTP shapes and framed protocol are source contracts.
control, ingress, relay, `tnl connect` and the publisher still need runtime
implementations of these boundaries before private connections can be used.

## connector handoff

1. `POST /v1/private-services/{private_service_id}/connector-sessions` with
   bearer authentication once per mux session. send its
   `PrivateConnectorSessionHello` on the outer TLS connection. ingress calls
   `claimPrivateConnectorSession` with its own lease and observed socket source;
   only after success may the mux accept visitor streams.
2. for **every** new visitor stream, call
   `POST /v1/private-services/{private_service_id}/connect` with the claimed
   `connector_session_id` under the same bearer identity. send a fresh
   `PrivateVisitorEntry` with that ticket and a 32-byte nonce on the new stream.
   ingress calls `claimPrivateServiceTicket` with its stored session ID, lease,
   trusted source and new `vc_` visitor connection ID. reject before forwarding if
   it fails; never reuse a ticket for another mux stream. ingress sends
   `PrivateVisitorAccepted` with the claimed session, identity, source and
   visitor connection ID before inner TLS begins.
3. compare `PrivateVisitorAccepted` with the ticket's session, identity and
   source, then establish inner TLS with the publisher and pin the TLS public
   key returned alongside this stream's ticket. verify `PrivateStreamProof`
   using `PrivateChallenge(entry, accepted)` before passing application bytes.

private service IDs start with `psvc_`, private run IDs with `psrun_`, connector
session IDs with `pcs_`, private service invitations with `psivt_` and private
service visitor grants with `psgr_`; each has 22 alphanumeric characters after the
prefix. these never substitute for public URL (`url_`) or publish run (`pr_`)
IDs. `tnl connect` and ingress must preserve the canonical fields
`private_service_id` and `private_run_id` on the wire.

the publisher prepares a run with `preparePrivateServiceRun`, signs
`tunnelv1.PrivateRunBindingDigest` using its enrolled publisher identity key,
then submits only its locally generated TLS **public** key and signature to
`bindPrivateServiceRunKey`. retries keep the same prepared ID, nonce, key and
signature; control may rotate the run token but never the TLS pin.
