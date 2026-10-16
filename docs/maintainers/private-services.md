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
control encrypts a separate assignment-credential seed so a retry can rotate
only the run token without changing the two relay credentials or TLS pin.

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
publisher is offline. first readiness needs two ready connections on different
relay services. afterward one surviving ready connection keeps the run
available and accepts new visitors while the other slot is replaced. inventory
alone never permits a connection; each ticket still needs a ready run and at
least one live ready slot at issuance and claim. at zero live slots control
demotes the run and publishes a tombstone. control never expires a surviving
slot simply because the other is missing; that slot's active visitor streams
continue.
each projected relay has its own lease deadline. a routing event expires at the
earlier of the run deadline and the last live relay deadline; ingress excludes
an expired relay without waiting for the other slot or replaying visitor bytes.
the first ready timestamp remains recorded if a zero-relay outage demotes the
run, so one reconnected relay can restore it.
the source IP binding on each ticket limits replay across hosts, but does not
grant access. invitations are bound to a verified email and become exact
identity grants, not team memberships. publisher grants similarly select one
private service ID and cannot authorize a public URL. a closed or replaced run
invalidates assignments and tickets. publish a tombstone for a disabled
service or closed run; ingress uses only projections from a current lease and
never receives publisher TLS private keys.

creating a private-service invitation returns its one-use secret exactly once;
the creator must give it to the intended recipient. listing invitations never
returns secrets. accepting the secret requires a signed-in identity with the
same verified email. retrying creation with a used idempotency key returns a
conflict because control cannot recover the already-issued secret.

the SQL baseline, HTTP shapes and framed protocol are source contracts.
controlstate stores saved services, exact grants and invitations, offline
inventory, signed run bindings, relay assignments, and one-use connector
sessions and tickets. controlapi, ingressapi, and relayapi expose their
private-service authority endpoints. private connections cannot be used until
the remaining generated browser identity and SSH handlers compile, and the
relay adapter, `tnl connect`, and publisher runtime use these endpoints.

ingress recognizes the shared infrastructure hostname only on public port 443.
it requires the `tnl-private/1` TLS ALPN, an explicit TLS config with the
WebPKI certificate for that hostname, a current ingress lease, and an
authenticated private relay forwarder. the control-managed ingress certificate
and relay adapter are not yet provided by `tnld` runtime wiring; leave the
private connector unconfigured until both are available. a configured shared
hostname without the connector handler closes instead of falling through to
public URL or HTTP routing. ingress authenticates the outer hello before
starting yamux and bounds pending stream frames to 2 KiB, 10 seconds by
default, and a capped per-session yamux window. the relay adapter must
acknowledge the private forwarding sideband and bind the exact assignment
before ingress writes PROXY v2 once and releases visitor bytes. ingress may
try another relay before the first visitor byte; after that, it closes the
stream on failure rather than replaying it.

after promotion, ingress rechecks each active visitor against the exact
consumed ticket's session, visitor connection ID, identity, trusted source,
current grant, run and ingress lease about every 30 seconds. the consumed
ticket may expire without ending the stream; it cannot be reused. a denied
recheck closes both ends. control supplies `valid_until` on the initial claim
and each successful live recheck: the earliest applicable grant, publisher
grant, run, ingress or live relay deadline, capped at two minutes. if control
is unavailable, ingress closes by that deadline even when it is sooner than
two minutes, and joins the stream copy before releasing capacity. a revoked
grant, disabled identity, or closed run is denied on the next check. the
connector-session credential's expiry stops **new** streams on that mux, not
already admitted streams. `tnl connect` must start a fresh authenticated mux
session for later streams without replaying or migrating the existing ones.
this private-stream guard does not replace public-URL admission.

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

the isolated private publisher stream boundary currently accepts only opaque
targets and checks a claimed assignment, PROXY v2 source, pinned TLS 1.3 key,
and signed visitor challenge before forwarding application bytes. the publisher
prepare and bind the signed run, heartbeat/close it, and race two relay claims
over WebPKI-authenticated QUIC and TLS/TCP. the local owner, relay adapter, and
installed private job registry are not yet wired to this runner. an assignment
replacement currently stops the run instead of replacing just that slot;
streams are never replayed. `tnl publish orders --install` for `protocol: tcp`
therefore fails before any grant or job write.
verified `target.tls` modes (`direct`, `postgres`, `mysql`) also fail closed until
their target negotiations and real-client fixtures are implemented. do not
describe TablePlus or mysql CLI compatibility as working yet.
