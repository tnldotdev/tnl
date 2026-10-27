# visitor tokens

Control decides who may visit each public URL or service in
[`visitor_tokens.go`](../../../internal/control/state/visitor_tokens.go). It checks
the visitor's current sign-in, team membership, share, device, or workload and
signs the result. Public URLs and services use the same grant table and identity
permission rule. Registering a device or making a service publicly reachable does
not grant access. A share covers only its captured public URL IDs and requires
its creator to retain permission to manage them.

Each token names one resource by kind and ID, its hostname and port, and an
expiry. [`visitortoken`](../../../internal/security/visitortoken) checks the
signature and these fields against current local policy. It does not contact
control or decide membership and grant rules. Tokens use Ed25519 signatures,
type `tnl-visitor+jwt`, and format version one, with a 2 KiB size limit. Each
credential kind has its own fixed set of fields.

Each issuance also has a random JWT ID (`jti`). Two browsers can receive the same
share permission in the same second, but their bearer tokens must stay distinct
so renewal, sign-out, and denial remain attached to the right source credential.

A visitor token permits visits. It does not identify a verified feedback author,
authorize management or publishing, or reserve connection capacity.

## keys and expiry

All control replicas share signing keys in PostgreSQL. The private keys are used
only for visitor tokens and are encrypted with the storage key. The saved issuer
is the configured control URL; another control URL cannot reuse that issuer
state.

When a signing key is replaced, control keeps its public key until every token
it signed has expired. Emergency rotation revokes the old keys immediately.
Storage-key rotation also re-encrypts retained visitor signing keys.

Renewable tokens last at most five minutes. They expire sooner when their
sign-in, share, workload, or other parent permission ends. A service credential
with an explicit expiry may last up to seven days. Its separate
`vrf1.<grant-id>.<secret>` credential is used only to ask control for tokens. Team
sign-in rules can tie the grant to a control session and shorten its lifetime.

A token's expiry does not say how current the local policy is. A serving process
may trust its policy view for at most ten seconds from the observation time. A
slow reply does not start a fresh ten-second window. Verification keys must
already be prepared: an unknown key causes verification to fail, without fetching
keys during the visitor request.

## policy updates

Control records a separate visitor-policy revision for each resource. Permission
changes and their invalidation events commit in the same transaction. Changes to
a person or team also invalidate dependent resources, including shares created
by someone who loses authority. Signing keys have their own revision; replacing
a key does not change a resource's permission revision.

Ingress and publisher fetch policy in the background every two seconds. Each
reply contains a consistent snapshot and the policy revisions it covers. Control
keeps 256 events per resource; a reader that falls behind needs a full snapshot.
Failed requests leave the last confirmed deadline unchanged.

publisher policy reads also record installed stream allocations. concurrent
refreshes can conflict, so control retries the rolled-back transaction for up to
two seconds, rechecking current run authority with a new snapshot and fresh time.
this does not repeat share redemption, a one-use handoff, or application admission.

service policy also carries direct endpoint reachability and the public client
certificate issuer once prepared. reachability does not grant visitor permission.
client trust is scoped to service policy and expires with the same fetch-start
deadline; readers receive independent certificate pools so they cannot mutate
another serving owner's roots.

[`publisher/visitorpolicy`](../../../internal/publisher/visitorpolicy) owns the
run-bound publisher fetch lifetime. Public URL and service runtimes both compose
it and depend on the policy lease below it. Keeping this owner below both
runtimes lets service publication reuse the same renewal and join behavior
without importing the public publisher process owner.

[`visitorlease`](../../../internal/policy/visitorlease) checks update order and
owns the local deadline. It fences replies that arrive after their lease expires
and stops affected admissions when permission, key trust, or freshness ends.
Serving owners supply the connection or request cancellation. Each HTTP request
has its own guard, so cancellation need not close an unrelated HTTP/2 stream.

The local deadline starts before the policy request. Token times are checked
using control's observation time plus elapsed local time, so clock differences
and slow replies cannot add authorization time.

## public http requests

Browser sign-in and share redemption return a signed permission. The publisher
sets it in the secure, HTTP-only `__Host-tnl-visitor` cookie. Native HTTP callers
can supply one `Tnl-Visitor-Token` header instead. Supplying both, a duplicate,
an invalid token, or the retired share-token header fails admission, including
on an anonymous public URL. The app's `Authorization` header is separate.

The publisher verifies ordinary requests locally against the current hostname,
policy, and ingress-owned source address. It strips tnl credentials before
forwarding to the app. Browser and share fact cookies remain available only to
publisher-owned operations such as sign-out and feedback authorship; a visitor
token does not establish a verified author.

The publish run owns bounded background renewal for explicitly redeemed browser
and share sessions. Application requests neither issue tokens nor wait for a
renewal. An unexpired old token may select an already prepared replacement for
the same subject and exact binding. An expired token cannot act as that handle.
Explicit renewal denial stops that source's requests and fences later uses of
its tokens until expiry. Outages and malformed replies never extend a deadline.

A changed policy revision gives an active renewable request only its last
confirmed policy window while the credential owner obtains fresh permission.
Unrelated policy updates cannot extend that window. The run cancels and joins
renewal work before discarding its private source credentials.

## direct service visitors

ingress selects a public service only from the socket's trusted destination
port and its prepared routing, reachability, policy, and capacity. the publisher
verifies service client certificates against the prepared issuer and signed
permission; each service HTTP request instead selects one signed visitor token
or verified client certificate. the old service-specific HTTP token header and
share cookie do not grant application access. a share link redeems a signed
permission into the same host-bound visitor cookie.

the publisher sends a verified, nonsecret certificate or grant reference back
to ingress on the visitor stream after local admission. ingress releases its
pending quota only for that exact run and allocation. control derives delayed
audit actor facts from immutable certificate issuance or sign-in state; a
bearer grant does not identify the person visiting or author feedback. neither
serving process calls control to authorize a prepared visitor request. HTTP/2
requests own independent target connections and request guards.

## native preparation

One service connector prepares its approved metadata and signed device or
workload permission together before accepting local sockets. The connector
refreshes that private snapshot every two seconds; socket setup reads it locally
instead of selecting a run through control. Its deadline starts before the fetch
and ends within ten seconds, or earlier at the metadata or token deadline.

A changed approved metadata revision stops that service's listener and active
connections so the owner can prepare it again. Outages retain only the last
confirmed window. Malformed replies and explicit denials stop the service;
shutdown cancels and joins pending preparation before releasing its control
client. Tokens and signing operations remain inside the native process, outside
the read-only connection metadata returned to SDKs.

Each native opening carries that permission, a visitor connection ID, and the
approved metadata revision. Its key proof covers the authenticated connector
session, visitor ID, token, revision, and bounded initial bytes. Ingress checks
the proof against its prepared service policy before making a stream decision.
Service routing is prepared independently of visitor arrivals; a missing or
expired local projection rejects setup without starting a routing fetch.

The ingress connector owns one preparation loop. Closing it cancels and joins
routing and policy/capacity workers before returning. Public URL and service
preparation share a two-second retirement budget across runs, with at most eight
retirements in flight; a failed control endpoint cannot multiply shutdown time
by the number of saved resources.

Ingress forwards the exact opening and its held reservation to the publisher.
The publisher verifies permission, source, metadata and the reservation before
target work. Both relay connections share reservation replay watermarks and the
run's final connection limit. Publisher admission and active permission checks
use local policy rather than a control authorization request.

The native process sends renewed, possession-bound permission on the same outer
request stream. Request framing is removed before visitor TLS or a native parser
reads data. A renewal keeps the original session, visitor ID, subject, source,
and metadata; it cannot move the connection to another target or restore an
expired guard. HTTP upgrade deadline interruptions retain partial frame state.

A verified renewal can arrive before background policy covers its revision.
The guard retains one pending permission without extending the prior confirmed
deadline. A covering policy snapshot activates it; missing coverage, revocation,
changed metadata or expiry still closes the admission.

native audit attribution uses the authenticated connector session and exact
publisher-observed ingress allocation. control derives the actor, device, source,
and publisher from those immutable facts; native streams have no per-stream
control admission or recheck record.

## stream capacity

A visitor token grants permission, not capacity. Control delegates bounded
portions of a run's connection limit to exact ingress process leases. Each
allocation lasts at most ten seconds and is renewed in the background. Retiring
or restarting an owner does not make its slots available before that deadline.

The publisher reports installed allocation IDs on its next background policy
request. Ingress waits for that observation before using new slots. This keeps
allocation preparation out of visitor setup without forwarding slots that the
publisher has not installed yet. The report is bound to the publisher's exact
resource, run, and run credential.

Ingress reserves a local slot before forwarding. Each use has a new reservation
ID and an increasing slot sequence. The publisher checks the current allocation
and retains the sequence after release, preventing replay through either relay
connection. Both relay connections also share the publisher's final run limit.
Allocation or policy expiry stops held connections. These connection slots are
separate from HTTP request concurrency, rate, and byte limits.

Ingress initially prepares a portion of the limit and can request more portions
in the background as local occupancy grows. Pending browser connections still
have their own connection, time, and byte quotas while holding a reservation;
publisher promotion does not bypass those quotas or the final run limit.

## certificate binding

For native TLS clients, control puts the same token in the certificate's standard
`subjectAltName` extension, OID `2.5.29.17`, as one URI:

```text
tnl://visitor-token/<compact-JWS>
```

Control takes only the proven public key from the certificate signing request
(CSR), discarding its supplied names and extensions. The token records the
certificate's serial number, a SHA-256 hash of its encoded public key (SPKI), and
the device or workload that permits access.

TLS must verify the certificate and prove that the visitor holds its private
key. The publisher then checks the token's certificate binding, resource,
hostname, port, expiry, and current policy. Copying the token into an HTTP bearer
header or a connector opening does not grant access.
