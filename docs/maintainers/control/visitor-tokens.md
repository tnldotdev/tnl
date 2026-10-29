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

A visitor token permits visits. It does not identify a verified feedback author,
authorize management or publishing, or reserve connection capacity.

The authority layer supplies issuance, policy, and allocation APIs plus their
local verification owners. The existing serving paths keep their current
authorization until the prepared-publication layer composes those owners. This
is a review boundary in one coordinated fresh-database cutover, not permission
to deploy issuance or capacity without its serving consumer. The schema and HTTP
contracts remain version 1, and the tunnel version and ALPN remain unchanged.

Only verification constructs `VerifiedPermission`; signing input cannot bind a
visitor guard. Policy views publish independent private key/lease maps once and
share immutable snapshots without copying them on each visitor admission.

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

The ingress and publisher fetch owners refresh policy every two seconds. Each
reply contains a consistent snapshot and the policy revisions it covers. Control
keeps 256 events per resource; a reader that falls behind needs a full snapshot.
Failed requests leave the last confirmed deadline unchanged.

[`visitorlease`](../../../internal/policy/visitorlease) checks update order and
owns the local deadline. It fences replies that arrive after their lease expires
and stops affected admissions when permission, key trust, or freshness ends.
Serving owners supply the connection or request cancellation. Each HTTP request
has its own guard, so cancellation need not close an unrelated HTTP/2 stream.

The local deadline starts before the policy request. Token times are checked
using control's observation time plus elapsed local time, so clock differences
and slow replies cannot add authorization time.

Publisher refresh serializes the fetch through local installation. A caller
waiting behind another refresh spends the same two-second request budget; its
revision cursor is read only after the preceding update applies. The owner checks
the absolute deadline before fetching and installing, including when a timer
callback has not delivered cancellation yet.

Control records the publisher's installed allocation IDs only under the exact
current run credential. If that repeatable-read transaction loses a serialization
race, the whole rolled-back operation retries with fresh time and authority.
Revoking the publisher grant between attempts rejects the retry and records no
observation. Credential redemption and application admission are never replayed.

## stream capacity

A visitor token grants permission, not capacity. Control delegates bounded
portions of a run's connection limit to exact ingress process leases. Each
allocation lasts at most ten seconds and is renewed in the background. Retiring
or restarting an owner does not make its slots available before that deadline.

The prepared serving consumer reserves a local slot before forwarding. Each use
has a new reservation ID and an increasing slot sequence. The publisher checks the current allocation
and retains the sequence after release, preventing replay through either relay
connection. Both relay connections also share the publisher's final run limit.
Allocation or policy expiry stops held connections. These connection slots are
separate from HTTP request concurrency, rate, and byte limits.

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
