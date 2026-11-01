# transport architecture

Ingress owns public URL and public service visitor acceptance and the retry commitment. Relay owns its lease,
publisher claim registry, capacity, and streams. Shared transport packages supply
bounded handshakes and copying mechanics without deciding placement or visitor
authorization.

## implementation map

| Owner                                                   | Responsibility                                                                                                                               |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `internal/ingress`                                      | Public URL and public service dispatch, public URL routing, pool selection, admission/promotion, live guards, usage, and forwarding lifetime |
| `internal/ingress/clienthello`                          | Bounded ClientHello hostname inspection                                                                                                      |
| `internal/ingress/backend`, `internal/ingress/pool`     | Forwarding interface/projections and shared pool identity                                                                                    |
| `internal/relay`                                        | Cohesive lease/claim registry, authenticated publisher sessions, stream admission/accounting, and drain                                      |
| `internal/transport/tunnel`                             | Shared tunnel handshakes, accepted peers, slots, and transport races                                                                         |
| `internal/transport/muxsession`                         | QUIC and TLS/TCP-yamux multiplexed byte streams                                                                                              |
| `internal/transport/peer`                               | Two-carrier authenticated packet delivery for a connector pair's retained inner QUIC session                                                 |
| `internal/transport/{proxyproto,streamcopy,httpstream}` | PROXY v2, joined bidirectional copies/half-close, and HTTP body/trailer ownership                                                            |
| `internal/transport/targettransport`                    | Protocol-aware publisher-to-target TLS preflight and handshake                                                                               |
| `pkg/protocol/tunnelv1`                                 | Sole handwritten frame/message wire contract                                                                                                 |

Routing, admission, usage, and visitor state remain cohesive in the ingress root;
the draft `ingress/{routing,admission,usage}` packages were not created. Relay also
retains one cohesive implementation. Children do not call a parent orchestrator
for mutable state. Neither role imports control's PostgreSQL package. Source
organization is not a reason to split a shared lifetime or weaken stale-state
checks.

## public visitor and retry boundary

```text
visitor TLS ClientHello
        v
ingress: hostname, optional IP filter, pending/ordinary admission
        v
relay: current lease and exact connected publisher claim
        v
publisher: visitor TLS, current access, capacity promotion
        v
target: independently selected HTTP/TCP/database transport
```

Ingress creates one PROXY v2 header carrying the original source/destination;
relay preserves it and the TLS bytes. On restricted URLs, bounded pending capacity
lasts until publisher authorization. Acceptance, rejection, promotion, response
data, and half-close use bounded return frames on that same visitor stream.
Promotion binds visitor, run, assignment, and connected relay; ingress checks
current policy and ordinary capacity before releasing the following response
bytes. It is a one-way notification, not a second authorization RPC. Promotion
validates the current claim even when there is no spare new-stream capacity:
the admitted visitor already owns its stream.

the stream owner bounds acceptance, rejection, and promotion from writer
acquisition through the last frame byte. cancellation resets only that stream,
joins its interrupt callback, and preserves the context cause. a pre-canceled
decision does no I/O. return-data writers share the same serialization; decision
writers never borrow or clear each other's deadlines.

public openings carry the header and a length-prefixed block of at most 64 KiB,
then raw request bytes. ingress includes PROXY v2 and the inspected ClientHello;
any excess prefix follows as raw bytes. a fresh exact session/assignment first
confirms metadata through the publisher, then sends visitor bytes on that same
stream. later openings pipeline the prefix without waiting for acceptance.
confirmation is scoped to that session and assignment, not a recovery timer.
public service openings retain metadata-only acceptance before application bytes.

ingress may try another connected relay before the first visitor byte is sent.
a rejected confirmation, failed PROXY-header write, or zero-byte ClientHello
write can still be retried. the first visitor byte commits the stream, even if
the rest of ClientHello fails or a later return frame rejects it. opening errors
retain the exact visitor-byte count, excluding framing and PROXY metadata.
copy/close then owns it; live connections are never replayed or migrated.
public URL and public service setup reserve time for alternate relays before that boundary.
a denied visitor may use separate admission to finish TLS at the publisher and
receive HTTPS 403.

The routing table copies relay process identity and last advertised lease
deadline. A renewal need not publish a new URL projection. The connected relay
checks its current lease and exact process/assignment identity before accepting
a stream; a copied deadline is not proof of current expiration. Expired ingress
lease/routing state fails closed. Run-lifetime usage survives tombstones,
resnapshots, and projection expiry; only explicit `publish_run_closed` evidence
permits retirement. The 100,000-key traffic bound fails closed rather than
discarding an unknown run because a newer sibling exists.

Public URL projections can name different relay runs during recovery. The
[forwarding pool](../../../internal/ingress/forwarding.go) replaces a session only
for a higher relay lease revision. An older projection cannot close a newer
session or its visitors, including while the newer session is connecting.

## authorization and tls boundaries

Public URL and public service HTTP requests verify signed visitor permissions
locally. Before serving, the publisher prepares a resource policy using its
current run credential. Fetching through installation has a two-second budget;
the policy expires within ten seconds of request start. Failed renewal cannot
extend that deadline. Control-clock translation also bounds credential and
parent expiry despite clock skew.

[`visitortoken`](../../../internal/security/visitortoken/token.go) owns signature,
resource, hostname, port, and proof verification. It depends on the shared exact
resource value in `internal/policy/visitorscope`, not control state.
[`visitorlease`](../../../internal/policy/visitorlease/lease.go) owns local policy
installation and request guards; publisher runtime owns fetching and joins.
These shared leaves let both HTTP frontends use one verifier without importing
the control authority or copying its grant rules.

Each request binds the trusted forwarding source and current policy. A request
uses one `Tnl-Visitor-Token` header, signed cookie, or service client certificate.
A supplied certificate cannot switch subjects through an HTTP credential;
malformed or ambiguous credentials fail closed. Browser/share
redemption and background renewal prepare permissions separately. Only that
credential owner may renew an active guard for the same subject, within its
parent deadline. Malformed renewal responses revoke that source's active requests;
an outage or pending policy/key installation can only retain the last confirmed
permission until its existing deadline. Expiry or revocation cancels the target request and resets only
the affected HTTP/2 stream; upgraded HTTP/1 closes directly. Application requests
perform no authorization RPC and never replay bytes.

connectors prepare two relay carriers bound to one signed owner, exact
publisher run, relay-process claims, and agreed socket source. their inner QUIC
session carries signed application openings; the publisher's current local guard
fences target resolution, dialing, greetings, and subsequent stream use. pair,
claim, and permission renewal retain their own fixed deadlines. a changed binding
requires a new session, not a retained-stream handoff. connector visitor TLS verifies
the service hostname. publicly reachable service HTTP instead selects one browser,
share, token, or optional client-certificate credential, checks Host including the
allocated port, and promotes ingress capacity before target access. Reachability
does not imply anonymous access. See [services](../control/services.md)
and [connector architecture](../connector/architecture.md).

connector traffic does not use ingress, PROXY v2, or ingress service-routing history.
its source comes from the two agreeing relay-process claims. the bounded native
frame reader keeps permission renewal independent of application reads and joins
its worker and callbacks before releasing admission. relay transport uses
`muxsession.ALPN` for both native and publisher connections; their proofs, not a
second ALPN, separate authority.

Visitor TLS ends at the publisher. Relay transport TLS authenticates the relay
address separately. `target.tls` controls the independent publisher-to-target hop:
direct HTTP/TCP TLS, PostgreSQL SSLRequest, or MySQL greeting/SSLRequest. Omission
permits plaintext target transport without disabling managed visitor TLS. The
connector does not interpret target CA trust. Kubernetes has its separate pinned
cluster identity/authentication boundary. Application authentication headers
remain application-owned after tnl removes untrusted forwarding/access headers.
Native PostgreSQL cancellation remains unsupported until a second connection
can prove ownership of the original backend key; see
[database cancellation](../publisher/database-cancellation.md).

## streaming and connection replacement

`httpstream` enables HTTP/1 full duplex before target responses and bounds the
upload, including trickles, to 30 seconds. Body completion ends the read deadline;
SSE and upgraded responses have no upload-derived total lifetime. HTTP/2 deadlines
apply to one stream. The adapter retains the original trailer owner through
request clones and copies trailer values only after body EOF. It neither buffers
nor replays payloads. Inspection can record interruption while retaining the
status already sent, without bodies, SQL, arguments, or credentials.

Publishers normally race QUIC first with delayed TLS/TCP-yamux fallback, keeping
the first authenticated transport. A failed claimed QUIC slot waits for control's
replacement assignment and tries TCP first; a later replacement returns to
QUIC-first. Healthy siblings survive. A slot's local connecting/serving/waiting
phase differs from stored assignment state; only a changed assignment identity
restarts it. Lost visitor streams cannot resume on a new transport. Normal stop
drains visitors before publisher connections close; rejected heartbeat or expired
certificate closes them immediately.
