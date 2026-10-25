# transport architecture

Ingress owns visitor acceptance and the retry commitment. Relay owns its lease,
publisher claim registry, capacity, and streams. Shared transport packages supply
bounded handshakes and copying mechanics without deciding placement or visitor
authorization.

## implementation map

| Owner                                                   | Responsibility                                                                                                                |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `internal/ingress`                                      | Public/private dispatch, routing projection, pool selection, admission/promotion, live guards, usage, and forwarding lifetime |
| `internal/ingress/clienthello`                          | Bounded ClientHello hostname inspection                                                                                       |
| `internal/ingress/backend`, `internal/ingress/pool`     | Forwarding interface/projections and shared pool identity                                                                     |
| `internal/relay`                                        | Cohesive lease/claim registry, authenticated publisher sessions, stream admission/accounting, and drain                       |
| `internal/transport/tunnel`                             | Shared tunnel handshakes, accepted peers, slots, and transport races                                                          |
| `internal/transport/muxsession`                         | QUIC and TLS/TCP-yamux multiplexed byte streams                                                                               |
| `internal/transport/{proxyproto,streamcopy,httpstream}` | PROXY v2, joined bidirectional copies/half-close, and HTTP body/trailer ownership                                             |
| `internal/transport/targettransport`                    | Protocol-aware publisher-to-target TLS preflight and handshake                                                                |
| `pkg/protocol/tunnelv1`                                 | Sole handwritten frame/message wire contract                                                                                  |

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
relay preserves it and the TLS bytes. Protocol version 1 and ALPN `tnl-tunnel/1`
require a coordinated client/server update. Each opening carries bounded metadata
and up to 64 KiB of initial bytes. On a confirmed relay session, ingress sends
metadata and initial bytes together without waiting for acceptance. On a newly
connected relay session, ingress sends metadata first and waits for relay
acceptance before sending visitor bytes. This prevents an old routing entry from
committing a visitor to a restarted relay process.

The return direction frames acceptance, rejection, promotion, data, and half-close
in order. Only data reaches visitor TLS. Promotion stays on that visitor's return
stream and binds its exact run, assignment, and connected relay. It precedes the
response bytes it permits and has no acknowledgment round trip. A stale or
rejected notification closes that stream without affecting its siblings. Pending
capacity remains bounded until publisher authorization.

Ingress may try another connected relay before the first visitor byte is sent.
A local opening failure, failed PROXY-header write, zero-byte ClientHello write,
or rejection of an unconfirmed relay session can still be retried. A return-side
rejection after the opening committed visitor bytes cannot be retried. The first
visitor byte commits the stream, even if the rest of ClientHello fails.
Copy/close then owns it; live connections are never replayed
or migrated. Public and private setup reserve time for alternate relays before
that boundary. A denied visitor may use separate admission to finish TLS at the
publisher and receive HTTPS 403.

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

public URL and service HTTP requests verify signed visitor permission against
current local policy and the trusted ingress-owned source. publisher policy
expires within ten seconds of fetch start; an earlier credential, parent,
allocation, or run deadline wins. unknown keys, invalid credentials, and stale
updates fail closed without a visitor-triggered fetch. each streaming request
or upgrade keeps its own local guard. denial cancels the target request and
resets only the affected HTTP/2 stream; upgraded HTTP/1 closes directly.
HTTP/2 requests use independent selected target connections, without replay.

private connector sessions authenticate two ingress paths and bind the observed
source, exact service/session/subject, nonce, expiry, and key proof. each stream
uses prepared permission and capacity at ingress and publisher before target
work. native visitor TLS verifies the service hostname. publicly reachable
service HTTP selects one signed browser, share, token, or verified client
certificate, checks Host including the allocated port, and promotes ingress
capacity over the authenticated return stream before target access. reachability
does not imply anonymous access. See [services](../control/services.md)
and [connector architecture](../connector/architecture.md).

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
