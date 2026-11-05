# connector relay reconnection

An authorized connector can replace a lost relay carrier while retaining its
inner QUIC connection, permission control stream, application streams, and target
sockets. The pair, owner, observed source IP, publisher run, relay process, and
publisher assignment must remain the same. A replacement owner or run needs a
new session.

## ownership and packet cuts

[`connectorConnection`](../../internal/connector/stream/peer_connection.go) retries
the lost leg with 100 ms exponential backoff capped at one second. Each attempt
has a two-second ceiling, further bounded by the previous leg and current owner
authority. It never reselects a run or opens an application stream.

[`connectorBridge`](../../internal/relay/connector_delivery.go) retains the
publisher's packet registration while replacing only the connector carrier.
This preserves the publisher's peer owner and replay history on both QUIC and
TLS/TCP. Loss of the publisher connection or its assignment ends this bridge.

[`CarrierSlot`](../../internal/transport/peer/carrier_slot.go) fences new work,
cancels old calls, and joins them. Endpoint queues retain the physical carrier
generation through final input copy and output dispatch. Partial packets cannot
combine fragments across a replacement. Sequence numbers and completed-packet
replay history survive the cut. Relay forwarding binds each sequence's fragments
to its first carrier generation, including on the retained publisher side.
Publisher packets receive their destination generation at shared transport
admission, before buffering; a later dequeue cannot select a successor carrier.

A handoff joins an entered publisher send without canceling it. The send keeps
its original one-second ceiling and bridge authority context so a TLS length
header cannot be separated from its body by connector retirement. Any send
failure ends that bridge; the partially written stream is never reused. Complete
submitted packets are an accepted prefix. Inner QUIC alone retransmits encrypted
packets; repair does not replay application bytes or redial targets.

## uncertain replies and authority

Each reconnect operation retains its predecessor nonce and replacement nonce
across fresh, signed hello attempts. Control already permits a newer claim only
from the same socket-observed source and exact relay process. Replaying a signed
hello remains forbidden. If activation commits but its reply is lost, the relay
accepts a fresh candidate for that same handoff. An older candidate or a retry
from before the next handoff cannot replace the current carrier. The relay keeps
at most 64 handoff identities per bridge.

Reconnection can narrow the previous leg deadline, never extend it. Ordinary
authority renewal remains separate. Denial is terminal; a stale assignment ends
only its leg while independently authorized sibling traffic remains bounded by
the owner's renewal. A missing carrier drops output rather than buffering it.
Temporary loss of both carriers can recover only before the inner QUIC session
or any applicable authority expires. Neither expiry nor cancellation is revived
by a late connection, installation, or renewal.
