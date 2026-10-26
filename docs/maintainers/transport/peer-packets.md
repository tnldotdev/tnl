# peer packet delivery

`internal/transport/peer` owns one logical packet endpoint beneath an end-to-end
QUIC session. changing the selected carrier changes packet delivery while QUIC
keeps its connection, streams, retransmission, and ordering state.

```text
connecting peer          relay a/b           publisher
      |-- encrypted packets -->|-- packets ------>|
      |                        |                  |
      |<---------- authenticated path probes ---->|
      |<============ direct packets =============>|
      |                        |                  |
      |       direct delivery stops               |
      |-- encrypted packets -->|-- packets ------>|
```

the shared owner is needed because ingress and native connectors need the same
packet lifetime and fallback engine. it depends only on transport mechanics and
the handwritten `pkg/protocol/tunnelv1` contract. it does not import role owners,
control state, or target forwarding. role owners supply authorized carriers and
an introduction key bound to one exact peer pair and publisher run.

## path and authorization boundary

the two relay carriers start warm. direct delivery becomes eligible only after
a fresh, key-bound challenge completes on that carrier. probes bind the sender,
path, sequence, and challenge; replaying relay evidence cannot validate direct
delivery. the production socket/ICE owner must also provide connectivity consent.

the endpoint key authenticates packet delivery, not permission to open an
application stream. publishers still verify signed permission, run/peer binding,
and one logical capacity reservation. a path change creates none of those values.
the role owner cancels the endpoint at its fixed serving deadline.

logical addresses stay stable. quic-go's connection migration APIs do not drive
this delivery switch. inner QUIC detects loss and adjusts its congestion state;
per-carrier probes measure delivery RTT separately from that end-to-end state.

## bounded carriers

inner QUIC uses 1200-byte packets with path MTU discovery disabled. the v1 peer
frame carries at most 1000 payload bytes plus 49 header/authenticator bytes, so
it fits an outer QUIC DATAGRAM on a 1200-byte path. at most two fragments form
an inner packet. a fixed 64-entry ring bounds incomplete reassembly and rejects
completed replays and fragments older than its window.

each carrier has a 64-frame queue, at most 67,136 queued frame bytes. a full queue
drops packets for inner QUIC to recover. an independent writer and bounded send
deadline prevent one backpressured TCP carrier from blocking its sibling.
TCP still orders bytes within that carrier and therefore has head-of-line delay.
canceling the endpoint interrupts all carriers and joins every worker.

## switching proof

run `mise exec -- task go:test:peer-transport -- -race`. the proof uses real
QUIC-datagram and TLS/TCP-yamux relay legs, direct UDP, and one real TCP target
exchange with a monotonic application counter. it exercises both relay fallbacks,
all-TCP operation, half-close, wrong packet evidence, fragment bounds, and an
unread TCP carrier. it reports recovery time, queue peaks, drops, and path RTT.

the role migration supplies shared relay demultiplexing, shared-socket STUN/ICE,
and control-authorized introduction/serving lifetimes around this packet owner.
