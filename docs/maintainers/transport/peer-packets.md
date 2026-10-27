# peer packet delivery

`internal/transport/peer` owns one logical packet endpoint beneath an end-to-end
QUIC session. changing the selected carrier changes packet delivery while QUIC
keeps its connection, streams, retransmission, and ordering state.

```text
public:
publisher                   ingress
    |---- outbound UDP/TCP ---->|
    |<--- authenticated probes ->|

native:
connector                relay a/b               publisher
    |-- encrypted packets -->|-- packets ------------>|
    |<------------- authenticated probes ------------>|
    |<============== direct packets ==================>|
```

the shared owner is needed because ingress and native connectors need the same
packet lifetime and fallback engine. it depends only on transport mechanics and
the handwritten `pkg/protocol/tunnelv1` contract. it does not import role owners,
control state, or target forwarding. role owners supply authorized carriers and
an introduction key bound to one exact peer pair and publisher run.

## path and authorization boundary

public peers use two publisher-initiated ingress carriers, UDP and framed
TLS/TCP-yamux. they do not use relay placement or ICE. native peers use two
distinct relay carriers and may later upgrade delivery to direct UDP. the mode
is explicit at endpoint creation; a public endpoint rejects a direct carrier,
and the packet MAC separates public from native even if a key is misused.

the two native relay carriers start warm. direct delivery becomes eligible only
after a fresh, key-bound challenge completes on that carrier. probes bind the sender,
path, sequence, and challenge; replaying relay evidence cannot validate direct
delivery. the production socket/ICE owner must also provide connectivity consent.

the endpoint key authenticates packet delivery, not permission to open an
application stream. publishers still verify signed permission, run/peer binding,
and one logical capacity reservation. a path change creates none of those values.
the role owner cancels the endpoint at its fixed serving deadline.

the [peer visitor opening](../../../pkg/protocol/tunnelv1/native_peer_opening.go)
is separate from ingress forwarding. its signed native proof binds the pair,
delivery ID, run, subject, visitor ID, relay-attested source, token, and first
bytes. [local verification](../../../internal/security/visitortoken/binding.go)
requires a current publisher-supplied pair deadline and compares the body's
source to the checked relay claim. the publisher must still bind current IP
policy and reserve one run-wide stream slot before dialing any target.

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

`SharedDatagrams` borrows one authenticated outer QUIC session (with DATAGRAMs
opted in on both sides) and exclusively reads its datagrams. the role owner
registers each exact introduction with a control-issued 16-byte delivery ID,
an increasing delivery generation, key, direction, and path. each v1 envelope
includes a 25-byte header and an independent 32-byte tag over the header and
complete inner frame, including its MAC. the tag separates datagrams from
TLS/yamux streams even if two pairs are mistakenly assigned the same key. the
largest envelope is 1106 bytes.
the owner verifies the tag, frame MAC, direction, path, and a 64-sequence
fragment replay window before queuing it. a delivery ID alone does not grant
access. per-peer ingress and egress queues each hold 16 frames; egress
holds at most 256 frames across 64 peers. the writer visits nonempty peers in
round-robin order. the owner retains at most 4096 pair tombstones per
outer session to reject a reused or stale generation; rotate the session when full.
closing one registration discards its queue without closing the QUIC connection.
the saved `npp_…` pair ID selects control's authorization record. it is not the
binary delivery ID and must never be truncated into the packet header.

`SharedStreams` can accept peer streams exclusively or take classified streams
from `tunnel.ServiceStreamDispatcher` on one authenticated TLS/yamux session.
the opener writes the same delivery header; the acceptor requires a
stream-mode-tagged first framed envelope matching that header before handing
the stream to its pair. every later framed envelope is checked against the
same pair, generation, and replay window. at most eight readers handle
introductions concurrently, each with a one-second deadline, so one incomplete
stream does not hold up another pair. shutdown interrupts and joins the readers.
unknown generations, duplicate streams, and incomplete introductions are closed.
`StreamPair.Open` and `StreamPair.Accept` hand out one `Carrier` per peer;
`CarrierSlot` may install a later stream without replacing the inner QUIC
session. each owner must join `Close` before retiring its outer session. the
dispatcher is the only `AcceptStream` reader when peer and service-forwarding
streams share the session: the first byte is `1` for the peer delivery header,
while the four-byte big-endian forwarding JSON length starts with `0` (the v1
limit is 8192 bytes). it bounds the frame, validates the service header, and
replays the original bytes to the authenticated tunnel's existing assignment
check. eight short-lived classifiers, eight peer introductions, and eight
forwarding header readers run independently with one-second read deadlines;
the forwarding queue holds at most 32 streams and expires unclaimed streams
after ten seconds. if all classifiers are stalled before their first byte, a
new stream interrupts the oldest incomplete classifier. over-capacity or
malformed streams close. the caller joins the dispatcher before closing the
peer owner and then the outer session. the role owner still authorizes peer
bindings and forwarding assignments.
normal pair closure leaves the outer session and sibling streams alive.
`muxsession` aborts an outer session only if yamux stream cleanup remains stuck
past its existing bounded timeout; role owners then reconnect.

## switching proof

run `mise exec -- task go:test:peer-transport -- -race`. the proof uses real
QUIC-datagram and TLS/TCP-yamux relay legs, direct UDP, and one real TCP target
exchange with a monotonic application counter. it exercises both relay fallbacks,
all-TCP operation, half-close, wrong packet evidence, fragment bounds, and an
unread TCP carrier. a public peer proof switches its existing inner QUIC stream
from UDP to TCP and back with no relay or ICE path. both report recovery time,
queue peaks, drops, and path RTT.
the shared-carrier proof multiplexes two exact pairs on one outer QUIC session,
keeps their inner QUIC streams alive across a pair-specific UDP-to-TLS/yamux
switch, and keeps one real TCP target connection through the switch. it also
checks same-key header relabeling, cross-mode injection, stale generations,
replays, bounded queues, sibling delivery past an incomplete introduction,
and peer shutdown without normally closing either outer session.
the mixed-session proof also uses real TLS/yamux with the v1 tunnel handshake:
stalled peer introductions do not delay an existing service-forwarding opening,
and two sibling peer pairs receive tagged first frames on that session.

## socket and replacement lifetime

`peer.Socket` owns the UDP socket used for relay QUIC and a Pion universal ICE
mux. quic-go dispatches STUN and v1 peer frames through its non-QUIC reader;
both have their first two bits clear. STUN discovery, ICE checks, and selected
direct delivery therefore use the same mapped port as relay QUIC. IPv4, IPv6,
and eligible local host candidates come from that mux. closing an ICE agent
leaves sibling agents and relay QUIC alive. library logging is disabled; role
owners report bounded outcomes through the existing observability boundary.

relay and standalone answer STUN Binding requests on their existing QUIC socket.
the server bounds request size and response rate and ignores ICE-authenticated
requests intended for a peer. its operational counter has fixed result labels.

the relay's opt-in native connector admission checks a `native_connector` hello
on the first authenticated control stream of a real accepted QUIC or TLS/yamux
session. only an explicitly configured direct-socket acceptor uses the accepted
socket's remote IP. it matches the current relay process lease and signing key,
signs that source with the process key, and calls control's checked pair-leg
claim before acknowledging. before the control claim, its local owner reserves
one of 64 native sessions by default, with at most two reservations per exact
pair, generation, and leg. the reservation covers claims in progress and the
acknowledged session; denial, close, cancellation, relay drain (checked every
100 ms), and the fixed claim deadline release it. it does not use publisher
connection capacity. without a configured publisher registry, this remains a
claim-only proof that closes after at most ten seconds. production relay
listeners do not configure native admission yet, so native connector hellos fail
closed.

the opt-in [relay packet handoff](../../../internal/relay/native_peer_delivery.go)
requires the exact local service, run, publisher connection, slot, assignment
revision, and relay process lease before acknowledging the connector. it borrows
the authenticated publisher session and registers only the checked control-issued
delivery ID, generation, key, direction, and path. QUIC must negotiate DATAGRAMs;
TLS/yamux uses bounded framed streams. the relay copies authenticated encrypted
frames in both directions, not application openings. publisher application
admission remains independent. the publisher endpoint must already have its own
control-prepared registration; the relay does not supply that authority.

control includes its observation time in the claim. the relay computes the local
deadline from request start plus the observed remaining duration, at most five
minutes, rejecting a response already expired in transit. it cannot restart this
deadline when delivery begins. publisher replacement, drain, close, cancellation,
or claim expiry interrupt and join the packet workers and partial introductions.
closing one pair removes its live registration while retaining the generation
tombstone; it leaves sibling pairs and the borrowed publisher session alive.

a relay behind a load balancer sees the balancer's address on its socket. that
socket cannot prove the connector source. a future PROXY source mode needs an
explicitly trusted listener and verified metadata before it can be wired to
native admission; SNI, connector frames, STUN/ICE and HTTP forwarded-IP headers
are not source authorities.

`CarrierSlot` accepts a late ICE result or a replacement relay carrier while
the logical endpoint keeps serving. installing a carrier fences old queued
packets and invalidates the previous path's probe evidence. the new carrier must
complete a fresh peer round trip before direct application delivery. failed
preparation, network changes, and late setup racing shutdown have joined cleanup.

[control state](../../../internal/control/state/native_peer_pairs.go) prepares an
exact native pair only after checking the signed enrolled subject, current
visitor access, ready publisher run and two distinct relay assignments. its
stored deadline advances only after a fresh authorized renewal; an uncertain
response repeats the same key and delivery generation. the transport binding
is not a publisher grant or permission to open an application stream.
[relay native admission](../../../internal/relay/native_connector.go) claims each
signed leg using the directly accepted socket's source. only after control
confirms that claim does the relay send a bounded `hello_accepted` receipt with
the source, exact delivery ID, pair, generation, slot, observation time, and
expiry. the connector subtracts the entire setup delay from the observed
remaining duration; it does not compare its clock with the relay's. the pair key
stays in the private control claim. [native dialing](../../../internal/transport/tunnel/session.go)
requires the delivery ID from the prepared pair and rejects a missing, expired,
or mismatched receipt before returning the session. only an explicitly configured
packet owner accepts further native streams under the fixed pair lifetime.
the publisher's run-token-only delivery request requires two current relay claims
with the same source before it returns the existing pair key. publisher
preparation converts control's observation and expiry to a local request-start
deadline; it cannot add serving time for a slow response or clock skew.
the run-token-only candidate inventory returns at most 64 pair ID/generation
references per page, without keys, subjects, or source addresses. it includes
unclaimed pairs so background preparation can reconcile them later; neither a
listed candidate nor a missed page changes serving authority. each pass restarts
at the first page, and every binding still needs the checked delivery request.
[connector preparation](../../../internal/connector/stream/peer_preparation.go)
can sign, recover, and renew a pair in background work using the enrolled device
or workload key. opting into native delivery denies the existing ingress
application path; a preparation failure never selects ingress instead.

the publisher reports installation only after both exact carrier registrations
and the inner QUIC listener exist. control rechecks the exact run token, delivery
ID/generation, parent authority, assignments, and two matching source claims
before recording `publisher_prepared_until`. the report returns no key and does
not renew authority. pair renewal alone cannot advance this barrier; replacement
starts without a report. narrower authority durably clips the report so a later
renewal cannot restore its older, longer deadline.

connector background work can read an unconfirmed pair for relay setup. packet
startup has a separate local read requiring an unexpired publisher report; it
never signs, contacts control, or waits for ICE. while confirmation is absent or
near expiry, preparation polls with the last exact signed proof, not a fresh
authorization. only a due pair renewal signs a new proof. control includes
`observed_at`; connector pair and report deadlines use request start plus the
observed remaining duration, rejecting authority expired in transit. the report
is an installation snapshot, not application permission or process liveness.

the publisher's [peer session](../../../internal/publisher/service/peer_admission.go)
accepts streams only against a control-prepared binding for the exact run and
its current assignments. both relay paths share this owner, its retained visitor
IDs, and the run's stream budget. capacity is reserved before decoding; permission
and IP policy are verified before managed visitor TLS or target work. a carrier
change does not create a second admission. the owner keeps at most 4096 visitor
IDs per pair and 64 pair owners per run, including stopped pairs retained for
the five-minute token replay window. close, assignment replacement, and the fixed
pair deadline interrupt and join its streams.
[packet serving](../../../internal/publisher/service/peer_packets.go) attaches
one inner QUIC connection to that owner using already-authorized carriers. it
uses the prepared service certificate, bounds stream readers, and preserves
admission and the target socket through a carrier failure.

the publisher run's opt-in `NativePeers` setting starts
[background reconciliation](../../../internal/publisher/service/peer_preparation.go).
one candidate page is read per second, with at most 64 queued/in-progress pair
preparations and four control-request workers. an unclaimed candidate is retried
on a later pass. current owners renew only from independently fetched bindings;
failed renewal never extends their last confirmed deadline. cancellation joins
preparation and all delivery sessions. the same replay retention bounds prevent
stopped pairs from being revived or forgotten early.

peer-capable claimed publisher slots register exact pairs on shared QUIC
DATAGRAMs or TLS/yamux streams. QUIC must negotiate DATAGRAMs before its hello
can consume a single-use publisher assignment; otherwise TCP remains eligible.
TLS/yamux has one service dispatcher for peer and existing forwarding streams.
closing one claimed slot leaves an admitted inner session using its other slot.
the publisher proof exercises all four slot transport combinations with one
admission and one target socket, but uses checked relay-session fixtures rather
than the control-backed relay bridge.

the opt-in [connector owner](../../../internal/connector/stream/peer_connection.go)
borrows one UDP socket for both relay QUIC attempts. each slot races QUIC against
TLS/TCP-yamux with fresh signed leg proofs and joins canceled or late losers.
both checked receipts must report the same source. the owner waits for the
publisher installation snapshot before starting packet probes or one inner QUIC
connection. application arrival reads only local prepared state and signs the
application permission, not pair setup. openings are never retried. a temporary
preparation outage fences new applications; existing streams retain only their
last confirmed authority. expiration or changed assignments stop the owner.

the control-backed continuity proof runs with
`mise exec -- task go:test:integration RUN='^TestIntegrationPeerPackets'`.
it uses disposable PostgreSQL, two real direct-socket relays, and no ingress.
QUIC and TLS/TCP publishers each serve all connector carrier combinations.
UDP packet loss and closing a native outer TCP session leave one target socket
and its monotonic application counter intact. this fixture does not qualify
load-balancer source handling or assignment replacement.

production publishers and connectors do not enable `NativePeers` yet, and
production relays leave native admission disabled. a relay hello receipt proves
its own checked claim, not publisher installation or application permission.
pair renewal does not extend an existing relay leg's fixed claim deadline.
checked leg renewal, assignment/source rebinding, and ICE integration remain
required before enabling the native path.
