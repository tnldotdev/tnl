# native packet transport

`internal/transport/peer` carries one retained inner QUIC connection over two
relay packet carriers and an optional direct UDP carrier. it owns packet delivery,
not visitor permission, target trust, or application readiness. control and role
owners must independently authorize the exact pair, delivery generation, direction
and serving deadline before supplying a binding.

## ownership

the peer package depends on `muxsession` and the handwritten protocol, never on
control or role startup. `muxsession` owns one outer session; it cannot own the
retained packet endpoint spanning replaceable carriers. tunnel consumes the small
`PeerStreamIntroduction` interface, so the packet owner does not import its
dispatcher or a publisher orchestrator.

when composing an accepted-setup wrapper, retain its complete `Session` and
`AcceptedPeer` capabilities, optional `SetupAuthentication`, and all three
`DatagramSession` methods only when the wrapped transport supports them. borrowing
must return the original transport, not an interface-only wrapper that erases
those methods. the credential owner confirms authentication; TLS, ALPN, hello
parsing and carrier keys never promote pending setup. the separate accepted-setup
and header/credential budgets are ten seconds, not a new serving deadline.

- `Endpoint` implements a stable `net.PacketConn`. bounded fragmentation, replay
  windows and fresh MAC probes belong to that endpoint. the MAC domain remains
  exactly `native_peer` followed by NUL; there is no public packet mode.
- `SharedDatagrams` owns the only datagram reader on a borrowed outer QUIC session.
  `SharedStreams` owns peer introductions, or consumes them from the tunnel's sole
  service stream dispatcher. neither owner closes the borrowed session.
- each shared datagram owner bounds live pairs to 64, queues to 16 frames per pair
  and 256 total, and retained admission generations to 4096. round-robin selection
  happens under the registry lock; cancelable outer writes happen after releasing
  it. retiring a pair cannot retire its siblings.
- `Socket` owns one physical UDP socket for relay QUIC, STUN, ICE and direct packets.
  child cleanup closes only its logical reads. the process owner closes the socket
  after joining its children and borrowed QUIC sessions.

## ice and packet health

Pion remains the ICE engine for gathering, nomination, consent and transaction
validation. the socket owner dispatches STUN requests by local username and replies
by exact transaction/source. non-STUN packets are enqueued only after exactly one
recipient matches; ambiguity drops rather than broadcasting or choosing by map
iteration. a MAC filter helps dispatch but grants no application authority.

ICE consent is not packet delivery. connectivity restarts probing when current
authenticated packet probes fail even if consent succeeds. a selected path index
alone is not evidence of health. replacement signaling still needs the retained
inner connection to recover before its existing idle or authority deadline; no
transport replacement extends that deadline or reopens an application target.

## checks and composition boundary

Run `mise exec -- task go:test:peer-transport -- -race` for real QUIC/TLS-yamux
carriers, reverse inner streams, shared socket and dispatcher consumers. use
`task go:test:fuzz:peer-transport TIME=3s` for a short wire-parser smoke.

These checks do not qualify default CLI/SDK preparation, publisher installation,
readiness, or authorized source/assignment recovery. those role owners compose
this foundation separately. fixed-public forwarding remains ingress -> exact
connected relay -> publisher, without public ICE or reverse-ingress sessions.
