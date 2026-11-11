package peer

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/stun/v4"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const (
	iceSocketSessions = 64
	iceSocketQueue    = 64
	// quic-go's shared reader caps UDP packets at 1452 bytes. staying below it
	// lets the dispatcher detect oversized packets rather than deliver truncation.
	iceSocketPacketBytes = 1400
	iceSocketSTUNBytes   = 64
	iceSocketWriteWait   = 100 * time.Millisecond
	// pion can send eight checks per candidate pair before failing it. reserve
	// dispatch for that complete bounded checklist, not just one network family.
	iceSocketTransactions  = tunnelv1.MaxConnectorPeerCandidates * tunnelv1.MaxConnectorPeerCandidates * 8
	iceSocketServers       = 128
	iceTransactionLifetime = 10 * time.Second
)

// socketICEMux replaces only pion's address-keyed UDP dispatch, not its ICE
// engine. requests name the local username fragment; responses name an outbound
// transaction and exact source. neither can steal a sibling's address association.
// discovery still uses pion, over a bounded logical view of the same UDP socket.
type socketICEMux struct {
	packet         net.PacketConn
	discovery      *ice.UniversalUDPMuxDefault
	discoveryConn  *icePacketConn
	localAddresses func() ([]netip.Addr, error)
	mu             sync.Mutex
	conns          map[string]*iceSession
	transactions   map[iceTransactionKey]iceTransaction
	servers        map[netip.AddrPort]struct{}
	discoveries    int
	discoveryCtx   context.Context
	discoveryStop  context.CancelFunc
	discoveryWait  sync.WaitGroup
	closed         bool
	done           chan struct{}
	writes         chan iceSocketWrite
	writeDone      chan struct{}
	once           sync.Once
	err            error
}

type iceTransactionKey struct {
	id     [stun.TransactionIDSize]byte
	remote netip.AddrPort
}

type iceTransaction struct {
	conn    *icePacketConn
	expires time.Time
	slot    int
}

type iceDatagram struct {
	data   []byte
	remote netip.AddrPort
}

type iceSocketWrite struct {
	conn    *icePacketConn
	data    []byte
	remote  netip.AddrPort
	expires time.Time
	result  chan iceSocketWriteResult
}

type iceSocketWriteResult struct {
	n   int
	err error
}

type iceConnKey struct {
	local netip.AddrPort
	url   string
}

type iceSession struct {
	password        string
	conns           map[iceConnKey]*icePacketConn
	refs            int
	queued          int
	remotes         map[netip.AddrPort]*icePacketConn
	transactions    []iceTransactionKey
	nextTransaction int
}

type icePacketConn struct {
	mux          *socketICEMux
	ufrag        string
	key          iceConnKey
	session      *iceSession
	acceptPacket func([]byte) bool
	queue        chan iceDatagram
	ready        chan struct{}
	done         chan struct{}
	// guarded by mux.mu, including logical references from host/srflx candidates.
	refs   int
	closed bool
	read   deadline
	write  deadline
}

func newICEPacketConn(m *socketICEMux, ufrag string, accept func([]byte) bool) *icePacketConn {
	c := &icePacketConn{mux: m, ufrag: ufrag, session: newICESession(), acceptPacket: accept, queue: make(chan iceDatagram, iceSocketQueue), ready: make(chan struct{}, 1), done: make(chan struct{})}
	c.read.changed, c.write.changed = make(chan struct{}), make(chan struct{})
	return c
}

func newICESession() *iceSession {
	return &iceSession{conns: make(map[iceConnKey]*icePacketConn), remotes: make(map[netip.AddrPort]*icePacketConn)}
}

func newSocketICEMux(packet net.PacketConn) *socketICEMux {
	m := &socketICEMux{packet: packet, conns: make(map[string]*iceSession), transactions: make(map[iceTransactionKey]iceTransaction), servers: make(map[netip.AddrPort]struct{}), done: make(chan struct{}), writes: make(chan iceSocketWrite, iceSocketQueue), writeDone: make(chan struct{})}
	m.localAddresses = socketInterfaceAddresses
	m.discoveryCtx, m.discoveryStop = context.WithCancel(context.Background())
	m.discoveryConn = newICEPacketConn(m, "", nil)
	logger := &logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled}
	m.discovery = ice.NewUniversalUDPMuxDefault(ice.UniversalUDPMuxParams{UDPConn: m.discoveryConn, Logger: logger.NewLogger("ice"), XORMappedAddrCacheTTL: time.Second})
	go m.readLoop()
	go m.writeLoop()
	return m
}

type agentICEMux struct {
	*socketICEMux
	acceptPacket    func([]byte) bool
	includeLoopback bool
	password        string
}

var _ ice.UniversalUDPMux = (*agentICEMux)(nil)

// the agent borrows this view; only the socket owner may close the dispatcher.
func (m *agentICEMux) Close() error { return nil }

func (m *agentICEMux) GetConn(ufrag string, addr net.Addr) (net.PacketConn, error) {
	return m.getConn(ufrag, "", addr)
}

func (m *agentICEMux) getConn(ufrag, url string, addr net.Addr) (net.PacketConn, error) {
	local, ok := iceRemote(addr)
	bound, valid := iceRemote(m.packet.LocalAddr())
	if !ok || !valid || local.Addr().IsUnspecified() || local.Port() != bound.Port() || !bound.Addr().IsUnspecified() && local != bound || len(url) > 2048 {
		return nil, ErrConfiguration
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, net.ErrClosed
	}
	key := iceConnKey{local, url}
	session := m.conns[ufrag]
	if session == nil {
		if ufrag == "" || len(ufrag) > 256 || len(m.conns) >= iceSocketSessions {
			return nil, ErrConfiguration
		}
		session = newICESession()
		session.password = m.password
		m.conns[ufrag] = session
	}
	if session.refs >= tunnelv1.MaxConnectorPeerCandidates {
		return nil, ErrConfiguration
	}
	c := session.conns[key]
	if c == nil {
		c = newICEPacketConn(m.socketICEMux, ufrag, m.acceptPacket)
		c.key, c.session = key, session
		session.conns[key] = c
	}
	c.refs++
	session.refs++
	return &icePacketRef{icePacketConn: c}, nil
}

func (m *agentICEMux) GetConnForURL(ufrag, url string, addr net.Addr) (net.PacketConn, error) {
	return m.getConn(ufrag, url, addr)
}

func (m *agentICEMux) GetListenAddresses() []net.Addr {
	bound, ok := iceRemote(m.packet.LocalAddr())
	if !ok {
		return nil
	}
	ips := []netip.Addr{bound.Addr()}
	if bound.Addr().IsUnspecified() {
		// the discovery mux's default network caches interfaces at construction.
		// enumerate afresh without replacing the shared mux or sibling agents.
		var err error
		ips, err = m.localAddresses()
		if err != nil {
			return nil
		}
	}
	var addresses []net.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		if validConnectivityIP(ip) && (!bound.Addr().Is4() || ip.Is4()) && (m.includeLoopback || !ip.IsLoopback()) {
			addresses = append(addresses, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, bound.Port())))
		}
	}
	return addresses
}

func socketInterfaceAddresses() ([]netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addresses {
			if prefix, err := netip.ParsePrefix(addr.String()); err == nil {
				ips = append(ips, prefix.Addr())
			}
		}
	}
	return ips, nil
}

func (m *socketICEMux) GetRelayedAddr(net.Addr, time.Duration) (*net.Addr, error) {
	return nil, errors.ErrUnsupported
}

func (m *socketICEMux) GetXORMappedAddr(addr net.Addr, timeout time.Duration) (*stun.XORMappedAddress, error) {
	return m.GetXORMappedAddrContext(context.Background(), addr, timeout)
}

// pion's gatherer uses this optional capability to join discovery immediately
// on agent cancellation rather than waiting for the STUN timeout.
func (m *socketICEMux) GetXORMappedAddrContext(ctx context.Context, addr net.Addr, timeout time.Duration) (*stun.XORMappedAddress, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	remote, ok := iceRemote(addr)
	if !ok || !validConnectivityIP(remote.Addr()) {
		return nil, ErrConfiguration
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, net.ErrClosed
	}
	if _, found := m.servers[remote]; !found && len(m.servers) >= iceSocketServers || m.discoveries >= iceSocketServers {
		m.mu.Unlock()
		return nil, ErrConfiguration
	}
	// pion retains its mapping cache. bound distinct discovery servers for this
	// socket's lifetime, and bound concurrent transactions even for one server.
	m.servers[remote] = struct{}{}
	m.discoveries++
	m.discoveryWait.Add(1)
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.discoveries--
		m.mu.Unlock()
		m.discoveryWait.Done()
	}()
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(m.discoveryCtx, cancel)
	defer stop()
	defer cancel()
	return m.discovery.GetXORMappedAddrContext(ctx, addr, min(timeout, 2*time.Second))
}

func (m *socketICEMux) RemoveConnByUfrag(ufrag string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if session := m.conns[ufrag]; session != nil {
		for _, c := range session.conns {
			m.removeLocked(c)
		}
	}
}

func (m *socketICEMux) removeLocked(c *icePacketConn) {
	if c.closed {
		return
	}
	c.closed = true
	close(c.done)
	if c.session.conns[c.key] == c {
		delete(c.session.conns, c.key)
		if len(c.session.conns) == 0 && m.conns[c.ufrag] == c.session {
			delete(m.conns, c.ufrag)
		}
	}
	for _, key := range c.session.transactions {
		if transaction, ok := m.transactions[key]; ok && transaction.conn == c {
			delete(m.transactions, key)
		}
	}
	for remote, owner := range c.session.remotes {
		if owner == c {
			delete(c.session.remotes, remote)
		}
	}
	for {
		select {
		case <-c.queue:
			c.session.queued--
		default:
			return
		}
	}
}

func (m *socketICEMux) Close() error {
	m.once.Do(func() {
		m.mu.Lock()
		m.stopLocked()
		m.mu.Unlock()
		m.err = errors.Join(m.packet.Close(), m.discovery.Close())
		<-m.done
		<-m.writeDone
		m.discoveryWait.Wait()
	})
	return m.err
}

func (m *socketICEMux) stopLocked() {
	m.closed = true
	m.discoveryStop()
	for _, session := range m.conns {
		for _, c := range session.conns {
			m.removeLocked(c)
		}
	}
	m.removeLocked(m.discoveryConn)
}

func iceRemote(addr net.Addr) (netip.AddrPort, bool) {
	a, ok := addr.(*net.UDPAddr)
	if !ok || a.Port < 1 || a.Port > 65535 {
		return netip.AddrPort{}, false
	}
	p := a.AddrPort()
	if !p.IsValid() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(p.Addr().Unmap(), p.Port()), true
}

func iceFamily(addr netip.AddrPort) int {
	if addr.Addr().Is6() {
		return 1
	}
	return 0
}

func (m *socketICEMux) readLoop() {
	defer func() {
		m.mu.Lock()
		m.stopLocked()
		m.mu.Unlock()
		close(m.done)
	}()
	var b [iceSocketPacketBytes + 1]byte
	for {
		n, addr, err := m.packet.ReadFrom(b[:])
		if err != nil {
			return
		}
		remote, ok := iceRemote(addr)
		if !ok || n > iceSocketPacketBytes {
			continue
		}
		m.dispatch(b[:n], remote)
	}
}

// one socket-owned writer bounds work even if the physical connection stalls.
// logical callers can retire without mutating the shared socket's deadlines;
// the socket owner closes the physical connection before joining this worker.
func (m *socketICEMux) writeLoop() {
	defer func() {
		for {
			select {
			case request := <-m.writes:
				request.result <- iceSocketWriteResult{err: net.ErrClosed}
			default:
				close(m.writeDone)
				return
			}
		}
	}()
	for {
		select {
		case <-m.done:
			return
		case request := <-m.writes:
			m.mu.Lock()
			closed := m.closed || request.conn.closed
			m.mu.Unlock()
			result := iceSocketWriteResult{}
			switch {
			case closed:
				result.err = net.ErrClosed
			case time.Now().After(request.expires) || request.conn.write.expired():
				result.err = os.ErrDeadlineExceeded
			default:
				result.n, result.err = m.packet.WriteTo(request.data, net.UDPAddrFromAddrPort(request.remote))
			}
			request.result <- result
		}
	}
}

func (c *icePacketConn) writePacket(b []byte, remote netip.AddrPort) (int, error) {
	request := iceSocketWrite{conn: c, data: append([]byte(nil), b...), remote: remote, expires: time.Now().Add(iceSocketWriteWait), result: make(chan iceSocketWriteResult, 1)}
	c.mux.mu.Lock()
	if c.closed || c.mux.closed {
		c.mux.mu.Unlock()
		return 0, net.ErrClosed
	}
	select {
	case c.mux.writes <- request:
	default:
		c.mux.mu.Unlock()
		return 0, ErrConfiguration
	}
	c.mux.mu.Unlock()
	budget := time.NewTimer(time.Until(request.expires))
	defer budget.Stop()
	for {
		timer, changed := c.write.wait()
		select {
		case <-c.done:
			timer.Stop()
			return 0, net.ErrClosed
		case result := <-request.result:
			timer.Stop()
			return result.n, result.err
		case <-changed:
			timer.Stop()
		case <-timer.C:
			return 0, os.ErrDeadlineExceeded
		case <-budget.C:
			timer.Stop()
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (m *socketICEMux) dispatch(b []byte, remote netip.AddrPort) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || len(b) > iceSocketPacketBytes {
		return
	}
	if stun.IsMessage(b) {
		message := &stun.Message{Raw: b}
		if message.Decode() != nil {
			return
		}
		var c *icePacketConn
		switch message.Type.Class {
		case stun.ClassRequest, stun.ClassIndication:
			username, err := message.Get(stun.AttrUsername)
			if err != nil {
				return
			}
			ufrag, _, ok := strings.Cut(string(username), ":")
			if !ok {
				return
			}
			// non-QUIC reads do not expose the destination interface. keep one
			// stable local candidate per agent/remote, so nomination requests and
			// their triggered checks reach the same candidate reader.
			if session := m.conns[ufrag]; session != nil {
				c = session.remotes[remote]
				if c == nil {
					// pion allocates peer-reflexive candidates before writing its reply.
					// authenticate and reserve a bounded source before handing it over;
					// forged checks cannot consume another agent's address budget.
					if len(session.remotes) >= tunnelv1.MaxConnectorPeerCandidates || message.Type != stun.BindingRequest || session.password == "" || stun.MessageIntegrity([]byte(session.password)).Check(message) != nil {
						return
					}
					c = session.candidateForFamily(remote)
					if c != nil {
						session.remotes[remote] = c
					}
				}
			}
		case stun.ClassSuccessResponse, stun.ClassErrorResponse:
			key := iceTransactionKey{message.TransactionID, remote}
			if tx, ok := m.transactions[key]; ok {
				if time.Now().Before(tx.expires) {
					c = tx.conn
				} else {
					delete(m.transactions, key)
				}
			}
		}
		if c != nil {
			c.enqueueLocked(b, remote)
		}
		return
	}
	// ICE application packets have no session identifier. the signaling owner
	// supplies an attempt-specific authentication filter; pion still checks the
	// selected remote. raw delivery is safe only when it has one recipient.
	var recipient *icePacketConn
	for _, session := range m.conns {
		c := session.remotes[remote]
		if c == nil || c.closed || c.acceptPacket != nil && !c.acceptPacket(b) {
			continue
		}
		if recipient != nil {
			return
		}
		recipient = c
	}
	if recipient != nil {
		recipient.enqueueLocked(b, remote)
	}
}

func (s *iceSession) candidateForFamily(remote netip.AddrPort) *icePacketConn {
	var selected *icePacketConn
	for key, c := range s.conns {
		if iceFamily(key.local) != iceFamily(remote) {
			continue
		}
		if selected == nil || key.local.Compare(selected.key.local) < 0 || key.local == selected.key.local && key.url < selected.key.url {
			selected = c
		}
	}
	return selected
}

func (c *icePacketConn) enqueueLocked(b []byte, remote netip.AddrPort) {
	if c.closed || c.session.queued >= iceSocketQueue {
		return
	}
	select {
	case c.queue <- iceDatagram{append([]byte(nil), b...), remote}:
		c.session.queued++
		c.notifyLocked()
	default:
	}
}

func (c *icePacketConn) notifyLocked() {
	select {
	case c.ready <- struct{}{}:
	default:
	}
}

func (c *icePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		// dequeue and account under one lock, including close. a blocked reader
		// cannot leave an unaccounted packet behind while its sibling is closed.
		c.mux.mu.Lock()
		if c.closed {
			c.mux.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		if c.read.expired() {
			c.mux.mu.Unlock()
			return 0, nil, os.ErrDeadlineExceeded
		}
		select {
		case packet := <-c.queue:
			c.session.queued--
			if len(c.queue) != 0 {
				c.notifyLocked()
			}
			c.mux.mu.Unlock()
			if len(b) < len(packet.data) {
				return 0, nil, io.ErrShortBuffer
			}
			return copy(b, packet.data), net.UDPAddrFromAddrPort(packet.remote), nil
		default:
		}
		timer, changed := c.read.wait()
		c.mux.mu.Unlock()
		select {
		case <-c.done:
		case <-c.ready:
		case <-changed:
		case <-timer.C:
		}
		timer.Stop()
	}
}

func (c *icePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	originalSize := len(b)
	if len(b) > iceSocketPacketBytes {
		return 0, io.ErrShortBuffer
	}
	if c.write.expired() {
		return 0, os.ErrDeadlineExceeded
	}
	remote, ok := iceRemote(addr)
	if !ok || remote.Addr().IsUnspecified() || remote.Addr().IsMulticast() {
		return 0, ErrConfiguration
	}
	m := c.mux
	m.mu.Lock()
	if c.closed || m.closed {
		m.mu.Unlock()
		return 0, net.ErrClosed
	}
	if stun.IsMessage(b) {
		message := &stun.Message{Raw: b}
		if message.Decode() != nil {
			m.mu.Unlock()
			return 0, ErrConfiguration
		}
		if c == m.discoveryConn && message.Type == stun.BindingRequest && len(b) < iceSocketSTUNBytes {
			var err error
			b, err = padSocketSTUN(message)
			if err != nil {
				m.mu.Unlock()
				return 0, err
			}
		}
		limit := tunnelv1.MaxConnectorPeerCandidates
		if c == m.discoveryConn {
			limit = iceSocketServers
		}
		if _, found := c.session.remotes[remote]; !found && len(c.session.remotes) >= limit {
			m.mu.Unlock()
			return 0, ErrConfiguration
		}
		if message.Type.Class == stun.ClassRequest {
			key := iceTransactionKey{message.TransactionID, remote}
			old, found := m.transactions[key]
			if found && old.conn != c {
				m.mu.Unlock()
				return 0, ErrConfiguration
			}
			slot := old.slot
			if !found {
				limit := iceSocketTransactions
				if c == m.discoveryConn {
					limit = iceSocketServers
				}
				session := c.session
				if len(session.transactions) < limit {
					slot = len(session.transactions)
					session.transactions = append(session.transactions, key)
				} else {
					// evict response dispatch only, never agents or peer associations.
					// pion owns retransmission and rejects unknown responses itself.
					slot = session.nextTransaction
					previous := session.transactions[slot]
					if tx, ok := m.transactions[previous]; ok && tx.conn.session == session && tx.slot == slot {
						delete(m.transactions, previous)
					}
					session.transactions[slot] = key
					session.nextTransaction = (session.nextTransaction + 1) % limit
				}
			}
			m.transactions[key] = iceTransaction{conn: c, expires: time.Now().Add(iceTransactionLifetime), slot: slot}
		}
		if c.session.remotes[remote] == nil {
			c.session.remotes[remote] = c
		}
	}
	m.mu.Unlock()
	n, err := c.writePacket(b, remote)
	if err == nil && n != len(b) {
		return 0, io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	return originalSize, nil
}

// relay discovery requires a request at least as large as its bounded response.
// rebuild the public binding request so padding precedes a recomputed fingerprint.
func padSocketSTUN(request *stun.Message) ([]byte, error) {
	if request.Contains(stun.AttrMessageIntegrity) || request.Contains(stun.AttrMessageIntegritySHA256) {
		return nil, ErrConfiguration
	}
	setters := []stun.Setter{stun.NewTransactionIDSetter(request.TransactionID), stun.BindingRequest}
	for _, attr := range request.Attributes {
		if attr.Type != stun.AttrFingerprint {
			setters = append(setters, attr)
		}
	}
	// attribute headers and values are multiples of four on the wire.
	padding := iceSocketSTUNBytes - len(request.Raw) - 4
	setters = append(setters, stun.RawAttribute{Type: stun.AttrPadding, Value: make([]byte, padding)})
	if request.Contains(stun.AttrFingerprint) {
		setters = append(setters, stun.Fingerprint)
	}
	message, err := stun.Build(setters...)
	if err != nil {
		return nil, err
	}
	return message.Raw, nil
}

func (c *icePacketConn) LocalAddr() net.Addr { return c.mux.packet.LocalAddr() }

func (c *icePacketConn) Close() error {
	c.mux.mu.Lock()
	defer c.mux.mu.Unlock()
	c.mux.removeLocked(c)
	return nil
}

func (c *icePacketConn) SetReadDeadline(t time.Time) error  { c.read.set(t); return nil }
func (c *icePacketConn) SetWriteDeadline(t time.Time) error { c.write.set(t); return nil }
func (c *icePacketConn) SetDeadline(t time.Time) error      { c.read.set(t); c.write.set(t); return nil }

type icePacketRef struct {
	*icePacketConn
	once sync.Once
}

func (c *icePacketRef) Close() error {
	c.once.Do(func() {
		c.mux.mu.Lock()
		defer c.mux.mu.Unlock()
		c.refs--
		c.session.refs--
		if c.refs == 0 {
			c.mux.removeLocked(c.icePacketConn)
		}
	})
	return nil
}
