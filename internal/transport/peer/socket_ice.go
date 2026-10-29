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
	// Pion can send eight checks per candidate pair before failing it. reserve
	// dispatch for that complete bounded checklist, not just one network family.
	iceSocketTransactions  = tunnelv1.MaxNativePeerCandidates * tunnelv1.MaxNativePeerCandidates * 8
	iceSocketServers       = 128
	iceTransactionLifetime = 10 * time.Second
)

// socketICEMux replaces only Pion's address-keyed UDP dispatch, not its ICE
// engine. requests name the local username fragment; responses name an outbound
// transaction and exact source. neither can steal a sibling's address association.
// discovery still uses Pion, over a bounded logical view of the same UDP socket.
type socketICEMux struct {
	packet        net.PacketConn
	discovery     *ice.UniversalUDPMuxDefault
	discoveryConn *icePacketConn
	mu            sync.Mutex
	conns         map[string]*iceSession
	transactions  map[iceTransactionKey]iceTransaction
	servers       map[netip.AddrPort]struct{}
	closed        bool
	done          chan struct{}
	once          sync.Once
	err           error
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

type iceConnKey struct {
	local netip.AddrPort
	url   string
}

type iceSession struct {
	conns           map[iceConnKey]*icePacketConn
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
	done         chan struct{}
	// guarded by mux.mu, including logical references from host/srflx candidates.
	refs   int
	closed bool
	read   deadline
	write  deadline
}

func newICEPacketConn(m *socketICEMux, ufrag string, accept func([]byte) bool) *icePacketConn {
	c := &icePacketConn{mux: m, ufrag: ufrag, session: newICESession(), acceptPacket: accept, queue: make(chan iceDatagram, iceSocketQueue), done: make(chan struct{})}
	c.read.changed, c.write.changed = make(chan struct{}), make(chan struct{})
	return c
}

func newICESession() *iceSession {
	return &iceSession{conns: make(map[iceConnKey]*icePacketConn), remotes: make(map[netip.AddrPort]*icePacketConn)}
}

func newSocketICEMux(packet net.PacketConn) *socketICEMux {
	m := &socketICEMux{packet: packet, conns: make(map[string]*iceSession), transactions: make(map[iceTransactionKey]iceTransaction), servers: make(map[netip.AddrPort]struct{}), done: make(chan struct{})}
	m.discoveryConn = newICEPacketConn(m, "", nil)
	logger := &logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled}
	m.discovery = ice.NewUniversalUDPMuxDefault(ice.UniversalUDPMuxParams{UDPConn: m.discoveryConn, Logger: logger.NewLogger("ice"), XORMappedAddrCacheTTL: time.Second})
	go m.readLoop()
	return m
}

type agentICEMux struct {
	*socketICEMux
	acceptPacket func([]byte) bool
}

var _ ice.UniversalUDPMux = (*agentICEMux)(nil)

func (m *agentICEMux) GetConn(ufrag string, addr net.Addr) (net.PacketConn, error) {
	return m.getConn(ufrag, "", addr)
}

func (m *agentICEMux) getConn(ufrag, url string, addr net.Addr) (net.PacketConn, error) {
	local, ok := iceRemote(addr)
	bound, valid := iceRemote(m.packet.LocalAddr())
	if !ok || !valid || local.Port() != bound.Port() || !bound.Addr().IsUnspecified() && local != bound {
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
		m.conns[ufrag] = session
	}
	c := session.conns[key]
	if c == nil {
		if len(session.conns) >= tunnelv1.MaxNativePeerCandidates {
			return nil, ErrConfiguration
		}
		c = newICEPacketConn(m.socketICEMux, ufrag, m.acceptPacket)
		c.key, c.session = key, session
		session.conns[key] = c
	}
	c.refs++
	return &icePacketRef{icePacketConn: c}, nil
}

func (m *agentICEMux) GetConnForURL(ufrag, url string, addr net.Addr) (net.PacketConn, error) {
	return m.getConn(ufrag, url, addr)
}

func (m *socketICEMux) GetListenAddresses() []net.Addr { return m.discovery.GetListenAddresses() }
func (m *socketICEMux) GetRelayedAddr(net.Addr, time.Duration) (*net.Addr, error) {
	return nil, errors.ErrUnsupported
}
func (m *socketICEMux) GetXORMappedAddr(addr net.Addr, timeout time.Duration) (*stun.XORMappedAddress, error) {
	return m.GetXORMappedAddrContext(context.Background(), addr, timeout)
}

// Pion's gatherer uses this optional capability to join discovery immediately
// on agent cancellation rather than waiting for the STUN timeout.
func (m *socketICEMux) GetXORMappedAddrContext(ctx context.Context, addr net.Addr, timeout time.Duration) (*stun.XORMappedAddress, error) {
	remote, ok := iceRemote(addr)
	if !ok {
		return nil, ErrConfiguration
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, net.ErrClosed
	}
	if _, found := m.servers[remote]; !found && len(m.servers) >= iceSocketServers {
		m.mu.Unlock()
		return nil, ErrConfiguration
	}
	// Pion retains its mapping cache. bound the number of distinct discovery
	// servers for this socket's lifetime rather than growing that cache forever.
	m.servers[remote] = struct{}{}
	m.mu.Unlock()
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
	})
	return m.err
}

func (m *socketICEMux) stopLocked() {
	m.closed = true
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
	var b [2048]byte
	for {
		n, addr, err := m.packet.ReadFrom(b[:])
		if err != nil {
			return
		}
		remote, ok := iceRemote(addr)
		if !ok {
			continue
		}
		m.dispatch(b[:n], remote)
	}
}

func (m *socketICEMux) dispatch(b []byte, remote netip.AddrPort) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
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
			// all candidates borrow the same physical port. non-QUIC reads do
			// not expose its destination interface, so keep one stable local
			// candidate per agent/remote. fanning nominations out, or changing
			// their reader between checks, can consume a nomination on a different
			// local candidate than the one whose triggered check succeeds.
			if session := m.conns[ufrag]; session != nil {
				c = session.remotes[remote]
				if c == nil {
					c = session.candidateForFamily(remote)
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
	// ICE has no session identifier in application packets. the native consumer
	// supplies its existing packet MAC filter; Pion still checks the selected
	// remote and Endpoint still enforces probes, generations and replay. the
	// low-level NewICE API retains raw packet delivery only when unambiguous.
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
	if c.closed {
		return
	}
	if c.session.queued >= iceSocketQueue {
		return
	}
	select {
	case c.queue <- iceDatagram{append([]byte(nil), b...), remote}:
		c.session.queued++
	default:
	}
}

func (c *icePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		timer, changed := c.read.wait()
		select {
		case <-c.done:
			timer.Stop()
			return 0, nil, net.ErrClosed
		case <-changed:
			timer.Stop()
			continue
		case <-timer.C:
			return 0, nil, os.ErrDeadlineExceeded
		case packet := <-c.queue:
			timer.Stop()
			c.mux.mu.Lock()
			c.session.queued--
			closed := c.closed
			c.mux.mu.Unlock()
			if closed {
				return 0, nil, net.ErrClosed
			}
			if len(b) < len(packet.data) {
				return 0, nil, io.ErrShortBuffer
			}
			return copy(b, packet.data), net.UDPAddrFromAddrPort(packet.remote), nil
		}
	}
}

func (c *icePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(b) > 2048 {
		return 0, io.ErrShortBuffer
	}
	if c.write.expired() {
		return 0, os.ErrDeadlineExceeded
	}
	remote, ok := iceRemote(addr)
	if !ok {
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
					// evict only response dispatch, never a live agent or its peer
					// associations. Pion owns retransmission and rejects unknown or
					// replayed responses independently of this bounded ring.
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
		limit := tunnelv1.MaxNativePeerCandidates
		if c == m.discoveryConn {
			limit = iceSocketServers
		}
		if _, found := c.session.remotes[remote]; !found && len(c.session.remotes) >= limit {
			m.mu.Unlock()
			return 0, ErrConfiguration
		}
		if c.session.remotes[remote] == nil {
			c.session.remotes[remote] = c
		}
	}
	m.mu.Unlock()
	return m.packet.WriteTo(b, addr)
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
		if c.refs == 0 {
			c.mux.removeLocked(c.icePacketConn)
		}
	})
	return nil
}

func nativeICEPacketFilter(config Config) func([]byte) bool {
	key, role := config.Key, config.Role
	return func(b []byte) bool {
		_, ok := authenticatePacket(b, key, role, Direct)
		return ok
	}
}
