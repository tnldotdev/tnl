package peer

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v4"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ConnectivityState string

const (
	ConnectivityChecking     ConnectivityState = "checking"
	ConnectivityDirect       ConnectivityState = "direct"
	ConnectivityRelay        ConnectivityState = "relay"
	connectivitySetupTimeout                   = 10 * time.Second
	connectivityRetryDelay                     = 5 * time.Second
)

// connectivity settings belong to the native owner, never an application opening.
type ConnectivityOptions struct {
	DisableDirect   bool
	IncludeLoopback bool
	Observe         func(ConnectivityState)
	ObserveAttempt  func(ConnectivityAttempt)
	ObserveFallback func()
}

type ConnectivityAttempt struct {
	Outcome  string
	Duration time.Duration
}

type ConnectivityBinding struct {
	Revision       BindingRevision
	DeliveryID     string
	RelayAddresses [2]string
}

type ConnectivityError struct {
	Code  tunnelv1.ErrorCode
	Cause error
}

func (e *ConnectivityError) Error() string { return "prepare direct UDP delivery" }
func (e *ConnectivityError) Unwrap() error { return e.Cause }

func connectivityInvalid(err error) error {
	return &ConnectivityError{Code: tunnelv1.InvalidMessage, Cause: err}
}

type connectivityNextOffer struct {
	message tunnelv1.ConnectorPeerConnectivity
}

func (*connectivityNextOffer) Error() string { return "replace direct UDP attempt" }

// Connectivity owns successive agents and a single signaling reader on one
// existing inner connection. native owners update only authenticated active
// bindings; suspension cancels an attempt without changing any authority clock.
type Connectivity struct {
	socket      *Socket
	connection  *quic.Conn
	packets     *Endpoint
	controlling bool
	options     ConnectivityOptions
	admit       func(tunnelv1.PeerPacket) bool
	mu          sync.Mutex
	binding     ConnectivityBinding
	changed     chan struct{}
	stopAttempt context.CancelFunc
	serving     atomic.Bool
}

func NewConnectivity(socket *Socket, connection *quic.Conn, packets *Endpoint, controlling bool, options ConnectivityOptions, admit func(tunnelv1.PeerPacket) bool) *Connectivity {
	return &Connectivity{socket: socket, connection: connection, packets: packets, controlling: controlling, options: options, admit: admit, changed: make(chan struct{})}
}

func (c *Connectivity) SetBinding(binding ConnectivityBinding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.binding == binding {
		return
	}
	c.binding = binding
	if c.stopAttempt != nil {
		c.stopAttempt()
	}
	close(c.changed)
	c.changed = make(chan struct{})
}

func (c *Connectivity) Suspend() { c.SetBinding(ConnectivityBinding{}) }

func (c *Connectivity) observe(state ConnectivityState) {
	if c.options.Observe != nil {
		c.options.Observe(state)
	}
}

func (c *Connectivity) snapshot() (ConnectivityBinding, <-chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.binding, c.changed
}

func (c *Connectivity) Serve(parent context.Context) error {
	if c.options.DisableDirect {
		return nil
	}
	if c.socket == nil || c.connection == nil || c.packets == nil {
		return connectivityInvalid(ErrConfiguration)
	}
	if !c.serving.CompareAndSwap(false, true) {
		return connectivityInvalid(ErrConfiguration)
	}
	ctx, cancel := context.WithCancel(parent)
	stop := interruptOnCancel(c.connection.Context(), func() error { cancel(); return nil })
	defer stop()
	signals := make(chan connectivitySignal, 1)
	readerDone := make(chan struct{})
	go func() { defer close(readerDone); readConnectivitySignals(ctx, c.connection, signals) }()
	defer func() { cancel(); <-readerDone }()
	defer c.observe(ConnectivityRelay)
	var attempt, previous uint64
	var lastStarted time.Time
	var pending *tunnelv1.ConnectorPeerConnectivity
	for {
		binding, changed := c.snapshot()
		revision, active := c.packets.CurrentBinding()
		if binding.DeliveryID == "" || !active || revision != binding.Revision {
			select {
			case <-ctx.Done():
				return nil
			case <-changed:
			case signal := <-signals:
				if signal.err != nil {
					if connectivityWasInterrupted(signal.err) {
						continue
					}
					return signal.err
				}
				// input received before local binding activation cannot start checks.
			}
			continue
		}
		var offer *tunnelv1.ConnectorPeerConnectivity
		if c.controlling {
			if attempt == math.MaxUint64 {
				return connectivityInvalid(ErrConfiguration)
			}
			attempt++
		} else {
			if pending != nil {
				offer, pending = pending, nil
				if !connectivityMatches(binding, *offer) || offer.Attempt <= previous {
					continue
				}
				previous, attempt = offer.Attempt, offer.Attempt
			} else {
				select {
				case <-ctx.Done():
					return nil
				case <-changed:
					continue
				case signal := <-signals:
					if signal.err != nil {
						if connectivityWasInterrupted(signal.err) {
							continue
						}
						return signal.err
					}
					if !connectivityMatches(binding, signal.message) || signal.message.Attempt <= previous {
						continue
					}
					previous, attempt = signal.message.Attempt, signal.message.Attempt
					offer = &signal.message
				}
			}
		}
		// rate limiting applies even across network-binding changes. the previous
		// agent has joined before this point; no offer can allocate a second one.
		if !lastStarted.IsZero() {
			timer := time.NewTimer(max(0, time.Until(lastStarted.Add(connectivityRetryDelay))))
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-changed:
				timer.Stop()
				continue
			case <-timer.C:
			}
		}
		life, finish := context.WithCancel(ctx)
		c.mu.Lock()
		if c.binding != binding {
			c.mu.Unlock()
			finish()
			continue
		}
		c.stopAttempt = finish
		c.mu.Unlock()
		lastStarted = time.Now()
		err := c.runAttempt(life, binding, attempt, offer, signals)
		finish()
		c.mu.Lock()
		c.stopAttempt = nil
		c.mu.Unlock()
		c.observe(ConnectivityRelay)
		if ctx.Err() != nil {
			return nil
		}
		var classified *ConnectivityError
		if errors.As(err, &classified) && (classified.Code == tunnelv1.InvalidMessage || classified.Code == tunnelv1.Unauthenticated) {
			return err
		}
		var next *connectivityNextOffer
		if errors.As(err, &next) {
			pending = &next.message
		}
		// retryable setup, consent and probe loss affect delivery only. neither
		// a retry nor a late answer creates a new application session or deadline.
	}
}

func connectivityMatches(binding ConnectivityBinding, message tunnelv1.ConnectorPeerConnectivity) bool {
	return message.PairID == binding.Revision.PairID && message.DeliveryID == binding.DeliveryID && message.DeliveryGeneration == binding.Revision.Generation
}

func (c *Connectivity) runAttempt(ctx context.Context, binding ConnectivityBinding, attempt uint64, offer *tunnelv1.ConnectorPeerConnectivity, signals <-chan connectivitySignal) (retErr error) {
	started, established, directActive := time.Now(), false, false
	defer func() {
		if !established && c.options.ObserveAttempt != nil {
			outcome := "failed"
			if ctx.Err() != nil {
				outcome = "canceled"
			}
			c.options.ObserveAttempt(ConnectivityAttempt{Outcome: outcome, Duration: time.Since(started)})
		}
		if directActive && ctx.Err() == nil && c.options.ObserveFallback != nil {
			c.options.ObserveFallback()
		}
	}()
	setup, cancel := context.WithTimeout(ctx, connectivitySetupTimeout)
	defer cancel()
	urls, err := connectivitySTUNURLs(setup, binding.RelayAddresses)
	if err != nil {
		return err
	}
	var packetBinding atomic.Pointer[connectivityPacketBinding]
	consent := new(connectivityConsent)
	agent, err := c.socket.newICE(urls, c.options.IncludeLoopback, func(packet []byte) bool {
		key := packetBinding.Load()
		if key == nil || ctx.Err() != nil || !consent.valid() {
			return false
		}
		frame, valid := key.open(packet)
		// socket dispatch holds its mux lock. only cryptographic checks belong
		// here; native authority is checked by the carrier outside shared locks.
		if !valid {
			return false
		}
		_, valid = authenticatePacket(frame, c.packets.config.Key, c.packets.config.Role, Direct)
		return valid
	})
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, agent.GracefulClose()) }()
	local, err := gatherConnectivity(setup, agent, binding, attempt)
	if err != nil {
		return err
	}
	if err := writeConnectivitySignal(setup, c.connection, local); err != nil {
		return err
	}
	var remote tunnelv1.ConnectorPeerConnectivity
	if c.controlling {
		for {
			select {
			case <-setup.Done():
				return context.Cause(setup)
			case signal := <-signals:
				if signal.err != nil {
					return signal.err
				}
				if !connectivityMatches(binding, signal.message) || signal.message.Attempt < attempt {
					continue
				}
				if signal.message.Attempt != attempt {
					return connectivityInvalid(tunnelv1.ErrConnectorPeerConnectivity)
				}
				remote = signal.message
			}
			break
		}
	} else {
		remote = *offer
	}
	for _, encoded := range remote.Candidates {
		candidate, err := ice.UnmarshalCandidate(encoded)
		if err != nil || !validConnectivityCandidate(candidate) {
			return connectivityInvalid(errors.Join(tunnelv1.ErrConnectorPeerConnectivity, err))
		}
		if err := agent.AddRemoteCandidate(candidate); err != nil {
			return err
		}
	}
	first, second := local, remote
	if !c.controlling {
		first, second = remote, local
	}
	key := connectivityPacketBinding{key: connectivityPacketKey(c.packets.config.Key, binding, first, second), generation: uint64(binding.Revision.Generation), attempt: attempt, role: c.packets.config.Role}
	packetBinding.Store(&key)
	c.observe(ConnectivityChecking)
	lost := make(chan struct{})
	var once sync.Once
	if err := agent.OnConnectionStateChange(func(state ice.ConnectionState) {
		if state == ice.ConnectionStateDisconnected || state == ice.ConnectionStateFailed || state == ice.ConnectionStateClosed {
			consent.lost.Store(true)
			once.Do(func() { close(lost) })
		}
	}); err != nil {
		return err
	}
	var direct *ice.Conn
	if c.controlling {
		direct, err = agent.Dial(setup, remote.UsernameFragment, remote.Password)
	} else {
		direct, err = agent.Accept(setup, remote.UsernameFragment, remote.Password)
	}
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		_ = direct.Close()
		return context.Cause(ctx)
	}
	if !consent.refresh(agent) {
		_ = direct.Close()
		return &ConnectivityError{Code: tunnelv1.Unavailable, Cause: errors.New("direct UDP consent was not proved")}
	}
	if err := c.packets.InstallDirect(binding.Revision, connectivityCarrier{Carrier: ICECarrier{Conn: direct}, binding: key, admit: c.admitFrame, sendAdmit: c.admitOutboundFrame, consent: consent}, consent.valid); err != nil {
		return err
	}
	defer func() { _ = c.packets.InstallDirect(binding.Revision, nil, nil) }()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	lastHealthy := time.Now()
	state := ConnectivityChecking
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-lost:
			return &ConnectivityError{Code: tunnelv1.Unavailable, Cause: errors.New("direct UDP consent expired")}
		case signal := <-signals:
			if signal.err != nil {
				if connectivityWasInterrupted(signal.err) {
					continue
				}
				return signal.err
			}
			if !c.controlling && connectivityMatches(binding, signal.message) && signal.message.Attempt > attempt {
				// the old carrier and agent join before the newer offer is used.
				return &connectivityNextOffer{message: signal.message}
			}
		case now := <-ticker.C:
			if !consent.refresh(agent) {
				return &ConnectivityError{Code: tunnelv1.Unavailable, Cause: errors.New("direct UDP consent expired")}
			}
			next := ConnectivityRelay
			if c.packets.PathHealthy(Direct) {
				next, lastHealthy = ConnectivityDirect, now
				if !established {
					established = true
					if c.options.ObserveAttempt != nil {
						c.options.ObserveAttempt(ConnectivityAttempt{Outcome: "succeeded", Duration: time.Since(started)})
					}
				}
			}
			if next != state {
				if directActive && next == ConnectivityRelay && c.options.ObserveFallback != nil {
					c.options.ObserveFallback()
				}
				directActive = next == ConnectivityDirect
				c.observe(next)
				state = next
			}
			if now.Sub(lastHealthy) >= max(5*time.Second, 2*c.packets.config.PathTimeout) {
				return &ConnectivityError{Code: tunnelv1.Unavailable, Cause: errors.New("direct UDP packet probes expired")}
			}
		}
	}
}

func connectivitySTUNURLs(ctx context.Context, addresses [2]string) ([]*stun.URI, error) {
	urls := make([]*stun.URI, 0, 4)
	for _, address := range addresses {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, connectivityInvalid(err)
		}
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 {
			return nil, connectivityInvalid(errors.Join(ErrConfiguration, err))
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		var families [2]bool
		for _, ip := range ips {
			ip = ip.Unmap()
			family := 0
			if ip.Is6() {
				family = 1
			}
			if !validConnectivityIP(ip) || families[family] {
				continue
			}
			families[family] = true
			// Pion receives literal IPs only: its non-context resolver must never
			// hold agent teardown while a native owner is being cancelled.
			urls = append(urls, &stun.URI{Scheme: stun.SchemeTypeSTUN, Proto: stun.ProtoTypeUDP, Host: ip.String(), Port: int(number)})
		}
	}
	return urls, nil
}

func (c *Connectivity) admitFrame(frame []byte) bool {
	packet, valid := authenticatePacket(frame, c.packets.config.Key, c.packets.config.Role, Direct)
	return valid && (c.admit == nil || c.admit(packet))
}

func (c *Connectivity) admitOutboundFrame(frame []byte) bool {
	packet, err := tunnelv1.VerifyPeerPacketFrame(frame, c.packets.config.Key)
	return err == nil && packet.Path == Direct && packet.Sender == c.packets.config.Role && (c.admit == nil || c.admit(packet))
}

func gatherConnectivity(ctx context.Context, agent *ice.Agent, binding ConnectivityBinding, attempt uint64) (tunnelv1.ConnectorPeerConnectivity, error) {
	message := tunnelv1.ConnectorPeerConnectivity{ProtocolVersion: tunnelv1.Version, Kind: "connector_peer_connectivity", PairID: binding.Revision.PairID, DeliveryID: binding.DeliveryID, DeliveryGeneration: binding.Revision.Generation, Attempt: attempt}
	var err error
	message.UsernameFragment, message.Password, err = agent.GetLocalUserCredentials()
	if err != nil {
		return message, err
	}
	var mu sync.Mutex
	var completed sync.Once
	complete := make(chan struct{})
	if err := agent.OnCandidate(func(candidate ice.Candidate) {
		if candidate == nil {
			completed.Do(func() { close(complete) })
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if len(message.Candidates) < tunnelv1.MaxConnectorPeerCandidates && validConnectivityCandidate(candidate) {
			message.Candidates = append(message.Candidates, candidate.Marshal())
		}
	}); err != nil {
		return message, err
	}
	if err := agent.GatherCandidates(); err != nil {
		return tunnelv1.ConnectorPeerConnectivity{}, err
	}
	select {
	case <-ctx.Done():
		// callbacks may still append candidates until the attempt joins its agent.
		// never copy the mutable slice header on the cancelled return path.
		return tunnelv1.ConnectorPeerConnectivity{}, context.Cause(ctx)
	case <-complete:
	}
	mu.Lock()
	local := message
	local.Candidates = append([]string(nil), message.Candidates...)
	mu.Unlock()
	return local, local.Validate()
}

func validConnectivityCandidate(candidate ice.Candidate) bool {
	if candidate == nil || candidate.Component() != 1 || candidate.Port() <= 0 || candidate.Port() > 65535 || !candidate.NetworkType().IsUDP() ||
		candidate.Type() != ice.CandidateTypeHost && candidate.Type() != ice.CandidateTypeServerReflexive {
		return false
	}
	validIP := func(value string) bool {
		address, err := netip.ParseAddr(value)
		return err == nil && validConnectivityIP(address)
	}
	if !validIP(candidate.Address()) {
		return false
	}
	if related := candidate.RelatedAddress(); related != nil && (!validIP(related.Address) || related.Port < 1 || related.Port > 65535) {
		return false
	}
	return true
}
