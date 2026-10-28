package peer

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v4"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ConnectivityState string

var ErrConnectivityConsent = errors.New("native direct connectivity consent expired")

const (
	ConnectivityChecking     ConnectivityState = "checking"
	ConnectivityDirect       ConnectivityState = "direct"
	ConnectivityRelay        ConnectivityState = "relay"
	connectivitySetupTimeout                   = 10 * time.Second
	connectivityRetryDelay                     = 5 * time.Second
)

// ConnectivityOptions are supplied by native owners, never by application
// requests. qualification can keep delivery relay-only or include loopback.
type ConnectivityOptions struct {
	DisableDirect   bool
	IncludeLoopback bool
	Observe         func(ConnectivityState)
}

type ConnectivityBinding struct {
	PairID, DeliveryID string
	Generation         int64
	RelayAddresses     [2]string
}

type ConnectivityError struct {
	Code  tunnelv1.ErrorCode
	Cause error
}

func (e *ConnectivityError) Error() string { return "native direct packet path could not be prepared" }
func (e *ConnectivityError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// ServeConnectivity owns successive ICE attempts on one existing inner QUIC
// connection. only the connector starts attempts. an attempt replaces delivery,
// never application admission, source authority, or the owner's expiry.
// each side has one reader and one agent at a time; cancellation joins both.
func ServeConnectivity(ctx context.Context, socket *Socket, connection *quic.Conn, packets *Endpoint, slot *CarrierSlot, binding ConnectivityBinding, controlling bool, options ConnectivityOptions) (retErr error) {
	if options.DisableDirect {
		return nil
	}
	if socket == nil || connection == nil || packets == nil || slot == nil {
		return &ConnectivityError{Code: tunnelv1.InvalidMessage, Cause: ErrConfiguration}
	}
	if options.Observe != nil {
		defer options.Observe(ConnectivityRelay)
	}
	defer func() {
		if ctx.Err() != nil {
			retErr = errors.Join(context.Cause(ctx), retErr)
			return
		}
		if retErr != nil {
			var classified *ConnectivityError
			if !errors.As(retErr, &classified) || classified == nil {
				retErr = &ConnectivityError{Code: tunnelv1.Unavailable, Cause: retErr}
			}
		}
	}()
	urls := make([]*stun.URI, 0, 2)
	for _, address := range binding.RelayAddresses {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return &ConnectivityError{Code: tunnelv1.InvalidMessage, Cause: err}
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return &ConnectivityError{Code: tunnelv1.InvalidMessage, Cause: errors.Join(ErrConfiguration, err)}
		}
		urls = append(urls, &stun.URI{Scheme: stun.SchemeTypeSTUN, Proto: stun.ProtoTypeUDP, Host: host, Port: number})
	}
	life, cancel := context.WithCancel(ctx)
	stopConnection := interruptOnCancel(connection.Context(), func() error { cancel(); return nil })
	defer stopConnection()
	signals := make(chan connectivitySignal, 1)
	readerDone := make(chan struct{})
	go func() { defer close(readerDone); readConnectivitySignals(life, connection, binding, signals) }()
	defer func() { cancel(); <-readerDone }()
	var attempt uint64
	var offer *tunnelv1.NativePeerConnectivity
	var lastStarted time.Time
	for {
		if life.Err() != nil {
			return context.Cause(life)
		}
		if controlling {
			if attempt == math.MaxUint64 {
				return &ConnectivityError{Code: tunnelv1.InvalidMessage, Cause: ErrConfiguration}
			}
			attempt++
		} else {
			if offer == nil {
				signal, err := nextConnectivitySignal(life, signals)
				if err != nil {
					return err
				}
				offer = &signal
			}
			attempt = offer.Attempt
			// bounded input and a local start interval limit an authenticated peer
			// to one agent at a time even if it sends offers faster than expected.
			if delay := time.Until(lastStarted.Add(connectivityRetryDelay)); delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-life.Done():
					timer.Stop()
					return context.Cause(life)
				case <-timer.C:
				}
			}
		}
		lastStarted = time.Now()
		var err error
		offer, err = runConnectivityAttempt(life, socket, connection, packets, slot, binding, urls, attempt, offer, signals, controlling, options)
		if options.Observe != nil {
			options.Observe(ConnectivityRelay)
		}
		if connectivityTerminal(err) {
			return err
		}
		if life.Err() != nil {
			return errors.Join(context.Cause(life), err)
		}
		if controlling {
			// a failed setup or lost path never spins agent creation. the previous
			// agent and all its socket registrations have been joined before waiting.
			if err := waitConnectivityRetry(life, signals, attempt); err != nil {
				return err
			}
		}
	}
}

func waitConnectivityRetry(ctx context.Context, signals <-chan connectivitySignal, attempt uint64) error {
	timer := time.NewTimer(connectivityRetryDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-timer.C:
			return nil
		case signal := <-signals:
			if signal.err != nil {
				return signal.err
			}
			// late answers cannot restart the retry timer or install a carrier.
			// the single reader rejects reused attempt numbers independently.
			if signal.message.Attempt > attempt {
				return &ConnectivityError{Code: tunnelv1.InvalidMessage, Cause: tunnelv1.ErrNativePeerConnectivity}
			}
		}
	}
}

func connectivityTerminal(err error) bool {
	var classified *ConnectivityError
	return errors.As(err, &classified) && classified != nil && (classified.Code == tunnelv1.InvalidMessage || classified.Code == tunnelv1.Unauthenticated)
}

func runConnectivityAttempt(ctx context.Context, socket *Socket, connection *quic.Conn, packets *Endpoint, slot *CarrierSlot, binding ConnectivityBinding, urls []*stun.URI, attempt uint64, offer *tunnelv1.NativePeerConnectivity, signals <-chan connectivitySignal, controlling bool, options ConnectivityOptions) (next *tunnelv1.NativePeerConnectivity, retErr error) {
	agent, err := socket.NewICE(urls, options.IncludeLoopback)
	if err != nil {
		return nil, err
	}
	defer func() { retErr = errors.Join(retErr, agent.Close()) }()
	setup, cancel := context.WithTimeout(ctx, connectivitySetupTimeout)
	defer cancel()
	local, err := gatherConnectivity(setup, agent, binding, attempt)
	if err != nil {
		return nil, err
	}
	if err := writeConnectivitySignal(setup, connection, local); err != nil {
		return nil, err
	}
	var remote tunnelv1.NativePeerConnectivity
	if controlling {
		for {
			remote, err = nextConnectivitySignal(setup, signals)
			if err != nil {
				return nil, err
			}
			if remote.Attempt < attempt {
				continue
			}
			if remote.Attempt != attempt {
				return nil, &ConnectivityError{Code: tunnelv1.InvalidMessage, Cause: tunnelv1.ErrNativePeerConnectivity}
			}
			break
		}
	} else {
		remote = *offer
	}
	for _, encoded := range remote.Candidates {
		candidate, err := ice.UnmarshalCandidate(encoded)
		if err != nil || !validConnectivityCandidate(candidate) {
			return nil, &ConnectivityError{Code: tunnelv1.InvalidMessage, Cause: errors.Join(tunnelv1.ErrNativePeerConnectivity, err)}
		}
		if err := agent.AddRemoteCandidate(candidate); err != nil {
			return nil, err
		}
	}
	if options.Observe != nil {
		options.Observe(ConnectivityChecking)
	}
	lostConsent := make(chan struct{})
	var lost sync.Once
	if err := agent.OnConnectionStateChange(func(state ice.ConnectionState) {
		if state == ice.ConnectionStateDisconnected || state == ice.ConnectionStateFailed || state == ice.ConnectionStateClosed {
			lost.Do(func() { close(lostConsent) })
		}
	}); err != nil {
		return nil, err
	}
	var direct *ice.Conn
	if controlling {
		direct, err = agent.Dial(setup, remote.UsernameFragment, remote.Password)
	} else {
		direct, err = agent.Accept(setup, remote.UsernameFragment, remote.Password)
	}
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		_ = direct.Close()
		return nil, context.Cause(ctx)
	}
	if err := slot.Install(ICECarrier{Conn: direct}); err != nil {
		return nil, err
	}
	defer slot.Install(nil)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	last, lastDirect := ConnectivityRelay, time.Now()
	for {
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-lostConsent:
			return nil, &ConnectivityError{Code: tunnelv1.Unavailable, Cause: ErrConnectivityConsent}
		case signal := <-signals:
			if signal.err != nil {
				return nil, signal.err
			}
			if controlling || signal.message.Attempt <= attempt {
				return nil, &ConnectivityError{Code: tunnelv1.InvalidMessage, Cause: tunnelv1.ErrNativePeerConnectivity}
			}
			// the reader has already checked binding and ordering. cleanup
			// removes this agent before the next offer may install another carrier.
			return &signal.message, nil
		case now := <-ticker.C:
			next := ConnectivityRelay
			if packets.ActivePath() == Direct {
				next, lastDirect = ConnectivityDirect, now
			}
			if next != last && options.Observe != nil {
				options.Observe(next)
			}
			last = next
			if controlling && now.Sub(lastDirect) >= max(5*time.Second, 2*packets.config.PathTimeout) {
				return nil, &ConnectivityError{Code: tunnelv1.Unavailable, Cause: ErrConnectivityConsent}
			}
		}
	}
}

func gatherConnectivity(ctx context.Context, agent *ice.Agent, binding ConnectivityBinding, attempt uint64) (tunnelv1.NativePeerConnectivity, error) {
	message := tunnelv1.NativePeerConnectivity{ProtocolVersion: tunnelv1.Version, Kind: "native_peer_connectivity", PairID: binding.PairID, DeliveryID: binding.DeliveryID, DeliveryGeneration: binding.Generation, Attempt: attempt}
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
		if len(message.Candidates) < tunnelv1.MaxNativePeerCandidates && validConnectivityCandidate(candidate) {
			message.Candidates = append(message.Candidates, candidate.Marshal())
		}
		mu.Unlock()
	}); err != nil {
		return message, err
	}
	if err := agent.GatherCandidates(); err != nil {
		return message, err
	}
	select {
	case <-ctx.Done():
		return tunnelv1.NativePeerConnectivity{}, context.Cause(ctx)
	case <-complete:
	}
	mu.Lock()
	local := message
	local.Candidates = append([]string(nil), message.Candidates...)
	mu.Unlock()
	if err := local.Validate(); err != nil {
		return tunnelv1.NativePeerConnectivity{}, &ConnectivityError{Code: tunnelv1.Unavailable, Cause: err}
	}
	return local, nil
}

func validConnectivityCandidate(candidate ice.Candidate) bool {
	if candidate == nil || candidate.Component() != 1 || candidate.Port() <= 0 || candidate.Port() > 65535 || !candidate.NetworkType().IsUDP() || (candidate.Type() != ice.CandidateTypeHost && candidate.Type() != ice.CandidateTypeServerReflexive) {
		return false
	}
	address, err := netip.ParseAddr(candidate.Address())
	return err == nil && address.IsValid() && !address.IsUnspecified() && !address.IsMulticast() && address.Zone() == ""
}
