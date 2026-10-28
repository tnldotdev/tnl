package peer

import (
	"context"
	"errors"
	"io"
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
	ConnectivityChecking ConnectivityState = "checking"
	ConnectivityDirect   ConnectivityState = "direct"
	ConnectivityRelay    ConnectivityState = "relay"
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

// ServeConnectivity is background work on an already-established inner QUIC
// connection. one bounded signaling stream in each direction is independent of
// application admission. the owner joins this function before closing its socket.
// ICE consent installs delivery only; endpoint MAC probes choose the new path.
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
	agent, err := socket.NewICE(urls, options.IncludeLoopback)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, agent.Close()) }()
	setup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	message := tunnelv1.NativePeerConnectivity{ProtocolVersion: tunnelv1.Version, Kind: "native_peer_connectivity", PairID: binding.PairID, DeliveryID: binding.DeliveryID, DeliveryGeneration: binding.Generation}
	message.UsernameFragment, message.Password, err = agent.GetLocalUserCredentials()
	if err != nil {
		return err
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
		return err
	}
	if err := agent.GatherCandidates(); err != nil {
		return err
	}
	select {
	case <-setup.Done():
		return context.Cause(setup)
	case <-complete:
	}
	mu.Lock()
	local := message
	local.Candidates = append([]string(nil), message.Candidates...)
	mu.Unlock()
	if err := local.Validate(); err != nil {
		return &ConnectivityError{Code: tunnelv1.Unavailable, Cause: err}
	}
	remote, err := exchangeConnectivity(setup, connection, local)
	if err != nil {
		return err
	}
	if remote.PairID != binding.PairID || remote.DeliveryID != binding.DeliveryID || remote.DeliveryGeneration != binding.Generation {
		return &ConnectivityError{Code: tunnelv1.Unauthenticated, Cause: tunnelv1.ErrNativePeerConnectivity}
	}
	for _, encoded := range remote.Candidates {
		candidate, err := ice.UnmarshalCandidate(encoded)
		if err != nil || !validConnectivityCandidate(candidate) {
			return &ConnectivityError{Code: tunnelv1.InvalidMessage, Cause: errors.Join(tunnelv1.ErrNativePeerConnectivity, err)}
		}
		if err := agent.AddRemoteCandidate(candidate); err != nil {
			return err
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
		return err
	}
	var direct *ice.Conn
	if controlling {
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
	if err := slot.Install(ICECarrier{Conn: direct}); err != nil {
		return err
	}
	defer slot.Install(nil)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	last := ConnectivityRelay
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-connection.Context().Done():
			return nil
		case <-lostConsent:
			return &ConnectivityError{Code: tunnelv1.Unavailable, Cause: ErrConnectivityConsent}
		case <-ticker.C:
			next := ConnectivityRelay
			if packets.ActivePath() == Direct {
				next = ConnectivityDirect
			}
			if next != last && options.Observe != nil {
				options.Observe(next)
			}
			last = next
		}
	}
}

func exchangeConnectivity(ctx context.Context, connection *quic.Conn, local tunnelv1.NativePeerConnectivity) (remote tunnelv1.NativePeerConnectivity, retErr error) {
	out, err := connection.OpenUniStreamSync(ctx)
	if err != nil {
		return remote, err
	}
	stopWrite := interruptOnCancel(ctx, func() error { out.CancelWrite(0); return nil })
	defer stopWrite()
	defer func() {
		if retErr != nil {
			out.CancelWrite(0)
		}
	}()
	if err := tunnelv1.WriteNativePeerConnectivity(out, local); err != nil {
		return remote, err
	}
	if err := out.Close(); err != nil {
		return remote, err
	}
	in, err := connection.AcceptUniStream(ctx)
	if err != nil {
		return remote, err
	}
	stopRead := interruptOnCancel(ctx, func() error { in.CancelRead(0); return nil })
	defer stopRead()
	defer in.CancelRead(0)
	remote, err = tunnelv1.ReadNativePeerConnectivity(in)
	if err != nil {
		return remote, &ConnectivityError{Code: tunnelv1.InvalidMessage, Cause: err}
	}
	// a signaling stream has exactly one frame. reject trailing data rather than
	// leaving an unbounded body or a second credential set attached to the pair.
	var extra [1]byte
	if n, err := in.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return remote, &ConnectivityError{Code: tunnelv1.InvalidMessage, Cause: errors.Join(tunnelv1.ErrNativePeerConnectivity, err)}
	}
	return remote, nil
}

func validConnectivityCandidate(candidate ice.Candidate) bool {
	if candidate == nil || candidate.Component() != 1 || candidate.Port() <= 0 || candidate.Port() > 65535 || !candidate.NetworkType().IsUDP() || (candidate.Type() != ice.CandidateTypeHost && candidate.Type() != ice.CandidateTypeServerReflexive) {
		return false
	}
	address, err := netip.ParseAddr(candidate.Address())
	return err == nil && address.IsValid() && !address.IsUnspecified() && !address.IsMulticast() && address.Zone() == ""
}
