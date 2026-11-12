package telemetry

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

func Path(transport tunnel.Transport) api.Path {
	switch transport {
	case tunnel.TransportTLSTCP:
		return api.TlsTcp
	case tunnel.TransportQUIC:
		return api.Quic
	default:
		return ""
	}
}

func (s *Scope) RelayAttempt(ctx context.Context, transport tunnel.Transport, elapsed time.Duration, err error) {
	outcome := api.Succeeded
	if err != nil {
		outcome = api.Failed
		if ctx.Err() != nil {
			outcome = api.Canceled
		}
	}
	s.Record(api.RelayConnect, Path(transport), outcome, elapsed)
}

func (s *Scope) Connectivity(options peer.ConnectivityOptions) peer.ConnectivityOptions {
	if s == nil {
		return options
	}
	previous := options.ObserveAttempt
	options.ObserveAttempt = func(attempt peer.ConnectivityAttempt) {
		if previous != nil {
			previous(attempt)
		}
		s.Record(api.DirectConnect, api.DirectUdp, api.Outcome(attempt.Outcome), attempt.Duration)
	}
	fallback := options.ObserveFallback
	options.ObserveFallback = func() {
		if fallback != nil {
			fallback()
		}
		s.Record(api.Fallback, api.DirectUdp, api.Succeeded, 0)
	}
	return options
}
