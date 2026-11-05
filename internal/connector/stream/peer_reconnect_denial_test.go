package stream

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorReconnectStopsOnAuthorizationDenial(t *testing.T) {
	f := newConfiguredConnectorFixture(t, "quic", "", func(f *connectorFixture, _ *Config) {
		f.drainRejections = true
		f.rejectionClosing = make(chan struct{}, 2)
	})
	setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
	p, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	f.denied.Store(true)
	p.mu.Lock()
	old := p.legs[0]
	p.mu.Unlock()
	opened := f.opened.Load()
	claims := f.assignments[0].Load()
	_ = old.session.Close()
	// network setup has its own two-second attempt ceiling. the assertion below
	// starts at a committed denial rather than treating setup time as a retry.
	select {
	case <-f.rejectionClosing:
	case <-time.After(3 * time.Second):
		t.Fatal("reconnect did not reach the denial reply")
	}
	select {
	case <-p.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("authorization rejection retried")
	}
	var rejected *tunnel.ProtocolError
	if !errors.As(context.Cause(p.ctx), &rejected) || rejected.Code != tunnelv1.Unauthenticated {
		t.Fatal("denial lost classification", context.Cause(p.ctx))
	}
	p.Close()
	if attempts := f.assignments[0].Load() - claims; attempts < 1 || attempts > 2 {
		t.Fatal("delivered denial started another two-candidate attempt", attempts)
	}
	if p.legs[0] != old || f.opened.Load() != opened {
		t.Fatal("denied reconnect replaced delivery or application")
	}
}

func TestConnectorReconnectRetryClassification(t *testing.T) {
	unavailable := &tunnel.ProtocolError{Code: tunnelv1.Unavailable}
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	capacity := &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
	stale := &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	for _, test := range []struct {
		err              error
		temporary, stale bool
	}{
		{io.EOF, true, false}, {unavailable, true, false}, {capacity, true, false}, {denied, false, false},
		{errors.Join(unavailable, denied), false, false}, {errors.Join(capacity, denied), false, false},
		{errors.Join(ErrServiceConnection, io.ErrUnexpectedEOF), true, false},
		{ErrServiceConnection, false, false}, {stale, false, true},
		{errors.Join(unavailable, stale), false, true}, {errors.Join(stale, unavailable), false, true},
		{errors.Join(stale, denied), false, false}, {errors.Join(denied, stale), false, false},
	} {
		if temporary, stale := connectorReconnectError(test.err); temporary != test.temporary || stale != test.stale {
			t.Fatal("wrong reconnect retry decision", test.err, temporary, stale)
		}
	}
}
