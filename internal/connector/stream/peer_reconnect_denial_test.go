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
	old := p.paths[0].leg
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
	if p.paths[0].leg != old || f.opened.Load() != opened {
		t.Fatal("denied reconnect replaced delivery or application")
	}
}

func TestConnectorReconnectRetryClassification(t *testing.T) {
	unavailable := &tunnel.ProtocolError{Code: tunnelv1.Unavailable}
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	capacity := &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
	stale := &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	for _, test := range []struct {
		err  error
		want reconnectDisposition
	}{
		{io.EOF, retryAttempt}, {unavailable, retryAttempt}, {capacity, retryAttempt}, {denied, terminateConnection},
		{errors.Join(unavailable, denied), terminateConnection}, {errors.Join(capacity, denied), terminateConnection},
		{errors.Join(ErrServiceConnection, io.ErrUnexpectedEOF), retryAttempt},
		{ErrServiceConnection, terminateConnection}, {stale, retirePath},
		{errors.Join(unavailable, stale), retirePath}, {errors.Join(stale, unavailable), retirePath},
		{errors.Join(stale, denied), terminateConnection}, {errors.Join(denied, stale), terminateConnection},
		{errors.Join(ErrServiceConnection, errors.Join(io.EOF, stale), denied), terminateConnection},
		{errors.Join(ErrServiceConnection, errors.Join(io.EOF, stale)), retirePath},
		{errors.Join(ErrServiceConnection, errors.Join(errors.New("other"), unavailable)), retryAttempt},
	} {
		if got := connectorReconnectError(test.err); got != test.want {
			t.Fatal("wrong reconnect retry decision", test.err, got, test.want)
		}
	}
}
