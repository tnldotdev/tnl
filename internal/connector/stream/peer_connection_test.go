package stream

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectorRefreshPreparesReplacementOpeningsBeforePublishing(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	var armed, blocked atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	resume := sync.OnceFunc(func() { close(release) })
	var once sync.Once
	signer := f.device
	signer.Sign = func(message []byte) []byte {
		if blocked.Load() {
			once.Do(func() { close(entered) })
			<-release
		}
		return f.device.Sign(message)
	}
	control, err := NewControlWithConfig(ControlConfig{
		Signer: f.ConnectorSigner, Resolve: f.ResolveService, Pair: f.PrepareConnectorPeerPair,
		Permission: func(ctx context.Context, service string) (controlv1.VisitorTokenResponse, error) {
			permission, err := f.VisitorPermission(ctx, service)
			if armed.Load() {
				blocked.Store(true)
			}
			return permission, err
		}, Close: func() error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	config := f.config
	config.Control, config.MaxConnections = control, 64
	setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
	p, err := prepareConnectorConnection(t.Context(), setup, config, signer)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	defer resume()
	exchange := func(message string) {
		t.Helper()
		local, app := net.Pipe()
		defer app.Close()
		done := make(chan error, 1)
		go func() { defer local.Close(); done <- p.Forward(t.Context(), local) }()
		_ = app.SetDeadline(time.Now().Add(time.Second))
		if _, err := io.WriteString(app, message); err != nil {
			t.Fatal("background refresh withdrew a prepared opening", err)
		}
		response := make([]byte, len(message))
		if _, err := io.ReadFull(app, response); err != nil || string(response) != message {
			t.Fatal("application waited for background signing or lost its prepared opening", err)
		}
		_ = app.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("application forwarding did not join")
		}
	}
	// consume the warm TCP stream so the next arrival needs an ordinary opening.
	exchange("before-refresh")
	armed.Store(true)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("refresh did not reach background opening preparation")
	}
	exchange("during-refresh")
	p.mu.Lock()
	changed := p.changed
	p.mu.Unlock()
	resume()
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("prepared replacement pool was not published")
	}
	exchange("after-refresh")
}

func TestConnectorRefreshRejectsAuthorityExpiredDuringSigning(t *testing.T) {
	for _, boundary := range []string{"run", "pair", "permission", "installation"} {
		t.Run(boundary, func(t *testing.T) {
			f := newConnectorFixture(t, "quic")
			var armed, blocked atomic.Bool
			entered, release := make(chan struct{}), make(chan struct{})
			resume := sync.OnceFunc(func() { close(release) })
			var once sync.Once
			var deadline time.Time
			signer := f.device
			signer.Sign = func(message []byte) []byte {
				if blocked.Load() {
					once.Do(func() { close(entered) })
					<-release
				}
				return f.device.Sign(message)
			}
			control, err := NewControlWithConfig(ControlConfig{
				Signer: f.ConnectorSigner,
				Resolve: func(ctx context.Context, service string) (Run, error) {
					run, err := f.ResolveService(ctx, service)
					if armed.Load() {
						deadline = time.Now().Add(200 * time.Millisecond)
						if boundary == "run" {
							run.ValidUntil = deadline
						}
					}
					return run, err
				},
				Pair: func(ctx context.Context, service string, request controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
					pair, err := f.PrepareConnectorPeerPair(ctx, service, request)
					if armed.Load() {
						if boundary == "pair" {
							pair.ExpiresAt = deadline
							pair.PublisherPreparedUntil = new(deadline)
						}
						if boundary == "installation" {
							pair.PublisherPreparedUntil = new(deadline)
						}
					}
					return pair, err
				},
				Permission: func(ctx context.Context, service string) (controlv1.VisitorTokenResponse, error) {
					permission, err := f.VisitorPermission(ctx, service)
					if armed.Load() {
						if boundary == "permission" {
							permission.ExpiresAt = deadline
						}
						blocked.Store(true)
					}
					return permission, err
				}, Close: func() error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			config := f.config
			config.Control = control
			setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
			p, err := prepareConnectorConnection(t.Context(), setup, config, signer)
			stop()
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			defer resume()
			p.mu.Lock()
			oldRun, oldPair, oldPermission, oldInstallation := p.run.ValidUntil, p.until, p.permission.ExpiresAt, p.preparedUntil
			p.mu.Unlock()
			armed.Store(true)
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("refresh did not reach background signing")
			}
			<-time.After(time.Until(deadline))
			resume()
			select {
			case <-p.ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("expired replacement authority was published")
			}
			p.mu.Lock()
			unchanged := p.run.ValidUntil.Equal(oldRun) && p.until.Equal(oldPair) && p.permission.ExpiresAt.Equal(oldPermission) && p.preparedUntil.Equal(oldInstallation)
			p.mu.Unlock()
			if !unchanged {
				t.Fatal("late signing replaced the last confirmed authority")
			}
		})
	}
}

func TestConnectorPreparationKeepsOriginalStartupDeadline(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	ownerSetup, stopOwner := context.WithTimeout(t.Context(), 3*time.Second)
	defer stopOwner()
	p, err := prepareConnectorConnection(t.Context(), ownerSetup, f.config, f.device)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	// prepare the real inner transport before starting this stream's fixed
	// budget, so scheduling other test packages cannot spend it in fixture setup.
	p.mu.Lock()
	entry, run := p.openings[0].entry, p.run
	p.mu.Unlock()
	gate := &fixtureTLSGate{entered: make(chan struct{}), release: make(chan struct{})}
	f.mu.Lock()
	f.tlsGate = gate
	f.mu.Unlock()
	defer close(gate.release)
	setup, stop := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer stop()
	deadline, _ := setup.Deadline()
	done := make(chan error, 1)
	go func() {
		prepared, err := prepareConnector(p.ctx, setup, p.session, run, entry)
		if prepared != nil {
			_ = prepared.Close()
		}
		done <- err
	}()
	select {
	case <-gate.entered:
	case err := <-done:
		t.Fatal("did not reach retained TCP preparation", err)
	case <-time.After(time.Second):
		t.Fatal("did not reach retained TCP preparation")
	}
	select {
	case err := <-done:
		// a socket deadline can fire before the context timer runs. the fixed
		// absolute deadline, not that goroutine's scheduling, is the assertion.
		if err == nil || time.Now().Before(deadline) {
			t.Fatal("retained preparation escaped the startup deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("retained TCP preparation reset the original startup budget")
	}
}

func TestConnectorPreparationPromotesStreamToOwnerLifetime(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
	p, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	local, app := net.Pipe()
	defer app.Close()
	done := make(chan error, 1)
	go func() { done <- p.Forward(t.Context(), local) }()
	_ = app.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(app, "promoted"); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("promoted"))
	if _, err := io.ReadFull(app, got); err != nil || string(got) != "promoted" {
		t.Fatal("startup cancellation closed the promoted stream", err)
	}
	_ = app.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("promoted stream did not join")
	}
}

func TestConnectorRevokedOwnerDoesNotCloseSiblingOwner(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	healthy := f.local(t)
	check := func(c net.Conn, message string) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, err := io.WriteString(c, message); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(message))
		if _, err := io.ReadFull(c, got); err != nil || string(got) != message {
			t.Fatal("owner lost its stream", err)
		}
	}
	check(healthy, "before")
	setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	p, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	local, revoked := net.Pipe()
	defer revoked.Close()
	done := make(chan error, 1)
	go func() { done <- p.Forward(t.Context(), local) }()
	check(revoked, "revoked")
	f.mu.Lock()
	session := f.peers[p.pair.PairId].session
	f.mu.Unlock()
	_ = session.Close()
	if _, err := revoked.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked owner retained its active stream")
	} else {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatal("revocation only timed out the stream")
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("revoked owner did not join its stream")
	}
	check(healthy, "after")
	if f.opened.Load() != 2 {
		t.Fatal("owner replacement replayed a stream", f.opened.Load())
	}
}

func TestConnectorInstallationDeadlineStopsOwnerBeforePairExpiry(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	p, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	local, app := net.Pipe()
	defer app.Close()
	done := make(chan error, 1)
	go func() { done <- p.Forward(t.Context(), local) }()
	_ = app.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(app, "ready"); err != nil {
		t.Fatal(err)
	}
	var b [5]byte
	if _, err := io.ReadFull(app, b[:]); err != nil || string(b[:]) != "ready" {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.preparedUntil = time.Now().Add(100 * time.Millisecond)
	if !p.until.After(p.preparedUntil.Add(time.Second)) {
		p.mu.Unlock()
		t.Fatal("fixture pair does not outlive its installation")
	}
	p.notifyLocked()
	p.mu.Unlock()
	if _, err := app.Read(b[:]); err == nil {
		t.Fatal("expired installation retained the local socket")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("installation waited for the pair or QUIC idle timeout", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("installation expiry did not join forwarding")
	}
}
