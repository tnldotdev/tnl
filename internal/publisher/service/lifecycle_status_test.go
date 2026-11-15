package service

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
)

type heldCertificateAcknowledgment struct {
	*lifecycleControl
	entered chan struct{}
	release chan struct{}
}

func (c *heldCertificateAcknowledgment) MarkServiceCertificateInstalled(ctx context.Context, service, run string, number int64, issuance string, expires time.Time, token credentials.ServiceRunToken) error {
	close(c.entered)
	select {
	case <-c.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return c.lifecycleControl.MarkServiceCertificateInstalled(ctx, service, run, number, issuance, expires, token)
}

func TestServiceRunReadinessRequiresCurrentLocalCertificate(t *testing.T) {
	cfg, control := lifecycleFixture(t)
	ack := &heldCertificateAcknowledgment{lifecycleControl: control, entered: make(chan struct{}), release: make(chan struct{})}
	cfg.Control = ack
	unblock := sync.OnceFunc(func() { close(ack.release) })
	defer unblock()
	prepared := make(chan *Prepared, 2)
	cfg.Connect = func(_ context.Context, bound *Bound, _ uint8, _ ConnectOptions) (SlotSession, error) {
		prepared <- bound.prepared
		return &heldSlot{stopped: make(chan struct{})}, nil
	}
	statuses := make(chan RunStatus, 128)
	cfg.ObserveReadiness = func(status RunStatus) { statuses <- status }
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	done := make(chan error, 1)
	go func() { done <- Publish(ctx, cfg) }()
	defer func() {
		unblock()
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	wait := func(predicate func(RunStatus) bool) RunStatus {
		t.Helper()
		for {
			select {
			case status := <-statuses:
				if predicate(status) {
					return status
				}
			case <-ctx.Done():
				t.Fatal("certificate readiness observation timed out")
			}
		}
	}
	select {
	case <-ack.entered:
	case <-ctx.Done():
		t.Fatal("certificate did not reach control acknowledgment")
	}
	before := wait(func(s RunStatus) bool { return s.Connected == [2]bool{true, true} })
	if before.Ready {
		t.Fatal("connected slots reported ready before certificate acknowledgment and installation")
	}
	unblock()
	wait(func(s RunStatus) bool { return s.Ready })
	p := <-prepared
	expired := time.Now()
	p.certMu.Lock()
	p.certValidTo = expired
	p.certMu.Unlock()
	wait(func(s RunStatus) bool { return s.LastCheck.After(expired) && !s.Ready })
}

func TestServiceRunStatusReportsConnectedTransportsAndActualDrain(t *testing.T) {
	cfg, _ := lifecycleFixture(t)
	cfg.HeartbeatInterval = 50 * time.Millisecond
	failedDial, allowTCP := make(chan struct{}), make(chan struct{})
	var attempts atomic.Int32
	cfg.Connect = func(ctx context.Context, _ *Bound, slot uint8, _ ConnectOptions) (SlotSession, error) {
		transport := tunnel.TransportQUIC
		if slot == 1 {
			if attempts.Add(1) == 1 {
				close(failedDial)
				return nil, errors.New("first relay dial failed")
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-allowTCP:
			}
			transport = tunnel.TransportTLSTCP
		}
		return &transportedSlot{heldSlot: &heldSlot{stopped: make(chan struct{})}, transport: transport}, nil
	}
	statuses := make(chan RunStatus, 128)
	cfg.ObserveReadiness = func(status RunStatus) { statuses <- status }
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	joined := make(chan struct{})
	go func() { defer close(joined); done <- Publish(ctx, cfg) }()
	defer func() { cancel(); <-joined }()
	wait := func(predicate func(RunStatus) bool) RunStatus {
		t.Helper()
		for {
			select {
			case status := <-statuses:
				if predicate(status) {
					return status
				}
			case err := <-done:
				t.Fatal("run ended before its status observation", err)
			case <-ctx.Done():
				t.Fatal("run status observation timed out")
			}
		}
	}
	select {
	case <-failedDial:
	case <-ctx.Done():
		t.Fatal("fixture did not attempt the initial relay dial")
	}
	initial := wait(func(s RunStatus) bool { return s.Connected[0] && !s.Connected[1] })
	if initial.Transports != [2]tunnel.Transport{tunnel.TransportQUIC, ""} || initial.Draining {
		t.Fatal("failed dial fabricated a fallback transport or drain", initial)
	}
	close(allowTCP)
	ready := wait(func(s RunStatus) bool { return s.Ready })
	if ready.Transports != [2]tunnel.Transport{tunnel.TransportQUIC, tunnel.TransportTLSTCP} || ready.Draining {
		t.Fatal("run status did not use the actual connected session transports", ready)
	}
	cancel()
	// caller cancellation is expected here; the drain observation belongs to
	// the run's independent cleanup and must still arrive before it returns.
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case status := <-statuses:
			if status.Draining {
				if status.Ready || status.LastCheck.Before(ready.LastCheck) {
					t.Fatal("drain retained a ready observation", status)
				}
				return
			}
		default:
			t.Fatal("run returned without observing actual drain")
		}
	}
}
