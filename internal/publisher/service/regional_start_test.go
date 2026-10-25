package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type measuredServiceControl struct {
	*lifecycleControl
	candidates controlv1.RelayCandidates
	preferred  []string
}

func (c *measuredServiceControl) RelayCandidates(context.Context, string) (controlv1.RelayCandidates, error) {
	return c.candidates, nil
}

func (c *measuredServiceControl) StartServiceRunInRegions(ctx context.Context, id, run, access string, number int64, preferred []string) (controlv1.ServiceRunSetup, error) {
	c.mu.Lock()
	c.preferred = slices.Clone(preferred)
	c.mu.Unlock()
	return c.lifecycleControl.StartServiceRun(ctx, id, run, access, number)
}

func TestPrivateRunStartsTwoSlotsAfterVerifiedTwoRegionMeasurement(t *testing.T) {
	config, base := lifecycleFixture(t)
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := issuer.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(issuer.Certificate())
	issuer.Close()
	config.TransportTLS = &tls.Config{RootCAs: roots}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var workers sync.WaitGroup
	var listeners []net.Listener
	t.Cleanup(func() {
		cancel()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		workers.Wait()
	})
	control := &measuredServiceControl{lifecycleControl: base}
	for _, site := range []struct {
		code  string
		delay time.Duration
	}{{"sjc", 0}, {"ord", 75 * time.Millisecond}} {
		for slot := range 2 {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			listeners = append(listeners, listener)
			workers.Go(func() {
				for {
					connection, err := listener.Accept()
					if err != nil {
						return
					}
					workers.Go(func() {
						defer connection.Close()
						stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
						defer stop()
						time.Sleep(site.delay)
						_, _, _ = muxsession.AcceptTLSYamuxOrProbe(ctx, connection, &tls.Config{Certificates: []tls.Certificate{certificate}}, muxsession.TLSYamuxConfig{})
					})
				}
			})
			control.candidates.Candidates = append(control.candidates.Candidates, controlv1.RelayProbeCandidate{
				Region: site.code, RelayServiceId: "relay-" + site.code + "-" + strconv.Itoa(slot),
				RelayAddress: listener.Addr().String(), TlsServerName: "127.0.0.1",
			})
		}
	}
	config.Control = control
	connected := make(chan uint8, 2)
	config.Connect = func(_ context.Context, _ *Bound, slot uint8) (SlotSession, error) {
		connected <- slot
		return &heldSlot{stopped: make(chan struct{})}, nil
	}
	ready := make(chan struct{})
	config.Ready = func() error { close(ready); return nil }
	done := make(chan error, 1)
	go func() { done <- Publish(ctx, config) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal("measured private run did not become ready", err)
	case <-time.After(5 * time.Second):
		t.Fatal("measured private run never became ready")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("private run did not join")
	}
	close(connected)
	var slots []uint8
	for slot := range connected {
		slots = append(slots, slot)
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if !slices.Equal(control.preferred, []string{"sjc", "ord"}) || len(slots) != 2 || slots[0] == slots[1] || control.prepares != 1 || control.binds != 2 || control.closes != 1 || control.bad != nil || base.setup.PublisherConnections[0].RelayServiceId == base.setup.PublisherConnections[1].RelayServiceId {
		t.Fatal("measured preference did not start and join two distinct ready slots", control.preferred, slots, control.bad)
	}
}
