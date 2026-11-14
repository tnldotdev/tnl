package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type completionWriteConn struct {
	net.Conn
	armed   atomic.Bool
	blocked chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (c *completionWriteConn) Write(p []byte) (int, error) {
	if c.armed.Load() {
		c.once.Do(func() { close(c.blocked) })
		<-c.release
	}
	return c.Conn.Write(p)
}

type completionSlot struct {
	*heldSlot
	closeErr error
}

func (s *completionSlot) Close() error {
	return errors.Join(s.heldSlot.Close(), s.closeErr)
}

func TestServiceRunCompletesHTTPBudgetAfterFinalResponseAndJoinedCleanup(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, mode := range []string{"total", "process", "cleanup_failure"} {
			name := map[bool]string{false: "http1", true: "http2"}[h2] + "/" + mode
			t.Run(name, func(t *testing.T) {
				cfg, control := lifecycleFixture(t)
				approved, err := control.GetPublisherService(t.Context(), cfg.ServiceID, "")
				if err != nil {
					t.Fatal(err)
				}
				approved.Protocol, approved.Endpoint.Port = controlv1.ServiceProtocolHTTP, 443
				approved.HttpLimits = &controlv1.ProjectHTTPApplicationLimits{Total: new(1)}
				if mode == "process" {
					approved.HttpLimits.Total = nil
				}
				control.approved = &approved
				cfg.Metadata.Protocol = controlv1.ServiceProtocolHTTP
				cfg.Target = ""
				// keep the final write outside the handler's request-budget lifetime.
				raw, visitor := net.Pipe()
				defer raw.Close()
				defer visitor.Close()
				unblock := make(chan struct{})
				release := sync.OnceFunc(func() { close(unblock) })
				defer release()
				wire := &completionWriteConn{Conn: raw, blocked: make(chan struct{}), release: unblock}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				cfg.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Trailer", "X-Final")
					_, _ = io.WriteString(w, "final")
					w.Header().Set("X-Final", "complete")
					wire.armed.Store(true)
					if mode == "process" {
						cancel()
					}
				})
				ready := make(chan struct{})
				bounds := make(chan *Bound, 2)
				var slots [2]*completionSlot
				cleanup := errors.New("independent slot cleanup failed")
				cfg.Connect = func(_ context.Context, bound *Bound, slot uint8, _ ConnectOptions) (SlotSession, error) {
					current := &completionSlot{heldSlot: &heldSlot{stopped: make(chan struct{})}}
					if mode == "cleanup_failure" && slot == 0 {
						current.closeErr = errors.Join(context.Canceled, cleanup)
					}
					slots[slot] = current
					bounds <- bound
					return current, nil
				}
				cfg.Ready = func() error { close(ready); return nil }
				published := make(chan error, 1)
				joined := make(chan struct{})
				go func() { defer close(joined); published <- Publish(ctx, cfg) }()
				defer func() { release(); cancel(); <-joined }()
				serviceHTTPAwait(t, ready)
				bound := serviceHTTPAwait(t, bounds)
				// certificate issuance continues as normal; this visitor fixture uses
				// an independent trusted leaf so its traffic has deterministic trust.
				certificate, trust := managedTestCertificate(t, approved.Endpoint.Hostname)
				trust.Certificates = []tls.Certificate{certificate}
				bound.prepared.visitorTLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
				auth := servicestream.CertificateVisitor{Check: func(context.Context, *x509.Certificate) (servicestream.Decision, error) {
					return servicestream.Decision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
				}}
				forwarded := make(chan error, 1)
				// the visitor lifetime is run-owned, not the canceled process input.
				go func() { forwarded <- bound.forwardManaged(t.Context(), wire, auth, "") }()
				transport := &http.Transport{ForceAttemptHTTP2: h2, TLSClientConfig: trust,
					DialContext: func(context.Context, string, string) (net.Conn, error) { return visitor, nil }}
				defer transport.CloseIdleConnections()
				responseDone := make(chan struct{})
				go func() {
					defer close(responseDone)
					request, err := http.NewRequestWithContext(t.Context(), "GET", "https://"+approved.Endpoint.Hostname+"/", nil)
					if err != nil {
						t.Error(err)
						return
					}
					response, err := transport.RoundTrip(request)
					if err != nil {
						t.Error(err)
						return
					}
					defer response.Body.Close()
					body, err := io.ReadAll(response.Body)
					protocol := 1
					if h2 {
						protocol = 2
					}
					if err != nil || string(body) != "final" || response.Trailer.Get("X-Final") != "complete" || response.ProtoMajor != protocol {
						t.Error("service completion lost its final response", string(body), response.Trailer, response.Proto, err)
					}
				}()
				serviceHTTPAwait(t, wire.blocked)
				if mode != "process" {
					serviceHTTPAwait(t, bound.prepared.serviceHTTPRequests.Completed())
				}
				select {
				case err := <-published:
					t.Fatal("run completed before final HTTP bytes", err)
				default:
				}
				for _, slot := range slots {
					select {
					case <-slot.stopped:
						t.Fatal("run closed a relay transport before joining its HTTP response")
					default:
					}
				}
				control.mu.Lock()
				closes := control.closes
				control.mu.Unlock()
				if closes != 0 {
					t.Fatal("run closed control authority before final HTTP response")
				}
				release()
				serviceHTTPAwait(t, responseDone)
				if err := serviceHTTPAwait(t, forwarded); err != nil {
					t.Fatal(err)
				}
				err = serviceHTTPAwait(t, published)
				if mode == "cleanup_failure" {
					if !errors.Is(err, cleanup) {
						t.Fatal("normal completion discarded independent cleanup failure", err)
					}
				} else if err != nil {
					t.Fatal("normal completion became authority expiry", err)
				}
				for _, slot := range slots {
					select {
					case <-slot.stopped:
					default:
						t.Fatal("completed run did not join and close both slots")
					}
				}
				control.mu.Lock()
				defer control.mu.Unlock()
				if control.closes != 1 || control.bad != nil {
					t.Fatal("completion did not close the exact run once", control.closes, control.bad)
				}
			})
		}
	}
}
