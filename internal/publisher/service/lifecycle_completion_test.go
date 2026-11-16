package service

import (
	"bytes"
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

func TestServiceTCPDrainKeepsHalfClosedVisitorThroughFinalTargetBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	entered, requestFIN := make(chan struct{}), make(chan struct{})
	finish := make(chan struct{})
	release := sync.OnceFunc(func() { close(finish) })
	defer release()
	payload := bytes.Repeat([]byte("final native response\n"), 32768)
	targetDone := make(chan error, 1)
	targetJoined := make(chan struct{})
	go func() {
		defer close(targetJoined)
		conn, err := target.Accept()
		if err != nil {
			targetDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		request := make([]byte, len("request"))
		if _, err := io.ReadFull(conn, request); err != nil || string(request) != "request" {
			targetDone <- errors.Join(err, errors.New("native request changed"))
			return
		}
		close(entered)
		trailing, err := io.ReadAll(conn)
		if err != nil || len(trailing) != 0 {
			targetDone <- errors.Join(err, errors.New("request half-close changed the target session"))
			return
		}
		close(requestFIN)
		select {
		case <-finish:
		case <-ctx.Done():
			targetDone <- ctx.Err()
			return
		}
		_, err = conn.Write(payload)
		targetDone <- err
	}()
	_, bound, _, verification := privateFixture(t, target.Addr().String())
	raw, visitor := net.Pipe()
	defer raw.Close()
	defer visitor.Close()
	auth := servicestream.CertificateVisitor{Check: func(context.Context, *x509.Certificate) (servicestream.Decision, error) {
		return servicestream.Decision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
	}}
	forwarded := make(chan error, 1)
	forwardJoined := make(chan struct{})
	go func() { defer close(forwardJoined); forwarded <- bound.forwardManaged(ctx, raw, auth, "", nil) }()
	defer func() {
		cancel()
		release()
		_ = raw.Close()
		_ = visitor.Close()
		_ = target.Close()
		<-forwardJoined
		<-targetJoined
	}()
	secured := tls.Client(visitor, verification)
	defer secured.Close()
	if err := secured.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(secured, "request"); err != nil {
		t.Fatal(err)
	}
	serviceHTTPAwait(t, entered)
	if err := bound.startDrain(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	joined := make(chan error, 1)
	go func() { joined <- bound.joinDrain() }()
	if err := secured.CloseWrite(); err != nil {
		t.Fatal("drain lost the visitor's request half-close", err)
	}
	serviceHTTPAwait(t, requestFIN)
	select {
	case err := <-joined:
		t.Fatal("drain finished before the half-closed target returned its final bytes", err)
	default:
	}
	release()
	body, err := io.ReadAll(secured)
	if err != nil || !bytes.Equal(body, payload) {
		t.Fatal("native drain lost final response bytes", len(body), len(payload), err)
	}
	if err := serviceHTTPAwait(t, forwarded); err != nil {
		t.Fatal("native forwarding did not join cleanly", err)
	}
	if err := serviceHTTPAwait(t, joined); err != nil {
		t.Fatal("native drain did not join before its fixed bound", err)
	}
	if err := serviceHTTPAwait(t, targetDone); err != nil {
		t.Fatal("native target failed", err)
	}
}

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
				payload := bytes.Repeat([]byte("complete visitor response\n"), 32768)
				cfg.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Trailer", "X-Final")
					_, _ = w.Write(payload)
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
				go func() { forwarded <- bound.forwardManaged(t.Context(), wire, auth, "", nil) }()
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
					if err != nil || !bytes.Equal(body, payload) || response.Trailer.Get("X-Final") != "complete" || response.ProtoMajor != protocol {
						t.Error("service completion lost its final response", len(body), len(payload), response.Trailer, response.Proto, err)
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
