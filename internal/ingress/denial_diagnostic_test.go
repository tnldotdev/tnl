package ingress

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type denialDiagnosticListener struct {
	net.Listener
	cleanup error
	closes  *atomic.Int32
}

func (l denialDiagnosticListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &denialDiagnosticConn{Conn: conn, cleanup: l.cleanup, closes: l.closes}, nil
}

type denialDiagnosticConn struct {
	net.Conn
	cleanup error
	closes  *atomic.Int32
	once    sync.Once
	err     error
}

func (c *denialDiagnosticConn) Close() error {
	c.once.Do(func() {
		c.closes.Add(1)
		c.err = errors.Join(c.Conn.Close(), c.cleanup)
	})
	return c.err
}

type diagnosticRefreshControl struct {
	PublicServiceControl
	reads atomic.Int32
	err   error
}

type diagnosticVisitorFailure interface {
	error
	ForwardingScope() (service, run, visitor string, number uint64)
	ForwardingCandidate() (run string, number uint64)
	ForwardingAdmitted() bool
	ForwardingPhase() string
	ForwardingCopyResult() error
	ForwardingCleanup() error
}

func (c *diagnosticRefreshControl) ReadIngressServices(ctx context.Context, id string, lease ingressv1.IngressLeaseIdentity) (ingressv1.IngressServices, error) {
	if c.reads.Add(1) == 1 {
		return c.PublicServiceControl.ReadIngressServices(ctx, id, lease)
	}
	return ingressv1.IngressServices{}, c.err
}

func TestIngressRoutingRefreshUsesConnectionErrorCallbackWithoutVisitor(t *testing.T) {
	var opens atomic.Int32
	config := serviceIngressConfig(t, func(context.Context, tunnelv1.ServiceForwardingHeader, func(context.Context) error) (net.Conn, error) {
		opens.Add(1)
		return nil, errors.New("routing refresh unexpectedly opened a relay")
	})
	failure := errors.New("independent routing snapshot read failure")
	control := &diagnosticRefreshControl{PublicServiceControl: config.Control, err: failure}
	config.Control = control
	reports := make(chan error, 1)
	config.OnError = func(err error) { reports <- err }
	server, _ := startIngress(t, config)
	ctx, cancel := context.WithCancel(ingressContext(t))
	done := ingressWorker(t, cancel, func() error { return server.RefreshServices(ctx) })
	reported := ingressAwait(t, reports)
	cancel()
	if err := ingressAwait(t, done); err != nil {
		t.Fatal("join diagnostic refresh worker", err)
	}
	if !errors.Is(reported, failure) || errors.Is(reported, ErrServiceAdmission) ||
		control.reads.Load() != 2 || opens.Load() != 0 || server.Load() != 0 {
		t.Fatal("refresh report was confused with a visitor admission or forwarding failure")
	}
	t.Logf("report boundary=ingress.OnError ingress_id=%s origin=background-routing-refresh visitor_connections=0", config.CurrentLease().IngressId)
}

func TestIngressSourceDenialReportsAdmissionAndIndependentCleanupCauses(t *testing.T) {
	for _, independent := range []bool{false, true} {
		name := "denial-only"
		if independent {
			name = "denial-and-independent-close"
		}
		t.Run(name, func(t *testing.T) {
			cleanup := errors.New("independent accepted socket close failure")
			var injected error
			if independent {
				injected = cleanup
			}
			var opens, closes atomic.Int32
			config := serviceIngressConfig(t, func(context.Context, tunnelv1.ServiceForwardingHeader, func(context.Context) error) (net.Conn, error) {
				opens.Add(1)
				return nil, errors.New("denied source unexpectedly reached relay")
			})
			control := config.Control.(*httpsServiceControl)
			audits := make(chan serviceaudit.Observation, 1)
			reports := make(chan error, 1)
			config.AuditSink = auditSinkFunc(func(event serviceaudit.Observation) bool {
				audits <- event
				return true
			})
			config.OnError = func(err error) { reports <- err }
			server, address := startIngress(t, config, func(server *Server) {
				server.listener = denialDiagnosticListener{Listener: server.listener, cleanup: injected, closes: &closes}
			})
			defer func() {
				if err := server.Drain(ingressContext(t)); err != nil {
					t.Error("drain diagnostic ingress", err)
				}
			}()
			visitor := ingressClient(t, address, "route.example", "198.51.100.7:40000")
			if err := visitor.Handshake(); err != io.EOF {
				t.Fatal("denied source did not end before visitor TLS", err)
			}
			if err := visitor.Close(); err != nil {
				t.Fatal("close denied visitor", err)
			}
			event, reported := ingressAwait(t, audits), ingressAwait(t, reports)
			server.active.Wait()
			var scoped diagnosticVisitorFailure
			if !errors.As(reported, &scoped) {
				t.Fatal("actual ingress report lost its scoped denial and final-cleanup provenance")
			}
			service, run, visitorID, number := scoped.ForwardingScope()
			candidate, candidateNumber := scoped.ForwardingCandidate()
			if service != event.ServiceID || run != "" || number != 0 || visitorID != event.VisitorConnectionID ||
				candidate != control.run || candidateNumber == 0 || scoped.ForwardingAdmitted() ||
				scoped.ForwardingPhase() != "selection" || scoped.ForwardingCopyResult() != nil ||
				independent != errors.Is(scoped.ForwardingCleanup(), cleanup) {
				t.Fatal("ingress denial invented an admitted run or lost its independent physical cleanup")
			}
			if event.ServiceID != control.service || event.RunID != "" || event.Outcome != "denied" || event.Reason != "ip_policy" ||
				event.SourceIP != "198.51.100.7" || !opaqueid.Valid(event.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) {
				t.Fatal("source denial lost its exact selection evidence")
			}
			if !errors.Is(reported, ErrServiceAdmission) || opens.Load() != 0 || closes.Load() != 1 || server.openContext.Err() != nil {
				t.Fatal("report did not originate from a live ingress source denial", opens.Load(), closes.Load())
			}
			if independent != errors.Is(reported, cleanup) || failure.Only(reported, ErrServiceAdmission) == independent {
				t.Fatal("source-denial report lost or hid an independent close failure")
			}
			if reason, specific := failure.ReasonOf(reported); specific {
				t.Fatal("denial unexpectedly supplied a more specific operator reason", reason)
			}
			select {
			case <-reports:
				t.Fatal("one denied visitor produced duplicate reports")
			default:
			}
			t.Logf("report boundary=ingress.OnError service_id=%s visitor_connection_id=%s origin=source-policy admission_cause=true independent_close=%t", event.ServiceID, event.VisitorConnectionID, independent)
		})
	}
}
