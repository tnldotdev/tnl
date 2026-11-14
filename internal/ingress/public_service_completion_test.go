package ingress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type serviceCompletionForwarder struct{ connection net.Conn }

func (f serviceCompletionForwarder) OpenPrivate(context.Context, ingressv1.ServiceRelay, tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
	return f.connection, nil
}

type serviceEOFConn struct{ net.Conn }

func (serviceEOFConn) Read([]byte) (int, error) { return 0, io.EOF }

type serviceFailedHalfCloseConn struct {
	net.Conn
	entered, closed chan struct{}
	closeOnce       sync.Once
	halfCloseError  error
	closeError      error
}

func (c *serviceFailedHalfCloseConn) CloseWrite() error {
	close(c.entered)
	// force authorization denial to close this stream before the independent
	// half-close failure returns. cancellation alone must not hide that cause.
	<-c.closed
	return c.halfCloseError
}

func (c *serviceFailedHalfCloseConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { close(c.closed) })
	return errors.Join(err, c.closeError)
}

func TestPublicServiceDenialRetainsIndependentCompletionFailures(t *testing.T) {
	for _, withCleanupFailure := range []bool{false, true} {
		name := "half_close"
		if withCleanupFailure {
			name = "half_close_and_cleanup"
		}
		t.Run(name, func(t *testing.T) {
			p, control, _, _ := publicServiceTestSetup(t)
			copyFailure, closeFailure := errors.New("half-close failed"), errors.New("backend close failed")
			upstream, peer := net.Pipe()
			connection, visitor := net.Pipe()
			for _, conn := range []net.Conn{upstream, peer, connection, visitor} {
				ownIngressConn(t, conn)
			}
			backend := &serviceFailedHalfCloseConn{Conn: upstream, entered: make(chan struct{}), closed: make(chan struct{}), halfCloseError: copyFailure}
			if withCleanupFailure {
				backend.closeError = closeFailure
			}
			control.deny, control.recheckGate = true, backend.entered
			p.config.Forwarder = serviceCompletionForwarder{connection: backend}
			decoded := ingressWorker(t, func() { _ = peer.Close() }, func() error {
				_, _, err := proxyproto.Decode(peer)
				return err
			})
			ctx := ingressContext(t)
			done := ingressWorker(t, func() { _ = backend.Close(); _ = connection.Close() }, func() error {
				return p.AcceptPublic(ctx, serviceEOFConn{connection},
					netip.MustParseAddrPort("192.0.2.4:42000"), netip.MustParseAddrPort("203.0.113.8:20000"), "", nil)
			})
			err := ingressAwait(t, done)
			if !errors.Is(err, ErrServiceAdmission) || !errors.Is(err, copyFailure) {
				t.Fatal("authorization denial hid the independent forwarding failure", err)
			}
			if withCleanupFailure && !errors.Is(err, closeFailure) {
				t.Fatal("authorization denial hid backend cleanup failure", err)
			}
			if err := ingressAwait(t, decoded); err != nil {
				t.Fatal(err)
			}
			if p.Load() != 0 || control.recheckActive.Load() != 0 {
				t.Fatal("failed forwarding retained an owned session or authorization worker")
			}
			control.mu.Lock()
			closed := control.closed
			control.mu.Unlock()
			if closed != 1 {
				t.Fatal("visitor admission was not released exactly once", closed)
			}
		})
	}
}
