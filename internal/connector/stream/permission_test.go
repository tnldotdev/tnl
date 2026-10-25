package stream

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type observedNativeConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *observedNativeConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func TestNativePermissionWaitsBehindUploadUntilConfirmedDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config, run := selectionFixture()
		run.Permission.ExpiresAt = time.Now().Add(30 * time.Second)
		next := run
		next.Permission.VisitorToken = "next-prepared-permission"
		next.Permission.ExpiresAt = time.Now().Add(40 * time.Second)
		prepared := &preparedSelection{config: config, run: next, until: time.Now().Add(20 * time.Second), stop: func(error) {}}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer := Signer{PublicKey: public, Sign: func(message []byte) []byte { return ed25519.Sign(private, message) }}
		session, err := opaqueid.New(opaqueid.ConnectorSessionPrefix)
		if err != nil {
			t.Fatal(err)
		}
		visitor, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
		if err != nil {
			t.Fatal(err)
		}
		client, server := net.Pipe()
		defer server.Close()
		raw := &observedNativeConn{Conn: client}
		stop := renewNativePermission(t.Context(), raw, tunnel.NewNativeRequestWriter(raw), prepared, signer, session, visitor, run)
		defer stop()
		time.Sleep(7 * time.Second)
		synctest.Wait()
		if raw.closed.Load() {
			t.Fatal("write backpressure closed an unexpired visitor permission")
		}
		frame, err := tunnelv1.ReadNativeRequestFrame(server)
		if err != nil || frame.Kind != tunnelv1.NativeRequestPermission || frame.Permission.Token != next.Permission.VisitorToken {
			t.Fatal("renewal did not resume after the upload", err)
		}
	})
}
