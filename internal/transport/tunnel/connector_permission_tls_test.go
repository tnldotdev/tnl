package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorTLSHalfCloseKeepsBoundedRenewalAndResponse(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			client, server := realTunnelPair(t, "quic")
			writer, control := permissionControlPair(t, client.transport, server.transport)
			ctx, cancel := context.WithCancel(tunnelContext(t))
			defer cancel()
			permission := connectorPermissionFixture()
			renewed := make(chan struct{}, 1)
			var permissionGate ConnectorPermissionGate
			done := tunnelWorker(t, cancel, func() error {
				return ServeConnectorPermissionControl(ctx, control, func(got tunnelv1.ConnectorPermissionUpdate, responder *ConnectorPermissionResponder) {
					if got != permission {
						t.Error("TLS half-close changed renewal permission")
					}
					renewed <- struct{}{}
					_ = responder.Respond(got, got == permission)
				}, func() {}, &permissionGate)
			})
			serverTLS, clientTLS := realTunnelTLS(t)
			serverTLS.MinVersion, serverTLS.MaxVersion = version, version
			clientTLS.MinVersion, clientTLS.MaxVersion = version, version
			clientTLS.ServerName = "relay.test"
			raw, err := client.transport.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			secured := tls.Client(raw, clientTLS)
			handshake := tunnelWorker(t, func() { _ = raw.Reset(0) }, func() error { return secured.HandshakeContext(ctx) })
			application, err := server.transport.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			remote := tls.Server(application, serverTLS)
			_ = secured.SetDeadline(time.Now().Add(3 * time.Second))
			_ = remote.SetDeadline(time.Now().Add(3 * time.Second))
			if err := remote.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			if err := await(t, handshake); err != nil {
				t.Fatal(err)
			}
			if err := secured.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if n, err := remote.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatal("TLS close_notify did not end application input", n, err)
			}
			renewal, cancelRenewal := context.WithTimeout(ctx, time.Second)
			err = writer.Renew(renewal, permission)
			cancelRenewal()
			if err != nil {
				t.Fatal("TLS close_notify deadline stopped permission renewal", err)
			}
			select {
			case <-renewed:
			case <-time.After(time.Second):
				t.Fatal("TLS half-close stopped the permission frame owner")
			}
			response := tunnelWorker(t, func() { _ = application.Reset(0) }, func() error { _, err := remote.Write([]byte("response")); return err })
			var got [8]byte
			if _, err := io.ReadFull(secured, got[:]); err != nil || string(got[:]) != "response" {
				t.Fatal("TLS half-close truncated the response", err)
			}
			if err := await(t, response); err != nil {
				t.Fatal(err)
			}
			cancel()
			_ = await(t, done)
		})
	}
}
