package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestRelayTransportRejectsNativePublisherRoleConfusion(t *testing.T) {
	proof := tunnelv1.NativePairLegProof{PairID: "npp_1234567890123456789012", DeliveryGeneration: 1, ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012", RunNumber: 1, PublisherIdentityID: "pub_1234567890123456789012", ConnectionSlot: 0, PublisherConnectionID: "pc_1234567890123456789012", AssignmentRevision: 1, RelayServiceID: "relay-a", RelayID: "process-a", RelayRunID: "relay_run", RelayLeaseRevision: 1, Nonce: make([]byte, 32), Signature: make([]byte, 64)}
	proof.RequestedAt = time.Now()
	if err := proof.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, transport := range []tunnel.Transport{tunnel.TransportQUIC, tunnel.TransportTLSTCP} {
		for _, variant := range []string{"publisher with native proof", "native with publisher credential", "native with publisher connection", "retired connector role"} {
			t.Run(string(transport)+"/"+variant, func(t *testing.T) {
				certificate := httptest.NewTLSServer(nil)
				t.Cleanup(certificate.Close)
				roots := x509.NewCertPool()
				roots.AddCert(certificate.Certificate())
				var native, publisher atomic.Int32
				acceptor, err := NewPublisherAcceptor(PublisherAcceptorConfig{
					Select: func(string) (PublisherConnectionController, *Registry, bool) {
						publisher.Add(1)
						return nil, nil, false
					},
					Native: func(string) (*NativeConnectorAcceptor, bool) { native.Add(1); return nil, false },
				})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				rejected := make(chan error, 1)
				address := traceMuxServer(t, ctx, transport, certificate.TLS, func(ctx context.Context, session muxsession.Session) error {
					err := acceptor.Accept(ctx, session)
					rejected <- err
					return err
				})
				var connector muxsession.Connector = muxsession.QUICConnector{TLSConfig: &tls.Config{RootCAs: roots}}
				if transport == tunnel.TransportTLSTCP {
					connector = muxsession.TLSYamuxConnector{TLSConfig: &tls.Config{RootCAs: roots}}
				}
				session, err := connector.Connect(ctx, muxsession.Endpoint{Address: address, ServerName: "example.com"})
				if err != nil {
					t.Fatal(err)
				}
				defer session.Close()
				stream, err := session.OpenStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer stream.Close()
				_ = stream.SetDeadline(time.Now().Add(time.Second))
				message := map[string]any{"type": "hello", "protocol_version": 1, "role": "native_connector", "native_pair_leg_proof": proof}
				switch variant {
				case "publisher with native proof":
					message["role"], message["credential"] = "publisher", "publisher-secret"
				case "native with publisher credential":
					message["credential"] = ""
				case "native with publisher connection":
					message["publisher_connection"] = nil
				case "retired connector role":
					message["role"] = "connector"
				}
				payload, err := json.Marshal(message)
				if err != nil {
					t.Fatal(err)
				}
				frame := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
				_, _ = stream.Write(append(frame, payload...))
				if response, err := tunnelv1.ReadControl(stream); err == nil && response.Type == tunnelv1.HelloAccepted {
					t.Fatal("confused role received authority")
				}
				select {
				case err := <-rejected:
					if err == nil {
						t.Fatal("confused role accepted")
					}
				case <-ctx.Done():
					t.Fatal("role rejection did not join")
				}
				if native.Load() != 0 || publisher.Load() != 0 {
					t.Fatal("confused role reached authority or publisher registration")
				}
			})
		}
	}
}
