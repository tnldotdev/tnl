package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type sessionWithoutAcceptedPeer struct{ muxsession.Session }

// peerNativeDial sends the first control stream through an accepted physical
// socket. no transport metadata is supplied by the test to relay admission.
func peerNativeDial(t *testing.T, kind string, acceptor *PublisherAcceptor, hello tunnelv1.Message, hidePeer bool, hint ...string) (error, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	root, certificate := testutil.TLSCertificate(t, []string{"relay.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(root) {
		t.Fatal("test root is invalid")
	}
	serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	clientTLS := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	var client muxsession.Session
	var done <-chan error
	endpoint := muxsession.Endpoint{ServerName: "relay.test"}
	switch kind {
	case "quic":
		listener, err := muxsession.ListenQUIC("127.0.0.1:0", serverTLS, muxsession.QUICConfig{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		endpoint.Address = listener.Addr().String()
		done = relayWorker(t, func() { cancel(); _ = listener.Close() }, func() error {
			accepted, err := listener.Accept(ctx)
			if err != nil {
				return err
			}
			if hidePeer {
				return acceptor.Accept(ctx, sessionWithoutAcceptedPeer{accepted})
			}
			return acceptor.Accept(ctx, accepted)
		})
		client, err = (muxsession.QUICConnector{TLSConfig: clientTLS}).Connect(ctx, endpoint)
		if err != nil {
			t.Fatal(err)
		}
	case "tls_yamux":
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		endpoint.Address = listener.Addr().String()
		done = relayWorker(t, func() { cancel(); _ = listener.Close() }, func() error {
			conn, err := listener.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			accepted, err := muxsession.AcceptTLSYamux(ctx, conn, serverTLS, muxsession.TLSYamuxConfig{})
			if err != nil {
				return err
			}
			if hidePeer {
				return acceptor.Accept(ctx, sessionWithoutAcceptedPeer{accepted})
			}
			return acceptor.Accept(ctx, accepted)
		})
		client, err = (muxsession.TLSYamuxConnector{TLSConfig: clientTLS}).Connect(ctx, endpoint)
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown native socket kind")
	}
	t.Cleanup(func() { _ = client.Close() })
	if len(hint) > 0 {
		stream, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
		payload, err := json.Marshal(hello)
		if err != nil {
			t.Fatal(err)
		}
		payload = append(payload[:len(payload)-1], []byte(`,"observed_source_ip":"`+hint[0]+`"}`)...)
		if _, err := stream.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(payload))), payload...)); err != nil {
			t.Fatal(err)
		}
		response, err := tunnelv1.ReadControl(stream)
		if err == nil && (response.Type != tunnelv1.Error || response.Code != tunnelv1.InvalidMessage) {
			t.Fatalf("source hint was accepted: %+v, %v", response, err)
		}
		return err, relayAwait(t, done)
	}
	session, dialErr := tunnel.Dial(ctx, client, hello)
	if session != nil {
		_ = session.Close()
	}
	return dialErr, relayAwait(t, done)
}

func peerNativeAssertDenied(t *testing.T, dialErr, acceptErr error) {
	t.Helper()
	var rejected *tunnel.ProtocolError
	// tunnel.Accept closes a denied outer transport after writing the error;
	// QUIC or yamux may report that close before the client reads the frame.
	if !errors.As(acceptErr, &rejected) || rejected.Code != tunnelv1.Unauthenticated || dialErr == nil {
		t.Fatalf("native claim admitted: dial=%v, accept=%v", dialErr, acceptErr)
	}
}
