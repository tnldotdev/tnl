package stream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

type stdioTLSCloseStream struct {
	muxsession.Stream
	failing atomic.Bool
	fault   error
}

func (s *stdioTLSCloseStream) Write(data []byte) (int, error) {
	n, err := s.Stream.Write(data)
	if s.failing.Load() {
		err = errors.Join(err, s.fault)
	}
	return n, err
}

func TestStdioTLSCloseRetainsOnlyIndependentFailures(t *testing.T) {
	for _, transport := range []string{"quic", "wss"} {
		for _, fault := range []error{nil, io.EOF, net.ErrClosed, errors.New("independent TLS alert write failure")} {
			name := "owned abort"
			if fault != nil {
				name = fault.Error()
			}
			t.Run(transport+"/"+name, func(t *testing.T) {
				raw, remote := stdioTransportPair(t, transport)
				stream := &stdioTLSCloseStream{Stream: raw, fault: fault}
				local, input := net.Pipe()
				defer input.Close()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				o := newStdioOperation(ctx, local)
				defer o.finish(nil)
				selected, err := o.bind(stream)
				if err != nil {
					t.Fatal(err)
				}
				root, certificate := providerCertificate(t)
				roots := x509.NewCertPool()
				roots.AppendCertsFromPEM(root)
				secured := tls.Client(selected, &tls.Config{RootCAs: roots, ServerName: "db.example", MinVersion: tls.VersionTLS13})
				server := tls.Server(remote, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
				setup, stop := context.WithTimeout(t.Context(), 5*time.Second)
				defer stop()
				handshake := make(chan error, 1)
				go func() { handshake <- server.HandshakeContext(setup) }()
				if err := errors.Join(secured.HandshakeContext(setup), <-handshake); err != nil {
					t.Fatal(err)
				}
				if err := o.activate(selected); err != nil {
					t.Fatal(err)
				}
				prepared := &PreparedConnector{ctx: o.ctx, conn: secured, stdio: selected}
				stream.failing.Store(fault != nil)
				cancel()
				<-o.abortDone
				// the interrupted path must not send close-notify. exercise the
				// actual TLS close result separately after the exact owned reset.
				if err := o.reset(); err != nil {
					t.Fatal(err)
				}
				o.mu.Lock()
				selected.released = true
				o.mu.Unlock()
				closeErr := selected.tlsCloseResult(secured.Close())
				if fault == nil && closeErr != nil || fault != nil && !errors.Is(closeErr, fault) {
					t.Fatal("TLS cleanup changed an independent close result", fault, closeErr)
				}
				err = prepared.closePhysical()
				if fault == nil && err != nil {
					t.Fatal("owned stdio reset became an independent TLS close failure", err)
				}
				if fault != nil && !errors.Is(errors.Join(err, closeErr), fault) {
					t.Fatal("owned stdio reset hid an independent TLS close failure", fault, err, closeErr)
				}
				if replay := prepared.closePhysical(); replay != err {
					t.Fatal("physical TLS cleanup changed on replay", replay, err)
				}
				o.complete()
			})
		}
	}
}
