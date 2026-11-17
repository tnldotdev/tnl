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
	for _, transport := range []string{"quic", "tls-tcp"} {
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
				err = prepared.closePhysical()
				if fault == nil && err != nil {
					t.Fatal("owned stdio reset became an independent TLS close failure", err)
				}
				if fault != nil && !errors.Is(err, fault) {
					t.Fatal("owned stdio reset hid an independent TLS close failure", fault, err)
				}
				if replay := prepared.closePhysical(); replay != err {
					t.Fatal("physical TLS cleanup changed on replay", replay, err)
				}
				o.complete()
			})
		}
	}
}
