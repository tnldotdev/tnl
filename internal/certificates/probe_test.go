package certificates

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/tlschallenge"
	"golang.org/x/crypto/acme"
)

func TestProbeTLSALPN(t *testing.T) {
	digest := sha256.Sum256([]byte("key authorization"))
	expiresAt := time.Now().Add(time.Hour)
	challenge := tlschallenge.TLSALPNChallenge{
		ID: "challenge", Hostname: testHostname, Digest: digest, ExpiresAt: expiresAt,
	}
	var challenges tlschallenge.TLSALPNChallenges
	if err := challenges.Install(challenge); err != nil {
		t.Fatal(err)
	}
	backend := &challengeBackend{t: t, challenges: &challenges}
	issuance := Issuance{
		Hostname: testHostname, ChallengeURL: challenge.ID,
		ChallengeDigest: digest, ChallengeExpires: expiresAt,
	}
	if err := ProbeTLSALPN(context.Background(), backend, issuance); err != nil {
		t.Fatal(err)
	}
	issuance.ChallengeDigest[0] ^= 0xff
	if err := ProbeTLSALPN(context.Background(), backend, issuance); err == nil {
		t.Fatal("probe accepted a mismatched challenge digest")
	}
}

type challengeBackend struct {
	t          *testing.T
	challenges *tlschallenge.TLSALPNChallenges
}

func (b *challengeBackend) Open(context.Context) (net.Conn, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() {
		defer listener.Close()
		server, err := listener.Accept()
		if err != nil {
			b.t.Errorf("accept probe: %v", err)
			return
		}
		defer server.Close()
		if _, replay, err := proxyproto.Decode(server); err != nil {
			b.t.Errorf("decode PROXY header: %v", err)
			return
		} else {
			server = &probeReaderConn{Conn: server, reader: replay}
		}
		connection := tls.Server(server, &tls.Config{
			GetCertificate: b.challenges.GetCertificate, NextProtos: []string{acme.ALPNProto},
			MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true,
		})
		_ = connection.Handshake()
	}()
	return net.Dial("tcp", listener.Addr().String())
}

type probeReaderConn struct {
	net.Conn
	reader interface{ Read([]byte) (int, error) }
}

func (c *probeReaderConn) Read(destination []byte) (int, error) {
	return c.reader.Read(destination)
}
