package certificates

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/sourceauth"
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
	sourceKey := [32]byte{1, 2, 3}
	backend.sourceKey = sourceKey
	issuance := Issuance{
		Hostname: testHostname, ChallengeURL: challenge.ID,
		ChallengeDigest: digest, ChallengeExpires: expiresAt,
	}
	if err := ProbeTLSALPN(context.Background(), backend, sourceKey, issuance); err != nil {
		t.Fatal(err)
	}
	issuance.ChallengeDigest[0] ^= 0xff
	if err := ProbeTLSALPN(context.Background(), backend, sourceKey, issuance); err == nil {
		t.Fatal("probe accepted a mismatched challenge digest")
	}
}

type challengeBackend struct {
	t          *testing.T
	challenges *tlschallenge.TLSALPNChallenges
	sourceKey  [32]byte
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
		claim, err := sourceauth.Server(server, b.sourceKey)
		if err != nil {
			b.t.Errorf("authenticate source metadata: %v", err)
			return
		}
		if claim.Purpose != sourceauth.PurposeACME {
			b.t.Errorf("source purpose = %v", claim.Purpose)
			return
		}
		connection := tls.Server(server, &tls.Config{
			GetCertificate: b.challenges.GetCertificate, NextProtos: []string{acme.ALPNProto},
			MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true,
		})
		_ = connection.Handshake()
	}()
	return net.Dial("tcp", listener.Addr().String())
}
