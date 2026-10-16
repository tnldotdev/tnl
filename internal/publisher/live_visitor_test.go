package publisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/livevisitor"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestDatabaseLiveAuthorizationClosesBlockedCopy(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		name := "certificate"
		if anonymous {
			name = "anonymous"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				certificate := publicURLTestCertificate(t, "route.example")
				client, visitor := net.Pipe()
				defer client.Close()
				defer visitor.Close()
				backend, target := net.Pipe()
				defer backend.Close()
				defer target.Close()
				secured := tls.Server(visitor, &tls.Config{Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequestClientCert})
				clientConfig := &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, certificate)}
				if !anonymous {
					clientConfig.Certificates = []tls.Certificate{certificate}
				}
				clientTLS := tls.Client(client, clientConfig)
				handshake := make(chan error, 1)
				go func() { handshake <- secured.HandshakeContext(t.Context()) }()
				if err := clientTLS.HandshakeContext(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err := <-handshake; err != nil {
					t.Fatal(err)
				}
				life, cancel := context.WithCancel(t.Context())
				session := &visitorSession{life: life, cancel: cancel, visitor: Visitor{
					Run: PublishRunIdentity{PublicURLID: "url", PublishRunID: "run", Number: 1}, Source: netip.MustParseAddrPort("192.0.2.10:1234")}}
				defer session.close()
				checks := 0
				d := &tcpForwarding{liveSlots: make(chan struct{}, 1), revalidate: func(_ context.Context, visitor Visitor, state tls.ConnectionState) (livevisitor.Decision, error) {
					checks++
					if visitor.Run.PublishRunID != "run" || !state.HandshakeComplete || (len(state.PeerCertificates) == 0) != anonymous {
						t.Error("live recheck lost its original proof")
					}
					return livevisitor.Decision{Allowed: checks == 1, ValidUntil: time.Now().Add(time.Minute)}, nil
				}}
				stop, err := d.authorizeTLS(t.Context(), session, secured, backend)
				if err != nil {
					t.Fatal(err)
				}
				defer stop()
				if extra, err := d.authorizeTLS(t.Context(), session, secured, backend); err == nil {
					extra()
					t.Fatal("pending live check exceeded existing connection capacity")
				}
				copied := make(chan struct{})
				go func() { _ = copyTCPConnections(visitor, secured, backend); close(copied) }()
				synctest.Wait()
				select {
				case <-copied:
					t.Fatal("forwarding ended before revocation")
				default:
				}
				time.Sleep(livevisitor.RefreshInterval)
				synctest.Wait()
				select {
				case <-copied:
				default:
					t.Fatal("denied recheck left Copy blocked")
				}
				if n, err := target.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
					t.Fatalf("backend remained open: %d, %v", n, err)
				}
				if n, err := client.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
					t.Fatalf("visitor remained open: %d, %v", n, err)
				}
				stop()
				if len(d.liveSlots) != 0 {
					t.Fatal("closed visitor retained watcher capacity")
				}
			})
		})
	}
}

type liveCertificateAuthorizerFunc func(context.Context, controlclient.VisitorCertificateScope, tls.ConnectionState) (time.Time, error)

func (f liveCertificateAuthorizerFunc) AuthorizeVisitorCertificateDecision(ctx context.Context, scope controlclient.VisitorCertificateScope, state tls.ConnectionState) (time.Time, error) {
	return f(ctx, scope, state)
}

func TestLiveCertificateDecisionBindsRunSourceAndDeadline(t *testing.T) {
	scope := controlclient.VisitorCertificateScope{PublishRunID: "run", PublicURLID: "url", PublishRunNumber: 4, PublishRunToken: credentials.PublishRunToken("private-run-token")}
	visitor := Visitor{Run: PublishRunIdentity{PublicURLID: "url", PublishRunID: "run", Number: 4}, Source: netip.MustParseAddrPort("[::ffff:192.0.2.10]:1234")}
	now := time.Now()
	state := tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{{Raw: []byte("certificate"), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Minute)}}}
	var resultErr error
	calls := 0
	authorize := LiveVisitorCertificateAuthorization(liveCertificateAuthorizerFunc(func(_ context.Context, got controlclient.VisitorCertificateScope, _ tls.ConnectionState) (time.Time, error) {
		calls++
		if got.SourceIP.String() != "192.0.2.10" || got.PublishRunID != scope.PublishRunID || got.PublicURLID != scope.PublicURLID || got.PublishRunToken != scope.PublishRunToken {
			t.Error("recheck changed trusted scope")
		}
		return now.Add(time.Hour), resultErr
	}), scope)
	for range 2 {
		decision, err := authorize(t.Context(), visitor, state)
		if err != nil || !decision.Allowed || !decision.ValidUntil.Equal(state.PeerCertificates[0].NotAfter) {
			t.Fatalf("fresh certificate deadline = %+v, %v", decision, err)
		}
	}
	if calls != 2 {
		t.Fatal("fresh revalidation reused the connection cache")
	}
	visitor.Run.PublishRunID = "replaced-run"
	if _, err := authorize(t.Context(), visitor, state); !errors.Is(err, livevisitor.ErrDenied) || calls != 2 {
		t.Fatal("revalidation accepted a different run")
	}
	visitor.Run.PublishRunID = scope.PublishRunID
	resultErr = &controlclient.ProblemError{Status: http.StatusForbidden, Problem: controlv1.Problem{Code: controlv1.Forbidden}}
	if decision, err := authorize(t.Context(), visitor, state); err != nil || decision.Allowed {
		t.Fatalf("explicit denial was not distinguishable from unknown: %+v, %v", decision, err)
	}
	resultErr = controlclient.ErrUnavailable
	if _, err := authorize(t.Context(), visitor, state); !errors.Is(err, controlclient.ErrUnavailable) {
		t.Fatal("transient failure became an explicit denial")
	}
}
