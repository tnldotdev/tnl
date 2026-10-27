package service

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	controlvisitor "github.com/tnldotdev/tnl/internal/control/certificates/visitor"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func directCertificateFixture(t *testing.T, observe func() time.Time) (*Bound, tunnelv1.ServiceForwardingHeader, tls.ConnectionState) {
	t.Helper()
	p, bound, ref, _ := privateFixture(t, "127.0.0.1:1")
	p.managedPublic = true
	header := privateHeader(t, ref)
	header.Connector = nil
	header.Direct = &tunnelv1.DirectAdmission{IngressID: header.Reservation.IngressID, IngressRunID: header.Reservation.IngressRunID, IngressLeaseRevision: header.Reservation.IngressLeaseRevision, DestinationPort: p.servicePort}
	key := nativeFixtureKey()
	issuer, err := controlvisitor.New(key.Seed())
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	now := observe()
	view, _, _ := p.policy.Current()
	digest, err := visitortoken.KeyDigest(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := issuer.IssuePermission(csr, now.Add(time.Minute), now, func(serial string, public any, expires time.Time) (visitortoken.Token, error) {
		keyDigest, err := visitortoken.KeyDigest(public)
		if err != nil {
			return "", err
		}
		return visitortoken.Sign(view.Issuer, "native-fixture", key, visitortoken.Permission{Scope: view.Scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision,
			Subject: visitortoken.Certificate{Serial: serial, KeySHA256: keyDigest, Source: visitortoken.Device{IdentityID: nativeFixtureSubject().IdentityID, DeviceID: nativeFixtureSubject().DeviceID, SessionID: "cs_" + strings.Repeat("d", 22), KeySHA256: digest}}, ExpiresAt: expires}, now)
	})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certificate)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(issuer.CertificatePEM()) {
		t.Fatal("client issuer is not a certificate")
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Fatal(err)
	}
	// this is a new control observation, not the previously translated local
	// snapshot. carrying its old clock origin can make a new JWT look future-issued.
	view.Public, view.ControlTime, view.ObservedAt, view.ValidUntil = true, time.Time{}, now, now.Add(10*time.Second)
	state := tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: chains}
	token, err := visitortoken.CertificateToken(leaf)
	if err != nil {
		t.Fatal(err)
	}
	permission, err := visitortoken.VerifyCertificateRenewalProof(token, view, state, now)
	if err != nil {
		t.Fatal(err)
	}
	binding, credentialDigest, err := visitortoken.CredentialBinding(permission.Facts().Subject)
	if err != nil {
		t.Fatal(err)
	}
	view = view.WithCredentialLeases(map[string]visitortoken.CredentialLease{binding: {SubjectSHA256: credentialDigest, ExpiresAt: permission.Facts().ExpiresAt}})
	a := controlv1.StreamCapacityAllocation{Id: header.Reservation.AllocationID, Resource: controlv1.VisitorResourceScope{Kind: "service", Id: p.Preparation.ServiceId}, RunId: ref.ServiceRunID, RunNumber: int64(ref.RunNumber), Capacity: 64,
		IngressId: header.Direct.IngressID, IngressRunId: header.Direct.IngressRunID, IngressLeaseRevision: int64(header.Direct.IngressLeaseRevision), ObservedAt: now, ValidUntil: now.Add(10 * time.Second), ReservationKey: bytes.Repeat([]byte{1}, 32)}
	if err := p.policy.Apply(p.policy.Begin(), visitorlease.Update{View: view, Snapshot: true, KeyRevision: 1, Enabled: true, ClientAuthorities: roots, Allocations: map[string]controlv1.StreamCapacityAllocation{a.Id: a}}); err != nil {
		t.Fatal(err)
	}
	if view.Scope.Kind != visitorscope.Service {
		t.Fatal("certificate permission crossed scopes")
	}
	return bound, header, state
}

func TestCertificateAuthorizationWaitsForAdmissionAndPreservesInfrastructureCause(t *testing.T) {
	for _, infrastructureFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "publisher-promotion", true: "infrastructure-failure"}[infrastructureFailure], func(t *testing.T) {
			bound, header, state := directCertificateFixture(t, time.Now)
			peer, stream := net.Pipe()
			defer peer.Close()
			defer stream.Close()
			cause := errors.New("fixture promotion transport failure")
			var calls atomic.Int32
			started, release := make(chan struct{}), make(chan struct{})
			_, visitor, finish, err := bound.admitDirect(t.Context(), stream, header, func(reference tunnelv1.ServiceVisitorReference) error {
				if !reference.Valid() || reference.Kind != "certificate" {
					return errors.New("promotion lost certificate attribution")
				}
				calls.Add(1)
				close(started)
				if infrastructureFailure {
					return cause
				}
				<-release
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer finish()
			certificate := visitor.(publisher.CertificateVisitor)
			type result struct {
				decision publisher.ServiceVisitorDecision
				err      error
			}
			done := make(chan result, 1)
			go func() { decision, err := certificate.Check(t.Context(), state); done <- result{decision, err} }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("local certificate permission did not reach promotion")
			}
			if !infrastructureFailure {
				select {
				case <-done:
					t.Fatal("certificate admission passed an incomplete promotion")
				default:
				}
				close(release)
			}
			got := <-done
			if infrastructureFailure {
				if !errors.Is(got.err, cause) || got.decision.Allowed {
					t.Fatal("promotion failure lost its cause or granted admission", got.err)
				}
			} else {
				if got.err != nil || !got.decision.Allowed {
					t.Fatal("local certificate permission denied", got.err)
				}
				if _, err := certificate.Check(t.Context(), state); err != nil {
					t.Fatal(err)
				}
			}
			if calls.Load() != 1 {
				t.Fatal("promotion was replayed")
			}
		})
	}
}

func TestCertificateAdmissionFixtureRefreshesAuthorityTime(t *testing.T) {
	// policy and issuance can straddle a JWT second. a later control observation
	// must not retain the previous snapshot's translated authority time.
	directCertificateFixture(t, func() time.Time { return time.Now().Add(time.Second) })
}
