package publisher

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const certificateTestRouteID = "route_0123456789abcdef0123456789abcdef"

func (c *certificateTestControl) CreateRouteSession(_ context.Context, routeID, key string) (controlv1.RouteSessionSetup, error) {
	if routeID != c.setup.Route.Id || key == "" {
		return controlv1.RouteSessionSetup{}, errors.New("unexpected route session request")
	}
	return c.setup, nil
}

func (c *certificateTestControl) CloseRouteSession(_ context.Context, session string, token credentials.RouteSessionToken) error {
	if session != c.setup.RouteSession.Id || token.String() != c.setup.RouteSessionToken {
		return errors.New("unexpected route session close")
	}
	c.mu.Lock()
	c.closedSessions = append(c.closedSessions, session)
	c.mu.Unlock()
	return nil
}

func (c *certificateTestControl) HeartbeatRouteSession(ctx context.Context, session string, version uint64, token credentials.RouteSessionToken) (controlv1.RouteSessionHeartbeat, error) {
	if session != c.setup.RouteSession.Id || version != uint64(c.setup.RouteSession.RouteVersion) || token.String() != c.setup.RouteSessionToken {
		return controlv1.RouteSessionHeartbeat{}, errors.New("unexpected heartbeat identity")
	}
	if c.heartbeat != nil {
		return c.heartbeat(ctx, session, version, token)
	}
	return controlv1.RouteSessionHeartbeat{RouteSession: c.setup.RouteSession, PublisherConnections: c.setup.PublisherConnections}, nil
}

func (c *certificateTestControl) MarkRouteSessionReady(_ context.Context, session string, version uint64, token credentials.RouteSessionToken) error {
	if session != c.setup.RouteSession.Id || version != uint64(c.setup.RouteSession.RouteVersion) || token.String() != c.setup.RouteSessionToken {
		return errors.New("unexpected readiness identity")
	}
	if c.ready != nil {
		return c.ready()
	}
	return nil
}

type certificateTestControl struct {
	publisherControlStub
	setup          controlv1.RouteSessionSetup
	store          *clientstate.Store
	signer         tls.Certificate
	create         func([]byte, string) (controlv1.CertificateIssuance, error)
	challengeReady func() (controlv1.CertificateIssuance, error)
	removed        func() error
	installed      func(string, uint64, string, time.Time) error
	change         func(*controlv1.CertificateIssuance, *x509.Certificate)
	ready          func() error
	mu             sync.Mutex
	installations  []string
	closedSessions []string
	issued         map[string]bool
}

func newCertificateTestControl(t *testing.T, hostname string, plan controlv1.CertificatePlan) *certificateTestControl {
	t.Helper()
	token, _, _, err := credentials.NewRouteSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	signer := routeTestCertificate(t, "issuer.example")
	signer.Leaf.IsCA, signer.Leaf.BasicConstraintsValid = true, true
	signer.Leaf.KeyUsage, signer.Leaf.ExtKeyUsage = x509.KeyUsageCertSign, nil
	signer.Leaf.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, signer.Leaf, signer.Leaf, signer.Leaf.PublicKey, signer.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	signer.Certificate = [][]byte{der}
	signer.Leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &certificateTestControl{
		publisherControlStub: publisherControlStub{allowed: []string{"lookup"}}, signer: signer,
		setup: controlv1.RouteSessionSetup{
			Route:             controlv1.Route{Id: certificateTestRouteID, CanonicalHostname: hostname, TeamId: "team_1", DomainId: "domain_1", MembershipId: pointer("membership_1"), RouteScope: controlv1.Member, LifecycleState: controlv1.Enabled},
			RouteSession:      controlv1.RouteSession{Id: "route_session_0123456789abcdef0123456789abcdef", RouteId: certificateTestRouteID, TeamId: "team_1", RouteVersion: 1, ExpiresAt: time.Now().Add(time.Hour)},
			RouteSessionToken: token.String(), CertificatePlan: plan,
		},
	}
}

func namespaceCertificateTestPlan() controlv1.CertificatePlan {
	return controlv1.CertificatePlan{CacheKey: "member.example", Scope: "member.example", Identifiers: []string{"member.example", "*.member.example"}, ChallengeMethod: controlv1.Dns01}
}

func routeCertificateTestPlan() controlv1.CertificatePlan {
	return controlv1.CertificatePlan{CacheKey: "route.example", Scope: "route.example", Identifiers: []string{"route.example"}, ChallengeMethod: controlv1.TlsAlpn01}
}

func newCertificateTransactionTest(t *testing.T) (*certificateTestControl, *RouteServer, *clientstate.CertificateCache) {
	t.Helper()
	control := newCertificateTestControl(t, "route.example", routeCertificateTestPlan())
	control.store = certificateTestStore(t, filepath.Join(t.TempDir(), "state"))
	state, err := control.store.Certificates(control.setup.Route.TeamId, control.setup.CertificatePlan)
	if err != nil {
		t.Fatal(err)
	}
	return control, certificateTestRoute(t, "route.example", control.setup.CertificatePlan), state
}

func certificateTestStore(t *testing.T, root string) *clientstate.Store {
	t.Helper()
	database, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store, err := database.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func certificateTestRoute(t *testing.T, hostname string, plan controlv1.CertificatePlan) *RouteServer {
	t.Helper()
	route, err := NewRouteServer(RouteServerConfig{Hostname: hostname, Target: "http://127.0.0.1:3000", CertificatePlan: plan})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	return route
}

func certificateTestChallenge() controlv1.CertificateChallenge {
	digest := sha256.Sum256([]byte("test TLS-ALPN key authorization"))
	return controlv1.CertificateChallenge{Token: "challenge_1", Identifier: "route.example", Method: controlv1.TlsAlpn01, Digest: base64.RawURLEncoding.EncodeToString(digest[:]), ExpiresAt: time.Now().Add(10 * time.Minute)}
}

// Sign only the submitted key and only when the CSR matches the certificate plan.
func (c *certificateTestControl) issue(csrDER []byte) (controlv1.CertificateIssuance, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return controlv1.CertificateIssuance{}, err
	}
	if err := csr.CheckSignature(); err != nil {
		return controlv1.CertificateIssuance{}, err
	}
	want, got := slices.Clone(c.setup.CertificatePlan.Identifiers), slices.Clone(csr.DNSNames)
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) || len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) != 0 || csr.Subject.String() != "" {
		return controlv1.CertificateIssuance{}, fmt.Errorf("CSR identifiers = %q; authoritative plan requires %q", csr.DNSNames, c.setup.CertificatePlan.Identifiers)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: csr.DNSNames,
		NotBefore: time.Now().Add(-time.Minute).UTC().Truncate(time.Second), NotAfter: time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	digest := sha256.Sum256(csrDER)
	i := controlv1.CertificateIssuance{Id: fmt.Sprintf("issuance_%x", digest[:16]), RouteId: c.setup.Route.Id, RouteSessionId: c.setup.RouteSession.Id, RouteVersion: c.setup.RouteSession.RouteVersion, CertificatePlan: c.setup.CertificatePlan, State: controlv1.CertificateIssuanceStateWaitingForInstall, NotBefore: pointer(leaf.NotBefore), NotAfter: pointer(leaf.NotAfter)}
	if c.change != nil {
		c.change(&i, leaf)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, c.signer.Leaf, csr.PublicKey, c.signer.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return i, err
	}
	if i.CertificatePem == nil {
		chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.signer.Certificate[0]})...)
		i.CertificatePem = pointer(string(chain))
	}
	c.mu.Lock()
	if c.issued == nil {
		c.issued = make(map[string]bool)
	}
	c.issued[i.Id] = true
	c.mu.Unlock()
	return i, nil
}

func (c *certificateTestControl) CreateCertificateIssuance(_ context.Context, session string, version uint64, token credentials.RouteSessionToken, csr []byte, key string) (controlv1.CertificateIssuance, error) {
	if session != c.setup.RouteSession.Id || version != uint64(c.setup.RouteSession.RouteVersion) || token.String() != c.setup.RouteSessionToken || key == "" {
		return controlv1.CertificateIssuance{}, errors.New("unexpected certificate request identity")
	}
	if c.create != nil {
		return c.create(csr, key)
	}
	return c.issue(csr)
}

func (c *certificateTestControl) MarkCertificateChallengeReady(_ context.Context, issuance string, token credentials.RouteSessionToken) (controlv1.CertificateIssuance, error) {
	c.mu.Lock()
	known := c.issued[issuance]
	c.mu.Unlock()
	if c.challengeReady == nil || !known || token.String() != c.setup.RouteSessionToken {
		return controlv1.CertificateIssuance{}, errors.New("unexpected challenge-ready request")
	}
	return c.challengeReady()
}

func (c *certificateTestControl) MarkCertificateChallengeRemoved(_ context.Context, issuance string, token credentials.RouteSessionToken) error {
	c.mu.Lock()
	known := c.issued[issuance]
	c.mu.Unlock()
	if c.removed == nil || !known || token.String() != c.setup.RouteSessionToken {
		return errors.New("unexpected challenge-removed request")
	}
	return c.removed()
}

func (c *certificateTestControl) MarkRouteSessionCertificateInstalled(_ context.Context, session string, version uint64, issuance string, notAfter time.Time, token credentials.RouteSessionToken) error {
	if token.String() != c.setup.RouteSessionToken || session != c.setup.RouteSession.Id || version != uint64(c.setup.RouteSession.RouteVersion) || issuance == "" || notAfter.IsZero() {
		return errors.New("unexpected certificate installation identity")
	}
	if c.installed != nil {
		if err := c.installed(session, version, issuance, notAfter); err != nil {
			return err
		}
	}
	c.mu.Lock()
	c.installations = append(c.installations, session+":"+issuance)
	c.mu.Unlock()
	return nil
}
