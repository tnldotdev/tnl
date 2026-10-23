package publisher

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const certificateTestPublicURLID = "url_0123456789abcdefghijkl"

func (c *certificateTestControl) CreatePublishRun(_ context.Context, publicURLID, key string) (controlv1.PublishRunSetup, error) {
	if publicURLID != c.setup.PublicUrl.Id || key == "" {
		return controlv1.PublishRunSetup{}, errors.New("unexpected publish run request")
	}
	return c.setup, nil
}

func (c *certificateTestControl) ClosePublishRun(_ context.Context, session string, token credentials.PublishRunToken) error {
	if session != c.setup.PublishRun.Id || token.String() != c.setup.PublishRunToken {
		return errors.New("unexpected publish run close")
	}
	c.mu.Lock()
	c.closedSessions = append(c.closedSessions, session)
	c.mu.Unlock()
	return nil
}

func (c *certificateTestControl) HeartbeatPublishRun(ctx context.Context, session string, version uint64, token credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
	if session != c.setup.PublishRun.Id || version != uint64(c.setup.PublishRun.PublishRunNumber) || token.String() != c.setup.PublishRunToken {
		return controlv1.PublishRunHeartbeat{}, errors.New("unexpected heartbeat identity")
	}
	if c.heartbeat != nil {
		return c.heartbeat(ctx, session, version, token)
	}
	return controlv1.PublishRunHeartbeat{PublishRun: c.setup.PublishRun, PublisherConnections: c.setup.PublisherConnections}, nil
}

func (c *certificateTestControl) MarkPublishRunReady(_ context.Context, session string, version uint64, token credentials.PublishRunToken) error {
	if session != c.setup.PublishRun.Id || version != uint64(c.setup.PublishRun.PublishRunNumber) || token.String() != c.setup.PublishRunToken {
		return errors.New("unexpected readiness identity")
	}
	if c.ready != nil {
		return c.ready()
	}
	return nil
}

type certificateTestControl struct {
	publisherControlStub
	setup          controlv1.PublishRunSetup
	store          *clientstate.Store
	signer         tls.Certificate
	create         func([]byte, string) (controlv1.CertificateIssuance, error)
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
	token, _, _, err := credentials.NewPublishRunToken()
	if err != nil {
		t.Fatal(err)
	}
	signer := publicURLTestCertificate(t, "issuer.example")
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
		setup: controlv1.PublishRunSetup{
			PublicUrl:       controlv1.PublicURL{Id: certificateTestPublicURLID, CanonicalHostname: hostname, TeamId: "team_1", DomainId: "domain_1", MembershipId: pointer("membership_1"), PublicUrlScope: controlv1.Member, Purpose: controlv1.App, ServiceProtocol: controlv1.Http, LifecycleState: controlv1.Enabled},
			PublishRun:      controlv1.PublishRun{Id: "pr_0123456789abcdefghijkl", PublicUrlId: certificateTestPublicURLID, TeamId: "team_1", PublishRunNumber: 1, ExpiresAt: time.Now().Add(time.Hour)},
			PublishRunToken: token.String(), CertificatePlan: plan,
		},
	}
}

func (c *certificateTestControl) ReadPublisherVisitorPolicy(_ context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	if body.Resource.Id != c.setup.PublicUrl.Id || body.Resource.Kind != "public_url" || body.RunId != c.setup.PublishRun.Id || body.RunNumber != c.setup.PublishRun.PublishRunNumber || token != c.setup.PublishRunToken {
		return controlv1.VisitorPolicyUpdate{}, errors.New("unexpected visitor policy identity")
	}
	now := time.Now()
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("v", 32)))
	return controlv1.VisitorPolicyUpdate{AfterRevision: body.AfterRevision, Revisions: []int64{}, SnapshotRequired: body.AfterRevision == 0,
		Policy: controlv1.VisitorPolicySnapshot{Resource: body.Resource, Hostname: c.setup.PublicUrl.CanonicalHostname, Port: 443, Issuer: "https://control.example.test",
			VisitorPolicyRevision: 1, KeyRevision: 1, ObservedAt: now, ValidUntil: now.Add(10 * time.Second), Enabled: true,
			Anonymous:        c.setup.PublicUrl.AccessMode == "" || c.setup.PublicUrl.AccessMode == "anonymous",
			VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "certificate-fixture", PublicKey: key.Public().(ed25519.PublicKey)}}, WorkloadLeases: []controlv1.VisitorWorkloadLease{}, StreamAllocations: testPublicAllocations(body, now)}}, nil
}

func (*certificateTestControl) IssueVisitorToken(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
	return controlv1.VisitorTokenResponse{}, errors.New("no test browser sign-in")
}

func namespaceCertificateTestPlan() controlv1.CertificatePlan {
	return controlv1.CertificatePlan{CacheKey: "member.example", Scope: "member.example", Identifiers: []string{"member.example", "*.member.example"}, ChallengeMethod: controlv1.Dns01}
}

func (*certificateTestControl) EnableShareAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error {
	return nil
}

func (*certificateTestControl) GetPublishRunShareState(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunShareState, error) {
	return controlv1.PublishRunShareState{Shares: []controlv1.PublisherShare{}}, nil
}

func (*certificateTestControl) RedeemPublishRunShare(context.Context, string, controlv1.RedeemShareRequest, credentials.PublishRunToken) (controlv1.ShareRedemption, error) {
	return controlv1.ShareRedemption{}, errors.New("no test share")
}

func publicURLCertificateTestPlan() controlv1.CertificatePlan {
	return controlv1.CertificatePlan{CacheKey: "route.example", Scope: "route.example", Identifiers: []string{"route.example"}, ChallengeMethod: controlv1.Dns01}
}

func newCertificateTransactionTest(t *testing.T) (*certificateTestControl, *PublicURLServer, *clientstate.CertificateCache) {
	t.Helper()
	control := newCertificateTestControl(t, "route.example", publicURLCertificateTestPlan())
	control.store = certificateTestStore(t, filepath.Join(t.TempDir(), "state"))
	state, err := control.store.CertificatesForPublisher(control.setup.PublicUrl.TeamId, control.PublisherIdentityID(), control.setup.CertificatePlan)
	if err != nil {
		t.Fatal(err)
	}
	return control, certificateTestPublicURL(t, "route.example", control.setup.CertificatePlan), state
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

func certificateTestPublicURL(t *testing.T, hostname string, plan controlv1.CertificatePlan) *PublicURLServer {
	t.Helper()
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: hostname, Target: "http://127.0.0.1:3000", CertificatePlan: plan})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	return route
}

// sign only the submitted key and only when the CSR matches the certificate plan.
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
	i := controlv1.CertificateIssuance{Id: fmt.Sprintf("issuance_%x", digest[:16]), PublicUrlId: c.setup.PublicUrl.Id, PublishRunId: c.setup.PublishRun.Id, PublishRunNumber: c.setup.PublishRun.PublishRunNumber, CertificatePlan: c.setup.CertificatePlan, State: controlv1.CertificateIssuanceStateWaitingForInstall, NotBefore: pointer(leaf.NotBefore), NotAfter: pointer(leaf.NotAfter)}
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

func (c *certificateTestControl) CreateCertificateIssuance(_ context.Context, session string, version uint64, token credentials.PublishRunToken, csr []byte, key string) (controlv1.CertificateIssuance, error) {
	if session != c.setup.PublishRun.Id || version != uint64(c.setup.PublishRun.PublishRunNumber) || token.String() != c.setup.PublishRunToken || key == "" {
		return controlv1.CertificateIssuance{}, errors.New("unexpected certificate request identity")
	}
	if c.create != nil {
		return c.create(csr, key)
	}
	return c.issue(csr)
}

func (c *certificateTestControl) MarkPublishRunCertificateInstalled(_ context.Context, session string, version uint64, issuance string, notAfter time.Time, token credentials.PublishRunToken) error {
	if token.String() != c.setup.PublishRunToken || session != c.setup.PublishRun.Id || version != uint64(c.setup.PublishRun.PublishRunNumber) || issuance == "" || notAfter.IsZero() {
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
