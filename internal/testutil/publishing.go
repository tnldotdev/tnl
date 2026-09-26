package testutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// IsolatedPublishingTest runs a command regression in its own test process so
// its private TLS roots cannot affect other tests or the machine's trust store.
// The caller returns immediately when this returns false.
func IsolatedPublishingTest(t *testing.T) bool {
	t.Helper()
	if os.Getenv("GO_TEST_PUBLISHING_HELPER") == t.Name() {
		return true
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.v", "-test.timeout=40s")
	command.Env = append(os.Environ(), "GO_TEST_PUBLISHING_HELPER="+t.Name(), "GORACE=atexit_sleep_ms=0")
	command.WaitDelay = time.Second
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("publishing regression: %v\n%s", err, output)
	}
	t.Logf("%s", output)
	return false
}

type PublishingHooks struct {
	Ready func(context.Context, controlv1.PublishRunSetup) error
	Close func(controlv1.PublishRunSetup) error
}

// PublishingFixture supplies local control/authority responses and real
// TLS/yamux publisher connections. It drives the unmodified command and
// publisher implementations without PostgreSQL, DNS, ACME, or paid resources.
type PublishingFixture struct {
	URL         string
	CAFile      string
	AccessToken string
	LoginToken  string
	Namespace   string
}

func NewPublishingFixture(t *testing.T, hooks PublishingHooks) *PublishingFixture {
	t.Helper()
	if os.Getenv("GO_TEST_PUBLISHING_HELPER") != t.Name() {
		t.Fatal("publishing fixture requires IsolatedPublishingTest")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",x509usefallbackroots=1")
	x509.SetFallbackRoots(roots)
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: ca}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	fixture := &PublishingFixture{Namespace: "member.routes.example", CAFile: filepath.Join(t.TempDir(), "ca.pem")}
	if err := os.WriteFile(fixture.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	login, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	fixture.AccessToken, fixture.LoginToken = access.String(), login.String()
	relayAddress := publishingRelay(t, tlsConfig)

	const teamID = "team_00000000000000000000000000000001"
	const domainID = "domain_00000000000000000000000000000001"
	const membershipID = "membership_00000000000000000000000000000001"
	identity := authorityv1.IdentityContext{
		Identity: authorityv1.Identity{Id: "identity_00000000000000000000000000000001"}, PersonalTeamId: teamID,
		Memberships: []authorityv1.Membership{{Id: membershipID, TeamId: teamID, ManagedLabel: "member", MemberSlug: "member", Role: authorityv1.TeamRoleOwner, TeamKind: authorityv1.Personal}},
	}
	team := authorityv1.Team{Id: teamID, DefaultDomainId: domainID, PolicyRevision: 1, Kind: authorityv1.Personal}
	domain := authorityv1.Domain{Id: domainID, CanonicalDomain: "routes.example", Kind: authorityv1.Managed, State: authorityv1.DomainStateReady}
	var mu sync.Mutex
	routes := make(map[string]controlv1.PublicURL)
	sessions := make(map[string]controlv1.PublishRunSetup)
	writeJSON := func(w http.ResponseWriter, value any) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(value); err != nil {
			t.Errorf("encode fixture response: %v", err)
		}
	}
	problem := func(w http.ResponseWriter, err error) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, controlv1.Problem{Type: "about:blank", Title: err.Error(), Status: 500, Code: controlv1.Internal})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/discovery", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, controlv1.ControlDiscovery{AuthorityEndpoint: fixture.URL, ManagedDeploymentDomain: "routes.example", Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{controlv1.LoginToken}}})
	})
	mux.HandleFunc("POST /v1/auth/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, authorityv1.ControlSessionResponse{AccessToken: fixture.AccessToken, Identity: identity, AccessExpiresAt: now.Add(time.Hour)})
	})
	mux.HandleFunc("GET /v1/identity", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, identity) })
	mux.HandleFunc("GET /v1/teams/{team}", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, team) })
	mux.HandleFunc("GET /v1/teams/{team}/domains", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, authorityv1.DomainPage{Domains: []authorityv1.Domain{domain}})
	})
	mux.HandleFunc("GET /v1/public-urls", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, controlv1.PublicURLPage{PublicUrls: []controlv1.PublicURL{}})
	})
	mux.HandleFunc("POST /v1/public-urls", func(w http.ResponseWriter, r *http.Request) {
		var request controlv1.CreatePublicURLRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			problem(w, err)
			return
		}
		mu.Lock()
		id := fmt.Sprintf("public_url_%032x", len(routes)+1)
		membership := membershipID
		route := controlv1.PublicURL{Id: id, CanonicalHostname: request.CanonicalHostname, Target: request.Target, TeamId: teamID, DomainId: domainID, MembershipId: &membership, PublicUrlScope: request.PublicUrlScope, LifecycleState: controlv1.Enabled, NextPublishRunNumber: 1, PolicyRevision: 1}
		routes[id] = route
		mu.Unlock()
		writeJSON(w, route)
	})
	mux.HandleFunc("POST /v1/public-urls/{route}/publish-runs", func(w http.ResponseWriter, r *http.Request) {
		token, _, _, err := credentials.NewPublishRunToken()
		if err != nil {
			problem(w, err)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		route := routes[r.PathValue("route")]
		id := fmt.Sprintf("publish_run_%032x", len(sessions)+1)
		setup := controlv1.PublishRunSetup{
			PublicUrl: route, PublishRunToken: token.String(),
			PublishRun:      controlv1.PublishRun{Id: id, PublicUrlId: route.Id, TeamId: teamID, PublishRunNumber: 1, ExpiresAt: now.Add(time.Hour), State: controlv1.PublishRunStateStarting},
			CertificatePlan: controlv1.CertificatePlan{CacheKey: route.CanonicalHostname, Scope: route.CanonicalHostname, Identifiers: []string{route.CanonicalHostname}, ChallengeMethod: controlv1.TlsAlpn01},
		}
		for slot := range 2 {
			setup.PublisherConnections = append(setup.PublisherConnections, controlv1.ConnectionAssignment{
				ConnectionSlot: slot, ConnectionAssignmentRevision: 1, PublisherConnectionId: fmt.Sprintf("connection_%032x", len(sessions)*2+slot+1),
				RelayServiceId: fmt.Sprintf("relay-%d", slot), RelayAddress: relayAddress, TlsServerName: "localhost", State: controlv1.PublisherConnectionStateAssigned,
				PublisherConnectionCredential: "fixture-credential", PublisherConnectionCredentialExpiresAt: now.Add(time.Hour),
			})
		}
		sessions[id] = setup
		writeJSON(w, setup)
	})
	lookup := func(r *http.Request) controlv1.PublishRunSetup {
		mu.Lock()
		defer mu.Unlock()
		return sessions[r.PathValue("session")]
	}
	mux.HandleFunc("POST /v1/publish-runs/{session}/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		setup := lookup(r)
		writeJSON(w, controlv1.PublishRunHeartbeat{PublishRun: setup.PublishRun, PublisherConnections: setup.PublisherConnections})
	})
	mux.HandleFunc("POST /v1/publish-runs/{session}/certificate-issuances", func(w http.ResponseWriter, r *http.Request) {
		setup := lookup(r)
		var request controlv1.CreateCertificateIssuanceRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			problem(w, err)
			return
		}
		csr, err := x509.ParseCertificateRequest(request.Csr)
		if err != nil {
			problem(w, err)
			return
		}
		if err := csr.CheckSignature(); err != nil {
			problem(w, err)
			return
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: csr.DNSNames, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, key)
		if err != nil {
			problem(w, err)
			return
		}
		chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
		writeJSON(w, controlv1.CertificateIssuance{Id: "issuance_00000000000000000000000000000001", PublicUrlId: setup.PublicUrl.Id, PublishRunId: setup.PublishRun.Id, PublishRunNumber: 1, CertificatePlan: setup.CertificatePlan, CertificatePem: &chain, NotBefore: &leaf.NotBefore, NotAfter: &leaf.NotAfter, State: controlv1.CertificateIssuanceStateWaitingForInstall})
	})
	mux.HandleFunc("POST /v1/publish-runs/{session}/certificate-installed", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, lookup(r).PublishRun) })
	mux.HandleFunc("POST /v1/publish-runs/{session}/ready", func(w http.ResponseWriter, r *http.Request) {
		setup := lookup(r)
		if hooks.Ready != nil {
			if err := hooks.Ready(r.Context(), setup); err != nil {
				problem(w, err)
				return
			}
		}
		writeJSON(w, setup.PublishRun)
	})
	mux.HandleFunc("DELETE /v1/publish-runs/{session}", func(w http.ResponseWriter, r *http.Request) {
		if hooks.Close != nil {
			if err := hooks.Close(lookup(r)); err != nil {
				problem(w, err)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected fixture request: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})
	server := httptest.NewUnstartedServer(mux)
	server.TLS = tlsConfig.Clone()
	server.StartTLS()
	fixture.URL = server.URL
	t.Cleanup(server.Close)
	return fixture
}

func publishingRelay(t *testing.T, tlsConfig *tls.Config) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer connection.Close()
				stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
				defer stop()
				transport, err := muxsession.AcceptTLSYamux(ctx, connection, tlsConfig, muxsession.TLSYamuxConfig{})
				if err != nil {
					return
				}
				session, _, err := tunnel.Accept(ctx, transport, func(context.Context, tunnelv1.Message) error { return nil })
				if err != nil {
					return
				}
				defer session.Close()
				_ = session.HandlePublisherDrain(ctx, func(context.Context) error { return nil })
			})
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		<-done
		workers.Wait()
	})
	return listener.Addr().String()
}
