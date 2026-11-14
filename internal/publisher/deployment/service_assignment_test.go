package deployment_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	publisherdeployment "github.com/tnldotdev/tnl/internal/publisher/deployment"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var errAssignmentFixture = errors.New("assignment fixture rejected service operation")

// the fixture replaces control and the CA, not the service worker, visitor TLS,
// HTTP frontend, target connection, or joined publisher connection shutdown.
type assignmentServiceControl struct {
	publisheridentity.ServiceControl
	url         string
	service     controlv1.Service
	preparation controlv1.ServiceRunPreparation
	setup       controlv1.ServiceRunSetup
	ca          *x509.Certificate
	caKey       ed25519.PrivateKey
	traffic     *controlv1.TrafficSelection
	prepares    atomic.Int32
	starts      atomic.Int32
	closes      atomic.Int32
	installed   chan struct{}
	installOnce sync.Once
}

func (f *assignmentServiceControl) ControlURL() string { return f.url }

func (f *assignmentServiceControl) GetPublisherService(_ context.Context, id, access string) (controlv1.Service, error) {
	if id != f.service.Id || access != "exact-service-access" {
		return controlv1.Service{}, errAssignmentFixture
	}
	return f.service, nil
}

func (f *assignmentServiceControl) PrepareServiceRun(_ context.Context, id, key, access string, declaration controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error) {
	f.prepares.Add(1)
	if id != f.service.Id || access != "exact-service-access" || declaration.Protocol != f.service.Protocol ||
		declaration.TrustRevision != f.service.TrustRevision || !reflect.DeepEqual(declaration.TargetTls, f.service.TargetTls) ||
		!reflect.DeepEqual(declaration.Traffic, f.traffic) {
		return controlv1.ServiceRunPreparation{}, errAssignmentFixture
	}
	result := f.preparation
	result.IdempotencyKey = key
	return result, nil
}

func (f *assignmentServiceControl) StartServiceRun(_ context.Context, id, run, access string, number int64) (controlv1.ServiceRunSetup, error) {
	f.starts.Add(1)
	if id != f.service.Id || run != f.setup.ServiceRunId || access != "exact-service-access" || number != f.setup.RunNumber {
		return controlv1.ServiceRunSetup{}, errAssignmentFixture
	}
	return f.setup, nil
}

func (f *assignmentServiceControl) CloseServiceRun(_ context.Context, id, run string, token credentials.ServiceRunToken) error {
	f.closes.Add(1)
	if id != f.service.Id || run != f.setup.ServiceRunId || token.String() != f.setup.RunToken {
		return errAssignmentFixture
	}
	return nil
}

func (f *assignmentServiceControl) HeartbeatServiceRun(ctx context.Context, id, run string, token credentials.ServiceRunToken, health controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	if id != f.service.Id || run != f.setup.ServiceRunId || token.String() != f.setup.RunToken || !health.Healthy {
		return controlv1.ServiceRunState{}, errAssignmentFixture
	}
	select {
	case <-f.installed:
	case <-ctx.Done():
		return controlv1.ServiceRunState{}, ctx.Err()
	}
	return controlv1.ServiceRunState{ServiceId: id, ServiceRunId: run, RunNumber: f.setup.RunNumber, State: controlv1.ServiceRunStateStateReady,
		PublisherExpiresAt: time.Now().Add(time.Minute), PublisherConnections: f.setup.PublisherConnections}, nil
}

func (f *assignmentServiceControl) CreateServiceCertificateIssuance(_ context.Context, service, run string, number int64, token credentials.ServiceRunToken, csr []byte, _ string) (controlv1.ServiceCertificateIssuance, error) {
	request, err := x509.ParseCertificateRequest(csr)
	if err != nil || request.CheckSignature() != nil || service != f.service.Id || run != f.setup.ServiceRunId || number != f.setup.RunNumber || token.String() != f.setup.RunToken {
		return controlv1.ServiceCertificateIssuance{}, errAssignmentFixture
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), DNSNames: request.DNSNames, NotBefore: time.Now().Add(-time.Minute).UTC().Truncate(time.Second),
		NotAfter: time.Now().Add(time.Hour).UTC().Truncate(time.Second), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.ca, request.PublicKey, f.caKey)
	if err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw})...)
	return controlv1.ServiceCertificateIssuance{Id: opaqueid.IssuancePrefix + "0000000000000000000001",
		ServiceId: service, ServiceRunId: run, RunNumber: number, PublisherIdentityId: f.preparation.PublisherIdentityId,
		CertificatePlan: *f.preparation.CertificatePlan, CertificatePem: new(string(chain)), NotBefore: &leaf.NotBefore, NotAfter: &leaf.NotAfter}, nil
}

func (f *assignmentServiceControl) MarkServiceCertificateInstalled(_ context.Context, service, run string, number int64, _ string, _ time.Time, token credentials.ServiceRunToken) error {
	if service != f.service.Id || run != f.setup.ServiceRunId || number != f.setup.RunNumber || token.String() != f.setup.RunToken {
		return errAssignmentFixture
	}
	f.installOnce.Do(func() { close(f.installed) })
	return nil
}

func (f *assignmentServiceControl) ReadPublisherVisitorPolicy(_ context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	if request.Resource.Kind != controlv1.VisitorResourceScopeKindService || request.Resource.Id != f.service.Id ||
		request.RunId != f.setup.ServiceRunId || request.RunNumber != f.setup.RunNumber || token != f.setup.RunToken {
		return controlv1.VisitorPolicyUpdate{}, errAssignmentFixture
	}
	now := time.Now()
	return controlv1.VisitorPolicyUpdate{AfterRevision: request.AfterRevision, Revisions: []int64{}, SnapshotRequired: request.AfterRevision == 0,
		Policy: controlv1.VisitorPolicySnapshot{Resource: request.Resource, Issuer: f.url, Hostname: f.preparation.Hostname, Port: 443,
			Enabled: true, Anonymous: true, VisitorPolicyRevision: 1, MetadataRevision: f.service.TrustRevision, KeyRevision: 1,
			ObservedAt: now, ValidUntil: now.Add(10 * time.Second),
			VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "deployment-fixture", PublicKey: f.caKey.Public().(ed25519.PublicKey)}}}}, nil
}

func (f *assignmentServiceControl) AuthorizeServiceHTTPVisitor(_ context.Context, service, run string, token credentials.ServiceRunToken, request controlv1.AuthorizeServiceHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	if service != f.service.Id || run != f.setup.ServiceRunId || token.String() != f.setup.RunToken || request.RunNumber != f.setup.RunNumber || request.DestinationPort != 443 {
		return controlv1.ServiceClientCertificateDecision{}, errAssignmentFixture
	}
	return controlv1.ServiceClientCertificateDecision{Allowed: true, Admitted: true, ValidUntil: time.Now().Add(time.Minute)}, nil
}

func (f *assignmentServiceControl) ListConnectorPeerPairs(_ context.Context, service, run, after string, token credentials.ServiceRunToken) (controlv1.ConnectorPeerPairCandidates, error) {
	if service != f.service.Id || run != f.setup.ServiceRunId || after != "" || token.String() != f.setup.RunToken {
		return controlv1.ConnectorPeerPairCandidates{}, errAssignmentFixture
	}
	return controlv1.ConnectorPeerPairCandidates{Items: []controlv1.ConnectorPeerPairCandidate{}}, nil
}

func (*assignmentServiceControl) ReportServiceRunObservations(context.Context, string, string, int64, credentials.ServiceRunToken, serviceaudit.Batch) error {
	return nil
}

func TestHTTPAssignmentUsesExistingSignedServiceRunAndRetainsSavedService(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	id := func(prefix string) string {
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caPublic, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		DNSNames: []string{"localhost"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caKey)
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
	member := controlv1.DeploymentPublisherIdentity{TeamId: id(opaqueid.TeamPrefix), DeploymentId: id("dpl_"), DeploymentName: "production",
		PublisherIdentityId: id(opaqueid.PublisherIdentityPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix)}
	serviceID, runID, grantID := id(opaqueid.ServicePrefix), id(opaqueid.ServiceRunPrefix), id(opaqueid.PublisherGrantPrefix)
	const hostname = "web.production.example.test"
	traffic := &controlv1.TrafficSelection{Connections: new(7), TotalDownloadBytes: new(int64(4096))}
	control := &assignmentServiceControl{ca: ca, caKey: caKey, traffic: traffic, installed: make(chan struct{}),
		service: controlv1.Service{Id: serviceID, TeamId: member.TeamId, Name: "web", Protocol: controlv1.ServiceProtocolHTTP, Enabled: true,
			TrustRevision: 1, RequirePostQuantum: true, HttpLimits: &controlv1.ProjectHTTPApplicationLimits{Total: new(1)},
			Endpoint: &controlv1.ServiceEndpoint{Hostname: hostname, Port: 443, Public: true}},
		preparation: controlv1.ServiceRunPreparation{ServiceId: serviceID, ServiceRunId: runID, RunNumber: 1, TeamId: member.TeamId,
			PublisherIdentityId: member.PublisherIdentityId, PublisherGrantId: grantID, PublisherKeyId: member.KeyId,
			Hostname: hostname, DomainId: id(opaqueid.DomainPrefix), ExpiresAt: time.Now().Add(time.Minute), RequirePostQuantum: true,
			CertificatePlan: &controlv1.CertificatePlan{CacheKey: "deployment-service", Scope: hostname, Identifiers: []string{hostname}, ChallengeMethod: controlv1.Dns01},
			Traffic:         controlv1.TrafficLimits{Connections: 7, Rate: 20, RatePerNs: int64(time.Second), Burst: 40, UploadBytes: 8 << 20, DownloadBytes: 16 << 20, TotalDownloadBytes: new(int64(4096))}},
		setup: controlv1.ServiceRunSetup{ServiceId: serviceID, ServiceRunId: runID, RunNumber: 1, RunToken: "service-run-token"},
	}
	var exchanges atomic.Int32
	var proofMu sync.Mutex
	proofs := map[string]bool{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request authorityv1.PublisherTokenRequest
		if r.URL.Path != "/v1/publisher-token" || r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Errorf("service worker attempted an allocation, deletion, or unexpected operation: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		proof, err := publisherproof.Verify(request.ClientAssertion, member.PublisherIdentityId, member.KeyId, grantID, control.url+"/v1/publisher-token", public, time.Now())
		proofMu.Lock()
		defer proofMu.Unlock()
		if err != nil || proofs[proof.ID] || request.ClientId != member.PublisherIdentityId || request.GrantId != grantID {
			t.Error("service assignment changed its original key or exact grant", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		proofs[proof.ID] = true
		exchanges.Add(1)
		_ = json.NewEncoder(w).Encode(authorityv1.PublisherTokenResponse{AccessToken: "exact-service-access", GrantId: grantID, TokenType: "Bearer", ExpiresIn: 300})
	}))
	defer server.Close()
	control.url = server.URL
	authority, err := clientauthority.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	for slot := range 2 {
		control.setup.PublisherConnections = append(control.setup.PublisherConnections, controlv1.ConnectionAssignment{
			PublisherConnectionId: id(opaqueid.PublisherConnectionPrefix), ConnectionSlot: slot, ConnectionAssignmentRevision: 1,
			RelayServiceId: []string{"relay-a", "relay-b"}[slot], RelayAddress: listener.Addr().String(), TlsServerName: "localhost",
			PublisherConnectionCredential: "assignment-credential", PublisherConnectionCredentialExpiresAt: time.Now().Add(time.Minute)})
	}
	relayCtx, stopRelay := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	type connectedRelay struct {
		session *tunnel.Session
		ref     tunnelv1.ServicePublisherConnectionRef
	}
	accepted := make(chan connectedRelay, 2)
	workers.Go(func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer connection.Close()
				stop := context.AfterFunc(relayCtx, func() { _ = connection.Close() })
				defer stop()
				transport, err := muxsession.AcceptTLSYamux(relayCtx, connection, &tls.Config{MinVersion: tls.VersionTLS13,
					Certificates: []tls.Certificate{{Certificate: [][]byte{ca.Raw}, PrivateKey: caKey}}}, muxsession.TLSYamuxConfig{})
				if err != nil {
					return
				}
				session, hello, err := tunnel.Accept(relayCtx, transport, func(_ context.Context, hello tunnelv1.Message) error {
					ref := hello.ServiceConnection
					if ref == nil || ref.ServiceID != serviceID || ref.ServiceRunID != runID || ref.RunNumber != 1 || hello.Credential != "assignment-credential" {
						return errAssignmentFixture
					}
					return nil
				})
				if err != nil {
					return
				}
				defer session.Close()
				accepted <- connectedRelay{session, *hello.ServiceConnection}
				_ = session.HandlePublisherDrain(relayCtx, func(context.Context) error { return nil })
				select {
				case <-session.Done():
				case <-relayCtx.Done():
				}
			})
		}
	})
	defer func() { stopRelay(); _ = listener.Close(); workers.Wait() }()
	var applicationRequests atomic.Int32
	applicationStarted, finishApplication := make(chan struct{}), make(chan struct{})
	var finishOnce sync.Once
	local := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		first := applicationRequests.Add(1) == 1
		_, _ = io.WriteString(w, "deployment application")
		w.(http.Flusher).Flush()
		if first {
			close(applicationStarted)
			select {
			case <-finishApplication:
			case <-request.Context().Done():
			}
		}
	}))
	defer local.Close()
	defer finishOnce.Do(func() { close(finishApplication) })
	targetCA := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: local.Certificate().Raw}))
	declaration, err := targettrust.NewDeclaration(local.Certificate().DNSNames[0], []byte(targetCA))
	if err != nil {
		t.Fatal(err)
	}
	targetTLS, err := declaration.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	control.service.TargetTls = publisheridentity.ServiceTargetTLS(targetTLS)
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	profile, err := database.Server(t.Context(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	publication := publisherdeployment.AssignmentPublisher{Member: member, Private: key, State: profile, Control: publisheridentity.NativeControl{Services: control}, Authority: authority}
	assignment := controlv1.DeploymentPublisherServiceAssignment{Service: "web", ServiceId: serviceID, GrantId: grantID, TrustRevision: 1,
		Configuration: controlv1.ProjectServiceConfiguration{Protocol: new(controlv1.ServiceProtocolHTTP), Target: local.URL, Traffic: traffic,
			TargetTls:          &controlv1.ProjectTargetTLS{Hostname: targetTLS.Hostname, CaPem: &targetCA, Digest: declaration.Digest},
			RequirePostQuantum: new(true), Http: &controlv1.ProjectServiceHTTP{Limits: &controlv1.ProjectHTTPApplicationLimits{Total: new(1)}}}}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	ready, done := make(chan struct{}, 1), make(chan struct{})
	var publicationErr error
	var healthy atomic.Bool
	go func() {
		defer close(done)
		publicationErr = publication.Publish(ctx, assignment, func(value bool) {
			healthy.Store(value)
			if value {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		})
	}()
	defer func() { cancel(); <-done }()
	select {
	case <-ready:
	case <-done:
		t.Fatal("service assignment stopped before readiness", publicationErr)
	case <-ctx.Done():
		t.Fatal("service assignment did not become traffic-ready")
	}
	var relay connectedRelay
	select {
	case relay = <-accepted:
	case <-ctx.Done():
		t.Fatal("service assignment did not join a relay")
	}
	visit := func(curves []tls.CurveID) (int, string, error) {
		// either accepted slot can carry the same exact saved service.
		slot := control.setup.PublisherConnections[relay.ref.ConnectionSlot]
		header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{ProtocolVersion: tunnelv1.Version,
			Kind: tunnelv1.ServiceForwardingStream, ServiceID: serviceID, ServiceRunID: runID, RunNumber: 1,
			PublisherConnectionID: slot.PublisherConnectionId, ConnectionAssignmentRevision: 1,
			VisitorConnectionID: id(opaqueid.VisitorConnectionPrefix), SourceIP: "192.0.2.10", ExpiresAt: time.Now().Add(10 * time.Second),
			PublicService: &tunnelv1.PublicServiceAdmission{IngressID: "ingress-a", IngressRunID: id(opaqueid.IngressRunPrefix), IngressLeaseRevision: 1, DestinationPort: 443}},
			ConnectionSlot: uint8(slot.ConnectionSlot), RelayServiceID: slot.RelayServiceId, RelayID: "relay-process",
			RelayRunID: id(opaqueid.RelayRunPrefix), RelayLeaseRevision: 1, LeaseExpiresAt: time.Now().Add(time.Minute)}
		stream, err := relay.session.OpenServiceForwardingStream(ctx, header)
		if err != nil {
			return 0, "", err
		}
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
		metadata, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:45123"), Destination: netip.MustParseAddrPort("203.0.113.1:443")})
		if err != nil {
			return 0, "", err
		}
		if _, err := stream.Write(metadata); err != nil {
			return 0, "", err
		}
		connection := tls.Client(stream, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: hostname, CurvePreferences: curves})
		defer connection.Close()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+hostname+"/", nil)
		request.Close = true
		if err := request.Write(connection); err != nil {
			return 0, "", err
		}
		response, err := http.ReadResponse(bufio.NewReader(connection), request)
		if err != nil {
			return 0, "", err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		return response.StatusCode, string(body), err
	}
	if _, _, err := visit([]tls.CurveID{tls.X25519}); err == nil || applicationRequests.Load() != 0 {
		t.Fatal("saved PQ requirement admitted a classical visitor")
	}
	type visitResult struct {
		status int
		body   string
		err    error
	}
	first := make(chan visitResult, 1)
	go func() {
		status, body, err := visit(nil)
		first <- visitResult{status, body, err}
	}()
	select {
	case <-applicationStarted:
	case <-done:
		t.Fatal("service assignment ended before delivering its request", publicationErr)
	case <-ctx.Done():
		t.Fatal("signed service assignment did not carry visitor traffic")
	}
	// the final admitted request holds the total budget until its body ends.
	// another connection must be denied without reaching the application.
	if status, _, err := visit(nil); err != nil || status != http.StatusServiceUnavailable || applicationRequests.Load() != 1 {
		t.Fatal("saved HTTP request limit did not apply across visitor connections", status, err)
	}
	finishOnce.Do(func() { close(finishApplication) })
	select {
	case result := <-first:
		if result.err != nil || result.status != http.StatusOK || result.body != "deployment application" {
			t.Fatal("signed service assignment did not finish visitor traffic", result.status, result.body, result.err)
		}
	case <-ctx.Done():
		t.Fatal("admitted request did not finish")
	}
	cancel()
	select {
	case <-done:
		if publicationErr != nil {
			t.Fatal(publicationErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("service assignment did not join cleanup")
	}
	if control.prepares.Load() != 1 || control.starts.Load() != 1 || control.closes.Load() != 1 || exchanges.Load() == 0 || healthy.Load() || !control.service.Enabled {
		t.Fatal("service assignment replaced its run, lost signed access, retained health, or deleted its saved service")
	}
}
