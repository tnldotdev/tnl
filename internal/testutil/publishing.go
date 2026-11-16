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
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// IsolatedPublishingTest runs a command regression in its own test process so
// its private TLS roots cannot affect other tests or the machine's trust store.
// the caller returns immediately when this returns false.
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

type PublishingRun struct {
	Service     controlv1.Service
	Preparation controlv1.ServiceRunPreparation
	Setup       controlv1.ServiceRunSetup
}

type PublishingHooks struct {
	Ready func(context.Context, PublishingRun) error
	Close func(PublishingRun) error
}

type publishingRunState struct {
	PublishingRun
	installed, closed, notified, healthy bool
	issuance                             *controlv1.ServiceCertificateIssuance
	csr                                  []byte
	issuanceKey                          string
}

type publishingConnection struct {
	session *tunnel.Session
	ref     tunnelv1.ServicePublisherConnectionRef
}

// publishingfixture is a local fake control boundary with real TLS/yamux
// connections. it contains no second publication engine or PostgreSQL dependency.
type PublishingFixture struct {
	URL, CAFile, AccessToken, Namespace string
	mu                                  sync.Mutex
	services                            map[string]controlv1.Service
	configurations                      map[string]controlv1.ProjectServiceConfiguration
	createKeys                          map[string]string
	publishers                          map[string]authorityv1.PublisherEnrollmentResult
	runs                                map[string]*publishingRunState
	current                             map[string]string
	connections                         map[string]publishingConnection
	relayAddress                        string
	ca                                  *x509.Certificate
	key                                 *ecdsa.PrivateKey
	hooks                               PublishingHooks
	t                                   *testing.T
}

func publishingID(t *testing.T, prefix string) string {
	t.Helper()
	id, err := opaqueid.New(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func publishingClone[T any](value T) T {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		panic(err)
	}
	return result
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
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
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
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: ca}}}
	f := &PublishingFixture{Namespace: "member.services.example", CAFile: filepath.Join(t.TempDir(), "ca.pem"), ca: ca, key: key, hooks: hooks, t: t,
		services: map[string]controlv1.Service{}, configurations: map[string]controlv1.ProjectServiceConfiguration{}, createKeys: map[string]string{},
		publishers: map[string]authorityv1.PublisherEnrollmentResult{}, runs: map[string]*publishingRunState{}, current: map[string]string{},
		connections: map[string]publishingConnection{}}
	if err := os.WriteFile(f.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	f.AccessToken = access.String()
	f.relayAddress = publishingRelay(t, tlsConfig, f)
	server := httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	server.TLS = tlsConfig.Clone()
	server.StartTLS()
	f.URL = server.URL
	t.Cleanup(server.Close)
	return f
}

func (f *PublishingFixture) Service(id string) (controlv1.Service, controlv1.ProjectServiceConfiguration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, found := f.services[id]
	return publishingClone(value), publishingClone(f.configurations[id]), found
}

// setserviceexpiration captures the allocation deadline in the saved service.
// allocation replies, scoped reads and renewals use this same fixed value.
func (f *PublishingFixture) SetServiceExpiration(id string, deadline *time.Time) (controlv1.Service, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	service, found := f.services[id]
	if !found {
		return controlv1.Service{}, errors.New("service expiration requires a saved service")
	}
	if service.ExpiresAt != nil && (deadline == nil || !service.ExpiresAt.Equal(*deadline)) {
		return controlv1.Service{}, errors.New("service expiration is already fixed")
	}
	if deadline != nil {
		value := *deadline
		service.ExpiresAt = &value
	}
	f.services[id] = service
	return publishingClone(service), nil
}

func (f *PublishingFixture) Run(id string) (PublishingRun, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	run := f.runs[id]
	if run == nil || run.closed {
		return PublishingRun{}, false
	}
	return publishingClone(run.PublishingRun), true
}

// bindpublisher receives facts already verified by the signed fixture's HTTP
// boundary. no grant or signing key is manufactured during run preparation.
func (f *PublishingFixture) BindPublisher(key string, identity authorityv1.PublisherEnrollmentResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.publishers[key] = publishingClone(identity)
}

func (f *PublishingFixture) Connection(service string) (*tunnel.Session, tunnelv1.ServicePublisherConnectionRef, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, connection := range f.connections {
		if connection.ref.ServiceID == service && connection.ref.ServiceRunID == f.current[service] {
			return connection.session, connection.ref, true
		}
	}
	return nil, tunnelv1.ServicePublisherConnectionRef{}, false
}

// OpenHTTPVisitor sends signed source metadata over the claimed relay session.
// the returned connection owns its capacity callback until physical close.
func (f *PublishingFixture) OpenHTTPVisitor(ctx context.Context, service string, source, destination netip.AddrPort) (_ net.Conn, result error) {
	session, ref, found := f.Connection(service)
	if !found {
		return nil, errors.New("service publisher connection is not ready")
	}
	run, found := f.Run(ref.ServiceRunID)
	if !found {
		return nil, errors.New("service run has stopped")
	}
	now := time.Now()
	slot := run.Setup.PublisherConnections[ref.ConnectionSlot]
	header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
		ServiceID: ref.ServiceID, ServiceRunID: ref.ServiceRunID, RunNumber: ref.RunNumber, PublisherConnectionID: ref.PublisherConnectionID,
		ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision, VisitorConnectionID: publishingID(f.t, opaqueid.VisitorConnectionPrefix),
		SourceIP: source.Addr().String(), ExpiresAt: now.Add(10 * time.Second),
		PublicService: &tunnelv1.PublicServiceAdmission{IngressID: "fixture-ingress", IngressRunID: publishingID(f.t, opaqueid.IngressRunPrefix),
			IngressLeaseRevision: 1, DestinationPort: destination.Port()},
	}, ConnectionSlot: ref.ConnectionSlot, RelayServiceID: slot.RelayServiceId, RelayID: "fixture-relay",
		RelayRunID: publishingID(f.t, opaqueid.RelayRunPrefix), RelayLeaseRevision: 1, LeaseExpiresAt: now.Add(time.Minute)}
	unregister, err := session.RegisterServiceCapacity(ctx, header, func(context.Context) error { return nil })
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			unregister()
		}
	}()
	stream, err := session.OpenServiceForwardingStream(ctx, header)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, stream.Close())
		}
	}()
	if err := stream.SetDeadline(header.ExpiresAt); err != nil {
		return nil, err
	}
	authority, key, err := visitortoken.IssueVisitorSourceAuthority([32]byte(run.Setup.VisitorSourceKey), tunnelv1.VisitorSourceAuthority{
		ServiceID: ref.ServiceID, ServiceRunID: ref.ServiceRunID, RunNumber: ref.RunNumber, EndpointRevision: run.Service.EndpointRevision,
		IngressID: header.PublicService.IngressID, IngressRunID: header.PublicService.IngressRunID, IngressLeaseRevision: 1,
		VisitorPolicyRevision: 1, ValidUntil: now.Add(visitortoken.PolicyLifetime).Unix(),
	}, now)
	if err != nil {
		return nil, err
	}
	proof, err := visitortoken.SignVisitorSource(key, authority, 1, tunnelv1.VisitorSourceBinding{
		ServiceID: ref.ServiceID, ServiceRunID: ref.ServiceRunID, RunNumber: ref.RunNumber,
		VisitorConnectionID: header.VisitorConnectionID, Source: source, Destination: destination,
	}, now)
	if err != nil {
		return nil, err
	}
	encoded, err := proof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	metadata, err := proxyproto.Encode(proxyproto.Header{Source: source, Destination: destination, VisitorSourceProof: string(encoded)})
	if err != nil {
		return nil, err
	}
	if _, err := stream.Write(metadata); err != nil {
		return nil, err
	}
	return &publishingVisitor{Conn: stream, unregister: unregister}, nil
}

type publishingVisitor struct {
	net.Conn
	unregister func()
	once       sync.Once
	err        error
}

func (c *publishingVisitor) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.unregister()
	})
	return c.err
}

func publishingWrite(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func publishingDecode(r *http.Request, value any) bool {
	return httpjson.Decode(json.NewDecoder(r.Body), value) == nil
}

func (f *PublishingFixture) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/v1/discovery" {
		publishingWrite(w, 200, controlv1.ControlDiscovery{ManagedDomain: "services.example", Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{controlv1.Oidc}}})
		return
	}
	if r.Method == http.MethodGet && r.Header.Get("Authorization") == "Bearer "+f.AccessToken {
		const team, domain = "tm_0000000000000000000001", "dom_0000000000000000000001"
		switch r.URL.Path {
		case "/v1/identity":
			publishingWrite(w, 200, authorityv1.IdentityContext{Identity: authorityv1.Identity{Id: "ident_0000000000000000000001"}, PersonalTeamId: team,
				Memberships: []authorityv1.Membership{{Id: "mem_0000000000000000000001", TeamId: team, ManagedLabel: "member", MemberSlug: "member", Role: authorityv1.TeamRoleOwner, TeamKind: authorityv1.Personal}}})
			return
		case "/v1/teams/" + team:
			publishingWrite(w, 200, authorityv1.Team{Id: team, DefaultDomainId: domain, PolicyRevision: 1, Kind: authorityv1.Personal})
			return
		case "/v1/teams/" + team + "/domains":
			publishingWrite(w, 200, authorityv1.DomainPage{Domains: []authorityv1.Domain{{Id: domain, CanonicalDomain: "services.example", Kind: authorityv1.Managed, State: authorityv1.DomainStateReady}}})
			return
		}
	}
	if r.URL.Path == "/v1/services" && r.Method == http.MethodPost {
		f.create(w, r)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "v1" || parts[1] != "services" {
		f.t.Errorf("unexpected fixture operation %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
		return
	}
	service := parts[2]
	if len(parts) == 3 {
		value, _, found := f.Service(service)
		if !found {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodDelete {
			f.mu.Lock()
			value.Enabled = false
			f.services[service] = value
			f.mu.Unlock()
			w.WriteHeader(204)
			return
		}
		publishingWrite(w, 200, value)
		return
	}
	if len(parts) == 4 && parts[3] == "runs" && r.Method == http.MethodPost {
		f.prepare(w, r, service)
		return
	}
	if len(parts) < 5 || parts[3] != "runs" {
		http.NotFound(w, r)
		return
	}
	f.runOperation(w, r, service, parts[4], parts[5:])
}

func (f *PublishingFixture) create(w http.ResponseWriter, r *http.Request) {
	var request controlv1.CreateServiceRequest
	if !publishingDecode(r, &request) || r.Header.Get("Authorization") != "Bearer "+f.AccessToken ||
		r.Header.Get("Idempotency-Key") == "" || request.Configuration == nil || request.Configuration.Protocol == nil ||
		*request.Configuration.Protocol != controlv1.ServiceProtocolHTTP || request.Configuration.Hostname == nil || request.Configuration.Target == "" {
		w.WriteHeader(400)
		return
	}
	c := publishingClone(*request.Configuration)
	metadata := controlv1.ServiceTargetTLS{}
	var trust *controlv1.ServiceTargetTLS
	if c.TargetTls != nil {
		pem := ""
		if c.TargetTls.CaPem != nil {
			pem = *c.TargetTls.CaPem
		}
		declaration, err := targettrust.NewDeclaration(c.TargetTls.Hostname, []byte(pem))
		if err != nil || c.TargetTls.Digest != "" && c.TargetTls.Digest != declaration.Digest {
			w.WriteHeader(400)
			return
		}
		snapshot, err := declaration.Snapshot()
		if err != nil {
			w.WriteHeader(400)
			return
		}
		metadata.Hostname, metadata.System, metadata.Digest = snapshot.Hostname, snapshot.System, snapshot.Digest
		if len(snapshot.PEM) != 0 {
			metadata.Pem = new(string(snapshot.PEM))
		}
		trust = &metadata
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key := r.Header.Get("Idempotency-Key")
	if id := f.createKeys[key]; id != "" {
		if !reflect.DeepEqual(f.configurations[id], c) || !f.services[id].Enabled {
			w.WriteHeader(409)
			return
		}
		publishingWrite(w, 200, f.services[id])
		return
	}
	value := controlv1.Service{Id: publishingID(f.t, opaqueid.ServicePrefix), TeamId: request.TeamId, Name: request.Name, DomainId: c.DomainId,
		Enabled: true, CreatedAt: time.Now(), Protocol: *c.Protocol, TrustRevision: 1, EndpointRevision: 1, TargetTls: trust,
		Ephemeral: c.Ephemeral != nil && *c.Ephemeral, RequirePostQuantum: c.RequirePostQuantum != nil && *c.RequirePostQuantum,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: *c.Hostname, Port: 443, Public: c.Public != nil && *c.Public}}
	if c.Http != nil {
		value.HttpLimits = c.Http.Limits
	}
	f.services[value.Id], f.configurations[value.Id], f.createKeys[key] = value, c, value.Id
	publishingWrite(w, 201, value)
}

func (f *PublishingFixture) prepare(w http.ResponseWriter, r *http.Request, service string) {
	var declaration controlv1.ServiceRunDeclaration
	if !publishingDecode(r, &declaration) {
		w.WriteHeader(400)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	saved, found := f.services[service]
	identity, bound := f.publishers[r.Header.Get("Idempotency-Key")]
	if !found || !saved.Enabled || saved.ExpiresAt != nil && !saved.ExpiresAt.After(time.Now()) ||
		!bound || identity.TeamId != saved.TeamId || declaration.Protocol != saved.Protocol ||
		declaration.TrustRevision != saved.TrustRevision || !reflect.DeepEqual(declaration.TargetTls, saved.TargetTls) {
		w.WriteHeader(403)
		return
	}
	number := int64(1)
	for _, previous := range f.runs {
		if previous.Service.Id != service {
			continue
		}
		if previous.Preparation.IdempotencyKey == r.Header.Get("Idempotency-Key") && !previous.closed {
			if previous.Preparation.PublisherGrantId != identity.GrantId || previous.Preparation.PublisherIdentityId != identity.ClientId || previous.Preparation.PublisherKeyId != identity.KeyId {
				w.WriteHeader(403)
				return
			}
			publishingWrite(w, 200, previous.Preparation)
			return
		}
		if !previous.closed {
			w.WriteHeader(409)
			return
		}
		number = max(number, previous.Preparation.RunNumber+1)
	}
	runID := publishingID(f.t, opaqueid.ServiceRunPrefix)
	token, _, err := credentials.NewServiceRunToken()
	if err != nil {
		w.WriteHeader(500)
		return
	}
	selection := declaration.Traffic
	if selection == nil {
		selection = f.configurations[service].Traffic
	}
	var selected trafficlimits.Selection
	if selection != nil {
		selected = trafficlimits.Selection{Connections: selection.Connections, Rate: selection.Rate, RatePer: selection.RatePer, Burst: selection.Burst,
			UploadBytes: selection.UploadBytes, DownloadBytes: selection.DownloadBytes, TotalConnections: selection.TotalConnections,
			TotalUploadBytes: selection.TotalUploadBytes, TotalDownloadBytes: selection.TotalDownloadBytes}
	}
	limits, err := selected.Resolve(trafficlimits.Default(), trafficlimits.Ceiling())
	if err != nil {
		w.WriteHeader(400)
		return
	}
	traffic := controlv1.TrafficLimits{Connections: limits.Connections, Rate: limits.Rate, RatePerNs: int64(limits.RatePer), Burst: limits.Burst,
		UploadBytes: limits.UploadBytes, DownloadBytes: limits.DownloadBytes}
	if limits.TotalConnections != 0 {
		traffic.TotalConnections = &limits.TotalConnections
	}
	if limits.TotalUploadBytes != 0 {
		traffic.TotalUploadBytes = &limits.TotalUploadBytes
	}
	if limits.TotalDownloadBytes != 0 {
		traffic.TotalDownloadBytes = &limits.TotalDownloadBytes
	}
	p := controlv1.ServiceRunPreparation{ServiceId: service, ServiceRunId: runID, TeamId: saved.TeamId, GuestId: saved.GuestId,
		RunToken:            token.String(),
		PublisherIdentityId: identity.ClientId, PublisherGrantId: identity.GrantId, PublisherKeyId: identity.KeyId,
		RunNumber: number, Hostname: saved.Endpoint.Hostname, DomainId: *saved.DomainId, ExpiresAt: time.Now().Add(time.Hour),
		IdempotencyKey: r.Header.Get("Idempotency-Key"), RequirePostQuantum: saved.RequirePostQuantum,
		CertificatePlan: &controlv1.CertificatePlan{CacheKey: saved.Endpoint.Hostname, Scope: saved.Endpoint.Hostname,
			Identifiers: []string{saved.Endpoint.Hostname}, ChallengeMethod: controlv1.Dns01},
		Traffic: traffic}
	if saved.ExpiresAt != nil && saved.ExpiresAt.Before(p.ExpiresAt) {
		p.ExpiresAt = *saved.ExpiresAt
	}
	setup := controlv1.ServiceRunSetup{ServiceId: service, ServiceRunId: runID, RunNumber: number, RunToken: token.String()}
	setup.VisitorSourceKey = make([]byte, 32)
	if _, err := rand.Read(setup.VisitorSourceKey); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	for slot := range 2 {
		setup.PublisherConnections = append(setup.PublisherConnections, controlv1.ConnectionAssignment{ConnectionSlot: slot,
			PublisherConnectionId: publishingID(f.t, opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: 1,
			RelayServiceId: fmt.Sprintf("relay-%d", slot), RelayAddress: f.relayAddress, TlsServerName: "localhost",
			PublisherConnectionCredential: publishingID(f.t, "credential_"), PublisherConnectionCredentialExpiresAt: time.Now().Add(time.Hour)})
	}
	f.runs[runID] = &publishingRunState{PublishingRun: PublishingRun{saved, p, setup}}
	f.current[service] = runID
	publishingWrite(w, 200, p)
}

func (f *PublishingFixture) runOperation(w http.ResponseWriter, r *http.Request, service, id string, path []string) {
	f.mu.Lock()
	run := f.runs[id]
	if run == nil || run.Service.Id != service {
		f.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	snapshot := publishingClone(run.PublishingRun)
	operation := strings.Join(path, "/")
	if operation != "start" && r.Header.Get("Authorization") != "Bearer "+run.Setup.RunToken {
		f.mu.Unlock()
		w.WriteHeader(401)
		return
	}
	if run.closed {
		f.mu.Unlock()
		if len(path) == 0 && r.Method == http.MethodDelete {
			w.WriteHeader(204)
		} else {
			http.NotFound(w, r)
		}
		return
	}
	if f.current[service] != id {
		f.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	f.mu.Unlock()
	switch {
	case operation == "start" && r.Method == http.MethodPost:
		var body controlv1.StartServiceRunJSONRequestBody
		if !publishingDecode(r, &body) || body.RunNumber != snapshot.Setup.RunNumber {
			w.WriteHeader(400)
			return
		}
		publishingWrite(w, 200, snapshot.Setup)
	case operation == "certificate-issuances" && r.Method == http.MethodPost:
		var body controlv1.CreateServiceCertificateIssuanceRequest
		if !publishingDecode(r, &body) || body.RunNumber != snapshot.Setup.RunNumber {
			w.WriteHeader(400)
			return
		}
		csr, err := x509.ParseCertificateRequest(body.Csr)
		if err != nil || csr.CheckSignature() != nil || !reflect.DeepEqual(csr.DNSNames, snapshot.Preparation.CertificatePlan.Identifiers) {
			w.WriteHeader(400)
			return
		}
		f.mu.Lock()
		if run.issuance != nil && run.issuanceKey == r.Header.Get("Idempotency-Key") {
			same, issuance := reflect.DeepEqual(run.csr, body.Csr), publishingClone(*run.issuance)
			f.mu.Unlock()
			if !same {
				w.WriteHeader(409)
				return
			}
			publishingWrite(w, 200, issuance)
			return
		}
		f.mu.Unlock()
		now := time.Now().UTC().Truncate(time.Second)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), DNSNames: csr.DNSNames, NotBefore: now.Add(-time.Minute),
			NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, f.ca, csr.PublicKey, f.key)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw})...)
		issuance := controlv1.ServiceCertificateIssuance{Id: publishingID(f.t, opaqueid.IssuancePrefix), ServiceId: service, ServiceRunId: id,
			RunNumber: snapshot.Setup.RunNumber, PublisherIdentityId: snapshot.Preparation.PublisherIdentityId,
			State:           controlv1.CertificateIssuanceStateWaitingForInstall,
			CertificatePlan: *snapshot.Preparation.CertificatePlan, CertificatePem: new(string(chain)), NotBefore: &leaf.NotBefore, NotAfter: &leaf.NotAfter}
		f.mu.Lock()
		run.issuance, run.issuanceKey, run.csr = &issuance, r.Header.Get("Idempotency-Key"), append([]byte(nil), body.Csr...)
		f.mu.Unlock()
		publishingWrite(w, 200, issuance)
	case operation == "certificate-installed":
		var body controlv1.ServiceCertificateInstalledRequest
		if !publishingDecode(r, &body) || body.RunNumber != snapshot.Setup.RunNumber {
			w.WriteHeader(400)
			return
		}
		f.mu.Lock()
		if run.issuance == nil || run.issuance.Id != body.IssuanceId || run.issuance.NotAfter == nil || !run.issuance.NotAfter.Equal(body.NotAfter) {
			f.mu.Unlock()
			w.WriteHeader(400)
			return
		}
		run.installed = true
		f.mu.Unlock()
		w.WriteHeader(204)
	case operation == "renew":
		var body controlv1.ServiceRunHeartbeat
		if !publishingDecode(r, &body) {
			w.WriteHeader(400)
			return
		}
		f.mu.Lock()
		run.healthy = body.Healthy
		connected := 0
		for _, connection := range f.connections {
			if connection.ref.ServiceRunID == id {
				connected++
			}
		}
		current := f.services[service]
		enabled := current.Enabled && (current.ExpiresAt == nil || current.ExpiresAt.After(time.Now()))
		ready := enabled && run.installed && connected == 2 && body.Healthy
		notify := ready && !run.notified
		if notify {
			run.notified = true
		}
		f.mu.Unlock()
		if notify && f.hooks.Ready != nil {
			if err := f.hooks.Ready(r.Context(), snapshot); err != nil {
				w.WriteHeader(503)
				return
			}
		}
		state := controlv1.ServiceRunStateState("starting")
		if ready {
			state = controlv1.ServiceRunStateStateReady
		}
		deadline := time.Now().Add(time.Minute)
		if snapshot.Preparation.ExpiresAt.Before(deadline) {
			deadline = snapshot.Preparation.ExpiresAt
		}
		if current.ExpiresAt != nil && current.ExpiresAt.Before(deadline) {
			deadline = *current.ExpiresAt
		}
		publishingWrite(w, 200, controlv1.ServiceRunState{ServiceId: service, ServiceRunId: id, RunNumber: snapshot.Setup.RunNumber,
			EndpointRevision: current.EndpointRevision, PublicEndpointReady: ready && current.Endpoint.Public,
			State: state, Healthy: &body.Healthy, PublisherExpiresAt: deadline, PublisherConnections: snapshot.Setup.PublisherConnections})
	case operation == "connector-peer-pairs" && r.Method == http.MethodGet:
		publishingWrite(w, 200, controlv1.ConnectorPeerPairCandidates{Items: []controlv1.ConnectorPeerPairCandidate{}})
	case operation == "service-observations" && r.Method == http.MethodPost:
		var body controlv1.ServiceRunObservations
		if !publishingDecode(r, &body) || body.RunNumber != snapshot.Setup.RunNumber {
			w.WriteHeader(400)
			return
		}
		publishingWrite(w, 200, controlv1.ServiceObservationResult{Accepted: len(body.Events)})
	case len(path) == 0 && r.Method == http.MethodDelete:
		if f.hooks.Close != nil {
			if err := f.hooks.Close(snapshot); err != nil {
				w.WriteHeader(503)
				return
			}
		}
		f.mu.Lock()
		run.closed = true
		f.mu.Unlock()
		w.WriteHeader(204)
	default:
		f.t.Errorf("unexpected service run operation %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func publishingRelay(t *testing.T, tlsConfig *tls.Config, f *PublishingFixture) string {
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
				session, hello, err := tunnel.Accept(ctx, transport, func(_ context.Context, hello tunnelv1.Message) error {
					ref := hello.ServiceConnection
					if ref == nil {
						return errors.New("service publisher reference missing")
					}
					f.mu.Lock()
					defer f.mu.Unlock()
					run := f.runs[ref.ServiceRunID]
					if run == nil || run.closed || f.current[ref.ServiceID] != ref.ServiceRunID || ref.ServiceID != run.Service.Id || ref.RunNumber != uint64(run.Setup.RunNumber) {
						return errors.New("stale service run")
					}
					for _, assignment := range run.Setup.PublisherConnections {
						if ref.PublisherConnectionID == assignment.PublisherConnectionId && ref.ConnectionSlot == uint8(assignment.ConnectionSlot) &&
							ref.ConnectionAssignmentRevision == uint64(assignment.ConnectionAssignmentRevision) && ref.RelayServiceID == assignment.RelayServiceId && hello.Credential == assignment.PublisherConnectionCredential {
							return nil
						}
					}
					return errors.New("service connection assignment mismatch")
				})
				if err != nil {
					return
				}
				ref := *hello.ServiceConnection
				defer session.Close()
				f.mu.Lock()
				f.connections[ref.PublisherConnectionID] = publishingConnection{session, ref}
				f.mu.Unlock()
				defer func() { f.mu.Lock(); delete(f.connections, ref.PublisherConnectionID); f.mu.Unlock() }()
				drained := make(chan struct{})
				go func() {
					defer close(drained)
					_ = session.HandlePublisherDrain(ctx, func(context.Context) error { return nil })
				}()
				_ = session.ServeServiceCapacity(ctx)
				_ = session.Close()
				<-drained
			})
		}
	}()
	t.Cleanup(func() { cancel(); _ = listener.Close(); <-done; workers.Wait() })
	return listener.Addr().String()
}
