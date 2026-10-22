// package groupdiscovery supplies local signed control/AWS HTTPS boundaries and
// a verified EKS TLS target. no fixture reads ambient credentials or calls AWS.
package groupdiscovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/miekg/dns"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/client/supervisor"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const targetHostname = "cluster.local.example.test"

type Fixture struct {
	Server           *httptest.Server
	Job              supervisor.Job
	Key              ed25519.PrivateKey
	Profile          *clientstate.Store
	Heartbeat        chan controlv1.ServiceRunHeartbeat
	DiscoveryStarted chan struct{}
	DiscoveryStopped chan struct{}
	Requests         atomic.Int32
	TargetHandshakes atomic.Int32
	Stops            atomic.Int32
	Closes           atomic.Int32
	Block            atomic.Bool
	mu               sync.Mutex
	assignment       controlv1.PublisherGroupAssignments
	service          controlv1.Service
	setup            controlv1.ServiceRunSetup
	prepare          controlv1.ServiceRunPreparation
	provider         publisherdiscovery.AWS
	port             string
	started, stopped sync.Once
	proofs           map[string]bool
}

func New(t *testing.T) *Fixture {
	t.Helper()
	id := func(prefix string) string {
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member := controlv1.PublisherGroupMember{TeamId: id(opaqueid.TeamPrefix), PublisherIdentityId: id(opaqueid.PublisherIdentityPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix), GroupId: id("pgrp_"), GroupName: "cloud", ProjectKey: strings.Repeat("a", 56)}
	serviceID, runID, grantID := id(opaqueid.ServicePrefix), id(opaqueid.ServiceRunPrefix), id(opaqueid.PublisherGrantPrefix)
	f := &Fixture{Key: key, Heartbeat: make(chan controlv1.ServiceRunHeartbeat, 16), DiscoveryStarted: make(chan struct{}), DiscoveryStopped: make(chan struct{}), proofs: map[string]bool{}}
	protocol := controlv1.ServiceProtocol("kubernetes")
	f.assignment = controlv1.PublisherGroupAssignments{Member: member, Revision: 1, ConfigurationHash: strings.Repeat("a", 64), CertificateStatePlans: []controlv1.CertificatePlan{}, Services: []controlv1.PublisherGroupServiceAssignment{{Service: "cluster", ServiceId: serviceID, ServiceKind: "service", GrantId: grantID, TrustRevision: 1, Configuration: controlv1.ProjectServiceConfiguration{Protocol: &protocol, PublisherGroup: &member.GroupName, TargetDiscovery: &controlv1.ProjectTargetDiscovery{Type: controlv1.Eks, Region: "us-east-1", Cluster: new("production")}}}}}
	f.service = controlv1.Service{Id: serviceID, TeamId: member.TeamId, Name: "cluster", Protocol: protocol, Enabled: true, TrustRevision: 1, PublisherPool: true, CreatedAt: time.Now(), Endpoint: &controlv1.ServiceEndpoint{Hostname: "managed.example.test", Port: 25443}}
	f.prepare = controlv1.ServiceRunPreparation{ServiceId: serviceID, ServiceRunId: runID, TeamId: member.TeamId, PublisherIdentityId: member.PublisherIdentityId, PublisherGrantId: grantID, PublisherKeyId: member.KeyId, RunNumber: 1, Hostname: f.service.Endpoint.Hostname, ServicePort: 25443, DomainId: id(opaqueid.DomainPrefix), ExpiresAt: time.Now().Add(time.Minute), CertificatePlan: &controlv1.CertificatePlan{CacheKey: "group-fixture", Scope: f.service.Endpoint.Hostname, Identifiers: []string{f.service.Endpoint.Hostname}, ChallengeMethod: controlv1.Dns01}}
	f.setup = controlv1.ServiceRunSetup{ServiceId: serviceID, ServiceRunId: runID, RunNumber: 1, RunToken: "fixture-run"}
	for slot := range 2 {
		f.setup.PublisherConnections = append(f.setup.PublisherConnections, controlv1.ConnectionAssignment{PublisherConnectionId: id(opaqueid.PublisherConnectionPrefix), ConnectionSlot: slot, ConnectionAssignmentRevision: 1, RelayServiceId: fmt.Sprintf("relay-%d", slot), RelayAddress: "127.0.0.1:1", TlsServerName: "relay.example.test", PublisherConnectionCredential: "fixture-connection", PublisherConnectionCredentialExpiresAt: time.Now().Add(time.Minute)})
	}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.serve(t, w, r) }))
	t.Cleanup(f.Server.Close)
	serverCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Server.Certificate().Raw})
	f.Job = supervisor.Job{Kind: supervisor.KindGroup, Name: "cloud-default", Server: f.Server.URL, ServerCAPEM: serverCA, PublisherIdentityID: member.PublisherIdentityId, GroupMember: &member, GroupInstance: "default"}
	f.Job.ID = supervisor.JobKey(f.Job.Server, "group", member.GroupId+":default")
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	f.Profile, err = database.Server(t.Context(), f.Server.URL)
	if err != nil {
		t.Fatal(err)
	}
	f.startAWSAndTarget(t)
	return f
}

func (f *Fixture) Assignment() controlv1.PublisherGroupServiceAssignment {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, _ := json.Marshal(f.assignment.Services[0])
	var result controlv1.PublisherGroupServiceAssignment
	_ = json.Unmarshal(data, &result)
	return result
}

func (f *Fixture) SetAssignment(assignment controlv1.PublisherGroupServiceAssignment) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.assignment.Services[0] = assignment
	f.assignment.Revision++
	sum := sha256.Sum256([]byte(fmt.Sprint(f.assignment.Revision)))
	f.assignment.ConfigurationHash = hex.EncodeToString(sum[:])
}

func (f *Fixture) ChangeService(change func(*controlv1.Service)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(&f.service)
}

func (f *Fixture) Discover(ctx context.Context, request publisherdiscovery.Request) (publisherdiscovery.ResolvedTarget, error) {
	f.Requests.Add(1)
	target, err := f.provider.Discover(ctx, request)
	if err != nil {
		return target, err
	}
	// EKS metadata requires port 443. redirect only the test dial port to an
	// unprivileged local listener, retaining its DNS name, CA, SNI and SDK checks.
	target.Address = net.JoinHostPort(target.ServerName, f.port)
	return target, nil
}

func write(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func (f *Fixture) verify(t *testing.T, proof, scope, audience string) bool {
	t.Helper()
	m := f.assignment.Member
	assertion, err := publisherproof.Verify(proof, m.PublisherIdentityId, m.KeyId, scope, audience, f.Key.Public().(ed25519.PublicKey), time.Now())
	if err != nil || f.proofs[assertion.ID] {
		t.Error("publisher proof or replay boundary failed")
		return false
	}
	f.proofs[assertion.ID] = true
	return true
}

func (f *Fixture) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.TLS == nil {
		t.Error("control request was not HTTPS")
		w.WriteHeader(400)
		return
	}
	m := f.assignment.Member
	switch r.URL.Path {
	case "/v1/publisher-runtime":
		var request controlv1.PublisherRuntimeRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		scope := publisherproof.RuntimeScope(m.GroupId, string(request.Action), request.ProcessRunId, request.ExpectedEpoch, "")
		if !f.verify(t, request.Assertion, scope, f.Server.URL+r.URL.Path) {
			w.WriteHeader(401)
			return
		}
		if request.Action == controlv1.RuntimeInspect {
			write(w, controlv1.PublisherRuntimeResponse{Epoch: 0})
			return
		}
		if request.Action == controlv1.RuntimeStop {
			f.Stops.Add(1)
		}
		until := time.Now().Add(time.Minute)
		write(w, controlv1.PublisherRuntimeResponse{Epoch: 1, LeaseExpiresAt: &until, GroupLease: &controlv1.PublisherGroupLease{AccessToken: "fixture-group", ExpiresAt: until}})
	case "/v1/publisher-groups/lease", "/v1/publisher-groups/verify":
		var request controlv1.PublisherGroupLeaseRequest
		_ = json.NewDecoder(r.Body).Decode(&request)
		if !f.verify(t, request.Assertion, m.GroupId, f.Server.URL+r.URL.Path) {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/v1/publisher-groups/verify" {
			write(w, controlv1.PublisherGroupVerification{Member: m, GroupNames: []string{m.GroupName}})
		} else {
			write(w, controlv1.PublisherGroupLease{AccessToken: "fixture-group", ExpiresAt: time.Now().Add(time.Minute)})
		}
	case "/v1/publisher-groups/assignments":
		if r.Header.Get("Authorization") != "Bearer fixture-group" {
			t.Error("assignment lacked group lease")
			w.WriteHeader(401)
			return
		}
		write(w, f.assignment)
	case "/v1/publisher-groups/ack":
		if r.Header.Get("Authorization") != "Bearer fixture-group" {
			t.Error("ack lacked group lease")
		}
		w.WriteHeader(http.StatusNoContent)
	case "/v1/publisher-token":
		var request authorityv1.PublisherTokenRequest
		_ = json.NewDecoder(r.Body).Decode(&request)
		if request.ClientId != m.PublisherIdentityId || request.GrantId != f.assignment.Services[0].GrantId || !f.verify(t, request.ClientAssertion, request.GrantId, f.Server.URL+r.URL.Path) {
			w.WriteHeader(401)
			return
		}
		write(w, authorityv1.PublisherTokenResponse{AccessToken: "fixture-service", GrantId: request.GrantId, TokenType: "Bearer", ExpiresIn: 60})
	case "/v1/publisher/service":
		if r.Header.Get("Authorization") != "Bearer fixture-service" {
			t.Error("saved service lacked scoped grant")
			w.WriteHeader(401)
			return
		}
		write(w, f.service)
	case "/v1/services/" + f.service.Id + "/runs":
		var declaration controlv1.ServiceRunDeclaration
		_ = json.NewDecoder(r.Body).Decode(&declaration)
		if declaration.Protocol != f.service.Protocol || declaration.TrustRevision != f.service.TrustRevision || declaration.TargetTls != nil {
			t.Error("discovered trust leaked into control declaration")
		}
		preparation := f.prepare
		preparation.IdempotencyKey = r.Header.Get("Idempotency-Key")
		write(w, preparation)
	case "/v1/services/" + f.service.Id + "/runs/" + f.setup.ServiceRunId + "/start":
		write(w, f.setup)
	case "/v1/services/" + f.service.Id + "/runs/" + f.setup.ServiceRunId:
		if r.Method == "DELETE" {
			f.Closes.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var health controlv1.ServiceRunHeartbeat
		_ = json.NewDecoder(r.Body).Decode(&health)
		select {
		case f.Heartbeat <- health:
		default:
		}
		// stop before relay admission: the fixture proves native preparation and
		// real verified target preflight, without inventing a ready relay.
		serviceapi.WriteProblem(w, http.StatusServiceUnavailable, "unavailable", "fixture heartbeat boundary")
	default:
		if strings.HasSuffix(r.URL.Path, "/certificate-issuances") {
			serviceapi.WriteProblem(w, http.StatusServiceUnavailable, "unavailable", "fixture certificate boundary")
			return
		}
		t.Errorf("unexpected control operation %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func (f *Fixture) startAWSAndTarget(t *testing.T) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{targetHostname}}
	der, err := x509.CreateCertificate(rand.Reader, root, root, public, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	_, f.port, _ = net.SplitHostPort(listener.Addr().String())
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.SetDeadline(time.Now().Add(time.Second))
			if connection.(*tls.Conn).HandshakeContext(t.Context()) == nil {
				f.TargetHandshakes.Add(1)
			}
			_ = connection.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-joined })
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsServer := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(r)
		for _, question := range r.Question {
			if question.Name == targetHostname+"." && question.Qtype == dns.TypeA {
				rr, _ := dns.NewRR(question.Name + " 0 IN A 127.0.0.1")
				response.Answer = append(response.Answer, rr)
			}
		}
		_ = w.WriteMsg(response)
	})}
	go dnsServer.ActivateAndServe()
	t.Cleanup(func() { _ = dnsServer.Shutdown() })
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", packet.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = previous })
	credential := aws.Credentials{AccessKeyID: "fixture-key", SecretAccessKey: "fixture-secret", SessionToken: "fixture-token"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		service := "eks"
		if r.Method == "POST" {
			service = "sts"
		}
		copy := r.Clone(r.Context())
		copy.Header = r.Header.Clone()
		copy.URL.Scheme, copy.URL.Host = "https", r.Host
		auth := copy.Header.Get("Authorization")
		_, signed, _ := strings.Cut(auth, "SignedHeaders=")
		signed, _, _ = strings.Cut(signed, ",")
		for header := range copy.Header {
			if !strings.Contains(";"+signed+";", ";"+strings.ToLower(header)+";") {
				copy.Header.Del(header)
			}
		}
		stamp, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
		sum := sha256.Sum256(body)
		if err != nil || v4.NewSigner().SignHTTP(r.Context(), credential, copy, hex.EncodeToString(sum[:]), service, "us-east-1", stamp) != nil || copy.Header.Get("Authorization") != auth {
			t.Error("AWS SigV4 proof failed")
			w.WriteHeader(403)
			return
		}
		if service == "sts" {
			w.Header().Set("Content-Type", "text/xml")
			_, _ = io.WriteString(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:role/fixture</Arn><UserId>fixture</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`)
			return
		}
		f.started.Do(func() { close(f.DiscoveryStarted) })
		if f.Block.Load() {
			<-r.Context().Done()
			f.stopped.Do(func() { close(f.DiscoveryStopped) })
			return
		}
		cluster := strings.TrimPrefix(r.URL.Path, "/clusters/")
		if cluster == r.URL.Path {
			t.Error("not an exact DescribeCluster call")
			w.WriteHeader(400)
			return
		}
		write(w, map[string]any{"cluster": map[string]any{"name": cluster, "arn": "arn:aws:eks:us-east-1:123456789012:cluster/" + cluster, "createdAt": 1700000000.5, "status": "ACTIVE", "accessConfig": map[string]any{"authenticationMode": "API"}, "endpoint": "https://" + targetHostname, "certificateAuthority": map[string]any{"data": base64.StdEncoding.EncodeToString(ca)}}})
	}))
	t.Cleanup(server.Close)
	cfg := aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider(credential.AccessKeyID, credential.SecretAccessKey, credential.SessionToken), HTTPClient: server.Client(), RetryMaxAttempts: 1}
	clients := publisherdiscovery.Clients{EKS: eks.NewFromConfig(cfg, func(o *eks.Options) { o.BaseEndpoint = aws.String(server.URL) }), Caller: sts.NewFromConfig(cfg, func(o *sts.Options) { o.BaseEndpoint = aws.String(server.URL) })}
	f.provider = publisherdiscovery.AWS{Load: func(context.Context, string) (publisherdiscovery.Clients, error) { return clients, nil }}
}
