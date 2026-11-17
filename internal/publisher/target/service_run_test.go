package target

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// the existing control/relay fixture owns runs, certificates and connections.
// this adapter supplies its scoped read and anonymous policy HTTP boundary only.
type targetRunControl struct {
	*clientcontrol.Client
	fixture  *testutil.PublishingFixture
	identity authorityv1.PublisherEnrollmentResult
}

func (c *targetRunControl) GetPublisherService(ctx context.Context, service, _ string) (controlv1.Service, error) {
	return c.GetService(ctx, service)
}

func (c *targetRunControl) PrepareServiceRun(ctx context.Context, service, key, access string, declaration controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error) {
	c.fixture.BindPublisher(key, c.identity)
	return c.Client.PrepareServiceRun(ctx, service, key, access, declaration)
}

func (c *targetRunControl) ReadPublisherVisitorPolicy(_ context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	run, found := c.fixture.Run(request.RunId)
	if !found || request.Resource.Id != run.Service.Id || request.RunNumber != run.Setup.RunNumber || token != run.Setup.RunToken {
		return controlv1.VisitorPolicyUpdate{}, errors.New("policy is outside the current fixture run")
	}
	now := time.Now()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	return controlv1.VisitorPolicyUpdate{AfterRevision: request.AfterRevision, Revisions: []int64{}, SnapshotRequired: request.AfterRevision == 0,
		Policy: controlv1.VisitorPolicySnapshot{Resource: request.Resource, Hostname: run.Service.Endpoint.Hostname, Port: 443, Issuer: c.ControlURL(),
			PublicEndpoint:        &controlv1.VisitorPublicEndpoint{Hostname: run.Service.Endpoint.Hostname, Port: 443, EndpointRevision: run.Service.EndpointRevision},
			VisitorPolicyRevision: 1, MetadataRevision: run.Service.TrustRevision, KeyRevision: 1, ObservedAt: now, ValidUntil: now.Add(10 * time.Second),
			Enabled: true, Anonymous: true, VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "fixture", PublicKey: key.Public().(ed25519.PublicKey)}}}}, nil
}

func (*targetRunControl) ReportServiceRunObservations(context.Context, string, string, int64, credentials.ServiceRunToken, serviceaudit.Batch) error {
	return nil
}

func TestHTTPProjectTargetReplacementKeepsRunAndOpenResponse(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	release := make(chan struct{})
	finishResponse := sync.OnceFunc(func() { close(release) })
	defer finishResponse()
	canceled := make(chan struct{})
	root, certificate := testutil.TLSCertificate(t, []string{"target.internal"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	var firstRequests, laterRequests, failedRequests, untrustedRequests atomic.Int32
	type connectionKey struct{}
	var connections atomic.Uint64
	start := func(certificate tls.Certificate, handler http.HandlerFunc) *httptest.Server {
		t.Helper()
		server := httptest.NewUnstartedServer(handler)
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, connectionKey{}, connections.Add(1))
		}
		server.StartTLS()
		t.Cleanup(server.Close)
		return server
	}
	first := start(certificate, func(w http.ResponseWriter, r *http.Request) {
		firstRequests.Add(1)
		_, _ = io.WriteString(w, "first")
		_ = http.NewResponseController(w).Flush()
		select {
		case <-release:
			_, _ = io.WriteString(w, "last")
		case <-r.Context().Done():
			close(canceled)
		}
	})
	later := start(certificate, func(w http.ResponseWriter, r *http.Request) {
		laterRequests.Add(1)
		if r.TLS == nil || r.TLS.ServerName != "target.internal" {
			t.Error("replacement did not retain approved target TLS")
		}
		if r.URL.Path == "/fail" {
			failedRequests.Add(1)
			connection, _, err := http.NewResponseController(w).Hijack()
			if err == nil {
				_ = connection.Close()
			} else {
				t.Error(err)
			}
			return
		}
		w.Header().Set("X-Target-Connection", fmt.Sprint(r.Context().Value(connectionKey{})))
		_, _ = io.WriteString(w, "later")
	})
	_, untrustedCertificate := testutil.TLSCertificate(t, []string{"target.internal"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	untrusted := start(untrustedCertificate, func(http.ResponseWriter, *http.Request) { untrustedRequests.Add(1) })

	var closed atomic.Int32
	fixture := testutil.NewPublishingFixture(t, testutil.PublishingHooks{Close: func(testutil.PublishingRun) error { closed.Add(1); return nil }})
	client, err := clientcontrol.New(fixture.URL, nil, credentials.AccessToken(fixture.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	id := func(prefix string) string {
		t.Helper()
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	domain, hostname := "dom_0000000000000000000001", "dynamic."+fixture.Namespace
	saved, err := client.CreateService(ctx, "tm_0000000000000000000001", "dynamic", id(opaqueid.IdempotencyPrefix), controlv1.ServiceMetadata{},
		&controlv1.ProjectServiceConfiguration{Protocol: new(controlv1.ServiceProtocolHTTP), Target: first.URL, Public: new(true),
			DomainId: &domain, Hostname: &hostname, TargetTls: &controlv1.ProjectTargetTLS{Hostname: "target.internal", CaPem: new(string(root))}})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := targettrust.NewDeclaration("target.internal", root)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := trust.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	control := &targetRunControl{Client: client, fixture: fixture, identity: authorityv1.PublisherEnrollmentResult{
		ClientId: id(opaqueid.PublisherIdentityPrefix), GrantId: id(opaqueid.PublisherGrantPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix),
		Kind: authorityv1.Service, TeamId: saved.TeamId, ServiceId: &saved.Id}}
	database, err := clientstate.OpenWithOptions(ctx, filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	profile, err := database.Server(ctx, fixture.URL)
	if err != nil {
		t.Fatal(err)
	}
	project := clientproject.Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{
		"web": {Target: &config.ServiceTarget{Type: "docker", Container: new("web"), Port: new(443),
			TLS: &config.TargetTLS{Hostname: new("target.internal"), CA: new(string(root))}}},
	}}}
	var selected atomic.Pointer[TargetSnapshot]
	selected.Store(&TargetSnapshot{Address: first.Listener.Addr().String(), Identity: "container-a"})
	resolver := TargetResolverFunc(func(context.Context, clientproject.Project, string) (string, string, error) {
		current := selected.Load()
		if current == nil {
			return "", "", errors.New("container disappeared")
		}
		return current.Address, current.Identity, nil
	})
	var status atomic.Pointer[publisherservice.RunStatus]
	changed := make(chan struct{}, 1)
	var preparations, captures atomic.Int32
	finished, joined := make(chan error, 1), make(chan struct{})
	cfg := publisherservice.RunConfig{Control: control, State: profile, Access: func(context.Context) (string, error) { return fixture.AccessToken, nil },
		PublisherIdentityID: control.identity.ClientId, PublisherGrantID: control.identity.GrantId, PublisherKeyID: control.identity.KeyId,
		ServiceID: saved.Id, Target: first.Listener.Addr().String(), Metadata: publisheridentity.ServiceMetadata(saved), InspectionMode: inspection.None,
		HeartbeatInterval: 25 * time.Millisecond, DrainTime: 200 * time.Millisecond, Connectivity: peer.ConnectivityOptions{DisableDirect: true},
		Prepared: func(controlv1.ServiceRunPreparation) error { preparations.Add(1); return nil },
		ObserveReadiness: func(value publisherservice.RunStatus) {
			status.Store(&value)
			select {
			case changed <- struct{}{}:
			default:
			}
		}}
	go func() {
		defer close(joined)
		finished <- PublishPrivate(ctx, TargetPlan{Protocol: config.ProtocolHTTP, Target: first.URL, Trust: snapshot, Project: &project, ProjectService: "web"}, cfg,
			TargetHooks{Resolver: resolver, Capture: func(TargetSnapshot) error { captures.Add(1); return nil }})
	}()
	defer func() { finishResponse(); cancel(); <-joined }()
	awaitHealth := func(after time.Time, healthy bool) publisherservice.RunStatus {
		t.Helper()
		for {
			if current := status.Load(); current != nil && current.LeaseExpiresAt.After(after) && current.TargetHealthy == healthy && current.Ready == healthy {
				return *current
			}
			select {
			case <-changed:
			case err := <-finished:
				t.Fatal("HTTP target change stopped the service run", err)
			case <-ctx.Done():
				t.Fatal("target health did not follow discovery", healthy, status.Load(), context.Cause(ctx))
			}
		}
	}
	healthy := awaitHealth(time.Time{}, true)
	connection := targetRunVisitor(t, ctx, fixture, saved)
	defer connection.Close()
	transport := &http.Transport{Protocols: new(http.Protocols), DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
		return connection, nil
	}}
	transport.Protocols.SetHTTP2(true)
	visitor, err := transport.NewClientConn(ctx, "https", net.JoinHostPort(hostname, "443"))
	if err != nil {
		t.Fatal(err)
	}
	defer visitor.Close()
	request := func(path string) *http.Response {
		t.Helper()
		input, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+hostname+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := visitor.RoundTrip(input)
		if err != nil {
			t.Fatal("request lost the original HTTP/2 visitor connection", path, err)
		}
		return response
	}
	check := func(path string, want int) string {
		t.Helper()
		response := request(path)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != want || response.ProtoMajor != 2 || want == http.StatusOK && string(body) != "later" {
			t.Fatal("later request did not follow its captured target", path, response.Status, string(body), err)
		}
		return response.Header.Get("X-Target-Connection")
	}
	held := request("/hold")
	defer held.Body.Close()
	prefix := make([]byte, len("first"))
	if _, err := io.ReadFull(held.Body, prefix); err != nil || string(prefix) != "first" {
		t.Fatal("initial response did not flush", string(prefix), err)
	}
	// close only the old listener: its admitted response stays open, while a
	// health check stuck on that address can no longer report success.
	_ = first.Listener.Close()
	selected.Store(&TargetSnapshot{Address: later.Listener.Addr().String(), Identity: "container-b"})
	healthy = awaitHealth(healthy.LeaseExpiresAt, true)
	warm := check("/replacement", http.StatusOK)
	if warm == "" || check("/warm", http.StatusOK) != warm {
		t.Fatal("same-identity requests did not reuse their target connection")
	}
	selected.Store(&TargetSnapshot{Address: later.Listener.Addr().String(), Identity: "container-b-replaced"})
	if replacement := check("/same-address", http.StatusOK); replacement == "" || replacement == warm {
		t.Fatal("same-address identity replacement reused the retired target transport")
	}
	selected.Store(nil)
	unhealthy := awaitHealth(healthy.LeaseExpiresAt, false)
	check("/missing", http.StatusBadGateway)
	selected.Store(&TargetSnapshot{Address: untrusted.Listener.Addr().String(), Identity: "untrusted"})
	unhealthy = awaitHealth(unhealthy.LeaseExpiresAt, false)
	check("/untrusted", http.StatusBadGateway)
	selected.Store(&TargetSnapshot{Address: later.Listener.Addr().String(), Identity: "container-b-recovered"})
	awaitHealth(unhealthy.LeaseExpiresAt, true)
	check("/recovered", http.StatusOK)
	check("/fail", http.StatusBadGateway)
	check("/after-failure", http.StatusOK)
	select {
	case <-canceled:
		t.Fatal("target replacement, disappearance, or failed request canceled an open response")
	default:
	}
	finishResponse()
	if tail, err := io.ReadAll(held.Body); err != nil || string(tail) != "last" {
		t.Fatal("the original response lost its captured target", string(tail), err)
	}
	if preparations.Load() != 1 || captures.Load() != 1 || closed.Load() != 0 || firstRequests.Load() != 1 ||
		laterRequests.Load() != 6 || failedRequests.Load() != 1 || untrustedRequests.Load() != 0 {
		t.Fatal("target changes restarted the run, replaced trust, or replayed requests",
			preparations.Load(), captures.Load(), closed.Load(), firstRequests.Load(), laterRequests.Load(), failedRequests.Load(), untrustedRequests.Load())
	}
	_ = visitor.Close()
	_ = connection.Close()
	cancel()
	<-joined
	if err := <-finished; err != nil || closed.Load() != 1 {
		t.Fatal("service run did not join exactly once", err, closed.Load())
	}
}

func targetRunVisitor(t *testing.T, ctx context.Context, fixture *testutil.PublishingFixture, saved controlv1.Service) *tls.Conn {
	t.Helper()
	stream, err := fixture.OpenHTTPVisitor(ctx, saved.Id, netip.MustParseAddrPort("127.0.0.1:45123"), netip.MustParseAddrPort("127.0.0.1:443"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	connection := tls.Client(stream, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: saved.Endpoint.Hostname, NextProtos: []string{"h2"}})
	if err := connection.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if connection.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("visitor did not negotiate HTTP/2")
	}
	return connection
}
