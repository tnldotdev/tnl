package public

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlProxy "github.com/tnldotdev/tnl/internal/control/proxy"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	publisherdeployment "github.com/tnldotdev/tnl/internal/publisher/deployment"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	processidentity "github.com/tnldotdev/tnl/internal/publisher/processidentity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// runtimeHTTPTransport runs the actual router/proxy without dialing a fixture IP.
type runtimeHTTPTransport struct {
	mu           sync.Mutex
	handler      http.Handler
	peer, source string
}

func (c *runtimeHTTPTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	h, peer, source := c.handler, c.peer, c.source
	c.mu.Unlock()
	r = r.Clone(r.Context())
	r.RemoteAddr = peer
	r.Header.Set("X-Forwarded-For", source)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Real-IP", "1.1.1.1")
	r.Header.Set("Forwarded", "for=1.1.1.1;proto=https")
	r.Header.Set("Fly-Client-IP", "1.1.1.1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Result(), nil
}

func (c *runtimeHTTPTransport) set(h http.Handler, peer, source string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handler, c.peer, c.source = h, peer, source
}

// publication heartbeat behavior has its own tests. this adapter isolates the
// existing heartbeat's runtime renewal while keeping the real signed HTTP/DB path.
type runtimeNativeControl struct{ *clientcontrol.Client }

var _ interface {
	HeartbeatServiceRun(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error)
} = (*runtimeNativeControl)(nil)

func (*runtimeNativeControl) HeartbeatPublishRun(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
	return controlv1.PublishRunHeartbeat{}, nil
}
func (*runtimeNativeControl) HeartbeatServiceRun(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	return controlv1.ServiceRunState{}, nil
}

func TestIntegrationPublisherRuntimeHTTPObservation(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	dsn := testutil.NewDisposablePostgresDatabaseURL(t, "runtime_http")
	if err := controlstate.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, dsn, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now().UTC()
	session, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	m := session.Identity.Memberships[0]
	const server = "https://control.example"
	h, err := NewHandler(Config{ControlURL: server}, DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = controlauthority.Register(h, controlauthority.Config{ControlURL: server}, d); err != nil {
		t.Fatal(err)
	}
	proxy, err := (controlProxy.Config{Origin: server, TrustedPeers: []string{"10.0.0.0/24"}, ClientIPHeader: "X-Forwarded-For"}).Handler(h)
	if err != nil {
		t.Fatal(err)
	}
	transport := &runtimeHTTPTransport{handler: proxy, peer: "10.0.0.2:1234", source: "8.8.8.8"}
	httpClient := &http.Client{Transport: transport}
	owner, err := clientcontrol.New(server, httpClient, session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	client, err := clientcontrol.New(server, httpClient, "")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(server, httpClient, "")
	if err != nil {
		t.Fatal(err)
	}
	deployment := "remote"
	applied, err := owner.ApplyProjectConfiguration(ctx, "egress", controlv1.ApplyProjectConfigurationRequest{Deployment: deployment, ServiceDeclarations: controlv1.ProjectServiceDeclarations{"api": "http", "db": "postgres"}, TeamId: m.TeamID, Source: &testProjectSource, Configuration: controlv1.ProjectConfiguration{Settings: &controlv1.DeploymentSettings{}, Services: map[string]controlv1.ProjectServiceConfiguration{"api": {Target: "api.internal:3000"}, "db": {Target: "db.internal:5432", Protocol: new(controlv1.Postgres)}}}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := owner.CreateDeploymentPublisherEnrollment(ctx, m.TeamID, "egress", deployment, "runtime-enrollment", controlv1.CreateDeploymentPublisherEnrollmentRequest{Services: []string{"api", "db"}, MaxMembers: new(2), ExpiresIn: new(600)})
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := client.RedeemDeploymentPublisherEnrollment(ctx, e.EnrollmentKey, public)
	if err != nil {
		t.Fatal(err)
	}
	read := func(id string) *controlv1.PublisherRuntimeStatus {
		t.Helper()
		page, err := owner.ListPublisherIdentities(ctx, m.TeamID, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range page.Identities {
			if p.Id == id {
				return p.Runtime
			}
		}
		t.Fatal("publisher missing from authorized status")
		return nil
	}
	if read(member.PublisherIdentityId) != nil {
		t.Fatal("enrollment recorded operator egress")
	}
	runtime, err := processidentity.New(client, server, member.PublisherIdentityId, member.KeyId, member.DeploymentId, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	first := read(member.PublisherIdentityId)
	if first == nil || first.Address == nil || *first.Address != "8.8.8.8" || first.AddressFamily != "ipv4" || !first.Active {
		t.Fatalf("proxy source: %+v", first)
	}
	transport.set(proxy, "10.0.0.2:1234", "8.8.4.4")
	deploymentClient, err := publisherdeployment.NewClient(server, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = deploymentClient.Verify(ctx, member, key); err != nil {
		t.Fatal(err)
	}
	if _, err = deploymentClient.Lease(ctx, member, key); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(read(member.PublisherIdentityId), first) {
		t.Fatal("operator verification/preflight overwrote replica")
	}
	if _, err = owner.RenameDeployment(ctx, "egress", deployment, controlv1.RenameDeploymentRequest{TeamId: m.TeamID, Name: "live", ExpectedRevision: applied.Revision}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(read(member.PublisherIdentityId), first) {
		t.Fatal("rename lost immutable observation")
	}
	transport.set(proxy, "10.0.0.2:1234", "2606:4700:4700::1111")
	if _, err = runtime.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	current := read(member.PublisherIdentityId)
	if current.AddressFamily != "ipv6" || current.Address == nil || *current.Address != "2606:4700:4700::1111" {
		t.Fatalf("IPv6 NAT change: %+v", current)
	}
	for _, tc := range []struct{ peer, source string }{{"10.2.0.1:1234", "8.8.4.4"}, {"10.0.0.2:1234", "8.8.4.4, 1.1.1.1"}} {
		transport.set(proxy, tc.peer, tc.source)
		if _, err = runtime.Renew(ctx); err == nil {
			t.Fatal("invalid proxy accepted", tc)
		}
		transport.set(proxy, "10.0.0.2:1234", "8.8.8.8")
		if !reflect.DeepEqual(read(member.PublisherIdentityId), current) {
			t.Fatal("rejected proxy wrote observation")
		}
	}
	// direct HTTPS trusts its socket peer; forwarded claims remain inert.
	transport.set(h, "8.8.4.4:1234", "1.1.1.1")
	if _, err = runtime.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	if s := read(member.PublisherIdentityId); s.Address == nil || *s.Address != "8.8.4.4" {
		t.Fatal("spoofed direct forwarding headers won", s)
	}
	transport.set(proxy, "10.0.0.2:1234", "127.0.0.1")
	if _, err = runtime.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	if s := read(member.PublisherIdentityId); s.Address != nil || s.AddressFamily != "unknown" || !s.Active {
		t.Fatal("local workflow failed", s)
	}
	if _, err = client.ListPublisherIdentities(ctx, m.TeamID, ""); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("anonymous status", err)
	}
	if _, err = owner.ListPublisherIdentities(ctx, "team_other", ""); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatal("cross-team status", err)
	}
	if _, err = client.GetProjectConfiguration(ctx, m.TeamID, "egress", deployment); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("anonymous project status", err)
	}
	project, err := owner.GetProjectConfiguration(ctx, m.TeamID, "egress", "live")
	if err != nil || len(project.Members) != 1 || project.Members[0].Runtime == nil {
		t.Fatal("server status missing runtime", err)
	}
	metadata, err := owner.GetProjectPublicMetadata(ctx, m.TeamID, "egress")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(metadata)
	if bytes.Contains(encoded, []byte("process_run_id")) || bytes.Contains(encoded, []byte("control_observed")) {
		t.Fatal("runtime leaked into project metadata")
	}
	// a publication proof cannot start or replace a runtime, even for this identity.
	proof, _ := publisherproof.Sign(member.PublisherIdentityId, member.KeyId, member.DeploymentId, server+"/v1/publisher/deployments/verify", key, time.Now())
	if _, err = client.PublisherRuntime(ctx, controlv1.PublisherRuntimeRequest{PublisherIdentityId: member.PublisherIdentityId, ScopeId: member.DeploymentId, ProcessRunId: strings.Repeat("e", 32), ExpectedEpoch: 1, Action: controlv1.RuntimeStart, Assertion: proof}); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("verification proof started runtime", err)
	}
	if err = runtime.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if s := read(member.PublisherIdentityId); s.Active || s.StoppedAt == nil {
		t.Fatal("stop not visible", s)
	}
	// the deployment publisher owns one runtime for its services and joins their shutdown.
	transport.set(proxy, "10.0.0.2:1234", "8.8.8.8")
	deploymentCtx, cancel := context.WithCancel(ctx)
	started := make(chan struct{}, 2)
	observed := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- (publisherdeployment.Runtime{Control: deploymentClient, Member: member, Private: key, PollInterval: time.Second, Observe: func(int64, bool) error {
			select {
			case observed <- struct{}{}:
			default:
			}
			return nil
		}, Publish: func(ctx context.Context, _ controlv1.DeploymentPublisherServiceAssignment, health func(bool)) error {
			started <- struct{}{}
			health(true)
			<-ctx.Done()
			return nil
		}}).Serve(deploymentCtx)
	}()
	for range 2 {
		select {
		case <-started:
		case <-time.After(10 * time.Second):
			cancel()
			t.Fatal("deployment publisher did not start both assignments")
		}
	}
	deploymentStatus := read(member.PublisherIdentityId)
	if deploymentStatus.Epoch != 2 || !deploymentStatus.Active {
		cancel()
		t.Fatal("deployment publisher did not own one replacement epoch")
	}
	select {
	case <-observed:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("deployment publisher did not acknowledge its assignments")
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if s := read(member.PublisherIdentityId); s.Active || s.Epoch != 2 {
		t.Fatal("deployment publisher stop", s)
	}

	// a public URL's installed identity uses the same signed lifecycle. the
	// existing native heartbeat performs renewal, not token exchange/preflight.
	domains, err := d.ListTeamDomains(ctx, session.Identity.Identity.ID, m.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	u, err := d.CreatePublicURL(ctx, controlstate.CreatePublicURLRequest{TeamID: m.TeamID, DomainID: domains[0].ID, MembershipID: m.ID, ActingIdentityID: session.Identity.Identity.ID, IdempotencyKey: "runtime-url", RequestDigest: sha256.Sum256([]byte("runtime-url")), CanonicalHostname: "egress." + m.ManagedLabel + ".example.test", Target: "http://127.0.0.1:3000", PublicURLScope: controlstate.PublicURLScopeMember, Purpose: controlstate.PublicURLPurposeApp, DNSState: controlstate.PublicURLDNSUnmanaged}, now)
	if err != nil {
		t.Fatal(err)
	}
	pe, err := owner.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: m.TeamID, Name: "installed", Kind: "installed", PublicUrlId: &u.ID})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := authority.RedeemPublisherEnrollment(ctx, pe.EnrollmentKey, pub)
	if err != nil {
		t.Fatal(err)
	}
	runtimeControl := &runtimeNativeControl{client}
	native, err := publisheridentity.NewNative(publisheridentity.NativeControl{PublicURLControl: runtimeControl, Runtime: runtimeControl}, authority, identity, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = native.Access(ctx); err != nil {
		t.Fatal(err)
	}
	if read(identity.ClientId) != nil {
		t.Fatal("installed provisioning observed the laptop")
	}
	installed, err := native.RemoteRuntime(server)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = installed.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	native.WithRuntime(installed)
	transport.set(proxy, "10.0.0.2:1234", "::ffff:8.8.4.4")
	if _, err = native.HeartbeatPublishRun(ctx, "run", 1, credentials.PublishRunToken("test")); err != nil {
		t.Fatal(err)
	}
	if s := read(identity.ClientId); s.Address == nil || *s.Address != "8.8.4.4" || s.AddressFamily != "ipv4" {
		t.Fatal("installed heartbeat missed egress", s)
	}
	before := read(identity.ClientId)
	transport.set(proxy, "10.0.0.2:1234", "1.1.1.1")
	if _, err = native.Access(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(read(identity.ClientId), before) {
		t.Fatal("installed verification overwrote egress")
	}
	replacement, err := native.RemoteRuntime(server)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = replacement.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = native.HeartbeatPublishRun(ctx, "old-run", 1, credentials.PublishRunToken("test")); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("old installed heartbeat escaped fence", err)
	}
	if err = installed.Stop(ctx); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("old stop escaped fence", err)
	}
	if err = replacement.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if s := read(identity.ClientId); s.Active || s.Address == nil || *s.Address != "1.1.1.1" || s.Epoch != 2 {
		t.Fatal("installed stop lost last evidence", s)
	}
	service, err := owner.CreateService(ctx, m.TeamID, "installed-db", "installed-db", controlv1.ServiceMetadata{Protocol: controlv1.Postgres, TrustRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	pe, err = owner.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: m.TeamID, Name: "installed-private", Kind: "installed", ServiceId: &service.Id})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err = authority.RedeemPublisherEnrollment(ctx, pe.EnrollmentKey, pub)
	if err != nil {
		t.Fatal(err)
	}
	runtimeControl = &runtimeNativeControl{client}
	native, err = publisheridentity.NewNative(publisheridentity.NativeControl{PublicURLControl: runtimeControl, Services: runtimeControl, Runtime: runtimeControl}, authority, identity, priv)
	if err != nil {
		t.Fatal(err)
	}
	installed, err = native.RemoteRuntime(server)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = installed.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	native.WithRuntime(installed)
	transport.set(proxy, "10.0.0.2:1234", "2606:4700:4700::1111")
	if _, err = native.HeartbeatServiceRun(ctx, service.Id, "service-run", credentials.ServiceRunToken("test"), controlv1.ServiceRunHeartbeat{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}
	if s := read(identity.ClientId); s.AddressFamily != "ipv6" || !s.Active {
		t.Fatal("private installed heartbeat missed egress", s)
	}
	if err = owner.RevokePublisherIdentity(ctx, m.TeamID, identity.ClientId); err != nil {
		t.Fatal(err)
	}
	before = read(identity.ClientId)
	if before.Active || before.Address == nil {
		t.Fatal("revocation lost historical evidence or retained liveness")
	}
	if _, err = installed.Renew(ctx); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("revoked runtime wrote", err)
	}
	if !reflect.DeepEqual(read(identity.ClientId), before) {
		t.Fatal("failed authentication changed revoked observation")
	}
}
