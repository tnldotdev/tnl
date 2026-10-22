package controlapi

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

	"github.com/tnldotdev/tnl/internal/authorityapi"
	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/controlproxy"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/grouppublisher"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/publisherruntime"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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
type runtimeNativeControl struct{ *controlclient.Client }

func (*runtimeNativeControl) HeartbeatPublishRun(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
	return controlv1.PublishRunHeartbeat{}, nil
}
func (*runtimeNativeControl) HeartbeatPrivateServiceRun(context.Context, string, string, credentials.PublishRunToken) (controlv1.PrivateServiceRunState, error) {
	return controlv1.PrivateServiceRunState{}, nil
}

func TestIntegrationPublisherRuntimeHTTPObservation(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	dsn := testutil.NewDisposablePostgresDatabaseURL(t, "runtime_http")
	if err := controlstate.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, dsn, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
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
	h, err := NewHandler(Config{ControlURL: server}, d, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authorityapi.Register(h, authorityapi.Config{ControlURL: server}, d); err != nil {
		t.Fatal(err)
	}
	proxy, err := (controlproxy.Config{Origin: server, TrustedPeers: []string{"10.0.0.0/24"}, ClientIPHeader: "X-Forwarded-For"}).Handler(h)
	if err != nil {
		t.Fatal(err)
	}
	transport := &runtimeHTTPTransport{handler: proxy, peer: "10.0.0.2:1234", source: "8.8.8.8"}
	httpClient := &http.Client{Transport: transport}
	owner, err := controlclient.New(server, httpClient, session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	client, err := controlclient.New(server, httpClient, "")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := authorityclient.New(server, httpClient, "")
	if err != nil {
		t.Fatal(err)
	}
	group := "remote"
	applied, err := owner.ApplyProjectConfiguration(ctx, "egress", controlv1.ApplyProjectConfigurationRequest{TeamId: m.TeamID, SourceFingerprint: strings.Repeat("a", 64), Configuration: controlv1.ProjectConfiguration{Publishers: map[string]controlv1.ProjectPublisherGroup{group: {}}, Services: map[string]controlv1.ProjectServiceConfiguration{"api": {Publisher: &group, Target: "api.internal:3000"}, "db": {Publisher: &group, Target: "db.internal:5432", Protocol: new(controlv1.Postgres)}}}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := owner.CreatePublisherGroupEnrollment(ctx, "egress", group, controlv1.CreatePublisherGroupEnrollmentRequest{TeamId: m.TeamID, MaxMembers: 2, ExpiresIn: 600})
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := client.RedeemPublisherGroupEnrollment(ctx, e.EnrollmentKey, public)
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
	runtime, err := publisherruntime.New(client, server, member.PublisherIdentityId, member.KeyId, member.GroupId, key)
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
	groupClient, err := grouppublisher.NewClient(server, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = groupClient.Verify(ctx, member, key); err != nil {
		t.Fatal(err)
	}
	if _, err = groupClient.Lease(ctx, member, key); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(read(member.PublisherIdentityId), first) {
		t.Fatal("operator verification/preflight overwrote replica")
	}
	if _, err = owner.RenamePublisherGroup(ctx, "egress", group, controlv1.RenamePublisherGroupRequest{TeamId: m.TeamID, Name: "live", ExpectedRevision: applied.Revision}); err != nil {
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
	if _, err = client.ListPublisherIdentities(ctx, m.TeamID, ""); !errors.Is(err, controlclient.ErrUnauthenticated) {
		t.Fatal("anonymous status", err)
	}
	if _, err = owner.ListPublisherIdentities(ctx, "team_other", ""); !errors.Is(err, controlclient.ErrNotFound) {
		t.Fatal("cross-team status", err)
	}
	if _, err = client.GetProjectConfiguration(ctx, m.TeamID, "egress"); !errors.Is(err, controlclient.ErrUnauthenticated) {
		t.Fatal("anonymous project status", err)
	}
	project, err := owner.GetProjectConfiguration(ctx, m.TeamID, "egress")
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
	proof, _ := publisheridentity.Sign(member.PublisherIdentityId, member.KeyId, member.GroupId, server+"/v1/publisher-groups/verify", key, time.Now())
	if _, err = client.PublisherRuntime(ctx, controlv1.PublisherRuntimeRequest{PublisherIdentityId: member.PublisherIdentityId, ScopeId: member.GroupId, ProcessRunId: strings.Repeat("e", 32), ExpectedEpoch: 1, Action: controlv1.RuntimeStart, Assertion: proof}); !errors.Is(err, controlclient.ErrUnauthenticated) {
		t.Fatal("verification proof started runtime", err)
	}
	if err = runtime.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if s := read(member.PublisherIdentityId); s.Active || s.StoppedAt == nil {
		t.Fatal("stop not visible", s)
	}
	// actual multi-service group loop owns one runtime and orderly stop.
	transport.set(proxy, "10.0.0.2:1234", "8.8.8.8")
	groupCtx, cancel := context.WithCancel(ctx)
	started := make(chan struct{}, 2)
	observed := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- (grouppublisher.Runtime{Control: groupClient, Member: member, Private: key, PollInterval: time.Second, Observe: func(int64, bool) error {
			select {
			case observed <- struct{}{}:
			default:
			}
			return nil
		}, Publish: func(ctx context.Context, _ controlv1.PublisherGroupServiceAssignment, health func(bool)) error {
			started <- struct{}{}
			health(true)
			<-ctx.Done()
			return nil
		}}).Serve(groupCtx)
	}()
	for range 2 {
		select {
		case <-started:
		case <-time.After(10 * time.Second):
			cancel()
			t.Fatal("group did not start both assignments")
		}
	}
	groupStatus := read(member.PublisherIdentityId)
	if groupStatus.Epoch != 2 || !groupStatus.Active {
		cancel()
		t.Fatal("group did not own one replacement epoch")
	}
	select {
	case <-observed:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("group did not acknowledge its assignments")
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if s := read(member.PublisherIdentityId); s.Active || s.Epoch != 2 {
		t.Fatal("group stop", s)
	}

	// non-group installed identity uses the exact same signed lifecycle. the
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
	native, err := nativeauth.NewNative(&runtimeNativeControl{client}, authority, identity, priv)
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
	if _, err = native.HeartbeatPublishRun(ctx, "old-run", 1, credentials.PublishRunToken("test")); !errors.Is(err, controlclient.ErrStatusConflict) {
		t.Fatal("old installed heartbeat escaped fence", err)
	}
	if err = installed.Stop(ctx); !errors.Is(err, controlclient.ErrStatusConflict) {
		t.Fatal("old stop escaped fence", err)
	}
	if err = replacement.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if s := read(identity.ClientId); s.Active || s.Address == nil || *s.Address != "1.1.1.1" || s.Epoch != 2 {
		t.Fatal("installed stop lost last evidence", s)
	}
	service, err := owner.CreatePrivateService(ctx, m.TeamID, "installed-db", "installed-db", controlv1.PrivateServiceMetadata{Protocol: controlv1.Postgres, TrustRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	pe, err = owner.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: m.TeamID, Name: "installed-private", Kind: "installed", PrivateServiceId: &service.Id})
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
	native, err = nativeauth.NewNative(&runtimeNativeControl{client}, authority, identity, priv)
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
	if _, err = native.HeartbeatPrivateServiceRun(ctx, service.Id, "private-run", credentials.PublishRunToken("test")); err != nil {
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
	if _, err = installed.Renew(ctx); !errors.Is(err, controlclient.ErrUnauthenticated) {
		t.Fatal("revoked runtime wrote", err)
	}
	if !reflect.DeepEqual(read(identity.ClientId), before) {
		t.Fatal("failed authentication changed revoked observation")
	}
}
