package daemon

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var testProjectSource = controlv1.GitProjectSource{GitOrigin: "https://example.test/example.git", ConfigurationPath: "tnl.yml"}

const testProjectSourceFingerprint = "a4c232311b1a5083342e81207d920e296029c9181e4a45f9f3492a13216aa45c"

// real clock: both siblings retain their original tcp, http and postgresql
// streams across the 90-second lease and 135-second startup proof. only the
// capped sibling ends at its original 205-second hard deadline.
func TestIntegrationWorkloadTransportLifecycle(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			f, issuer := newWorkloadTransportFixture(t)
			byName, pg := startWorkloadRuntimeServices(t, f, transport)
			job, err := workload.New(f.controlConfig.ControlOrigin(), f.publicHTTP)
			if err != nil {
				t.Fatal(err)
			}
			initialClaims := githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())
			initialClaims["exp"] = time.Now().Add(135 * time.Second).Unix()
			assertion := issuer.Sign(t, initialClaims)
			session, err := job.Exchange(t.Context(), f.identity.teamID, "workload", testProjectSourceFingerprint, "test", assertion, nil)
			if err != nil {
				t.Fatal(err)
			}
			assertWorkloadRuntimeInventory(t, job, byName)
			stopRenew := renewRuntimeWorkload(t, job, session.ExpiresAt)
			paths := openWorkloadPaths(t, f, job, byName, pg, transport)
			t.Cleanup(func() {
				if !t.Failed() {
					return
				}
				t.Logf("workload source=%s lease=%s expires=%s", session.Id, session.LeaseExpiresAt, session.ExpiresAt)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				var bindings string
				var authority string
				err := f.inspect.QueryRowContext(ctx, `SELECT jsonb_build_object(
					'lease_expires_at',lease_expires_at,'identity_expires_at',identity_expires_at,
					'expires_at',expires_at,'renewed_at',renewed_at,'renewal_sequence',renewal_sequence)::text
					FROM control.workload_sessions WHERE id=$1`, session.Id).Scan(&authority)
				t.Logf("workload current authority: %s: %v", authority, err)
				err = f.inspect.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(jsonb_build_object(
					'service_id',service_id,'expires_at',expires_at,'publisher_prepared_until',publisher_prepared_until,
					'claims',(SELECT jsonb_agg(jsonb_build_object('slot',connection_slot,'checked_at',checked_at,'confirmed_until',confirmed_until))
					FROM control.connector_peer_pair_leg_claims WHERE pair_id=pair.id)))::text,'[]')
					FROM control.connector_peer_pairs pair WHERE subject_kind='workload_session' AND subject_id=$1`, session.Id).Scan(&bindings)
				t.Logf("workload retained bindings: %s: %v", bindings, err)
			})
			paths.step(t, 0)
			nativeBinding := workloadNativeRuntimeBinding(t, f, session.Id, *session.ExpiresAt)
			continuous, err := workload.New(f.controlConfig.ControlOrigin(), f.publicHTTP)
			if err != nil {
				t.Fatal(err)
			}
			continuousClaims := githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())
			continuousClaims["check_run_id"], continuousClaims["jti"] = "555", "continuous-initial-proof"
			continuousClaims["exp"] = time.Now().Add(135 * time.Second).Unix()
			continuousSession, err := continuous.Exchange(t.Context(), f.identity.teamID, "workload", testProjectSourceFingerprint, "continuous", issuer.Sign(t, continuousClaims), nil)
			if err != nil || continuousSession.ExpiresAt != nil {
				t.Fatal("continuous session acquired a hard limit", err)
			}
			renewRuntimeWorkload(t, continuous, nil)
			continuousPaths := openWorkloadPaths(t, f, continuous, byName, pg, transport)
			continuousPaths.step(t, 0)
			continuousBinding := workloadNativeRuntimeBinding(t, f, continuousSession.Id, continuousSession.IdentityExpiresAt)
			for i, at := range []time.Time{session.LeaseExpiresAt.Add(5 * time.Second), session.LeaseExpiresAt.Add(95 * time.Second)} {
				paths.wait(t, at)
				if i == 0 {
					fresh := githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())
					fresh["jti"] = "rotated-platform-proof"
					assertion = issuer.Sign(t, fresh)
					refreshed, err := job.Attach(t.Context(), assertion)
					if err != nil || refreshed.Id != session.Id || !refreshed.IdentityExpiresAt.After(session.IdentityExpiresAt) || !refreshed.ExpiresAt.Equal(*session.ExpiresAt) {
						t.Fatal("fresh platform proof changed the original session or fixed window", err)
					}
					continuousProof := githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())
					continuousProof["check_run_id"], continuousProof["jti"] = "555", "continuous-refreshed-proof"
					updated, err := continuous.Attach(t.Context(), issuer.Sign(t, continuousProof))
					if err != nil || updated.ExpiresAt != nil || updated.Id != continuousSession.Id || !updated.IdentityExpiresAt.After(continuousSession.IdentityExpiresAt) {
						t.Fatal("uncapped refresh replaced original authority", err)
					}
				} else if !time.Now().After(session.IdentityExpiresAt) {
					t.Fatal("retained streams did not cross the original platform proof deadline")
				}
				paths.step(t, int(time.Until(*session.ExpiresAt).Seconds()))
				continuousPaths.step(t, i+1)
				currentContinuous, err := continuous.Session()
				if err != nil || workloadNativeRuntimeBinding(t, f, continuousSession.Id, workload.SessionDeadline(currentContinuous)) != continuousBinding {
					t.Fatal("uncapped refresh replaced connector owners or exact bindings", err)
				}
				if workloadNativeRuntimeBinding(t, f, session.Id, *session.ExpiresAt) != nativeBinding {
					t.Fatal("workload renewal replaced its connector owners or exact bindings")
				}
			}
			var humans int
			if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.visitor_devices`).Scan(&humans); err != nil || humans != 0 {
				t.Fatal("workload enrolled a human device", err)
			}
			waitRuntimeTime(t, session.ExpiresAt.Add(time.Second))
			stopRenew()
			paths.denied(t, 3*time.Second)
			continuousPaths.step(t, 3)
			currentContinuous, err := continuous.Session()
			if err != nil || currentContinuous.ExpiresAt != nil || !time.Now().After(continuousSession.IdentityExpiresAt) || workloadNativeRuntimeBinding(t, f, continuousSession.Id, workload.SessionDeadline(currentContinuous)) != continuousBinding {
				t.Fatal("continuous streams ended at the sibling's hard limit or startup proof", err)
			}
			t.Log("original HTTP, PostgreSQL and opaque streams crossed lease and startup-proof expiry with exact native bindings; only the capped sibling ended at its hard deadline")
		})
	}
}

func TestIntegrationWorkloadTransportClosure(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			f, issuer := newWorkloadTransportFixture(t)
			services, pg := startWorkloadRuntimeServices(t, f, transport)
			for i, reason := range []string{"revocation", "lease-expiry"} {
				t.Run(reason, func(t *testing.T) {
					job, err := workload.New(f.controlConfig.ControlOrigin(), f.publicHTTP)
					if err != nil {
						t.Fatal(err)
					}
					claims := githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())
					claims["check_run_id"], claims["jti"] = strconv.Itoa(333+i), reason
					policy := "test"
					if reason == "revocation" {
						policy = "continuous"
					}
					session, err := job.Exchange(t.Context(), f.identity.teamID, "workload", testProjectSourceFingerprint, policy, issuer.Sign(t, claims), nil)
					if err != nil {
						t.Fatal(err)
					}
					paths := openWorkloadPaths(t, f, job, services, pg, transport)
					paths.step(t, 0)
					if reason == "revocation" {
						if err := job.Revoke(t.Context()); err != nil {
							t.Fatal(err)
						}
						paths.denied(t, 31*time.Second)
					} else {
						waitRuntimeTime(t, session.LeaseExpiresAt.Add(time.Second))
						paths.denied(t, 3*time.Second)
					}
				})
			}
		})
	}
}

func startWorkloadRuntimeServices(t *testing.T, f *privateSeparatedFixture, transport string) (map[string]string, *pgx.ConnConfig) {
	t.Helper()
	echo := startPrivateEchoTarget(t, f.owner)
	httpTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Tnl-Access-Token") != "" || r.Header.Get("Tnl-Visitor-Token") != "" || strings.Contains(r.Header.Get("Cookie"), "__Host-tnl-") {
			t.Error("target received visitor credential")
		}
		if r.URL.Path == "/stream" {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				if _, err := io.WriteString(w, "tick\n"); err != nil {
					return
				}
				if err := http.NewResponseController(w).Flush(); err != nil {
					return
				}
				select {
				case <-r.Context().Done():
					return
				case <-ticker.C:
				}
			}
		}
		_, _ = io.WriteString(w, "workload HTTP")
	}))
	cleanupIntegrationHTTPServer(t, httpTarget, f.owner)
	pg, err := pgx.ParseConfig(f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	group := "private"
	tcpProtocol, httpProtocol, pgProtocol := controlv1.Tcp, controlv1.ServiceProtocolHTTP, controlv1.Postgres
	services := map[string]controlv1.ProjectServiceConfiguration{
		"tcp":  {PublisherGroup: &group, Protocol: &tcpProtocol, Target: echo.address},
		"http": {PublisherGroup: &group, Protocol: &httpProtocol, Target: strings.TrimPrefix(httpTarget.URL, "http://")},
		"db":   {PublisherGroup: &group, Protocol: &pgProtocol, Target: net.JoinHostPort(pg.Host, strconv.Itoa(int(pg.Port)))},
	}
	policies := map[string]controlv1.ProjectWorkload{"test": {Provider: controlv1.WorkloadGitHub, Github: &controlv1.ProjectWorkloadGitHub{Repository: "example/repository", RepositoryId: "12345", RepositoryOwnerId: "6789", WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Events: []string{"push"}}, Services: []string{"tcp", "http", "db"}, MaxDurationSeconds: 205}}
	continuous := policies["test"]
	continuous.MaxDurationSeconds = 0
	policies["continuous"] = continuous
	applied, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "workload", controlv1.ApplyProjectConfigurationRequest{TeamId: f.identity.teamID, Source: &testProjectSource, Configuration: controlv1.ProjectConfiguration{Workloads: &policies, PublisherGroups: map[string]controlv1.ProjectPublisherGroup{group: {}}, Services: services, Webhooks: map[string]controlv1.ProjectWebhook{}}})
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]string, len(services))
	if len(applied.Services) != len(services) {
		t.Fatal("configuration did not retain all workload services")
	}
	for _, service := range applied.Services {
		if service.ServiceId == nil {
			t.Fatal("configuration did not return saved service ID")
		}
		byName[service.Service] = *service.ServiceId
	}
	startWorkloadPublishers(t, f, group, transport)
	return byName, pg
}

func assertWorkloadRuntimeInventory(t *testing.T, job *workload.Client, services map[string]string) {
	t.Helper()
	inventory, err := job.ListServices(t.Context())
	if err != nil || len(inventory.Services) != len(services) {
		t.Fatal("workload inventory", err)
	}
	for _, service := range inventory.Services {
		if services[service.Service] != service.Id {
			t.Fatal("configuration keys did not retain exact saved service IDs")
		}
	}
}

func newWorkloadTransportFixture(t *testing.T) (*privateSeparatedFixture, *githubtest.Issuer) {
	t.Helper()
	issuer := githubtest.New(t)
	f := newServiceRuntimeFixtureTiming(t, false, nil, true, func(_ *daemonconfig.Config, tr *http.Transport, _ *testCertificateAuthority) {
		base := tr.Clone()
		t.Cleanup(base.CloseIdleConnections)
		tr.RegisterProtocol("https", splitACMERoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == "token.actions.githubusercontent.com" {
				return issuer.Client.Transport.RoundTrip(r)
			}
			return base.RoundTrip(r)
		}))
	})
	return f, issuer
}

func TestIntegrationWorkloadTransportHTTPNoFallback(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f, issuer := newWorkloadTransportFixture(t)
	process := startSeparatedPrivateIngress(t, f, 0, "tls-tcp", nil)
	startSeparatedPrivateIngress(t, f, 1, "tls-tcp", nil)
	var forwarded atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		if r.Header.Get("Tnl-Access-Token") != "" || r.Header.Get("Tnl-Visitor-Token") != "" || strings.Contains(r.Header.Get("Cookie"), "__Host-tnl-") {
			t.Error("target received visitor credential")
		}
		_, _ = io.WriteString(w, "workload HTTP")
	}))
	cleanupIntegrationHTTPServer(t, target, f.owner)
	group, protocol := "public", controlv1.ServiceProtocolHTTP
	policies := map[string]controlv1.ProjectWorkload{"test": {Provider: controlv1.WorkloadGitHub, Github: &controlv1.ProjectWorkloadGitHub{Repository: "example/repository", RepositoryId: "12345", RepositoryOwnerId: "6789", WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Events: []string{"push"}}, Services: []string{"api"}, MaxDurationSeconds: 60}}
	_, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "workload", controlv1.ApplyProjectConfigurationRequest{TeamId: f.identity.teamID, Source: &testProjectSource, Configuration: controlv1.ProjectConfiguration{Workloads: &policies, PublisherGroups: map[string]controlv1.ProjectPublisherGroup{group: {Public: new(true)}}, Services: map[string]controlv1.ProjectServiceConfiguration{"api": {PublisherGroup: &group, Protocol: &protocol, Target: strings.TrimPrefix(target.URL, "http://")}}, Webhooks: map[string]controlv1.ProjectWebhook{}}})
	if err != nil {
		t.Fatal(err)
	}
	startWorkloadPublishers(t, f, group, "tls-tcp")
	job, err := workload.New(f.controlConfig.ControlOrigin(), f.publicHTTP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = job.Exchange(t.Context(), f.identity.teamID, "workload", testProjectSourceFingerprint, "test", issuer.Sign(t, githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())), nil); err != nil {
		t.Fatal(err)
	}
	inventory, err := job.ListServices(t.Context())
	if err != nil || len(inventory.Services) != 1 {
		t.Fatal("workload inventory", err)
	}
	s := inventory.Services[0]
	grant, err := f.identity.routes.CreateServiceHTTPGrant(t.Context(), s.Id, controlv1.CreateVisitorCredentialRequest{Kind: "token", ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := job.ClientTLSCertificate(t.Context(), s.Id)
	if err != nil {
		t.Fatal(err)
	}
	verification := f.visitorRoots.Clone()
	verification.ServerName = s.Endpoint.Hostname
	verification.Certificates = []tls.Certificate{certificate}
	tr := &http.Transport{TLSClientConfig: verification, DialContext: workloadPublicEndpointDialer(t, process.ingresses[0].publicServices, s.Endpoint.Port)}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	humanTLS := verification.Clone()
	humanTLS.Certificates = nil
	humanTransport := &http.Transport{TLSClientConfig: humanTLS, DialContext: tr.DialContext}
	t.Cleanup(humanTransport.CloseIdleConnections)
	humanClient := &http.Client{Transport: humanTransport, Timeout: 5 * time.Second, CheckRedirect: client.CheckRedirect}
	endpoint := "https://" + net.JoinHostPort(s.Endpoint.Hostname, strconv.Itoa(s.Endpoint.Port))
	request := func(client *http.Client, path, header, credential string, status int) {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), "GET", endpoint+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if header != "" {
			r.Header.Set(header, credential)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != status {
			t.Fatalf("workload HTTP status %d, want %d", response.StatusCode, status)
		}
	}
	currentPermission := func() controlv1.VisitorTokenResponse {
		t.Helper()
		source, err := json.Marshal(controlv1.VisitorTokenGrantSource{Kind: controlv1.VisitorTokenGrant, Credential: grant.RefreshCredential})
		if err != nil {
			t.Fatal(err)
		}
		permission, err := f.identity.routes.IssueVisitorToken(t.Context(), controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKindService, Id: s.Id}, Source: source})
		if err != nil {
			t.Fatal(err)
		}
		return permission
	}
	awaitServiceHTTPStatus(t, client, endpoint, "", "", 200)
	request(client, "/", "", "", 200)
	permission := currentPermission()
	awaitServiceHTTPStatus(t, humanClient, endpoint, "Tnl-Visitor-Token", permission.VisitorToken, 200)
	request(humanClient, "/", "Tnl-Visitor-Token", permission.VisitorToken, 200)
	beforeMixedCredentials := forwarded.Load()
	// a supplied certificate cannot switch subjects through another credential.
	request(client, "/", "Tnl-Visitor-Token", permission.VisitorToken, 403)
	request(client, "/", "Cookie", "__Host-tnl-browser=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 403)
	request(client, "/", "Tnl-Visitor-Token", "invalid", 403)
	request(client, "/", "Cookie", "__Host-tnl-visitor=invalid", 403)
	if forwarded.Load() != beforeMixedCredentials {
		t.Fatal("mixed certificate and HTTP credentials reached the target")
	}
	if err = job.Revoke(t.Context()); err != nil {
		t.Fatal(err)
	}
	awaitServiceHTTPStatus(t, client, endpoint, "", "", 403)
	request(client, "/", "", "", 403)
	// workload revocation does not revoke an independent human credential, but
	// the revoked certificate's connection cannot adopt that human's permission.
	permission = currentPermission()
	awaitServiceHTTPStatus(t, humanClient, endpoint, "Tnl-Visitor-Token", permission.VisitorToken, 200)
	request(humanClient, "/", "Tnl-Visitor-Token", permission.VisitorToken, 200)
	beforeMixedCredentials = forwarded.Load()
	request(client, "/", "Tnl-Visitor-Token", permission.VisitorToken, 403)
	request(client, "/__tnl/login", "Tnl-Visitor-Token", permission.VisitorToken, 403)
	if forwarded.Load() != beforeMixedCredentials {
		t.Fatal("revoked workload certificate selected a human credential")
	}
}

func startWorkloadPublishers(t *testing.T, f *privateSeparatedFixture, group, transport string, wrappers ...func(publisherservice.RunControl) publisherservice.RunControl) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e, err := f.identity.routes.CreatePublisherGroupEnrollment(t.Context(), "workload", group, controlv1.CreatePublisherGroupEnrollmentRequest{TeamId: f.identity.teamID, MaxMembers: 1, ExpiresIn: 600})
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.identity.routes.RedeemPublisherGroupEnrollment(t.Context(), e.EnrollmentKey, public)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := publisheridentity.NewGroup(publisheridentity.NativeControl{PublicURLControl: f.identity.routes, Services: f.identity.routes}, f.identity.routes, f.identity.authority, f.identity.routes.ControlURL(), member, key)
	if err != nil {
		t.Fatal(err)
	}
	assignments, err := owner.Poll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, assignment := range assignments.Services {
		native, err := owner.Service(assignment)
		if err != nil {
			t.Fatal(err)
		}
		service, err := native.SavedService(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		identity := authorityv1.PublisherEnrollmentResult{ClientId: member.PublisherIdentityId, KeyId: member.KeyId, TeamId: member.TeamId, GrantId: assignment.GrantId, Kind: authorityv1.Service, ServiceId: &assignment.ServiceId}
		quic, tcp := f.connectors()
		if transport == "quic" {
			tcp = privateDisabledConnector()
		} else {
			quic = privateDisabledConnector()
		}
		publisherContext := t.Context()
		if f.processContext != nil {
			publisherContext = f.processContext("publisher")
		}
		ctx, cancel := context.WithCancel(publisherContext)
		var control publisherservice.RunControl = native
		for _, wrap := range wrappers {
			control = wrap(control)
		}
		ready, done := make(chan struct{}), make(chan error, 1)
		go func() {
			done <- publisherservice.Publish(ctx, publisherservice.RunConfig{Control: control, State: f.identity.state, Access: native.Access, Identity: identity, ServiceID: service.Id, Target: assignment.Configuration.Target, Metadata: publisheridentity.ServiceMetadata(service), HeartbeatInterval: time.Second, Ready: func() error { close(ready); return nil }, RelayQUIC: quic, RelayTCP: tcp})
		}()
		t.Cleanup(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(15 * time.Second):
				t.Error("workload publisher did not join")
			}
		})
		select {
		case <-ready:
		case err := <-done:
			done <- err
			t.Fatal("workload publisher", err)
		case <-time.After(20 * time.Second):
			t.Fatal("workload publisher not ready")
		}
	}
}

func renewRuntimeWorkload(t *testing.T, job *workload.Client, expires *time.Time) func() {
	t.Helper()
	ctx, stop := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		for {
			s, err := job.Session()
			if err != nil {
				done <- err
				return
			}
			timer := time.NewTimer(max(time.Millisecond, time.Until(s.RenewAfter)))
			select {
			case <-ctx.Done():
				timer.Stop()
				done <- nil
				return
			case <-timer.C:
			}
			next, err := job.Renew(ctx)
			if err != nil {
				if ctx.Err() != nil || expires != nil && !time.Now().Before(*expires) {
					err = nil
				}
				done <- err
				return
			}
			if (next.ExpiresAt == nil) != (expires == nil) || expires != nil && !next.ExpiresAt.Equal(*expires) {
				done <- errors.New("renewal changed fixed expiry")
				return
			}
		}
	}()
	finish := sync.OnceFunc(func() {
		stop()
		if err := <-done; err != nil {
			t.Error("workload renewal", err)
		}
	})
	t.Cleanup(finish)
	return finish
}

func waitRuntimeTime(t *testing.T, at time.Time) {
	t.Helper()
	timer := time.NewTimer(max(time.Nanosecond, time.Until(at)))
	defer timer.Stop()
	select {
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	case <-timer.C:
	}
}

type workloadRuntimePaths struct {
	ended          chan error
	connection     net.Conn
	client         *http.Client
	url            string
	streamDone     chan struct{}
	streamProgress chan struct{}
	streamError    error
	database       *pgx.Conn
	backendPID     uint32
}

func openWorkloadPaths(t *testing.T, f *privateSeparatedFixture, job *workload.Client, services map[string]string, pg *pgx.ConnConfig, transport string) *workloadRuntimePaths {
	t.Helper()
	source, err := job.Session()
	if err != nil {
		t.Fatal(err)
	}
	p := &workloadRuntimePaths{ended: make(chan error, len(services)), streamDone: make(chan struct{}), streamProgress: make(chan struct{}, 1)}
	for _, name := range []string{"tcp", "http", "db"} {
		service := services[name]
		control, err := connectorstream.NewWorkloadControl(job)
		if err != nil {
			t.Fatal(err)
		}
		run, err := control.ResolveService(t.Context(), service)
		if err != nil {
			t.Fatal(err)
		}
		verification := f.visitorRoots.Clone()
		verification.ServerName = run.Endpoint.Hostname
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		address := listener.Addr().String()
		ctx, cancel := context.WithCancel(t.Context())
		ready, done := make(chan struct{}), make(chan error, 1)
		quic, tcp := f.connectors()
		if transport == "quic" {
			tcp = privateDisabledConnector()
		} else {
			quic = privateDisabledConnector()
		}
		go func() {
			err := connectorstream.Serve(ctx, listener, connectorstream.Config{Control: control, ServiceID: service, Protocol: run.Protocol, TrustRevision: run.TrustRevision, Endpoint: run.Endpoint, ServiceTLS: verification, TransportTLS: f.roots, RelayQUIC: quic, RelayTCP: tcp, Ready: func() error { close(ready); return nil }})
			if ctx.Err() == nil {
				p.ended <- fmt.Errorf("workload connector %s/%s source=%s ended: %v", transport, name, source.Id, err)
			}
			done <- err
		}()
		var stoppedError error
		stop := sync.OnceFunc(func() {
			cancel()
			select {
			case stoppedError = <-done:
			case <-time.After(10 * time.Second):
				t.Error("workload connector did not join")
			}
		})
		t.Cleanup(stop)
		select {
		case <-ready:
		case err := <-done:
			done <- err
			t.Fatal(err)
		// match Serve's fixed startup budget; preparation includes the
		// publisher's background policy snapshot and both relay paths.
		case <-time.After(30 * time.Second):
			// capture the blocked request before cancellation releases its database
			// locks. this independent, bounded snapshot cannot make setup pass late.
			diagnostics, diagnosticErr := f.database.Diagnostics(t.Context())
			encoded, encodeErr := json.Marshal(diagnostics)
			if len(encoded) <= controlstate.MaxDatabaseDiagnosticBytes && encodeErr == nil {
				t.Logf("workload startup database diagnostics: %s; error=%v", encoded, diagnosticErr)
			} else {
				t.Logf("workload startup database diagnostics omitted: bytes=%d error=%v", len(encoded), encodeErr)
			}
			stop()
			t.Fatalf("workload connector %s/%s source=%s not ready within 30s; joined setup: %v", transport, name, source.Id, stoppedError)
		}
		dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
		if name == "db" {
			cfg := pg.Copy()
			host, port, _ := net.SplitHostPort(address)
			n, _ := strconv.Atoi(port)
			cfg.Host, cfg.Port, cfg.TLSConfig, cfg.Fallbacks = host, uint16(n), verification, nil
			cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
			p.database, err = pgx.ConnectConfig(t.Context(), cfg)
			if err != nil {
				t.Fatal("native PostgreSQL", err)
			}
			p.backendPID = p.database.PgConn().PID()
			t.Cleanup(func() { _ = p.database.Close(context.Background()) })
		} else if name == "tcp" {
			p.connection, err = dial(t.Context(), "tcp", "")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = p.connection.Close() })
		} else {
			// step probes cross a 95-second gap, beyond the server's one-minute
			// idle timeout. use fresh probe sockets; the separate streaming
			// responses below must retain their original streams across renewal.
			tr := &http.Transport{TLSClientConfig: verification, DialContext: dial, DisableKeepAlives: true}
			t.Cleanup(tr.CloseIdleConnections)
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			endpoint := "https://" + net.JoinHostPort(run.Endpoint.Hostname, strconv.Itoa(run.Endpoint.Port))
			p.client, p.url = client, endpoint
			streamClient := *client
			streamClient.Timeout = 0
			request, err := http.NewRequestWithContext(ctx, "GET", endpoint+"/stream", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := streamClient.Do(request)
			if err != nil {
				t.Fatal("active workload HTTP stream", err)
			}
			t.Cleanup(func() {
				_ = response.Body.Close()
				select {
				case <-p.streamDone:
				case <-time.After(5 * time.Second):
					t.Error("workload HTTP stream did not join")
				}
			})
			go func() {
				defer close(p.streamDone)
				defer response.Body.Close()
				scanner := bufio.NewScanner(response.Body)
				for scanner.Scan() {
					if scanner.Text() != "tick" {
						p.streamError = fmt.Errorf("unexpected HTTP stream data %q", scanner.Text())
						t.Errorf("workload HTTP stream: %v", p.streamError)
						return
					}
					select {
					case p.streamProgress <- struct{}{}:
					default:
					}
				}
				p.streamError = scanner.Err()
			}()
			if response.StatusCode != 200 {
				t.Fatal("active workload HTTP stream status", response.StatusCode)
			}
		}
	}
	return p
}

func workloadNativeRuntimeBinding(t *testing.T, f *privateSeparatedFixture, session string, expiry time.Time) string {
	t.Helper()
	var count int
	var valid bool
	var binding string
	err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*),COALESCE(bool_and(pair.expires_at<=$2 AND pair.publisher_prepared_until IS NOT NULL
		AND (SELECT count(*)=2 AND bool_and(host(source_ip)='127.0.0.1') FROM control.connector_peer_pair_leg_claims claim WHERE claim.pair_id=pair.id)),false),
		COALESCE(jsonb_agg(jsonb_build_array(pair.id,pair.service_id,pair.service_run_id,pair.run_number,pair.owner_key,encode(pair.delivery_id,'hex'),pair.delivery_generation,encode(pair.key_ciphertext,'hex'),pair.slots) ORDER BY pair.id)::text,'')
		FROM control.connector_peer_pairs pair WHERE pair.subject_kind='workload_session' AND pair.subject_id=$1`, session, expiry).Scan(&count, &valid, &binding)
	if err != nil || count != 3 || !valid {
		t.Fatalf("workload native source/install/fixed-expiry scope: pairs=%d valid=%t: %v", count, valid, err)
	}
	return binding
}

func (p *workloadRuntimePaths) wait(t *testing.T, at time.Time) {
	t.Helper()
	timer := time.NewTimer(max(time.Nanosecond, time.Until(at)))
	defer timer.Stop()
	select {
	case err := <-p.ended:
		t.Fatal(err)
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	case <-timer.C:
	}
}

func (p *workloadRuntimePaths) step(t *testing.T, step int) {
	t.Helper()
	select {
	case err := <-p.ended:
		t.Fatal(err)
	default:
	}
	_ = p.connection.SetDeadline(time.Now().Add(5 * time.Second))
	line := fmt.Sprintf("step-%d\n", step)
	if _, err := io.WriteString(p.connection, line); err != nil {
		t.Fatal("active workload TCP", err)
	}
	got := make([]byte, len(line))
	if _, err := io.ReadFull(p.connection, got); err != nil || string(got) != line {
		t.Fatal("workload TCP step", err)
	}
	_ = p.connection.SetDeadline(time.Time{})
	response, err := p.client.Get(p.url + "/step")
	if err != nil {
		t.Fatal("workload HTTP step", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(body) != "workload HTTP" {
		t.Fatalf("workload HTTP step: %d %q %v", response.StatusCode, body, err)
	}
	var pid uint32
	var n int
	queryContext, cancelQuery := context.WithTimeout(t.Context(), 5*time.Second)
	err = p.database.QueryRow(queryContext, "SELECT pg_backend_pid(),41+1").Scan(&pid, &n)
	cancelQuery()
	if err != nil || n != 42 || pid != p.backendPID {
		t.Fatalf("native PostgreSQL original backend: pid=%d want=%d result=%d: %v", pid, p.backendPID, n, err)
	}
	// require fresh data on the original response, not a merely unclosed body.
	select {
	case <-p.streamProgress:
	default:
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	select {
	case <-p.streamDone:
		t.Fatal("active HTTP stream ended before expiry", p.streamError)
	case <-p.streamProgress:
	case <-ctx.Done():
		t.Fatal("active HTTP stream stopped producing data", ctx.Err())
	}
}

func (p *workloadRuntimePaths) denied(t *testing.T, bound time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), bound)
	defer cancel()
	deadline, _ := ctx.Deadline()
	var failures [3]error
	var checks sync.WaitGroup
	checks.Go(func() {
		if err := p.connection.SetReadDeadline(deadline); err != nil {
			failures[0] = fmt.Errorf("set original TCP closure deadline: %w", err)
			return
		}
		var one [1]byte
		_, err := p.connection.Read(one[:])
		var timeout net.Error
		if err == nil {
			failures[0] = errors.New("denied original TCP connection remained active")
		} else if errors.As(err, &timeout) && timeout.Timeout() {
			failures[0] = fmt.Errorf("TCP exceeded revocation/expiry bound: %w", err)
		}
	})
	checks.Go(func() {
		select {
		case <-p.streamDone:
		case <-ctx.Done():
			failures[1] = fmt.Errorf("HTTP stream exceeded revocation/expiry bound: %w", ctx.Err())
		}
	})
	checks.Go(func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			_, err := p.database.Exec(ctx, "SELECT 1")
			if err != nil {
				var timeout net.Error
				if ctx.Err() != nil || errors.As(err, &timeout) && timeout.Timeout() {
					failures[2] = fmt.Errorf("PostgreSQL did not observe runtime closure before its query deadline: %w", err)
				}
				return
			}
			select {
			case <-ctx.Done():
				failures[2] = fmt.Errorf("PostgreSQL exceeded revocation/expiry bound: %w", ctx.Err())
				return
			case <-ticker.C:
			}
		}
	})
	checks.Wait()
	if err := errors.Join(failures[:]...); err != nil {
		t.Fatal(err)
	}

	// new admissions have their own budget, after all original streams closed.
	requestContext, cancelRequest := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelRequest()
	request, err := http.NewRequestWithContext(requestContext, "GET", p.url+"/step", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := p.client.Do(request)
	if err != nil {
		var timeout net.Error
		if requestContext.Err() != nil || errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatal("fresh workload HTTP admission timed out instead of observing denial", err)
		}
		return
	}
	_ = response.Body.Close()
	if response.StatusCode == 200 || response.StatusCode >= 300 && response.StatusCode < 400 {
		t.Fatal("denied workload fell back to browser approval or target")
	}
}

func workloadPublicEndpointDialer(t *testing.T, connector *ingress.PublicServices, port int) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := ingress.New(listener, ingress.Config{PublicServicesOnly: true, RequireProxyHeader: true, TrustedProxyPeers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, PublicServices: connector, ServicePortRanges: []tcpport.Range{{First: port, Last: port}}, MaxConnections: 64})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Drain(ctx)
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
		if err != nil {
			return nil, err
		}
		header, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.44:4242"), Destination: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.10"), uint16(port))})
		if err == nil {
			_, err = conn.Write(header)
		}
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
}
