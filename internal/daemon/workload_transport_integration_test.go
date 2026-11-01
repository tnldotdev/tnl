package daemon

import (
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

// real clock: the original 90-second lease and certificate are crossed twice.
// every authorization uses the actual HTTP adapters and disposable PostgreSQL.
func TestIntegrationWorkloadTransportLifecycle(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			t.Parallel()
			opened := make(chan privateObservation, 256)
			f, issuer := newWorkloadTransportFixture(t, opened)
			for slot := range 2 {
				startSeparatedPrivateIngress(t, f, slot, transport, opened)
			}
			echo := startPrivateEchoTarget(t)
			httpTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Tnl-Access-Token") != "" || r.Header.Get("Tnl-Visitor-Token") != "" {
					t.Error("target received visitor credential")
				}
				if r.URL.Path == "/stream" {
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
						case <-time.After(100 * time.Millisecond):
						}
					}
				}
				_, _ = io.WriteString(w, "workload HTTP")
			}))
			t.Cleanup(httpTarget.Close)
			pg, err := pgx.ParseConfig(f.databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			private, public := "private", "public"
			tcpProtocol, httpProtocol, pgProtocol := controlv1.Tcp, controlv1.ServiceProtocolHTTP, controlv1.Postgres
			services := map[string]controlv1.ProjectServiceConfiguration{
				"private-tcp":  {PublisherGroup: &private, Protocol: &tcpProtocol, Target: echo.address},
				"public-tcp":   {PublisherGroup: &public, Protocol: &tcpProtocol, Target: echo.address},
				"private-http": {PublisherGroup: &private, Protocol: &httpProtocol, Target: strings.TrimPrefix(httpTarget.URL, "http://")},
				"public-http":  {PublisherGroup: &public, Protocol: &httpProtocol, Target: strings.TrimPrefix(httpTarget.URL, "http://")},
				"db":           {PublisherGroup: &private, Protocol: &pgProtocol, Target: net.JoinHostPort(pg.Host, strconv.Itoa(int(pg.Port)))},
			}
			keys := []string{"private-tcp", "public-tcp", "private-http", "public-http", "db"}
			policies := map[string]controlv1.ProjectWorkload{"test": {Provider: controlv1.WorkloadGitHub, Github: &controlv1.ProjectWorkloadGitHub{Repository: "example/repository", RepositoryId: "12345", RepositoryOwnerId: "6789", WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Events: []string{"push"}}, Services: keys, MaxDurationSeconds: 205}}
			applied, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "workload", controlv1.ApplyProjectConfigurationRequest{TeamId: f.identity.teamID, SourceFingerprint: strings.Repeat("a", 64), Configuration: controlv1.ProjectConfiguration{Workloads: &policies, PublisherGroups: map[string]controlv1.ProjectPublisherGroup{private: {}, public: {Public: new(true)}}, Services: services, Webhooks: map[string]controlv1.ProjectWebhook{}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, group := range []string{private, public} {
				startWorkloadPublishers(t, f, group, transport)
			}
			job, err := workload.New(f.controlConfig.ControlOrigin(), f.publicHTTP)
			if err != nil {
				t.Fatal(err)
			}
			assertion := issuer.Sign(t, githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now()))
			session, err := job.Exchange(t.Context(), f.identity.teamID, "workload", strings.Repeat("a", 64), "test", assertion, keys)
			if err != nil {
				t.Fatal(err)
			}
			inventory, err := job.ListServices(t.Context())
			if err != nil || len(inventory.Services) != len(keys) {
				t.Fatal("workload inventory", err)
			}
			byName := map[string]string{}
			for _, service := range inventory.Services {
				byName[service.Service] = service.Id
			}
			for _, service := range applied.Services {
				if service.ServiceId == nil || byName[service.Service] != *service.ServiceId {
					t.Fatal("configuration keys did not retain exact saved service IDs")
				}
			}
			stopRenew := renewRuntimeWorkload(t, job, session.ExpiresAt)
			paths := openWorkloadPaths(t, f, job, byName, pg, transport)
			paths.step(t, 0)
			nativeBinding := workloadNativeRuntimeBinding(t, f, session.Id, session.ExpiresAt)
			unrenewed, err := workload.New(f.controlConfig.ControlOrigin(), f.publicHTTP)
			if err != nil {
				t.Fatal(err)
			}
			unrenewedClaims := githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())
			unrenewedClaims["check_run_id"], unrenewedClaims["jti"] = "444", "unrenewed-execution"
			unrenewedSession, err := unrenewed.Exchange(t.Context(), f.identity.teamID, "workload", strings.Repeat("a", 64), "test", issuer.Sign(t, unrenewedClaims), keys)
			if err != nil {
				t.Fatal(err)
			}
			unrenewedPaths := openWorkloadPaths(t, f, unrenewed, byName, pg, transport)
			unrenewedPaths.step(t, 0)
			// a second ephemeral key cannot steal the execution or reuse its cert.
			other, err := workload.New(f.controlConfig.ControlOrigin(), f.publicHTTP)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = other.Exchange(t.Context(), f.identity.teamID, "workload", strings.Repeat("a", 64), "test", assertion, keys); err == nil {
				t.Fatal("execution key takeover")
			}
			// revocation traverses the same paths while the main job keeps renewing.
			claims := githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())
			claims["check_run_id"], claims["jti"] = "333", "revoked-execution"
			if _, err = other.Exchange(t.Context(), f.identity.teamID, "workload", strings.Repeat("a", 64), "test", issuer.Sign(t, claims), keys); err != nil {
				t.Fatal(err)
			}
			revokedPaths := openWorkloadPaths(t, f, other, byName, pg, transport)
			revokedPaths.step(t, 0)
			if err = other.Revoke(t.Context()); err != nil {
				t.Fatal(err)
			}
			revokedPaths.denied(t, 31*time.Second)
			for i, at := range []time.Time{session.LeaseExpiresAt.Add(5 * time.Second), session.LeaseExpiresAt.Add(95 * time.Second)} {
				waitRuntimeTime(t, at)
				paths.step(t, int(time.Until(session.ExpiresAt).Seconds()))
				if workloadNativeRuntimeBinding(t, f, session.Id, session.ExpiresAt) != nativeBinding {
					t.Fatal("workload renewal replaced its connector owners or exact bindings")
				}
				before, _ := job.Session()
				replayed, err := job.Exchange(t.Context(), f.identity.teamID, "workload", strings.Repeat("a", 64), "test", assertion, keys)
				if err != nil || !replayed.ExpiresAt.Equal(session.ExpiresAt) || !replayed.LeaseExpiresAt.Equal(before.LeaseExpiresAt) {
					t.Fatal("replay extended fixed expiry", err)
				}
				if i == 0 {
					waitRuntimeTime(t, unrenewedSession.LeaseExpiresAt.Add(time.Second))
					unrenewedPaths.denied(t, 3*time.Second)
					if _, err = unrenewed.ClientTLSCertificate(t.Context(), byName["public-tcp"]); err == nil {
						t.Fatal("expired lease issued a new certificate")
					}
				}
			}
			var humans int
			if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.visitor_devices`).Scan(&humans); err != nil || humans != 0 {
				t.Fatal("workload enrolled a human device", err)
			}
			for len(opened) > 0 {
				o := <-opened
				if o.header.PublicService == nil || o.header.SourceIP != "127.0.0.1" {
					t.Fatal("direct transport lost destination/source binding")
				}
			}
			waitRuntimeTime(t, session.ExpiresAt.Add(time.Second))
			stopRenew()
			paths.denied(t, 3*time.Second)
			if _, err = job.Renew(t.Context()); err == nil {
				t.Fatal("hard-expired job renewed")
			}
			if _, err = job.SelectServiceRun(t.Context(), byName["private-tcp"]); err == nil {
				t.Fatal("hard-expired job received a native signing snapshot")
			}
			if _, err = job.ClientTLSCertificate(t.Context(), byName["public-tcp"]); err == nil {
				t.Fatal("hard-expired job received a certificate")
			}
		})
	}
}

func newWorkloadTransportFixture(t *testing.T, opened chan<- privateObservation) (*privateSeparatedFixture, *githubtest.Issuer) {
	t.Helper()
	issuer := githubtest.New(t)
	f := newServiceRuntimeFixtureTiming(t, false, opened, true, func(_ *daemonconfig.Config, tr *http.Transport, _ *testCertificateAuthority) {
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
	f, issuer := newWorkloadTransportFixture(t, nil)
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
	t.Cleanup(target.Close)
	group, protocol := "public", controlv1.ServiceProtocolHTTP
	policies := map[string]controlv1.ProjectWorkload{"test": {Provider: controlv1.WorkloadGitHub, Github: &controlv1.ProjectWorkloadGitHub{Repository: "example/repository", RepositoryId: "12345", RepositoryOwnerId: "6789", WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Events: []string{"push"}}, Services: []string{"api"}, MaxDurationSeconds: 60}}
	_, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "workload", controlv1.ApplyProjectConfigurationRequest{TeamId: f.identity.teamID, SourceFingerprint: strings.Repeat("a", 64), Configuration: controlv1.ProjectConfiguration{Workloads: &policies, PublisherGroups: map[string]controlv1.ProjectPublisherGroup{group: {Public: new(true)}}, Services: map[string]controlv1.ProjectServiceConfiguration{"api": {PublisherGroup: &group, Protocol: &protocol, Target: strings.TrimPrefix(target.URL, "http://")}}, Webhooks: map[string]controlv1.ProjectWebhook{}}})
	if err != nil {
		t.Fatal(err)
	}
	startWorkloadPublishers(t, f, group, "tls-tcp")
	job, err := workload.New(f.controlConfig.ControlOrigin(), f.publicHTTP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = job.Exchange(t.Context(), f.identity.teamID, "workload", strings.Repeat("a", 64), "test", issuer.Sign(t, githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())), nil); err != nil {
		t.Fatal(err)
	}
	inventory, err := job.ListServices(t.Context())
	if err != nil || len(inventory.Services) != 1 {
		t.Fatal("workload inventory", err)
	}
	s := inventory.Services[0]
	grant, err := f.identity.routes.CreateServiceHTTPGrant(t.Context(), s.Id, controlv1.CreateVisitorCredentialRequest{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: s.Id}, Kind: "token", ExpiresAt: time.Now().Add(time.Minute)})
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
	owner, err := publisheridentity.NewGroup(f.identity.routes, f.identity.routes, f.identity.authority, f.controlConfig.ControlOrigin(), member, key)
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
		ctx, cancel := context.WithCancel(t.Context())
		var control publisherservice.RunControl = native
		for _, wrap := range wrappers {
			control = wrap(control)
		}
		ready, done := make(chan struct{}), make(chan error, 1)
		go func() {
			done <- publisherservice.Publish(ctx, publisherservice.RunConfig{Control: control, State: f.identity.state, Access: native.Access, Identity: identity, ServiceID: service.Id, Target: assignment.Configuration.Target, Metadata: publisheridentity.ServiceMetadata(service), HeartbeatInterval: time.Second, Ready: func() error { close(ready); return nil }, Connect: func(ctx context.Context, bound *publisherservice.Bound, slot uint8) (publisherservice.SlotSession, error) {
				return bound.ConnectSlotWithTransports(ctx, slot, false, quic, tcp)
			}})
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

func renewRuntimeWorkload(t *testing.T, job *workload.Client, expires time.Time) func() {
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
				if ctx.Err() != nil || !time.Now().Before(expires) {
					err = nil
				}
				done <- err
				return
			}
			if !next.ExpiresAt.Equal(expires) {
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
	connections []net.Conn
	clients     []*http.Client
	urls        []string
	streams     []io.ReadCloser
	streamDone  []<-chan error
	database    *pgx.Conn
}

func openWorkloadPaths(t *testing.T, f *privateSeparatedFixture, job *workload.Client, services map[string]string, pg *pgx.ConnConfig, transport string) *workloadRuntimePaths {
	t.Helper()
	p := &workloadRuntimePaths{}
	for _, name := range []string{"private-tcp", "private-http", "public-tcp", "public-http", "db"} {
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
		var address string
		var dial func(context.Context, string, string) (net.Conn, error)
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address = listener.Addr().String()
		ctx, cancel := context.WithCancel(t.Context())
		ready, done := make(chan struct{}), make(chan error, 1)
		quic, tcp := f.connectors()
		if transport == "quic" {
			tcp = privateDisabledConnector()
		} else {
			quic = privateDisabledConnector()
		}
		go func() {
			done <- connectorstream.Serve(ctx, listener, connectorstream.Config{Control: control, ServiceID: service, Protocol: run.Protocol, TrustRevision: run.TrustRevision, Endpoint: run.Endpoint, ServiceTLS: verification, TransportTLS: f.roots, RelayQUIC: quic, RelayTCP: tcp, Ready: func() error { close(ready); return nil }})
		}()
		t.Cleanup(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("workload connector did not join")
			}
		})
		select {
		case <-ready:
		case err := <-done:
			done <- err
			t.Fatal(err)
		case <-time.After(10 * time.Second):
			t.Fatal("workload connector not ready")
		}
		dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
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
			t.Cleanup(func() { _ = p.database.Close(context.Background()) })
		} else if strings.HasSuffix(name, "tcp") {
			conn, err := dial(t.Context(), "tcp", "")
			if err != nil {
				t.Fatal(err)
			}
			p.connections = append(p.connections, conn)
			t.Cleanup(func() { _ = conn.Close() })
		} else {
			tr := &http.Transport{TLSClientConfig: verification, DialContext: dial}
			t.Cleanup(tr.CloseIdleConnections)
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			endpoint := "https://" + net.JoinHostPort(run.Endpoint.Hostname, strconv.Itoa(run.Endpoint.Port))
			p.clients, p.urls = append(p.clients, client), append(p.urls, endpoint)
			streamClient := *client
			streamClient.Timeout = 0
			response, err := streamClient.Get(endpoint + "/stream")
			if err != nil || response.StatusCode != 200 {
				t.Fatal("active workload HTTP stream", err)
			}
			p.streams = append(p.streams, response.Body)
			t.Cleanup(func() { _ = response.Body.Close() })
			done := make(chan error, 1)
			p.streamDone = append(p.streamDone, done)
			go func() { _, err := io.Copy(io.Discard, response.Body); done <- err }()
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
	if err != nil || count != 5 || !valid {
		t.Fatalf("workload native source/install/fixed-expiry scope: pairs=%d valid=%t: %v", count, valid, err)
	}
	return binding
}

func (p *workloadRuntimePaths) step(t *testing.T, step int) {
	t.Helper()
	for _, conn := range p.connections {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		line := fmt.Sprintf("step-%d\n", step)
		if _, err := io.WriteString(conn, line); err != nil {
			t.Fatal("active workload TCP", err)
		}
		got := make([]byte, len(line))
		if _, err := io.ReadFull(conn, got); err != nil || string(got) != line {
			t.Fatal("workload TCP step", err)
		}
		_ = conn.SetDeadline(time.Time{})
	}
	for i, client := range p.clients {
		response, err := client.Get(p.urls[i] + "/step")
		if err != nil {
			t.Fatal("workload HTTP step", err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != 200 || string(body) != "workload HTTP" {
			t.Fatalf("workload HTTP step: %d %q %v", response.StatusCode, body, err)
		}
	}
	var n int
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := p.database.QueryRow(ctx, "SELECT 41+1").Scan(&n); err != nil || n != 42 {
		t.Fatal("native PostgreSQL multi-step query", err)
	}
	for _, done := range p.streamDone {
		select {
		case err := <-done:
			t.Fatal("active HTTP stream ended before expiry", err)
		default:
		}
	}
}

func (p *workloadRuntimePaths) denied(t *testing.T, bound time.Duration) {
	t.Helper()
	deadline := time.Now().Add(bound)
	for _, conn := range p.connections {
		_ = conn.SetReadDeadline(deadline)
		var one [1]byte
		if _, err := conn.Read(one[:]); err == nil {
			t.Fatal("denied TCP remained active")
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("TCP exceeded revocation/expiry bound")
		}
	}
	for _, done := range p.streamDone {
		select {
		case <-done:
		case <-time.After(max(time.Nanosecond, time.Until(deadline))):
			t.Fatal("HTTP stream exceeded revocation/expiry bound")
		}
	}
	for i, client := range p.clients {
		response, err := client.Get(p.urls[i] + "/step")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == 200 || response.StatusCode >= 300 && response.StatusCode < 400 {
				t.Fatal("denied workload fell back to browser approval or target")
			}
		}
	}
	for {
		ctx, cancel := context.WithDeadline(t.Context(), minTime(deadline, time.Now().Add(3*time.Second)))
		_, err := p.database.Exec(ctx, "SELECT 1")
		cancel()
		if err != nil {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("PostgreSQL exceeded revocation/expiry bound")
		}
		time.Sleep(10 * time.Millisecond)
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
