package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/policy/controloutage"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// real public HTTPS, not a connector: each original response must cross the
// first permission, workload lease, and provider proof. the two independent
// subjects then end at their actual hard expiry or explicit revocation.
func TestIntegrationWorkloadHTTPPublicStreamRenewal(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	gate := &outageTrafficGate{grants: make(map[string]controloutage.Confirmation), refusals: make(map[string]int)}
	var stopProxy func()
	f, issuer := newWorkloadTransportFixture(t, func(cfg *daemonconfig.Config, _ *http.Transport, ca *testCertificateAuthority) {
		cfg.RequireProxyHeader, cfg.IngressTrustedProxies = true, []string{"127.0.0.1/32"}
		stopProxy = newOutagePrivateProxy(t, cfg, ca, gate)
	})
	f.owner.cleanupResource(t, stopProxy)
	t.Cleanup(func() { gate.transition(false) })
	if f.controlConfig.ControlOutageTolerance != controloutage.DefaultTolerance {
		t.Fatal("public workload proof must retain the product's default outage allowance")
	}
	// the same public transport serves the workload and native publisher APIs.
	// block it as well as the private role APIs; no control request may succeed
	// merely because the test forgot a second address.
	publicTransport := f.publicHTTP.Transport.(*http.Transport)
	base := publicTransport.Clone()
	t.Cleanup(base.CloseIdleConnections)
	var publicBlocked atomic.Bool
	t.Cleanup(func() { publicBlocked.Store(false) })
	publicTransport.RegisterProtocol("https", splitACMERoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if publicBlocked.Load() {
			gate.mu.Lock()
			gate.refusals["public"]++
			gate.mu.Unlock()
			return nil, clientcontrol.ErrUnavailable
		}
		return base.RoundTrip(r)
	}))
	startSeparatedPrivateIngress(t, f, 0, "tls-tcp", nil)
	publicFront := serviceRuntimeListener(t, f.owner)
	startSplitIngressProxy(t, f.owner, publicFront, f.ingressAddresses[0])
	progress := map[string]chan string{"/fixed": make(chan string), "/revoked": make(chan string)}
	counts := map[string]*atomic.Int32{"/fixed": new(atomic.Int32), "/revoked": new(atomic.Int32)}
	targetDone := map[string]chan time.Time{"/fixed": make(chan time.Time, 1), "/revoked": make(chan time.Time, 1)}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		steps, streaming := progress[r.URL.Path]
		if !streaming {
			_, _ = io.WriteString(w, "ready\n")
			return
		}
		if counts[r.URL.Path].Add(1) != 1 {
			http.Error(w, "original request was replayed", http.StatusConflict)
			return
		}
		defer func() { targetDone[r.URL.Path] <- time.Now() }()
		if _, err := io.WriteString(w, "ready\n"); err != nil {
			return
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}
		for {
			select {
			case line := <-steps:
				if _, err := io.WriteString(w, line); err != nil {
					return
				}
				if err := http.NewResponseController(w).Flush(); err != nil {
					return
				}
			case <-r.Context().Done():
				return
			}
		}
	}))
	cleanupIntegrationHTTPServer(t, target, f.owner)
	const deployment = "public"
	protocol := controlv1.ServiceProtocolHTTP
	policy := controlv1.ProjectWorkload{Deployment: deployment, Provider: controlv1.WorkloadGitHub,
		Github: &controlv1.ProjectWorkloadGitHub{Repository: "example/repository", RepositoryId: "12345", RepositoryOwnerId: "6789",
			WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Events: []string{"push"}},
		Services: []string{"api"}, MaxDurationSeconds: 180}
	continuous := policy
	continuous.MaxDurationSeconds = 0
	policies := map[string]controlv1.ProjectWorkload{"fixed": policy, "revoked": continuous}
	applied, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "workload", controlv1.ApplyProjectConfigurationRequest{
		Deployment: deployment, ServiceDeclarations: controlv1.ProjectServiceDeclarations{"api": protocol}, TeamId: f.identity.teamID, Source: &testProjectSource,
		Configuration: controlv1.ProjectConfiguration{Workloads: &policies, Settings: &controlv1.DeploymentSettings{},
			Services: map[string]controlv1.ProjectServiceConfiguration{"api": {Protocol: &protocol, Target: target.URL, Public: new(true)}},
			Webhooks: map[string]controlv1.ProjectWebhook{}}})
	if err != nil {
		t.Fatal(err)
	}
	startWorkloadPublishers(t, f, deployment, "tls-tcp", func(control publisherservice.RunControl) publisherservice.RunControl {
		return outagePublisherControl{control, gate}
	})
	type original struct {
		job               *workload.Client
		first             authorityv1.WorkloadSession
		stream            *outageHTTPStream
		permission        time.Time
		certificateExpiry time.Time
		execution         string
	}
	streams := make(map[string]original)
	for i, name := range []string{"fixed", "revoked"} {
		job, err := workload.New(f.controlConfig.ControlOrigin(), f.publicHTTP)
		if err != nil {
			t.Fatal(err)
		}
		execution := strconv.Itoa(701 + i)
		claims := githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())
		claims["check_run_id"], claims["jti"], claims["exp"] = execution, name+"-initial-proof", time.Now().Add(105*time.Second).Unix()
		session, err := job.Exchange(t.Context(), f.identity.teamID, "workload", applied.SourceFingerprint, name, issuer.Sign(t, claims), nil)
		if err != nil {
			t.Fatal(err)
		}
		if (session.ExpiresAt == nil) != (name == "revoked") {
			t.Fatal("workload acquired the wrong hard-expiry policy", name)
		}
		inventory, err := job.ListServices(t.Context())
		if err != nil || len(inventory.Services) != 1 {
			t.Fatal("public workload inventory", err)
		}
		service := inventory.Services[0]
		certificate, err := job.ClientTLSCertificate(t.Context(), service.Id)
		if err != nil {
			t.Fatal(err)
		}
		verification := f.visitorRoots.Clone()
		verification.ServerName = service.Endpoint.Hostname
		verification.Certificates = []tls.Certificate{certificate}
		transport := &http.Transport{TLSClientConfig: verification, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, publicFront.Addr().String())
		}}
		t.Cleanup(transport.CloseIdleConnections)
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		address := "https://" + net.JoinHostPort(service.Endpoint.Hostname, strconv.Itoa(service.Endpoint.Port))
		// policy preparation is separate from the one original stream. do not
		// retry /fixed or /revoked, even if their admission fails.
		awaitServiceHTTPStatus(t, client, address+"/ready", "", "", http.StatusOK)
		stream := openOutageHTTPStream(t, client, address+"/"+name, "")
		if stream.response.TLS == nil || len(stream.response.TLS.VerifiedChains) == 0 {
			t.Fatal("public workload stream did not verify its visitor TLS chain")
		}
		permissionUntil := minTime(session.LeaseExpiresAt, workload.SessionDeadline(session))
		if !certificate.Leaf.NotAfter.After(permissionUntil) {
			t.Fatal("workload identity certificate still carries only the initial short permission")
		}
		streams["/"+name] = original{job: job, first: session, stream: stream, permission: permissionUntil,
			certificateExpiry: certificate.Leaf.NotAfter, execution: execution}
		t.Logf("original public workload path=/%s session=%s initial_permission=%s credential_expiry=%s provider_expiry=%s hard_expiry=%v",
			name, session.Id, permissionUntil.Format(time.RFC3339Nano), certificate.Leaf.NotAfter.Format(time.RFC3339Nano),
			session.IdentityExpiresAt.Format(time.RFC3339Nano), session.ExpiresAt)
	}
	receive := func(path, want string) {
		t.Helper()
		select {
		case line := <-streams[path].stream.lines:
			if line != want {
				t.Fatal("original public response changed bytes", path, line, want)
			}
		case end := <-streams[path].stream.done:
			current, err := streams[path].job.Session()
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("current workload authority: session=%s sequence=%d lease=%s proof=%s hard_expiry=%v original_target_requests=%d",
				current.Id, current.RenewalSequence, current.LeaseExpiresAt.Format(time.RFC3339Nano),
				current.IdentityExpiresAt.Format(time.RFC3339Nano), current.ExpiresAt, counts[path].Load())
			t.Fatalf("original public workload response stopped: path=%s at=%s initial_permission=%s error=%v",
				path, end.at.Format(time.RFC3339Nano), streams[path].permission.Format(time.RFC3339Nano), end.err)
		case <-time.After(3 * time.Second):
			t.Fatal("original public workload response made no progress", path)
		}
	}
	exchange := func(label string) {
		t.Helper()
		for path, original := range streams {
			select {
			case progress[path] <- label + "\n":
			case end := <-original.stream.done:
				current, err := original.job.Session()
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("original public consumer ended: path=%s at=%s initial_permission=%s certificate_expiry=%s current_sequence=%d current_lease=%s current_proof=%s hard_expiry=%v target_requests=%d error=%v",
					path, end.at.Format(time.RFC3339Nano), original.permission.Format(time.RFC3339Nano),
					original.certificateExpiry.Format(time.RFC3339Nano),
					current.RenewalSequence, current.LeaseExpiresAt.Format(time.RFC3339Nano),
					current.IdentityExpiresAt.Format(time.RFC3339Nano), current.ExpiresAt, counts[path].Load(), end.err)
			case <-time.After(3 * time.Second):
				t.Fatal("original public target did not accept progress", path)
			}
			receive(path, label+"\n")
			if counts[path].Load() != 1 {
				t.Fatal("workload progress reopened the original GET", path, counts[path].Load())
			}
			t.Logf("same original public response path=%s phase=%s target_requests=%d", path, label, counts[path].Load())
		}
	}
	for path := range streams {
		receive(path, "ready\n")
	}
	assertSame := func(before, after authorityv1.WorkloadSession) {
		t.Helper()
		if after.Id != before.Id || !reflect.DeepEqual(after.Subject, before.Subject) || !reflect.DeepEqual(after.Github, before.Github) ||
			!reflect.DeepEqual(after.ServiceIds, before.ServiceIds) || !reflect.DeepEqual(after.ExpiresAt, before.ExpiresAt) || after.Credential != before.Credential {
			t.Fatal("renewal or provider attachment changed the original subject, selected service, credential, or fixed expiry")
		}
	}
	for round := 1; round <= 4; round++ {
		for _, original := range streams {
			current, err := original.job.Session()
			if err != nil {
				t.Fatal(err)
			}
			waitRuntimeTime(t, current.RenewAfter)
			next, err := original.job.Renew(t.Context())
			if err != nil {
				t.Fatal("renew original public workload", err)
			}
			assertSame(original.first, next)
			if next.RenewalSequence != original.first.RenewalSequence+int64(round) || !next.LeaseExpiresAt.After(original.first.LeaseExpiresAt) {
				t.Fatal("workload did not cross multiple actual permission renewals")
			}
			if round == 2 {
				fresh := githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())
				fresh["check_run_id"], fresh["jti"] = original.execution, "refreshed-"+original.execution
				attached, err := original.job.Attach(t.Context(), issuer.Sign(t, fresh))
				if err != nil {
					t.Fatal("refresh original provider proof", err)
				}
				assertSame(original.first, attached)
				if !attached.IdentityExpiresAt.After(original.first.IdentityExpiresAt) {
					t.Fatal("provider attachment did not move the proof horizon")
				}
			}
		}
		exchange("renewal-" + strconv.Itoa(round))
		if round == 1 {
			publicBlocked.Store(true)
			outageAt, _ := gate.transition(true)
			for _, original := range streams {
				before, err := original.job.Session()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := original.job.Renew(t.Context()); !errors.Is(err, clientcontrol.ErrUnavailable) {
					t.Fatal("workload renewal bypassed the control outage", err)
				}
				after, err := original.job.Session()
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatal("failed renewal changed the accepted session", err)
				}
			}
			privateWait(t, 4*time.Second, func(context.Context) (bool, error) {
				gate.mu.Lock()
				defer gate.mu.Unlock()
				return gate.refusals["publisher"] != 0 && gate.refusals["private"] != 0 && gate.refusals["public"] != 0, nil
			})
			exchange("without-control")
			gate.transition(false)
			publicBlocked.Store(false)
			privateWait(t, 5*time.Second, func(context.Context) (bool, error) {
				gate.mu.Lock()
				defer gate.mu.Unlock()
				return gate.grants["publisher"].ObservedAt.After(outageAt) && gate.grants["policy"].ObservedAt.After(outageAt), nil
			})
			exchange("control-recovered")
		}
	}
	for _, original := range streams {
		if !time.Now().After(original.first.IdentityExpiresAt) || !time.Now().After(original.first.LeaseExpiresAt) ||
			!time.Now().After(original.permission) {
			t.Fatal("original public stream did not cross its original permission, lease, and provider proof")
		}
	}
	exchange("past-initial-authority")
	fixed, revoked := streams["/fixed"], streams["/revoked"]
	revokedAt := time.Now()
	if err := revoked.job.Revoke(t.Context()); err != nil {
		t.Fatal(err)
	}
	requireEnd := func(path string, earliest, latest time.Time) {
		t.Helper()
		timer := time.NewTimer(max(0, time.Until(latest)))
		defer timer.Stop()
		select {
		case end := <-streams[path].stream.done:
			if end.at.Before(earliest) || end.at.After(latest) {
				t.Fatal("original public stream ended outside its terminal authority bound", path, end.at, earliest, latest, end.err)
			}
			t.Logf("original public consumer closed path=%s at=%s error=%v", path, end.at.Format(time.RFC3339Nano), end.err)
		case <-timer.C:
			t.Fatal("original public stream survived its terminal authority", path)
		}
		select {
		case joinedAt := <-targetDone[path]:
			t.Logf("original public target handler joined path=%s at=%s target_requests=%d", path, joinedAt.Format(time.RFC3339Nano), counts[path].Load())
		case <-time.After(3 * time.Second):
			t.Fatal("original public target handler did not join after authority ended", path)
		}
		if counts[path].Load() != 1 {
			t.Fatal("terminal proof reopened the original public GET", path)
		}
	}
	requireEnd("/revoked", revokedAt, revokedAt.Add(30*time.Second))
	// only the fixed sibling remains; it must keep progressing until its own
	// actual deadline, not inherit revocation from another workload subject.
	select {
	case progress["/fixed"] <- "sibling-revoked\n":
	case end := <-fixed.stream.done:
		t.Fatal("sibling revocation ended the fixed original stream", end)
	case <-time.After(3 * time.Second):
		t.Fatal("fixed original target stopped after sibling revocation")
	}
	receive("/fixed", "sibling-revoked\n")
	// DER's whole-second certificate expiry can precede the absolute session
	// limit. that real earlier credential fence must still terminate this stream.
	fixedFence := minTime(fixed.certificateExpiry, *fixed.first.ExpiresAt)
	requireEnd("/fixed", fixedFence.Add(-time.Second), fixedFence.Add(time.Second))
	t.Log("the same two public HTTPS responses crossed permission renewals, provider turnover, and control outage/recovery; fixed expiry and revocation closed their original handlers without replay")
}
