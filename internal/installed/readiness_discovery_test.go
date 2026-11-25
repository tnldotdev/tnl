package installed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func installedDiscoveryProject(t *testing.T) *clientproject.Project {
	t.Helper()
	return &clientproject.Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{
		"web": {Target: &config.ServiceTarget{Type: "docker", Container: new("web"), Port: new(443)}},
	}}}
}

// these are the installed caller's real readiness callbacks composed with the
// existing target and service owners, not another simulated publisher loop.
func TestInstalledHTTPDiscoveryHealthKeepsRunAndOpenResponse(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	worker, stop := context.WithCancelCause(ctx)
	defer stop(context.Canceled)
	root, certificate := testutil.TLSCertificate(t, []string{"target.internal"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	entered, oldJoined, releaseOld := make(chan struct{}), make(chan struct{}), make(chan struct{})
	finishOld := sync.OnceFunc(func() { close(releaseOld) })
	defer finishOld()
	var oldRequests, laterRequests, laterHealth atomic.Int32
	type healthGate struct {
		entered chan struct{}
		release chan struct{}
		once    sync.Once
	}
	var gate atomic.Pointer[healthGate]
	var healthReleases []func()
	newGate := func() (*healthGate, func()) {
		value := &healthGate{entered: make(chan struct{}), release: make(chan struct{})}
		release := sync.OnceFunc(func() { close(value.release) })
		healthReleases = append(healthReleases, release)
		return value, release
	}
	startTarget := func(old bool) *httptest.Server {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || r.TLS.ServerName != "target.internal" {
				t.Error("installed target request lost its approved TLS identity")
			}
			if r.URL.Path == "/health" {
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("local health borrowed a visitor or owner credential")
				}
				if !old {
					laterHealth.Add(1)
					if held := gate.Load(); held != nil {
						held.once.Do(func() { close(held.entered) })
						select {
						case <-held.release:
						case <-r.Context().Done():
							return
						}
					}
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if !old {
				laterRequests.Add(1)
				_, _ = io.WriteString(w, "replacement")
				return
			}
			oldRequests.Add(1)
			defer close(oldJoined)
			_, _ = io.WriteString(w, "first")
			_ = http.NewResponseController(w).Flush()
			close(entered)
			select {
			case <-releaseOld:
				_, _ = io.WriteString(w, "last")
			case <-r.Context().Done():
				t.Error("discovered HTTP replacement canceled an admitted old response")
			}
		}))
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
		server.StartTLS()
		t.Cleanup(server.Close)
		return server
	}
	first, later := startTarget(true), startTarget(false)
	var closed atomic.Int32
	readyRun := make(chan testutil.PublishingRun, 1)
	fixture := publishingtest.New(t, testutil.PublishingHooks{
		Ready: func(_ context.Context, run testutil.PublishingRun) error { readyRun <- run; return nil },
		Close: func(testutil.PublishingRun) error { closed.Add(1); return nil },
	})
	saved, err := fixture.SavedService(ctx, "web", controlv1.ProjectServiceConfiguration{
		Target: first.URL, Public: new(true),
		TargetTls: &controlv1.ProjectTargetTLS{Hostname: "target.internal", CaPem: new(string(root))},
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := testRegistry(t)
	profile, err := registry.Profile(ctx, fixture.URL)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := fixture.Owner()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(fixture.URL, fixture.HTTP, credentials.AccessToken(fixture.OwnerToken))
	if err != nil {
		t.Fatal(err)
	}
	native, identity, err := publisheridentity.EnsureServiceOwner(ctx, profile, owner, authority, saved)
	if err != nil {
		t.Fatal(err)
	}
	key, found, err := profile.PublisherIdentity(ctx, identity.ClientId)
	if err != nil || !found {
		t.Fatal("installed fixture lost its actual enrolled signing key", err)
	}
	trust, err := publisheridentity.ServiceTrust(saved)
	if err != nil {
		t.Fatal(err)
	}
	project := installedDiscoveryProject(t)
	definition := project.Config.Services["web"]
	definition.Target.TLS = &config.TargetTLS{Hostname: new("target.internal"), CA: new(string(root))}
	project.Config.Services["web"] = definition
	job := Job{Kind: KindService, Name: "web", Server: fixture.URL,
		PublisherIdentityID: identity.ClientId, GrantID: identity.GrantId, ServiceID: saved.Id,
		Target: first.URL, Protocol: config.ProtocolHTTP, Trust: trust, TrustRevision: saved.TrustRevision,
		PublisherPool: saved.PublisherPool, ReadinessPath: "/health", Project: project, ProjectService: "web"}
	job, err = registry.Install(ctx, job, identity, ed25519.PrivateKey(key.SigningKey))
	if err != nil {
		t.Fatal(err)
	}
	job, err = registry.ResolveJob(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	jobEvents := make(chan Status, 32)
	engine := Engine{Registry: registry, Observe: func(_ Job, status Status) error {
		jobEvents <- status
		return nil
	}}
	readiness := newPublicationReadiness(worker, stop, job, saved, 1, func(ctx context.Context, status Status) error {
		return engine.status(ctx, job, status)
	})
	var selected atomic.Pointer[targetplan.TargetSnapshot]
	selected.Store(&targetplan.TargetSnapshot{Address: first.Listener.Addr().String(), Identity: "container-a"})
	readiness.resolver = targetplan.TargetResolverFunc(func(ctx context.Context, _ clientproject.Project, name string) (string, string, error) {
		if name != "web" {
			return "", "", errors.New("discovery selected another installed service")
		}
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
		current := selected.Load()
		if current == nil {
			return "", "", errors.New("container disappeared")
		}
		return current.Address, current.Identity, nil
	})
	// public readiness still traverses real visitor TLS, authorization and the
	// exact run's proof. only DNS dialing is supplied by the existing fixture.
	readiness.probe = func(ctx context.Context, run httpaccess.ReadinessRun, path string, proof *httpaccess.ReadinessProof) error {
		return verifyServiceReadiness(ctx, run, path, proof, readinessTransport(func(request *http.Request) (*http.Response, error) {
			status, headers, body, err := fixture.VisitWithHeaders(request.Context(), request.URL.String(), request.Header)
			if err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(bytes.NewReader(body)), Request: request}, nil
		}))
	}
	var observations atomic.Pointer[publisherservice.RunStatus]
	changed := make(chan struct{}, 1)
	var preparations atomic.Int32
	cfg := publisherservice.RunConfig{
		Control: native, State: profile, Access: native.Access,
		PublisherIdentityID: identity.ClientId, PublisherGrantID: identity.GrantId, PublisherKeyID: identity.KeyId,
		ServiceID: saved.Id, Target: job.Target, Metadata: publisheridentity.ServiceMetadata(saved),
		HeartbeatInterval: 25 * time.Millisecond, DrainTime: 200 * time.Millisecond,
		Connectivity: peer.ConnectivityOptions{DisableDirect: true},
		Prepared: func(prepared controlv1.ServiceRunPreparation) error {
			preparations.Add(1)
			return readiness.Prepared(prepared)
		},
		ObserveReadiness: func(status publisherservice.RunStatus) {
			readiness.Observe(status)
			observations.Store(&status)
			select {
			case changed <- struct{}{}:
			default:
			}
		},
		Healthy: readiness.Healthy, ReadinessProof: readiness.Proof,
	}
	done := make(chan struct{})
	var publishErr error
	go func() {
		defer close(done)
		publishErr = targetplan.PublishPrivate(worker, job.TargetPlan(), cfg,
			targetplan.TargetHooks{Resolver: readiness.resolver, Capture: readiness.Capture})
	}()
	defer func() {
		finishOld()
		for _, release := range healthReleases {
			release()
		}
		stop(context.Canceled)
		<-done
		if publishErr != nil && !failure.Only(publishErr, context.Canceled) {
			t.Error("installed publication did not join", publishErr)
		}
		if _, err := readiness.Close(); err != nil {
			t.Error("installed readiness did not join", err)
		}
	}()
	awaitHealth := func(after time.Time, healthy bool) {
		t.Helper()
		for {
			readiness.mu.Lock()
			run := readiness.current
			readiness.mu.Unlock()
			current := observations.Load()
			if run != nil && time.Unix(0, run.checked.Load()).After(after) && current != nil &&
				current.TargetHealthy == healthy && current.Ready == healthy {
				return
			}
			select {
			case <-changed:
			case <-done:
				t.Fatal("discovery ended the installed publication", publishErr)
			case <-ctx.Done():
				t.Fatal("installed health did not follow discovery", healthy, context.Cause(ctx))
			}
		}
	}
	awaitJob := func(state JobState) {
		t.Helper()
		for {
			status := receiveInstalledDiscovery(t, ctx, jobEvents)
			if status.State != state || status.RunNumber != 1 {
				continue
			}
			current, err := registry.ResolveJob(ctx, job.ID)
			if err != nil || current.Status != status {
				t.Fatal("installed observation preceded status persistence", state, err)
			}
			return
		}
	}
	awaitHealth(time.Time{}, true)
	awaitJob(JobReady)
	run := receiveInstalledDiscovery(t, ctx, readyRun)
	if run.Preparation.PublisherIdentityId != identity.ClientId || run.Preparation.PublisherGrantId != identity.GrantId ||
		run.Preparation.PublisherKeyId != identity.KeyId || run.Service.Id != job.ServiceID {
		t.Fatal("installed publication replaced its enrolled service authority")
	}
	permission, err := fixture.OwnerVisitorToken(ctx, saved.Id)
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{httpaccess.VisitorTokenHeader: {permission.VisitorToken}}
	type response struct {
		status int
		body   []byte
		err    error
	}
	oldResponse := make(chan response, 1)
	go func() {
		status, _, body, err := fixture.VisitWithHeaders(ctx, "https://"+saved.Endpoint.Hostname+"/hold", headers)
		oldResponse <- response{status, body, err}
	}()
	receiveInstalledDiscovery(t, ctx, entered)
	_ = first.Listener.Close()
	replacedAt := time.Now()
	selected.Store(&targetplan.TargetSnapshot{Address: later.Listener.Addr().String(), Identity: "container-b"})
	awaitHealth(replacedAt, true)
	if laterHealth.Load() == 0 {
		t.Fatal("replacement health was reported without probing the new target")
	}
	status, _, body, err := fixture.VisitWithHeaders(ctx, "https://"+saved.Endpoint.Hostname+"/replacement", headers)
	if err != nil || status != http.StatusOK || string(body) != "replacement" {
		t.Fatal("installed publication did not reach its new target", status, string(body), err)
	}
	select {
	case <-oldJoined:
		t.Fatal("replacement interrupted the admitted old response")
	default:
	}
	finishOld()
	result := receiveInstalledDiscovery(t, ctx, oldResponse)
	if result.err != nil || result.status != http.StatusOK || string(result.body) != "firstlast" {
		t.Fatal("old response lost its captured target", result.status, string(result.body), result.err)
	}
	receiveInstalledDiscovery(t, ctx, oldJoined)
	missingAt := time.Now()
	selected.Store(nil)
	awaitHealth(missingAt, false)
	awaitJob(JobTargetUnavailable)
	recoveredAt := time.Now()
	selected.Store(&targetplan.TargetSnapshot{Address: later.Listener.Addr().String(), Identity: "container-b"})
	awaitHealth(recoveredAt, true)
	awaitJob(JobReady)

	// the address is unchanged while an old identity's successful health request
	// is outstanding. its successor cannot inherit that response's readiness.
	stale, releaseStale := newGate()
	gate.Store(stale)
	receiveInstalledDiscovery(t, ctx, stale.entered)
	current, releaseCurrent := newGate()
	gate.Store(current)
	staleAt := time.Now()
	selected.Store(&targetplan.TargetSnapshot{Address: later.Listener.Addr().String(), Identity: "container-c"})
	releaseStale()
	receiveInstalledDiscovery(t, ctx, current.entered)
	if readiness.Healthy(ctx) {
		t.Fatal("same-address replacement inherited the old identity's successful probe")
	}
	awaitHealth(staleAt, false)
	awaitJob(JobTargetUnavailable)
	// heartbeat callbacks continue while the new target's probe is held.
	callbacks := make(chan struct{})
	go func() {
		for range 1000 {
			readiness.Healthy(ctx)
		}
		close(callbacks)
	}()
	receiveInstalledDiscovery(t, ctx, callbacks)
	freshAt := time.Now()
	gate.Store(nil)
	releaseCurrent()
	awaitHealth(freshAt, true)
	awaitJob(JobReady)
	if preparations.Load() != 1 || fixture.Runs.Load() != 1 || fixture.Enrollments.Load() != 1 ||
		closed.Load() != 0 || oldRequests.Load() != 1 || laterRequests.Load() != 1 {
		t.Fatal("target discovery restarted publication, changed grants, or replayed application work",
			preparations.Load(), fixture.Runs.Load(), fixture.Enrollments.Load(), closed.Load(), oldRequests.Load(), laterRequests.Load())
	}
	currentJob, err := registry.ResolveJob(ctx, job.ID)
	if err != nil || currentJob.ServiceID != job.ServiceID || currentJob.GrantID != job.GrantID ||
		currentJob.PublisherIdentityID != job.PublisherIdentityID || currentJob.Revision != job.Revision {
		t.Fatal("discovery changed installed identity or desired state", err)
	}
	stop(context.Canceled)
	receiveInstalledDiscovery(t, ctx, done)
	if publishErr != nil || closed.Load() != 1 {
		t.Fatal("the one installed service run did not join exactly once", publishErr, closed.Load())
	}
}

func receiveInstalledDiscovery[T any](t *testing.T, ctx context.Context, events <-chan T) T {
	t.Helper()
	select {
	case value := <-events:
		return value
	case <-ctx.Done():
		t.Fatal("installed discovery did not reach its observable boundary", context.Cause(ctx))
		var zero T
		return zero
	}
}

func TestInstalledHTTPDiscoveryHealthKeepsCapturedTargetTLS(t *testing.T) {
	root, certificate := testutil.TLSCertificate(t, []string{"target.internal"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	_, untrusted := testutil.TLSCertificate(t, []string{"target.internal"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	var trustedRequests, untrustedRequests atomic.Int32
	start := func(certificate tls.Certificate, requests *atomic.Int32) *httptest.Server {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			if r.URL.Path != "/health" || r.TLS.ServerName != "target.internal" || r.Header.Get("Authorization") != "" {
				t.Error("discovery changed the configured readiness path, target TLS name, or credentials")
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
		server.StartTLS()
		t.Cleanup(server.Close)
		return server
	}
	good, bad := start(certificate, &trustedRequests), start(untrusted, &untrustedRequests)
	job, _, _ := fixture(t, "web")
	job.Project, job.ProjectService, job.ReadinessPath = installedDiscoveryProject(t), "web", "/health"
	job.Trust = capturedTrust(t, "target.internal", root)
	definition := job.Project.Config.Services["web"]
	definition.Target.TLS = &config.TargetTLS{Hostname: new("target.internal"), CA: new(string(root))}
	job.Project.Config.Services["web"] = definition
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(context.Canceled)
	readiness := newPublicationReadiness(ctx, cancel, job, controlv1.Service{}, 1, nil)
	address := bad.Listener.Addr().String()
	readiness.resolver = targetplan.TargetResolverFunc(func(context.Context, clientproject.Project, string) (string, string, error) {
		return address, "captured-container", nil
	})
	if readiness.checkLocalTarget(ctx, job.Target) || untrustedRequests.Load() != 0 {
		t.Fatal("discovered target replaced the installed job's approved TLS roots")
	}
	address = good.Listener.Addr().String()
	if !readiness.checkLocalTarget(ctx, job.Target) || trustedRequests.Load() != 1 {
		t.Fatal("discovered target did not use its captured trust and configured health path")
	}
}

func TestInstalledHTTPDiscoveryHealthSharesOriginalProbeDeadline(t *testing.T) {
	for _, stage := range []string{"discovery", "request", "identity fence"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				job, _, _ := fixture(t, "web")
				job.Project, job.ProjectService = installedDiscoveryProject(t), "web"
				ctx, cancel := context.WithCancelCause(t.Context())
				defer cancel(context.Canceled)
				readiness := newPublicationReadiness(ctx, cancel, job, controlv1.Service{}, 1, nil)
				calls := 0
				start := time.Now()
				readiness.resolver = targetplan.TargetResolverFunc(func(ctx context.Context, _ clientproject.Project, _ string) (string, string, error) {
					calls++
					deadline, ok := ctx.Deadline()
					if !ok || !deadline.Equal(start.Add(5*time.Second)) {
						t.Error("discovery or identity fence received a renewed probe deadline")
					}
					if stage == "discovery" || stage == "identity fence" && calls == 2 {
						<-ctx.Done()
						return "", "", context.Cause(ctx)
					}
					return "127.0.0.1:443", "container-a", nil
				})
				readiness.localProbe = func(ctx context.Context, address string) bool {
					deadline, ok := ctx.Deadline()
					if !ok || !deadline.Equal(start.Add(5*time.Second)) || !strings.HasPrefix(address, "http://") {
						t.Error("local target probe lost its captured address or original deadline")
					}
					if stage == "request" {
						<-ctx.Done()
					} else {
						time.Sleep(3 * time.Second)
					}
					return true
				}
				if readiness.checkLocalTarget(ctx, job.Target) || time.Since(start) != 5*time.Second {
					t.Fatal("discovery extended or bypassed the health deadline", stage, time.Since(start))
				}
			})
		})
	}
}

func TestInstalledHTTPDiscoveryHealthJoinsCanceledResolution(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		job, _, _ := fixture(t, "web")
		job.Project, job.ProjectService = installedDiscoveryProject(t), "web"
		ctx, cancel := context.WithCancelCause(t.Context())
		defer cancel(context.Canceled)
		cleanupProblem := errors.New("readiness observation cleanup failed")
		readiness := newPublicationReadiness(ctx, cancel, job, controlv1.Service{Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.example"}}, 1,
			func(_ context.Context, status Status) error {
				if status.State == JobDraining {
					return cleanupProblem
				}
				return nil
			})
		started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		defer unblock()
		readiness.resolver = targetplan.TargetResolverFunc(func(ctx context.Context, _ clientproject.Project, _ string) (string, string, error) {
			close(started)
			<-ctx.Done()
			close(canceled)
			<-release
			return "", "", context.Cause(ctx)
		})
		if err := readiness.Prepared(controlv1.ServiceRunPreparation{ServiceId: job.ServiceID, ServiceRunId: "run-one", RunNumber: 1, Hostname: "web.example"}); err != nil {
			t.Fatal(err)
		}
		<-started
		joined := make(chan error, 1)
		go func() { _, err := readiness.Close(); joined <- err }()
		<-canceled
		synctest.Wait()
		select {
		case err := <-joined:
			t.Fatal("installed readiness returned before discovery cleanup joined", err)
		default:
		}
		unblock()
		if err := <-joined; !errors.Is(err, cleanupProblem) {
			t.Fatal("canceled discovery hid the independent observation cleanup failure", err)
		}
	})
}
