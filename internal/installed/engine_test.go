package installed

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/filelock"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	processidentity "github.com/tnldotdev/tnl/internal/publisher/processidentity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type jobAuthority struct {
	identity authorityv1.PublisherEnrollmentResult
	public   ed25519.PublicKey
}

func (*jobAuthority) RedeemPublisherEnrollment(context.Context, string, ed25519.PublicKey) (authorityv1.PublisherEnrollmentResult, error) {
	return authorityv1.PublisherEnrollmentResult{}, errors.New("unexpected enrollment")
}
func (a *jobAuthority) ExchangePublisherAssertion(_ context.Context, client, grant, key string, private ed25519.PrivateKey) (string, error) {
	if client != a.identity.ClientId || grant != a.identity.GrantId || key != a.identity.KeyId || !private.Public().(ed25519.PublicKey).Equal(a.public) {
		return "", publisheridentity.ErrScope
	}
	return "test-access-never-log", nil
}

type jobControl struct {
	publisheridentity.ServiceControl
	service         controlv1.Service
	public          ed25519.PublicKey
	runs            chan string
	runError        error
	renewError      error
	onPrepare       func()
	runtimeMu       sync.Mutex
	runtimeRequests []controlv1.PublisherRuntimeRequest
	preparationMu   sync.Mutex
	preparation     controlv1.ServiceRunPreparation
	prepareKeys     []string
	closedRuns      []string
	closed          bool
	serviceStarts   int
}

func (*jobControl) ControlURL() string { return "https://control.example" }

func jobClients(control *jobControl) PublisherClients {
	return PublisherClients{NativeControl: publisheridentity.NativeControl{Services: control, Runtime: control}}
}

func (c *jobControl) PublisherRuntime(_ context.Context, r controlv1.PublisherRuntimeRequest) (controlv1.PublisherRuntimeResponse, error) {
	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()
	c.runtimeRequests = append(c.runtimeRequests, r)
	if r.Action == controlv1.RuntimeRenew && c.renewError != nil {
		return controlv1.PublisherRuntimeResponse{}, c.renewError
	}
	kid, err := publisherproof.KeyID(r.Assertion)
	if err != nil {
		return controlv1.PublisherRuntimeResponse{}, err
	}
	if _, err = publisherproof.Verify(r.Assertion, r.PublisherIdentityId, kid, publisherproof.RuntimeScope(r.ScopeId, string(r.Action), r.ProcessRunId, r.ExpectedEpoch, ""), "https://control.example/v1/publisher/runtimes/"+r.PublisherIdentityId+"/"+string(r.Action), c.public, time.Now()); err != nil {
		return controlv1.PublisherRuntimeResponse{}, err
	}
	epoch := r.ExpectedEpoch
	if r.Action == controlv1.RuntimeStart {
		epoch++
	}
	return controlv1.PublisherRuntimeResponse{Epoch: epoch, LeaseExpiresAt: new(time.Now().Add(2 * time.Minute))}, nil
}

func (c *jobControl) GetPublisherService(_ context.Context, _, access string) (controlv1.Service, error) {
	if access != "test-access-never-log" {
		return controlv1.Service{}, publisheridentity.ErrScope
	}
	return c.service, nil
}

func (c *jobControl) PrepareServiceRun(ctx context.Context, service, key, access string, declaration controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error) {
	if service != c.service.Id || access != "test-access-never-log" || declaration.Protocol != c.service.Protocol || declaration.TrustRevision != c.service.TrustRevision {
		return controlv1.ServiceRunPreparation{}, publisheridentity.ErrScope
	}
	c.preparationMu.Lock()
	c.prepareKeys = append(c.prepareKeys, key)
	if c.runError != nil {
		c.preparationMu.Unlock()
		select {
		case c.runs <- key:
		default:
		}
		if c.onPrepare != nil {
			c.onPrepare()
		}
		return controlv1.ServiceRunPreparation{}, c.runError
	}
	if c.preparation.IdempotencyKey == key {
		prepared, closed := c.preparation, c.closed
		c.preparationMu.Unlock()
		if closed {
			return controlv1.ServiceRunPreparation{}, clientcontrol.ErrStatusConflict
		}
		return prepared, nil
	}
	if c.preparation.ServiceRunId != "" && !c.closed {
		c.preparationMu.Unlock()
		return controlv1.ServiceRunPreparation{}, clientcontrol.ErrStatusConflict
	}
	run, err := opaqueid.New(opaqueid.ServiceRunPrefix)
	if err != nil {
		c.preparationMu.Unlock()
		return controlv1.ServiceRunPreparation{}, err
	}
	token, _, err := credentials.NewServiceRunToken()
	if err != nil {
		c.preparationMu.Unlock()
		return controlv1.ServiceRunPreparation{}, err
	}
	c.preparation.ServiceRunId, c.preparation.IdempotencyKey = run, key
	c.preparation.RunToken, c.preparation.ExpiresAt = token.String(), time.Now().Add(2*time.Minute)
	c.preparation.RunNumber++
	c.closed = false
	c.preparationMu.Unlock()
	// commit before notifying the caller. the original response is lost on
	// cancellation; detached recovery returns this exact preparation and token.
	select {
	case c.runs <- key:
	default:
	}
	if c.onPrepare != nil {
		c.onPrepare()
	}
	<-ctx.Done()
	return controlv1.ServiceRunPreparation{}, context.Cause(ctx)
}

func (c *jobControl) StartServiceRun(context.Context, string, string, string, int64) (controlv1.ServiceRunSetup, error) {
	c.preparationMu.Lock()
	defer c.preparationMu.Unlock()
	c.serviceStarts++
	return controlv1.ServiceRunSetup{}, errors.New("unexpected service run Start during preparation cleanup")
}

func (c *jobControl) CloseServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken) error {
	c.preparationMu.Lock()
	defer c.preparationMu.Unlock()
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	if service != c.preparation.ServiceId || run != c.preparation.ServiceRunId || token.String() != c.preparation.RunToken {
		return publisheridentity.ErrScope
	}
	c.closedRuns = append(c.closedRuns, run)
	c.closed = true
	return nil
}

func jobBoundary(job Job, identity authorityv1.PublisherEnrollmentResult, key ed25519.PrivateKey) (*jobControl, *jobAuthority) {
	hostname := job.ID + ".example"
	return &jobControl{service: controlv1.Service{Id: job.ServiceID, TeamId: identity.TeamId, Name: job.ID, Protocol: controlv1.ServiceProtocol(job.Protocol),
		Enabled: true, TrustRevision: job.TrustRevision, EndpointRevision: 1, PublisherPool: job.PublisherPool,
		TargetTls: publisheridentity.ServiceTargetTLS(job.Trust), Endpoint: &controlv1.ServiceEndpoint{Hostname: hostname, Port: 443}},
		preparation: controlv1.ServiceRunPreparation{ServiceId: job.ServiceID, TeamId: identity.TeamId,
			PublisherIdentityId: identity.ClientId, PublisherGrantId: identity.GrantId, PublisherKeyId: identity.KeyId,
			Hostname: hostname, DomainId: opaqueid.DomainPrefix + "1234567890123456789012",
			CertificatePlan: &controlv1.CertificatePlan{CacheKey: "installed-job-test", Scope: hostname, Identifiers: []string{hostname}, ChallengeMethod: controlv1.Dns01},
			Traffic:         controlv1.TrafficLimits{Connections: 64, Rate: 64, RatePerNs: int64(time.Second), Burst: 64, UploadBytes: 1 << 20, DownloadBytes: 1 << 20}},
		public: key.Public().(ed25519.PublicKey), runs: make(chan string, 32)}, &jobAuthority{identity: identity, public: key.Public().(ed25519.PublicKey)}
}

func startEngine(t *testing.T, engine Engine) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- engine.Serve(ctx) }()
	t.Cleanup(cancel)
	return cancel, done
}

func joinEngine(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("service did not join its workers")
	}
}

func await(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for !ready() {
		select {
		case <-deadline.C:
			t.Fatal("job did not reach expected boundary")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestInstalledTelemetryOptOutSurvivesSupervisorRestart(t *testing.T) {
	for _, disabled := range []bool{true, false} {
		t.Run(fmt.Sprint(disabled), func(t *testing.T) {
			registry := userRegistry(t)
			job, _, _ := kindFixture(t, KindConnector)
			job.TelemetryDisabled = disabled
			if err := registry.InstallConnector(t.Context(), job); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				observed := make(chan bool, 1)
				engine := Engine{Telemetry: &clienttelemetry.Collector{}, Registry: registry, PollInterval: 5 * time.Millisecond,
					Connect: func(ctx context.Context, _ Job, telemetry *clienttelemetry.Collector, _ func() error, _ func() time.Time, _ context.Context) error {
						observed <- telemetry == nil
						<-ctx.Done()
						return nil
					}}
				cancel, done := startEngine(t, engine)
				select {
				case value := <-observed:
					if value != disabled {
						t.Fatal("installed job lost choice")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("job did not start")
				}
				joinEngine(t, cancel, done)
			}
		})
	}
}

type testUserRunner func(context.Context) error

func (f testUserRunner) Serve(ctx context.Context, _ func() time.Time, _ context.Context) error {
	return f(ctx)
}

func TestUserJobRunnerSharesSupervisorLifetime(t *testing.T) {
	r := testRegistry(t)
	started, joined := make(chan struct{}), make(chan struct{})
	engine := Engine{Registry: r, PollInterval: 5 * time.Millisecond, UserJobs: []UserJobRunner{testUserRunner(func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		close(joined)
		return nil
	})}}
	cancel, done := startEngine(t, engine)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("user job runner did not start")
	}
	joinEngine(t, cancel, done)
	select {
	case <-joined:
	default:
		t.Fatal("user job runner was not joined")
	}
}

func TestInstalledServiceRequiresExplicitServiceControl(t *testing.T) {
	registry := testRegistry(t)
	job, identity, private := fixture(t, "web")
	control, authority := jobBoundary(job, identity, private)
	if err := registry.Install(t.Context(), job, identity, private); err != nil {
		t.Fatal(err)
	}
	engine := Engine{Registry: registry, Clients: func(Job) (PublisherClients, publisheridentity.EnrollmentAuthority, error) {
		clients := jobClients(control)
		clients.Services = nil
		return clients, authority, nil
	}}
	var runtime *processidentity.Owner
	if _, err := engine.attempt(t.Context(), job, 1, &runtime); !errors.Is(err, publisheridentity.ErrScope) || runtime != nil {
		t.Fatal("missing service capability started a publisher runtime", err)
	}
}

func TestInstalledRunConflictRetriesOnlyWhileRuntimeIsCurrent(t *testing.T) {
	for _, fenced := range []bool{false, true} {
		t.Run(fmt.Sprint(fenced), func(t *testing.T) {
			registry := testRegistry(t)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
			defer target.Close()
			job, identity, key := fixture(t, "web")
			job.Target = target.URL
			control, authority := jobBoundary(job, identity, key)
			control.runError = clientcontrol.ErrStatusConflict
			if fenced {
				control.onPrepare = func() {
					control.runtimeMu.Lock()
					control.renewError = clientcontrol.ErrStatusConflict
					control.runtimeMu.Unlock()
				}
			}
			if err := registry.Install(t.Context(), job, identity, key); err != nil {
				t.Fatal(err)
			}
			engine := Engine{Registry: registry, PollInterval: 5 * time.Millisecond, RetryMin: 5 * time.Millisecond, RetryMax: 10 * time.Millisecond,
				Clients: func(Job) (PublisherClients, publisheridentity.EnrollmentAuthority, error) {
					return jobClients(control), authority, nil
				}}
			cancel, done := startEngine(t, engine)
			await(t, func() bool {
				jobs, _ := registry.List(t.Context())
				return len(jobs) == 1 && (fenced && jobs[0].Status.State == JobBlocked || !fenced && jobs[0].Status.Attempts >= 2 && jobs[0].Status.State == JobRetrying)
			})
			joinEngine(t, cancel, done)
			if fenced && len(control.runs) != 1 || !fenced && len(control.runs) < 2 {
				t.Fatal("conflict retried across the runtime fence")
			}
			inspects, starts := 0, 0
			for _, request := range control.runtimeRequests {
				if request.Action == controlv1.RuntimeInspect {
					inspects++
				}
				if request.Action == controlv1.RuntimeStart {
					starts++
				}
			}
			if inspects != 1 || starts != 1 {
				t.Fatal("retry reclaimed another runtime epoch")
			}
		})
	}
}

func TestRealNativeRunSignsWithTheSameKeyAfterBoot(t *testing.T) {
	options := testOptions(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer target.Close()
	job, identity, private := fixture(t, "web")
	job.Target = target.URL
	control, authority := jobBoundary(job, identity, private)
	previousRun := ""
	previousServiceRun := ""
	for boot := range 2 {
		control.runtimeRequests, control.runs = nil, make(chan string, 32)
		control.prepareKeys, control.closedRuns = nil, nil
		r, err := Open(t.Context(), options)
		if err != nil {
			t.Fatal(err)
		}
		if boot == 0 {
			if err := r.Install(t.Context(), job, identity, private); err != nil {
				t.Fatal(err)
			}
		}
		engine := Engine{Registry: r, PollInterval: 5 * time.Millisecond, RetryMin: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond,
			Clients: func(Job) (PublisherClients, publisheridentity.EnrollmentAuthority, error) {
				return jobClients(control), authority, nil
			}}
		cancel, done := startEngine(t, engine)
		var preparationKey string
		select {
		case preparationKey = <-control.runs:
		case <-time.After(5 * time.Second):
			t.Fatal("native publisher did not prepare its run")
		}
		joinEngine(t, cancel, done)
		if len(control.prepareKeys) != 2 || control.prepareKeys[0] != preparationKey || control.prepareKeys[1] != preparationKey ||
			len(control.closedRuns) != 1 || control.closedRuns[0] != control.preparation.ServiceRunId || !control.closed || control.serviceStarts != 0 {
			t.Fatal("boot cancellation did not recover and close only its exact original preparation")
		}
		if control.preparation.ServiceRunId == previousServiceRun || control.preparation.RunToken == "" ||
			control.preparation.PublisherIdentityId != identity.ClientId || control.preparation.PublisherGrantId != identity.GrantId ||
			control.preparation.PublisherKeyId != identity.KeyId || control.preparation.RunNumber != int64(boot+1) {
			t.Fatal("boot preparation changed its captured identity or reused a previous run")
		}
		previousServiceRun = control.preparation.ServiceRunId
		requests := control.runtimeRequests
		if len(requests) < 3 || requests[0].Action != controlv1.RuntimeInspect || requests[1].Action != controlv1.RuntimeStart || requests[len(requests)-1].Action != controlv1.RuntimeStop {
			t.Fatal("installed engine missed runtime start/stop")
		}
		run := requests[1].ProcessRunId
		if run == previousRun {
			t.Fatal("installed reboot reused runtime identity")
		}
		previousRun = run
		for _, request := range requests {
			if request.ProcessRunId != run || request.PublisherIdentityId != identity.ClientId || request.ScopeId != identity.GrantId {
				t.Fatal("installed retry changed runtime ownership")
			}
		}
		profile, _ := r.Profile(t.Context(), job.Server)
		if _, found, err := profile.ControlSession(t.Context()); err != nil || found {
			t.Fatal("boot acquired an operator session", err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIndependentTargetsAndServersUseBoundedRetries(t *testing.T) {
	r := testRegistry(t)
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer target.Close()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	missing := "http://" + closed.Addr().String()
	_ = closed.Close()
	type boundary struct {
		c *jobControl
		a *jobAuthority
	}
	boundaries := map[string]boundary{}
	for _, name := range []string{"healthy", "target-down", "server-down"} {
		job, identity, private := fixture(t, name)
		job.Target = target.URL
		if name == "target-down" {
			job.Target = missing
		}
		if name == "server-down" {
			job.Server = "https://unavailable.example"
		}
		if err := r.Install(t.Context(), job, identity, private); err != nil {
			t.Fatal(err)
		}
		c, a := jobBoundary(job, identity, private)
		c.runError = errors.New("publisher retry must not leak access=secret")
		boundaries[name] = boundary{c, a}
	}
	var mu sync.Mutex
	var retries []time.Time
	parked := make(map[string]bool)
	retryReady := map[string]uint64{"healthy": 2, "target-down": 3, "server-down": 4}
	releaseRetry := make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseRetry) })
	defer release()
	engine := Engine{Registry: r, PollInterval: 5 * time.Millisecond, RetryMin: 15 * time.Millisecond, RetryMax: 30 * time.Millisecond,
		Observe: func(job Job, status Status) error {
			if status.State == JobRetrying && status.Attempts >= retryReady[job.ID] {
				// stop after the retryable failure has been recorded, not while
				// the attempt may still return an independent failure.
				mu.Lock()
				parked[job.ID] = true
				mu.Unlock()
				<-releaseRetry
			}
			return nil
		},
		Clients: func(job Job) (PublisherClients, publisheridentity.EnrollmentAuthority, error) {
			if job.ID == "server-down" {
				mu.Lock()
				retries = append(retries, time.Now())
				mu.Unlock()
				return PublisherClients{}, nil, errors.New("server unavailable with token=secret")
			}
			b := boundaries[job.ID]
			return jobClients(b.c), b.a, nil
		}}
	cancel, done := startEngine(t, engine)
	join := sync.OnceFunc(func() { cancel(); release(); joinEngine(t, cancel, done) })
	defer join()
	await(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		jobs, _ := r.List(t.Context())
		targetRetried := false
		for _, j := range jobs {
			if j.ID == "target-down" {
				targetRetried = j.Status.Attempts >= 3 && j.Status.State == JobRetrying
			}
		}
		return len(parked) == 3 && len(retries) >= 4 && len(boundaries["healthy"].c.runs) >= 2 && targetRetried
	})
	join()
	if len(boundaries["target-down"].c.runs) != 0 {
		t.Fatal("unavailable target reached run creation")
	}
	mu.Lock()
	defer mu.Unlock()
	if retries[1].Sub(retries[0]) < 15*time.Millisecond || retries[3].Sub(retries[2]) < 30*time.Millisecond || retries[3].Sub(retries[2]) > time.Second {
		t.Fatal("unbounded or instant retry", retries)
	}
	jobs, err := r.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range jobs {
		if j.Status.Failure != "" {
			t.Fatal("joined service retained failure", j.Status)
		}
	}
}

func TestInstalledCancellationPreservesIndependentPublicationFailure(t *testing.T) {
	r := testRegistry(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer target.Close()
	job, identity, private := fixture(t, "cancelled-attempt")
	job.Target = target.URL
	if err := r.Install(t.Context(), job, identity, private); err != nil {
		t.Fatal(err)
	}
	control, authority := jobBoundary(job, identity, private)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cause := errors.New("independent publication failure")
	control.runError = errors.Join(context.Canceled, cause)
	control.onPrepare = cancel
	engine := Engine{Registry: r, RetryMin: time.Millisecond, RetryMax: time.Millisecond,
		Clients: func(Job) (PublisherClients, publisheridentity.EnrollmentAuthority, error) {
			return jobClients(control), authority, nil
		}}
	if err := engine.run(ctx, job); !errors.Is(err, cause) {
		t.Fatal("cancellation hid an independent publication failure", err)
	}
}

func TestReconcileDoesNotBlockOnAnotherJobsDrain(t *testing.T) {
	r := userRegistry(t)
	for _, name := range []string{"slow", "next"} {
		job, _, _ := kindFixture(t, KindConnector)
		job.ID = name
		if err := r.InstallConnector(t.Context(), job); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Stop(t.Context(), "next"); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var draining, running atomic.Bool
	engine := Engine{Registry: r, PollInterval: 5 * time.Millisecond, Connect: func(ctx context.Context, j Job, _ *clienttelemetry.Collector, ready func() error, _ func() time.Time, _ context.Context) error {
		if err := ready(); err != nil {
			return err
		}
		if j.ID == "next" {
			running.Store(true)
		}
		<-ctx.Done()
		if j.ID == "slow" {
			draining.Store(true)
			<-release
		}
		return nil
	}}
	cancel, done := startEngine(t, engine)
	await(t, func() bool { jobs, _ := r.List(t.Context()); return len(jobs) == 2 && jobs[1].Status.State == JobReady })
	if err := r.Stop(t.Context(), "slow"); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(t.Context(), "next"); err != nil {
		t.Fatal(err)
	}
	await(t, func() bool { return draining.Load() && running.Load() })
	wait, stop := context.WithTimeout(t.Context(), 20*time.Millisecond)
	if err := r.WaitStopped(wait, "slow"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("stop preceded drain join", err)
	}
	stop()
	cancel()
	select {
	case <-done:
		t.Fatal("supervisor returned before worker join")
	case <-time.After(30 * time.Millisecond):
	}
	once.Do(func() { close(release) })
	joinEngine(t, cancel, done)
	if err := r.WaitStopped(t.Context(), "slow"); err != nil {
		t.Fatal(err)
	}
}

func TestBlockedGrantCanRestartWithoutLeakingErrorText(t *testing.T) {
	r := testRegistry(t)
	job, identity, private := fixture(t, "one")
	if err := r.Install(t.Context(), job, identity, private); err != nil {
		t.Fatal(err)
	}
	control, authority := jobBoundary(job, identity, private)
	control.service.Id, _ = opaqueid.New(opaqueid.ServicePrefix)
	var calls atomic.Int64
	engine := Engine{Registry: r, PollInterval: 5 * time.Millisecond, Clients: func(Job) (PublisherClients, publisheridentity.EnrollmentAuthority, error) {
		calls.Add(1)
		return jobClients(control), authority, nil
	}}
	cancel, done := startEngine(t, engine)
	await(t, func() bool {
		jobs, _ := r.List(t.Context())
		return len(jobs) == 1 && jobs[0].Status.State == JobBlocked
	})
	if calls.Load() != 1 {
		t.Fatal("scope failure kept retrying")
	}
	if err := r.Start(t.Context(), job.ID); err != nil {
		t.Fatal(err)
	}
	await(t, func() bool {
		jobs, _ := r.List(t.Context())
		return calls.Load() == 2 && len(jobs) == 1 && jobs[0].Status.State == JobBlocked
	})
	joinEngine(t, cancel, done)
	if safeFailure(errors.New("enrollment=secret assertion=secret")) != "publication unavailable" {
		t.Fatal("raw failure escaped")
	}
}

func TestServicePublicationRejectsDriftBeforePreparingAnyRun(t *testing.T) {
	for _, name := range []string{"id", "protocol", "trust", "pool", "disabled"} {
		t.Run(name, func(t *testing.T) {
			r := testRegistry(t)
			job, identity, key := fixture(t, "web")
			if err := r.Install(t.Context(), job, identity, key); err != nil {
				t.Fatal(err)
			}
			control, authority := jobBoundary(job, identity, key)
			switch name {
			case "id":
				control.service.Id = ""
			case "protocol":
				control.service.Protocol = controlv1.Tcp
			case "trust":
				control.service.TrustRevision++
			case "pool":
				control.service.PublisherPool = !job.PublisherPool
			case "disabled":
				control.service.Enabled = false
			}
			engine := Engine{Registry: r, Clients: func(Job) (PublisherClients, publisheridentity.EnrollmentAuthority, error) {
				return jobClients(control), authority, nil
			}}
			var owner *processidentity.Owner
			if _, err := engine.attempt(t.Context(), job, 1, &owner); err == nil || len(control.runs) != 0 {
				t.Fatal("saved service drift reached preparation", err)
			}
			if owner != nil {
				_ = owner.Stop(t.Context())
			}
		})
	}
}

func TestServiceRejectsASecondSupervisor(t *testing.T) {
	r := testRegistry(t)
	locked := make(chan struct{})
	cancel, done := startEngine(t, Engine{Registry: r, PollInterval: 5 * time.Millisecond, Initialize: func(context.Context) error { close(locked); return nil }})
	select {
	case <-locked:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor lock missing")
	}
	ctx, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if err := (Engine{Registry: r}).Serve(ctx); !errors.Is(err, filelock.ErrLocked) {
		t.Fatal("second supervisor did not report lock contention", err)
	}
	joinEngine(t, cancel, done)
}
