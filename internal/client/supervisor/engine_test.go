package supervisor

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/filelock"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type jobAuthority struct {
	identity authorityv1.PublisherEnrollmentResult
	public   ed25519.PublicKey
}

type testUserRunner func(context.Context) error

func (f testUserRunner) Serve(ctx context.Context) error { return f(ctx) }

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
	publisheridentity.NativeControl
	publicURL       controlv1.PublicURL
	public          ed25519.PublicKey
	runs            chan string
	runError        error
	renewError      error
	runtimeMu       sync.Mutex
	runtimeRequests []controlv1.PublisherRuntimeRequest
}

func (c *jobControl) PublisherRuntime(_ context.Context, r controlv1.PublisherRuntimeRequest) (controlv1.PublisherRuntimeResponse, error) {
	c.runtimeMu.Lock()
	c.runtimeRequests = append(c.runtimeRequests, r)
	c.runtimeMu.Unlock()
	if r.Action == controlv1.RuntimeRenew && c.renewError != nil {
		return controlv1.PublisherRuntimeResponse{}, c.renewError
	}
	kid, err := publisherproof.KeyID(r.Assertion)
	if err != nil {
		return controlv1.PublisherRuntimeResponse{}, err
	}
	if _, err = publisherproof.Verify(r.Assertion, r.PublisherIdentityId, kid, publisherproof.RuntimeScope(r.ScopeId, string(r.Action), r.ProcessRunId, r.ExpectedEpoch), "https://control.example/v1/publisher-runtime", c.public, time.Now()); err != nil {
		return controlv1.PublisherRuntimeResponse{}, err
	}
	epoch := r.ExpectedEpoch
	if r.Action == controlv1.RuntimeStart {
		epoch++
	}
	return controlv1.PublisherRuntimeResponse{Epoch: epoch, LeaseExpiresAt: new(time.Now().Add(2 * time.Minute))}, nil
}

func TestInstalledRunConflictRetriesOnlyWhileRuntimeIsCurrent(t *testing.T) {
	for _, fenced := range []bool{false, true} {
		t.Run(fmt.Sprint(fenced), func(t *testing.T) {
			registry := testRegistry(t)
			job, identity, key := fixture(t, "web")
			control, authority := jobBoundary(job, identity, key)
			if fenced {
				control.renewError = clientcontrol.ErrStatusConflict
			}
			if err := registry.Install(t.Context(), job, identity, key); err != nil {
				t.Fatal(err)
			}
			var attempts atomic.Int64
			engine := Engine{Registry: registry, PollInterval: 5 * time.Millisecond, RetryMin: 5 * time.Millisecond, RetryMax: 10 * time.Millisecond,
				Clients: func(Job) (publisheridentity.NativeControl, publisheridentity.EnrollmentAuthority, error) {
					return control, authority, nil
				},
				Publish: func(ctx context.Context, cfg publisher.Config) error {
					if attempts.Add(1) == 1 {
						return clientcontrol.ErrStatusConflict
					}
					if err := cfg.Observe(publisher.Event{Type: publisher.EventReady, PublishRunNumber: 2, PublicURL: "https://web.example"}); err != nil {
						return err
					}
					<-ctx.Done()
					return nil
				}}
			cancel, done := startEngine(t, engine)
			await(t, func() bool {
				jobs, err := registry.List(t.Context())
				if err != nil || len(jobs) != 1 {
					return false
				}
				if fenced {
					return jobs[0].Status.State == "blocked" && jobs[0].Status.Failure == string(failure.ServerConflict)
				}
				return jobs[0].Status.State == "ready"
			})
			joinEngine(t, cancel, done)
			want := int64(2)
			if fenced {
				want = 1
			}
			if attempts.Load() != want {
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

func (c *jobControl) PublisherPublicURL(context.Context, string) (controlv1.PublicURL, error) {
	return c.publicURL, nil
}
func (c *jobControl) CreatePublisherRun(_ context.Context, url, retry, access, proof string) (controlv1.PublishRunSetup, error) {
	if access != "test-access-never-log" {
		return controlv1.PublishRunSetup{}, publisheridentity.ErrScope
	}
	if _, err := publisherproof.VerifyRun(c.public, proof, url, retry); err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	select {
	case c.runs <- retry:
	default:
	}
	return controlv1.PublishRunSetup{}, c.runError
}

func jobBoundary(job Job, identity authorityv1.PublisherEnrollmentResult, key ed25519.PrivateKey) (*jobControl, *jobAuthority) {
	domain, _ := opaqueid.New(opaqueid.DomainPrefix)
	return &jobControl{publicURL: controlv1.PublicURL{Id: job.PublicURLID, TeamId: identity.TeamId, DomainId: domain, PublicUrlScope: controlv1.Shared, Purpose: controlv1.App, ServiceProtocol: controlv1.Http, CanonicalHostname: job.ID + ".example", Target: job.Target, LifecycleState: controlv1.Enabled}, public: key.Public().(ed25519.PublicKey), runs: make(chan string, 32)}, &jobAuthority{identity: identity, public: key.Public().(ed25519.PublicKey)}
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

func TestRealNativeRunSignsWithTheSameKeyAfterBoot(t *testing.T) {
	options := testOptions(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer target.Close()
	job, identity, private := fixture(t, "web")
	job.Target = target.URL
	control, authority := jobBoundary(job, identity, private)
	control.runError = errors.New("test ends after verified signed run creation")
	var previousRun string
	for boot := range 2 {
		control.runtimeRequests = nil
		control.runs = make(chan string, 32)
		r, err := Open(t.Context(), options)
		if err != nil {
			t.Fatal(err)
		}
		if boot == 0 {
			if err := r.Install(t.Context(), job, identity, private); err != nil {
				t.Fatal(err)
			}
		}
		engine := Engine{Registry: r, PollInterval: 5 * time.Millisecond, RetryMin: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond, Clients: func(Job) (publisheridentity.NativeControl, publisheridentity.EnrollmentAuthority, error) {
			return control, authority, nil
		}}
		// Publish is deliberately unset: this executes publisher.Run, target
		// preflight, URL reconciliation, and the signed native run adapter.
		cancel, done := startEngine(t, engine)
		select {
		case <-control.runs:
		case <-time.After(5 * time.Second):
			t.Fatal("native publisher did not create a signed run")
		}
		joinEngine(t, cancel, done)
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
	missingTarget := "http://" + closed.Addr().String()
	closed.Close()
	var boundaries = map[string]struct {
		c *jobControl
		a *jobAuthority
	}{}
	for _, name := range []string{"healthy", "target-down", "server-down"} {
		job, identity, private := fixture(t, name)
		job.Target = target.URL
		if name == "target-down" {
			job.Target = missingTarget
		}
		if name == "server-down" {
			job.Server = "https://unavailable.example"
		}
		if err := r.Install(t.Context(), job, identity, private); err != nil {
			t.Fatal(err)
		}
		control, authority := jobBoundary(job, identity, private)
		control.runError = errors.New("publisher retry must not leak access=secret")
		boundaries[name] = struct {
			c *jobControl
			a *jobAuthority
		}{control, authority}
	}
	var retryMu sync.Mutex
	var retries []time.Time
	engine := Engine{Registry: r, PollInterval: 5 * time.Millisecond, RetryMin: 15 * time.Millisecond, RetryMax: 30 * time.Millisecond, Clients: func(job Job) (publisheridentity.NativeControl, publisheridentity.EnrollmentAuthority, error) {
		if job.ID == "server-down" {
			retryMu.Lock()
			retries = append(retries, time.Now())
			retryMu.Unlock()
			return nil, nil, errors.New("server unavailable with token=secret")
		}
		boundary := boundaries[job.ID]
		return boundary.c, boundary.a, nil
	}}
	cancel, done := startEngine(t, engine)
	await(t, func() bool {
		retryMu.Lock()
		defer retryMu.Unlock()
		jobs, err := r.List(t.Context())
		if err != nil {
			return false
		}
		targetRetried := false
		for _, job := range jobs {
			if job.ID == "target-down" {
				targetRetried = job.Status.Attempts >= 3 && job.Status.State != "blocked"
			}
		}
		return len(retries) >= 4 && len(boundaries["healthy"].c.runs) >= 2 && targetRetried
	})
	joinEngine(t, cancel, done)
	if len(boundaries["target-down"].c.runs) != 0 {
		t.Fatal("unavailable target reached run creation")
	}
	retryMu.Lock()
	defer retryMu.Unlock()
	if retries[1].Sub(retries[0]) < 15*time.Millisecond || retries[3].Sub(retries[2]) < 30*time.Millisecond || retries[3].Sub(retries[2]) > time.Second {
		t.Fatalf("unbounded/instant retry: %v", retries)
	}
	jobs, err := r.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range jobs {
		if job.Status.Failure != "" {
			t.Fatalf("joined service retained a failure: %+v", job.Status)
		}
	}
}

func TestReconcileDoesNotBlockOnAnotherJobsDrain(t *testing.T) {
	r := testRegistry(t)
	controls := map[string]*jobControl{}
	authorities := map[string]*jobAuthority{}
	for _, name := range []string{"slow", "next"} {
		job, identity, private := fixture(t, name)
		if err := r.Install(t.Context(), job, identity, private); err != nil {
			t.Fatal(err)
		}
		controls[name], authorities[name] = jobBoundary(job, identity, private)
	}
	if err := r.Stop(t.Context(), "next"); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var slowDraining, nextRunning atomic.Bool
	engine := Engine{Registry: r, PollInterval: 5 * time.Millisecond, Clients: func(job Job) (publisheridentity.NativeControl, publisheridentity.EnrollmentAuthority, error) {
		return controls[job.ID], authorities[job.ID], nil
	}, Publish: func(ctx context.Context, cfg publisher.Config) error {
		if err := cfg.Observe(publisher.Event{Type: publisher.EventReady, PublishRunNumber: 7}); err != nil {
			return err
		}
		if cfg.Hostname == "next.example" {
			nextRunning.Store(true)
		}
		<-ctx.Done()
		if cfg.Hostname == "slow.example" {
			slowDraining.Store(true)
			<-release
		}
		return nil
	}}
	cancel, done := startEngine(t, engine)
	await(t, func() bool { jobs, _ := r.List(t.Context()); return len(jobs) == 2 && jobs[1].Status.State == "ready" })
	if err := r.Stop(t.Context(), "slow"); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(t.Context(), "next"); err != nil {
		t.Fatal(err)
	}
	await(t, func() bool { return slowDraining.Load() && nextRunning.Load() })
	stopping, stopWait := context.WithTimeout(t.Context(), 20*time.Millisecond)
	if err := r.WaitStopped(stopping, "slow"); !errors.Is(err, context.DeadlineExceeded) {
		stopWait()
		t.Fatalf("stop acknowledged before drain join: %v", err)
	}
	stopWait()
	cancel()
	select {
	case <-done:
		t.Fatal("Serve returned before the slow worker joined")
	case <-time.After(30 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("drain join failed")
	}
	if err := r.WaitStopped(t.Context(), "slow"); err != nil {
		t.Fatalf("joined stop was not acknowledged: %v", err)
	}
	if _, _, _, err := r.signingIdentity(t.Context(), func() Job { jobs, _ := r.List(t.Context()); return jobs[1] }()); err != nil {
		t.Fatal("local stop revoked or removed the signing identity")
	}
}

func TestBlockedGrantCanRestartWithoutLeakingErrorText(t *testing.T) {
	r := testRegistry(t)
	job, identity, private := fixture(t, "one")
	if err := r.Install(t.Context(), job, identity, private); err != nil {
		t.Fatal(err)
	}
	control, authority := jobBoundary(job, identity, private)
	control.publicURL.Id, _ = opaqueid.New(opaqueid.PublicURLPrefix)
	var calls atomic.Int64
	engine := Engine{Registry: r, PollInterval: 5 * time.Millisecond, Clients: func(Job) (publisheridentity.NativeControl, publisheridentity.EnrollmentAuthority, error) {
		calls.Add(1)
		return control, authority, nil
	}}
	cancel, done := startEngine(t, engine)
	await(t, func() bool {
		jobs, _ := r.List(t.Context())
		return len(jobs) == 1 && jobs[0].Status.State == "blocked"
	})
	if calls.Load() != 1 {
		t.Fatal("scope failure kept retrying")
	}
	if err := r.Start(t.Context(), job.ID); err != nil {
		t.Fatal(err)
	}
	await(t, func() bool { return calls.Load() == 2 })
	joinEngine(t, cancel, done)
	if safeFailure(errors.New("enrollment=secret assertion=secret")) != "publication unavailable" {
		t.Fatal("raw failure escaped the boundary")
	}
}

func TestServiceRejectsASecondSupervisor(t *testing.T) {
	r := testRegistry(t)
	cancel, done := startEngine(t, Engine{Registry: r, PollInterval: 5 * time.Millisecond})
	await(t, func() bool {
		lock, err := filelock.Acquire(filepath.Join(r.Root(), "service.lock"), filelock.Nonblocking, r.owner)
		if lock != nil {
			lock.Close()
		}
		return errors.Is(err, filelock.ErrLocked)
	})
	ctx, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if err := (Engine{Registry: r}).Serve(ctx); err == nil {
		t.Fatal("two supervisors acquired the same registry")
	}
	joinEngine(t, cancel, done)
}
