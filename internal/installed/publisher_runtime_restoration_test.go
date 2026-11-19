package installed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	"github.com/tnldotdev/tnl/internal/publisher/processidentity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/testutil"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	telemetryv1 "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

type restoredPublisherRoundTrip func(*http.Request) (*http.Response, error)

func (f restoredPublisherRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func restoredPublisherFixture(t *testing.T) (*publishingtest.Fixture, *publishingtest.Runtime) {
	t.Helper()
	f := publishingtest.New(t, testutil.PublishingHooks{})
	transport, err := f.Transport()
	if err != nil {
		t.Fatal(err)
	}
	transport.DisableKeepAlives = true
	original := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { transport.CloseIdleConnections(); http.DefaultTransport = original })
	return f, f.Runtime()
}

func restoredInstallPublisher(t *testing.T, r *Registry, f *publishingtest.Fixture, name, target string, disabled bool) (Job, authorityv1.PublisherEnrollmentResult, ed25519.PrivateKey) {
	t.Helper()
	saved, err := f.SavedService(t.Context(), name, controlv1.ProjectServiceConfiguration{Target: "app", Public: new(true)})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := r.Profile(t.Context(), f.URL)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := f.Owner()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(f.URL, f.HTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	_, identity, err := publisheridentity.EnsureServiceOwner(t.Context(), profile, owner, authority, saved)
	if err != nil {
		t.Fatal(err)
	}
	retained, found, err := profile.PublisherIdentity(t.Context(), identity.ClientId)
	if err != nil || !found || len(retained.SigningKey) != ed25519.PrivateKeySize {
		t.Fatal("missing actually enrolled signing key", err)
	}
	job := Job{Kind: KindService, ID: name, Server: f.URL, ServiceID: saved.Id, PublisherIdentityID: identity.ClientId,
		GrantID: identity.GrantId, TrustRevision: saved.TrustRevision, PublisherPool: saved.PublisherPool,
		Protocol: config.ProtocolHTTP, Target: target, TelemetryDisabled: disabled}
	if err := r.Install(t.Context(), job, identity, retained.SigningKey); err != nil {
		t.Fatal(err)
	}
	return job, identity, retained.SigningKey
}

func restoredPublisherClients(t *testing.T, f *publishingtest.Fixture, runtime *publishingtest.Runtime, transport http.RoundTripper) ClientFactory {
	t.Helper()
	control, err := clientcontrol.New(f.URL, &http.Client{Transport: transport}, "")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(f.URL, f.HTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	return func(job Job) (PublisherClients, publisheridentity.EnrollmentAuthority, error) {
		if job.Server != f.URL {
			return PublisherClients{}, nil, publisheridentity.ErrScope
		}
		return PublisherClients{NativeControl: publisheridentity.NativeControl{Services: control, Runtime: runtime}}, authority, nil
	}
}

func restoredStartPublisher(t *testing.T, engine Engine) func() error {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- engine.Serve(ctx) }()
	var once sync.Once
	var result error
	join := func() error {
		once.Do(func() {
			cancel()
			select {
			case result = <-done:
			case <-time.After(2 * time.Second):
				result = errors.New("installed publisher did not join within 2s")
			}
		})
		return result
	}
	t.Cleanup(func() {
		if err := join(); err != nil {
			t.Error("independent installed publisher cleanup failure", err)
		}
	})
	return join
}

type restoredPublisherStatus struct {
	job    string
	status Status
}

func restoredPublisherStatusUntil(t *testing.T, events <-chan restoredPublisherStatus, predicate func(restoredPublisherStatus) bool) restoredPublisherStatus {
	t.Helper()
	return restoredPublisherStatusWithin(t, events, 2*time.Second, predicate)
}

func restoredPublisherReadyStatus(t *testing.T, events <-chan restoredPublisherStatus) restoredPublisherStatus {
	t.Helper()
	// the first heartbeat can precede the separate local health observation.
	// wait for the next scheduled heartbeat without changing the engine.
	return restoredPublisherStatusWithin(t, events, 12*time.Second, func(e restoredPublisherStatus) bool {
		return e.status.State == JobReady || e.status.State == JobBlocked || e.status.State == JobRetrying
	})
}

func restoredPublisherStatusWithin(t *testing.T, events <-chan restoredPublisherStatus, budget time.Duration, predicate func(restoredPublisherStatus) bool) restoredPublisherStatus {
	t.Helper()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	var last Status
	for {
		select {
		case event := <-events:
			last = event.status
			if predicate(event) {
				return event
			}
		case <-timer.C:
			t.Fatalf("installed publisher did not reach its status boundary within %s: last status=%+v", budget, last)
			return restoredPublisherStatus{}
		}
	}
}

type restoredPublisherTelemetry struct {
	collector   *clienttelemetry.Collector
	mu          sync.Mutex
	connections int64
	barriers    map[string]bool
}

func restoredPublisherCollector(t *testing.T) *restoredPublisherTelemetry {
	t.Helper()
	observed := &restoredPublisherTelemetry{barriers: map[string]bool{}}
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, telemetryv1.MaximumBatchBytes+1))
		var batch telemetryv1.Batch
		if err != nil || telemetryv1.ValidateBatch(body) != nil || json.Unmarshal(body, &batch) != nil {
			t.Error("actual collector delivered invalid telemetry", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		observed.mu.Lock()
		defer observed.mu.Unlock()
		for _, collected := range batch.Events {
			if marker, err := collected.Event.AsCommandEvent(); err == nil && marker.Name == "command.outcome" {
				observed.barriers[marker.EventId] = true
			}
			event, err := collected.Event.AsTransportEvent()
			if err == nil && event.Name == "transport.report" && event.Payload.Role == telemetryv1.TransportReportRolePublisher {
				for _, measurement := range event.Payload.Measurements {
					if measurement.Operation == telemetryv1.RelayConnect && measurement.Outcome == telemetryv1.Succeeded {
						observed.connections += measurement.Count
					}
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(receiver.Close)
	root := filepath.Join(t.TempDir(), "telemetry")
	state, err := clientstate.OpenWithOptions(t.Context(), root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	if enabled, err := state.TelemetryEnabled(t.Context()); err != nil || !enabled {
		t.Fatal("fresh installed-publisher state did not default telemetry on", err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	observed.collector, err = clienttelemetry.New(t.Context(), clienttelemetry.Config{Root: root, Protection: clientstate.ProtectionFile,
		Endpoint: receiver.URL, Client: &http.Client{Timeout: clienttelemetry.RequestTimeout}, Interval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(observed.close)
	return observed
}

func (o *restoredPublisherTelemetry) count() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.connections
}
func (o *restoredPublisherTelemetry) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	o.collector.Close(ctx)
}

func (o *restoredPublisherTelemetry) barrier(t *testing.T) {
	t.Helper()
	// this marked command event is only a queue/delivery barrier. publisher
	// assertions count exclusively the real transport reports above.
	event := clienttelemetry.Command(telemetryv1.CommandOutcome{Command: "other", Outcome: telemetryv1.Succeeded})
	marker, err := event.AsCommandEvent()
	if err != nil {
		t.Fatal(err)
	}
	o.collector.Report(event)
	o.collector.Flush()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		o.mu.Lock()
		delivered := o.barriers[marker.EventId]
		o.mu.Unlock()
		if delivered {
			return
		}
		select {
		case <-timer.C:
			t.Fatal("central collector did not complete its explicit delivery barrier")
		case <-tick.C:
		}
	}
}

type restoredCertificateAcknowledgment struct {
	boot                   int
	service, run, issuance string
	number                 int64
	notAfter               time.Time
	accepted               bool
}

type restoredCertificateAcknowledgments struct {
	mu      sync.Mutex
	records []restoredCertificateAcknowledgment
}

type restoredAcknowledgmentControl struct {
	publisheridentity.ServiceControl
	t      *testing.T
	boot   int
	record *restoredCertificateAcknowledgments
}

func (c restoredAcknowledgmentControl) MarkServiceCertificateInstalled(ctx context.Context, service, run string, number int64, issuance string, notAfter time.Time, token credentials.ServiceRunToken) error {
	err := c.ServiceControl.MarkServiceCertificateInstalled(ctx, service, run, number, issuance, notAfter, token)
	c.record.mu.Lock()
	c.record.records = append(c.record.records, restoredCertificateAcknowledgment{boot: c.boot, service: service, run: run,
		number: number, issuance: issuance, notAfter: notAfter, accepted: err == nil})
	c.record.mu.Unlock()
	c.t.Logf("boot=%d certificate-installed service=%s current_run=%s run_number=%d issuance=%s not_after=%s error=%v",
		c.boot, service, run, number, issuance, notAfter.Format(time.RFC3339Nano), err)
	return err
}

func (a *restoredCertificateAcknowledgments) assertBoot(t *testing.T, boot int, jobs []Job) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, job := range jobs {
		var first restoredCertificateAcknowledgment
		found := false
		for _, record := range a.records {
			if record.service != job.ServiceID || !record.accepted {
				continue
			}
			if first.issuance == "" {
				first = record
			}
			if record.boot != boot {
				continue
			}
			if record.run == "" || record.issuance == "" || record.number != int64(boot) ||
				record.issuance != first.issuance || !record.notAfter.Equal(first.notAfter) ||
				boot == 2 && (first.boot != 1 || record.run == first.run) {
				t.Fatalf("boot %d changed its actual retained issuance or current run: %+v", boot, record)
			}
			found = true
		}
		if !found {
			t.Fatalf("boot %d did not acknowledge its actual certificate for service %s", boot, job.ServiceID)
		}
	}
}

func TestInstalledPublishersKeepTelemetryChoiceAcrossTwoSupervisorStarts(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	telemetry := restoredPublisherCollector(t)
	f, runtime := restoredPublisherFixture(t)
	options := testOptions(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(target.Close)
	var originalJobs []Job
	originalKeys := map[string]ed25519.PrivateKey{}
	acknowledgments := &restoredCertificateAcknowledgments{}
	for boot := range 2 {
		r, err := Open(t.Context(), options)
		if err != nil {
			t.Fatal(err)
		}
		var closeOnce sync.Once
		var closeError error
		closeRegistry := func() error {
			closeOnce.Do(func() { closeError = r.Close() })
			return closeError
		}
		t.Cleanup(func() {
			if err := closeRegistry(); err != nil {
				t.Error(err)
			}
		})
		if boot == 0 {
			for _, disabled := range []bool{true, false} {
				name := "enabled"
				if disabled {
					name = "disabled"
				}
				job, _, key := restoredInstallPublisher(t, r, f, name, target.URL, disabled)
				originalJobs = append(originalJobs, job)
				originalKeys[job.ID] = append(ed25519.PrivateKey(nil), key...)
			}
		}
		jobs, err := r.List(t.Context())
		if err != nil || len(jobs) != 2 {
			t.Fatal("saved publishers did not survive boot", err)
		}
		for _, job := range jobs {
			if job.TelemetryDisabled != (job.ID == "disabled") || job.Server != f.URL || job.Kind != KindService {
				t.Fatal("publisher restart changed saved selection")
			}
			identity, key, _, err := r.signingIdentity(t.Context(), job)
			if err != nil || identity.ClientId != job.PublisherIdentityID || identity.GrantId != job.GrantID || !bytes.Equal(key, originalKeys[job.ID]) {
				t.Fatal("supervisor restart changed the actually enrolled identity or key", err)
			}
		}
		var enabled Job
		for _, job := range originalJobs {
			if !job.TelemetryDisabled {
				enabled = job
			}
		}
		release := make(chan struct{})
		allowEnabled := sync.OnceFunc(func() { close(release) })
		t.Cleanup(allowEnabled)
		transport := restoredPublisherRoundTrip(func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodPost && request.URL.Path == "/v1/services/"+enabled.ServiceID+"/runs" {
				select {
				case <-release:
				case <-request.Context().Done():
					return nil, request.Context().Err()
				}
			}
			return f.HTTP.Transport.RoundTrip(request)
		})
		statuses := make(chan restoredPublisherStatus, 64)
		clients := restoredPublisherClients(t, f, runtime, transport)
		engine := Engine{Registry: r, Telemetry: telemetry.collector, PollInterval: 5 * time.Millisecond,
			RetryMin: 5 * time.Millisecond, RetryMax: 10 * time.Millisecond,
			Clients: func(job Job) (PublisherClients, publisheridentity.EnrollmentAuthority, error) {
				control, authority, err := clients(job)
				if err == nil {
					control.Services = restoredAcknowledgmentControl{ServiceControl: control.Services, t: t, boot: boot + 1, record: acknowledgments}
				}
				return control, authority, err
			},
			Observe: func(job Job, status Status) error {
				statuses <- restoredPublisherStatus{job: job.ID, status: status}
				return nil
			}}
		join := restoredStartPublisher(t, engine)
		defer func() {
			// release setup gates and join before test cleanup cancels the
			// shared relay's parent context. retain the complete joined error.
			allowEnabled()
			if err := join(); err != nil {
				t.Error("installed publisher deferred join failed", err)
			}
		}()
		// release before the join cleanup on an early assertion failure too.
		t.Cleanup(allowEnabled)
		disabledReady := restoredPublisherReadyStatus(t, statuses)
		if disabledReady.job != "disabled" || disabledReady.status.State != JobReady || disabledReady.status.Attempts != 1 || disabledReady.status.RunNumber != uint64(boot+1) {
			t.Fatalf("boot %d disabled publisher did not reach actual Ready before the enabled preparation was released: %+v", boot+1, disabledReady)
		}
		telemetry.barrier(t)
		if telemetry.count() != int64(boot*2) {
			t.Fatal("opted-out publisher delivered transport telemetry before its enabled sibling started")
		}
		allowEnabled()
		for {
			event := restoredPublisherReadyStatus(t, statuses)
			if event.status.State != JobReady || event.status.Attempts != 1 || event.status.RunNumber != uint64(boot+1) {
				t.Fatalf("boot %d publisher did not reach real Ready on its first boot attempt: %+v", boot+1, event)
			}
			if event.job == "enabled" {
				break
			}
		}
		acknowledgments.assertBoot(t, boot+1, originalJobs)
		for _, job := range originalJobs {
			permission, err := f.OwnerVisitorToken(t.Context(), job.ServiceID)
			if err != nil {
				t.Fatal(err)
			}
			owner, err := f.Owner()
			if err != nil {
				t.Fatal(err)
			}
			service, err := owner.GetService(t.Context(), job.ServiceID)
			if err != nil {
				t.Fatal(err)
			}
			if service.Endpoint == nil || !service.Enabled || permission.Resource.Kind != controlv1.VisitorResourceScopeKindService ||
				permission.Resource.Id != job.ServiceID || permission.Hostname != service.Endpoint.Hostname || permission.Port != service.Endpoint.Port ||
				permission.ServiceTrustRevision == nil || *permission.ServiceTrustRevision != service.TrustRevision || permission.VisitorToken == "" {
				t.Fatal("owner visitor permission did not bind the actual saved service endpoint/trust")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
			status, _, _, err := f.VisitWithHeaders(ctx, "https://"+service.Endpoint.Hostname, http.Header{httpaccess.VisitorTokenHeader: {permission.VisitorToken}})
			cancel()
			if err != nil || status != http.StatusNoContent {
				t.Fatal("ready installed publisher did not serve through actual visitor TLS", status, err)
			}
		}
		if err := join(); err != nil {
			t.Fatal("publisher cleanup failed independently", err)
		}
		// each boot must inspect once and start once per saved identity. stop and
		// renew keep those exact run IDs and epochs; boot two uses a fresh run.
		for _, job := range originalJobs {
			var starts []controlv1.PublisherRuntimeRequest
			inspects, stops := 0, 0
			for _, request := range runtime.Requests() {
				if request.PublisherIdentityId == job.PublisherIdentityID {
					switch request.Action {
					case controlv1.RuntimeStart:
						starts = append(starts, request)
					case controlv1.RuntimeInspect:
						inspects++
					case controlv1.RuntimeStop:
						stops++
					}
				}
			}
			if len(starts) != boot+1 || inspects != boot+1 || stops != boot+1 || starts[boot].ExpectedEpoch != int64(boot) || boot == 1 && starts[0].ProcessRunId == starts[1].ProcessRunId {
				t.Fatal("publisher boot replaced its signing scope or reused a process run")
			}
		}
		if err := closeRegistry(); err != nil {
			t.Fatal(err)
		}
		telemetry.barrier(t)
		if telemetry.count() != int64((boot+1)*2) {
			t.Fatal("opted-out publisher emitted transport observations")
		}
	}
	telemetry.close()
	if telemetry.count() != 4 || f.Enrollments.Load() != 2 || f.Runs.Load() != 4 {
		t.Fatal("two starts did not preserve publisher-specific opt-out and sibling delivery", telemetry.count(), f.Enrollments.Load(), f.Runs.Load())
	}
}

// reserve an actual earlier preparation with the enrolled key. the first
// supervisor request must receive the backend's real conflict before this
// adapter closes that earlier run; the next attempt uses the same backend.
func restoredPreparationConflict(t *testing.T, registry *Registry, f *publishingtest.Fixture, job Job, runtime *publishingtest.Runtime, fenced bool, attempts *atomic.Int32) http.RoundTripper {
	t.Helper()
	control, err := clientcontrol.New(f.URL, f.HTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := f.Owner()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(f.URL, f.HTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := registry.Profile(t.Context(), f.URL)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := owner.GetService(t.Context(), job.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	native, _, err := publisheridentity.EnsureServiceOwner(t.Context(), profile, owner, authority, saved)
	if err != nil {
		t.Fatal(err)
	}
	access, err := native.Access(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := native.PrepareServiceRun(t.Context(), job.ServiceID, key, access, publisheridentity.ServiceDeclaration(saved))
	if err != nil || previous.RunNumber != 1 {
		t.Fatal("could not reserve the actual earlier service run", err)
	}
	var closeOnce sync.Once
	var closeError error
	closePrevious := func() error {
		closeOnce.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			closeError = native.CloseServiceRun(ctx, job.ServiceID, previous.ServiceRunId, credentials.ServiceRunToken(previous.RunToken))
		})
		return closeError
	}
	t.Cleanup(func() {
		if err := closePrevious(); err != nil {
			t.Error("independent earlier-preparation cleanup failure", err)
		}
	})
	return restoredPublisherRoundTrip(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/services/"+job.ServiceID+"/runs" {
			return f.HTTP.Transport.RoundTrip(request)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		_ = request.Body.Close()
		request.Body = io.NopCloser(bytes.NewReader(body))
		service, err := control.GetPublisherService(request.Context(), job.ServiceID, strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "))
		if err != nil {
			return nil, err
		}
		var declaration controlv1.ServiceRunDeclaration
		if json.Unmarshal(body, &declaration) != nil || service.Id != job.ServiceID ||
			!reflect.DeepEqual(declaration, publisheridentity.ServiceDeclaration(service)) || !opaqueid.Valid(request.Header.Get("Idempotency-Key"), opaqueid.IdempotencyPrefix) {
			return nil, errors.New("conflict request lost exact authorized service declaration")
		}
		attempt := attempts.Add(1)
		response, err := f.HTTP.Transport.RoundTrip(request)
		if attempt != 1 || err != nil {
			return response, err
		}
		if response.StatusCode != http.StatusConflict {
			_ = response.Body.Close()
			return nil, errors.New("the actual earlier preparation did not conflict")
		}
		if err := closePrevious(); err != nil {
			_ = response.Body.Close()
			return nil, errors.Join(clientcontrol.ErrStatusConflict, err)
		}
		if fenced {
			runtime.FailRenewal(job.PublisherIdentityID, failure.Wrap("renew fenced publisher", failure.ServerConflict, clientcontrol.ErrStatusConflict))
		}
		// the shared backend returns a bare 409. give that observed conflict its
		// public wire problem shape; do not manufacture the conflict decision.
		_ = response.Body.Close()
		problem, err := json.Marshal(controlv1.Problem{Type: "about:blank", Title: "previous service run", Status: http.StatusConflict, Code: controlv1.Conflict})
		if err != nil {
			return nil, err
		}
		response.Body = io.NopCloser(bytes.NewReader(problem))
		response.ContentLength = int64(len(problem))
		response.Header.Set("Content-Type", "application/problem+json")
		response.Header.Del("Content-Length")
		return response, nil
	})
}

func TestInstalledRealPreparationConflictReachesReadyExactlyOnAttemptTwo(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	f, runtime := restoredPublisherFixture(t)
	r := testRegistry(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(target.Close)
	job, _, _ := restoredInstallPublisher(t, r, f, "retry", target.URL, false)
	var attempts atomic.Int32
	statuses := make(chan restoredPublisherStatus, 64)
	join := restoredStartPublisher(t, Engine{Registry: r, PollInterval: 5 * time.Millisecond, RetryMin: 5 * time.Millisecond, RetryMax: 10 * time.Millisecond,
		Clients: restoredPublisherClients(t, f, runtime, restoredPreparationConflict(t, r, f, job, runtime, false, &attempts)),
		Observe: func(job Job, status Status) error {
			statuses <- restoredPublisherStatus{job: job.ID, status: status}
			return nil
		}})
	defer func() {
		if err := join(); err != nil {
			t.Error("retry publisher deferred join failed", err)
		}
	}()
	retry := restoredPublisherStatusUntil(t, statuses, func(e restoredPublisherStatus) bool {
		return e.status.State == JobRetrying || e.status.State == JobBlocked || e.status.State == JobReady
	})
	if retry.status.State != JobRetrying || retry.status.Attempts != 1 || retry.status.Failure != string(failure.InstalledPublishRunPending) {
		t.Fatal("first real preparation conflict lost exact retry code/count", retry)
	}
	ready := restoredPublisherStatusUntil(t, statuses, func(e restoredPublisherStatus) bool {
		return e.status.State == JobReady || e.status.State == JobRetrying || e.status.State == JobBlocked
	})
	if ready.status.State != JobReady || ready.status.Attempts != 2 || ready.status.RunNumber != 2 || ready.status.Failure != "" || attempts.Load() != 2 || f.Runs.Load() != 2 {
		t.Fatal("one real conflict did not reach actual Ready on exactly attempt two", ready, attempts.Load(), f.Runs.Load())
	}
	if err := join(); err != nil {
		t.Fatal("retry publication cleanup failed independently", err)
	}
	restoredAssertSingleRuntime(t, runtime, job.PublisherIdentityID)
	if attempts.Load() != 2 {
		t.Fatal("publisher retried again after Ready")
	}
}

func restoredAssertSingleRuntime(t *testing.T, runtime *publishingtest.Runtime, identity string) {
	t.Helper()
	inspects, starts := 0, 0
	var run string
	for _, request := range runtime.Requests() {
		if request.PublisherIdentityId != identity {
			t.Fatal("runtime used another actually enrolled identity")
		}
		if request.Action == controlv1.RuntimeInspect {
			inspects++
			run = request.ProcessRunId
		}
		if request.Action == controlv1.RuntimeStart {
			starts++
		}
		if request.ProcessRunId != run {
			t.Fatal("retry crossed the process run fence")
		}
	}
	if inspects != 1 || starts != 1 {
		t.Fatal("retry reclaimed a runtime epoch", inspects, starts)
	}
}

func TestInstalledRealPreparationConflictBlocksAtRuntimeFence(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	f, runtime := restoredPublisherFixture(t)
	r := testRegistry(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(target.Close)
	job, _, _ := restoredInstallPublisher(t, r, f, "fenced", target.URL, false)
	var attempts atomic.Int32
	statuses := make(chan restoredPublisherStatus, 64)
	join := restoredStartPublisher(t, Engine{Registry: r, PollInterval: 5 * time.Millisecond, RetryMin: 5 * time.Millisecond, RetryMax: 10 * time.Millisecond,
		Clients: restoredPublisherClients(t, f, runtime, restoredPreparationConflict(t, r, f, job, runtime, true, &attempts)),
		Observe: func(job Job, status Status) error {
			statuses <- restoredPublisherStatus{job: job.ID, status: status}
			return nil
		}})
	defer func() {
		if err := join(); err != nil {
			t.Error("fenced publisher deferred join failed", err)
		}
	}()
	blocked := restoredPublisherStatusUntil(t, statuses, func(e restoredPublisherStatus) bool {
		return e.status.State == JobBlocked || e.status.State == JobRetrying || e.status.State == JobReady
	})
	if blocked.status.State != JobBlocked || blocked.status.Failure != string(failure.ServerConflict) || blocked.status.Attempts != 1 || attempts.Load() != 1 || f.Runs.Load() != 1 {
		t.Fatal("fenced preparation lost exact blocked failure/count", blocked, attempts.Load(), f.Runs.Load())
	}
	if err := join(); err != nil {
		t.Fatal("fenced publisher cleanup failed independently", err)
	}
	restoredAssertSingleRuntime(t, runtime, job.PublisherIdentityID)
	if attempts.Load() != 1 {
		t.Fatal("fenced publisher prepared a second attempt")
	}
}

type restoredCloseFailureControl struct {
	publisheridentity.ServiceControl
	failure error
}

func (c restoredCloseFailureControl) CloseServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken) error {
	return errors.Join(c.ServiceControl.CloseServiceRun(ctx, service, run, token), c.failure)
}

func TestInstalledRealPublisherPreservesIndependentCloseFailure(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	f, runtime := restoredPublisherFixture(t)
	r := testRegistry(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(target.Close)
	job, _, _ := restoredInstallPublisher(t, r, f, "cleanup", target.URL, false)
	independent := errors.New("independent close response failure")
	clients := restoredPublisherClients(t, f, runtime, f.HTTP.Transport)
	statuses := make(chan restoredPublisherStatus, 64)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	engine := Engine{Registry: r, PollInterval: 5 * time.Millisecond, Clients: func(job Job) (PublisherClients, publisheridentity.EnrollmentAuthority, error) {
		control, authority, err := clients(job)
		control.Services = restoredCloseFailureControl{ServiceControl: control.Services, failure: independent}
		return control, authority, err
	}, Observe: func(job Job, status Status) error {
		statuses <- restoredPublisherStatus{job: job.ID, status: status}
		return nil
	}}
	go func() { done <- engine.Serve(ctx) }()
	joined := false
	defer func() {
		cancel()
		if !joined {
			select {
			case err := <-done:
				if !errors.Is(err, independent) {
					t.Error("cleanup discarded independent failure", err)
				}
			case <-time.After(2 * time.Second):
				t.Error("publisher cleanup did not join within 2s")
			}
		}
	}()
	restoredPublisherStatusUntil(t, statuses, func(e restoredPublisherStatus) bool { return e.status.State == JobReady })
	cancel()
	select {
	case err := <-done:
		joined = true
		if !errors.Is(err, independent) {
			t.Fatal("cancellation hid actual publisher close failure", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("publisher close did not join within 2s")
	}
	restoredAssertSingleRuntime(t, runtime, job.PublisherIdentityID)
}

func TestInstalledRuntimeFixtureRejectsWrongAudienceScopeAndEpoch(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	f, runtime := restoredPublisherFixture(t)
	r := testRegistry(t)
	job, identity, key := restoredInstallPublisher(t, r, f, "proof", "http://127.0.0.1:3000", false)
	owner, err := processidentity.New(runtime, f.URL, identity.ClientId, identity.KeyId, identity.GrantId, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Renew(t.Context()); err != nil {
		t.Fatal(err)
	}
	accepted := runtime.Requests()
	run := accepted[len(accepted)-1].ProcessRunId
	for _, test := range []struct {
		name, audience, scope string
		epoch                 int64
	}{
		{"audience", "https://control.example", identity.GrantId, 1},
		{"scope", f.URL, "pg_0000000000000000000000", 1},
		{"epoch", f.URL, identity.GrantId, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertion, err := publisherproof.Sign(identity.ClientId, identity.KeyId, publisherproof.RuntimeScope(test.scope, "renew", run, test.epoch, ""),
				test.audience+"/v1/publisher/runtimes/"+identity.ClientId+"/renew", key, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := runtime.PublisherRuntime(t.Context(), controlv1.PublisherRuntimeRequest{PublisherIdentityId: identity.ClientId, ScopeId: test.scope,
				ProcessRunId: run, ExpectedEpoch: test.epoch, Action: controlv1.RuntimeRenew, Assertion: assertion}); err == nil {
				t.Fatal("runtime accepted wrong " + test.name)
			}
		})
	}
	if _, err := owner.Renew(t.Context()); err != nil {
		t.Fatal("negative proof changed valid runtime authority", err)
	}
	if err := owner.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if job.Server != f.URL {
		t.Fatal("test rewrote the service's actual server")
	}
}
