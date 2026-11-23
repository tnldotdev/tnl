package local

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/config"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	telemetryv1 "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

type restoredWorkerCapture struct {
	service publisherapp.Service
	config  publisherservice.RunConfig
}

func restoredConfiguredWorkers(t *testing.T, definitions config.Services, aliases map[string]config.Alias, resolver targetplan.TargetResolver) (*appRuntime, *publishingtest.Fixture, <-chan restoredWorkerCapture) {
	t.Helper()
	f := publishingtest.New(t, testutil.PublishingHooks{})
	transport, err := f.Transport()
	if err != nil {
		t.Fatal(err)
	}
	original := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { transport.CloseIdleConnections(); http.DefaultTransport = original })
	t.Setenv("TNL_SERVER", f.URL)
	t.Setenv("TNL_ACCESS_TOKEN", f.OwnerToken)
	a, _ := testAppRuntimeWorkers(t, true)
	a.project.Config = config.TNL{Server: &f.URL, Services: definitions, Aliases: aliases}
	a.project.Selection = clientproject.Selection{Path: filepath.Join(a.project.Root, "tnl.json")}
	a.TargetResolver = resolver
	if err := a.manager.Configure(publisherapp.ConfiguredServices(a.project)); err != nil {
		t.Fatal(err)
	}
	source := a.project.LocalPublicationIdentity()
	salt, err := a.state.WorktreeHashSalt(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	hash := hmac.New(sha256.New, salt[:])
	_, _ = hash.Write([]byte(f.URL + "\x00tm_0000000000000000000001\x00" + a.project.LocalWorktreeKey()))
	declarations := map[string]controlv1.ProjectServiceConfiguration{}
	for name, definition := range definitions {
		declarations[name] = controlv1.ProjectServiceConfiguration{Name: new(name), Protocol: new(controlv1.ServiceProtocolHTTP), Target: "app", Public: definition.Public}
	}
	if err := f.ConfigureLocal(publishingtest.LocalProject{Key: source.Key, Fingerprint: source.Fingerprint,
		Worktree: a.project.LocalWorktreeKey(), Label: a.project.Worktree.Label.FullLabel,
		PreviewKey: hex.EncodeToString(hash.Sum(nil)), Services: declarations}); err != nil {
		t.Fatal(err)
	}
	captured := make(chan restoredWorkerCapture, 16)
	a.AttachPublication = func(_ context.Context, service publisherapp.Service, cfg *publisherservice.RunConfig) error {
		// observe the configuration immediately before the real publisher, without
		// changing its callbacks, collector, control, or publication operation.
		captured <- restoredWorkerCapture{service: service, config: *cfg}
		return nil
	}
	return a, f, captured
}

func restoredWorkerReceive[T any](t *testing.T, channel <-chan T, bound time.Duration) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(bound):
		t.Fatal("worker boundary was not reached")
		var zero T
		return zero
	}
}

func restoredAliasCandidateEvidence(ctx context.Context, a *appRuntime, f *publishingtest.Fixture) string {
	counts := fmt.Sprintf("enrollments=%d runs=%d allocations=%d", f.Enrollments.Load(), f.Runs.Load(), f.Allocations.Load())
	service, found := f.LocalService(ctx, "web")
	if !found {
		return counts + "; entry service not realized"
	}
	authority, err := clientauthority.New(f.URL, f.HTTP, credentials.AccessToken(f.OwnerToken))
	if err != nil {
		return fmt.Sprintf("%s; authority client: %+v", counts, err)
	}
	identity, err := authority.IdentityContext(ctx)
	if err != nil {
		return fmt.Sprintf("%s; current membership read: %+v", counts, err)
	}
	for _, membership := range identity.Memberships {
		if membership.TeamId != service.TeamId {
			continue
		}
		selection, err := a.state.AliasSelection(ctx, clientstate.AliasScope{Server: f.URL,
			ProjectKey: clientproject.SharedProjectIdentity(a.project.Worktree, a.project.Root),
			TeamID:     service.TeamId, MembershipID: membership.Id, Namespace: f.Namespace, Name: "stable"})
		if err != nil {
			return fmt.Sprintf("%s; actual alias selection: %+v", counts, err)
		}
		current, receiver, err := a.state.AliasCandidate(ctx, selection.ID)
		return fmt.Sprintf("%s; alias candidate=%+v receiver=%+v candidate error=%+v", counts, current, receiver, err)
	}
	return counts + "; actual entry service has no current membership"
}

func restoredAliasWorkerFailure(t *testing.T, a *appRuntime, f *publishingtest.Fixture, registration publisherprotocol.Registration, message string) {
	t.Helper()
	snapshot := a.manager.Snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	journal, journalErr := a.state.SnapshotProject(ctx, a.project.Root)
	candidate := restoredAliasCandidateEvidence(ctx, a, f)
	cancel()
	done := make(chan error, 1)
	go func() {
		done <- a.manager.UnregisterTarget(registration.RegistrationID, registration.Owner, registration.Target)
	}()
	select {
	case err := <-done:
		t.Fatalf("%s; joined worker/cleanup error: %+v; services: %+v; journal: %+v; journal error: %+v; setup evidence: %s",
			message, err, snapshot.Services, journal, journalErr, candidate)
	case <-time.After(2 * time.Second):
		t.Fatalf("%s; worker/cleanup did not join within 2s; services: %+v; journal: %+v; journal error: %+v; setup evidence: %s",
			message, snapshot.Services, journal, journalErr, candidate)
	}
}

func restoredAliasPublication(t *testing.T, a *appRuntime, f *publishingtest.Fixture, registration publisherprotocol.Registration, captured <-chan restoredWorkerCapture) restoredWorkerCapture {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case publication := <-captured:
			if publication.service.RegistrationID != registration.RegistrationID || publication.service.Target != registration.Target {
				restoredAliasWorkerFailure(t, a, f, registration, "alias parent capture returned another registration/target")
			}
			return publication
		case <-tick.C:
			if service, found := a.manager.ServiceForRegistration(registration.RegistrationID); found && service.Failure != "" {
				restoredAliasWorkerFailure(t, a, f, registration, "alias parent failed before publication capture: "+service.Failure)
			}
		case <-deadline.C:
			restoredAliasWorkerFailure(t, a, f, registration, "alias parent publication capture was not reached within 2s")
		}
	}
}

func restoredAliasPreparation(t *testing.T, a *appRuntime, f *publishingtest.Fixture, registration publisherprotocol.Registration) {
	t.Helper()
	// an initially unready receiver follows the inherited four-second election
	// cadence. observe the real alias preparation before its readiness assertion;
	// this admission test does not assert a two-second cold-start guarantee.
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for f.Runs.Load() < 2 {
		select {
		case <-deadline.C:
			restoredAliasWorkerFailure(t, a, f, registration, "real alias preparation did not follow its four-second eligibility check within 5s")
		case <-tick.C:
		}
	}
	if f.Runs.Load() != 2 || f.Enrollments.Load() != 2 || f.Allocations.Load() != 0 {
		t.Fatal("alias setup did not prepare exactly its own enrolled saved service")
	}
}

func restoredWorkerService(t *testing.T, a *appRuntime, name string, predicate func(publisherapp.Service) bool) publisherapp.Service {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		for _, service := range a.manager.Snapshot().Services {
			if service.Name == name && predicate(service) {
				return service
			}
			if service.Name == name && service.Failure != "" {
				t.Fatalf("configured worker failed: %s", service.Failure)
			}
		}
		select {
		case <-deadline.C:
			t.Fatalf("configured publication did not reach its boundary within 2s: %+v", a.manager.Snapshot().Services)
		case <-tick.C:
		}
	}
}

func restoredRegisterApp(t *testing.T, a *appRuntime, name, target string, disabled bool) publisherprotocol.Registration {
	t.Helper()
	assignment, err := a.prepare(t.Context(), publisherprotocol.Prepare{Version: 1, Directory: a.project.Root,
		Service: name, Owner: strings.Repeat("a", 32), PID: os.Getpid(), Framework: publisherprotocol.FrameworkNode, TelemetryDisabled: disabled})
	if err != nil {
		t.Fatal(err)
	}
	registration := publisherprotocol.Registration{Version: 1, RegistrationID: assignment.RegistrationID, Owner: strings.Repeat("a", 32), Target: target}
	if err := a.register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	return registration
}

func restoredUnregister(t *testing.T, a *appRuntime, registration publisherprotocol.Registration) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- a.manager.UnregisterTarget(registration.RegistrationID, registration.Owner, registration.Target)
	}()
	if err := restoredWorkerReceive(t, done, 2*time.Second); err != nil {
		t.Fatal("independent publication cleanup failure", err)
	}
}

func restoredWorkerCollector(t *testing.T) (*clienttelemetry.Collector, func() int64) {
	t.Helper()
	var mu sync.Mutex
	var connections int64
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(io.LimitReader(r.Body, telemetryv1.MaximumBatchBytes+1))
		var batch telemetryv1.Batch
		if err != nil || telemetryv1.ValidateBatch(data) != nil || json.Unmarshal(data, &batch) != nil {
			t.Error("collector delivered an invalid batch", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for _, collected := range batch.Events {
			event, err := collected.Event.AsTransportEvent()
			if err == nil && event.Name == "transport.report" && event.Payload.Role == telemetryv1.TransportReportRolePublisher {
				for _, measurement := range event.Payload.Measurements {
					if measurement.Operation == telemetryv1.RelayConnect && measurement.Outcome == telemetryv1.Succeeded {
						connections += measurement.Count
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
	if err := state.SetTelemetryEnabled(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	collector, err := clienttelemetry.New(t.Context(), clienttelemetry.Config{Root: root, Protection: clientstate.ProtectionFile,
		Endpoint: receiver.URL, Client: &http.Client{Timeout: clienttelemetry.RequestTimeout}, Interval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	closeCollector := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		collector.Close(ctx)
	}
	t.Cleanup(closeCollector)
	return collector, func() int64 { closeCollector(); mu.Lock(); defer mu.Unlock(); return connections }
}

func TestConfiguredWorkersSelectCollectorAtRealPublicationBoundary(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	collector, delivered := restoredWorkerCollector(t)
	a, f, captured := restoredConfiguredWorkers(t, config.Services{"web": {Public: new(true)}, "api": {Public: new(true)}}, nil, nil)
	a.Telemetry = collector
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(target.Close)
	web := restoredRegisterApp(t, a, "web", target.URL, true)
	api := restoredRegisterApp(t, a, "api", target.URL, false)
	seen := map[string]bool{}
	for range 2 {
		actual := restoredWorkerReceive(t, captured, 2*time.Second)
		if seen[actual.service.Name] || actual.service.Name != "web" && actual.service.Name != "api" {
			t.Fatal("publication capture did not contain the two distinct configured siblings")
		}
		seen[actual.service.Name] = true
		want := collector
		if actual.service.Name == "web" {
			want = nil
		}
		if actual.config.Telemetry != want || actual.config.ServiceID == "" || actual.config.PublisherIdentityID == "" ||
			actual.config.PublisherGrantID == "" || actual.config.PublisherKeyID == "" || actual.config.Prepared == nil || actual.config.AdmitRequest == nil {
			t.Fatal("configured-project publication lost its collector or real signed callbacks")
		}
	}
	if len(seen) != 2 {
		t.Fatal("a configured sibling bypassed the real publication boundary")
	}
	for _, name := range []string{"web", "api"} {
		restoredWorkerService(t, a, name, func(s publisherapp.Service) bool { return s.Routable })
	}
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	snapshot, err := a.workers.Check(ctx, nil)
	cancel()
	if err != nil || len(snapshot.Services) != 2 || !snapshot.Services[0].Ready || !snapshot.Services[1].Ready {
		t.Fatal("real owner proofs did not establish sibling readiness within 250ms", err)
	}
	restoredUnregister(t, a, web)
	restoredUnregister(t, a, api)
	if f.Enrollments.Load() != 2 || f.Runs.Load() != 2 || f.Allocations.Load() != 0 {
		t.Fatal("configured workers bypassed saved-service enrollment/publication")
	}
	if count := delivered(); count != 2 {
		t.Fatalf("publisher transport deliveries=%d, want exactly two successful connections from the enabled sibling", count)
	}
}

func TestConfiguredAdmissionAndAliasRejectStaleRegistration(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, f, captured := restoredConfiguredWorkers(t, config.Services{"web": {Public: new(true)}}, map[string]config.Alias{"stable": {Service: "web"}}, nil)
	// a non-git project's worktree root is still its actual canonical directory.
	// aliases use this fact for their shared integration scope before publishing.
	a.project.Worktree.Root = a.project.Root
	if clientproject.SharedProjectIdentity(a.project.Worktree, a.project.Root) != a.project.Root {
		t.Fatal("alias fixture lost its actual primary project directory")
	}
	var alive atomic.Bool
	alive.Store(true)
	a.manager.Alive = func(int) bool { return alive.Load() }
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetRequests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	registration := restoredRegisterApp(t, a, "web", target.URL, false)
	old := restoredAliasPublication(t, a, f, registration, captured).config
	current := restoredWorkerService(t, a, "web", func(s publisherapp.Service) bool { return s.Routable })
	if !a.manager.CurrentRegistration("web", registration.RegistrationID, target.URL) || !a.manager.CurrentRun("web", registration.RegistrationID, target.URL, current.RunNumber) {
		t.Fatal("real run never became current")
	}
	restoredAliasPreparation(t, a, f, registration)
	var alias clientstate.AliasInfo
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for alias.ServiceID == "" {
		snapshot, err := a.state.SnapshotProject(t.Context(), a.project.Root)
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range snapshot.Aliases {
			if candidate.Name == "stable" && candidate.State == "ready" {
				alias = candidate
			}
		}
		if alias.ServiceID != "" {
			break
		}
		select {
		case <-deadline.C:
			restoredAliasWorkerFailure(t, a, f, registration, "real attached alias did not become ready within 2s")
		case <-tick.C:
		}
	}
	permission, err := f.OwnerVisitorToken(t.Context(), alias.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	if permission.Resource.Kind != controlv1.VisitorResourceScopeKindService || permission.Resource.Id != alias.ServiceID ||
		permission.Hostname != alias.Hostname || permission.Port != 443 || permission.VisitorToken == "" {
		t.Fatal("owner visitor permission did not bind the actual alias endpoint")
	}
	headers := http.Header{httpaccess.VisitorTokenHeader: {permission.VisitorToken}}
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	status, _, _, err := f.VisitWithHeaders(ctx, alias.PublicURL, headers)
	cancel()
	if err != nil || status != http.StatusNoContent {
		t.Fatal("alias did not serve the real parent target", status, err)
	}
	request := httptest.NewRequest(http.MethodGet, current.PublicURL, nil)
	if err := old.AdmitRequest(request); err != nil {
		t.Fatal("current production admission rejected its run", err)
	}
	before := targetRequests.Load()
	alive.Store(false)
	if err := old.AdmitRequest(request); !errors.Is(err, publisherapp.ErrRegistrationStale) {
		t.Error("production admission accepted a dead registration", err)
	}
	ctx, cancel = context.WithTimeout(t.Context(), 250*time.Millisecond)
	status, _, _, err = f.VisitWithHeaders(ctx, alias.PublicURL, headers)
	cancel()
	if err != nil || status != http.StatusServiceUnavailable || targetRequests.Load() != before {
		t.Error("attached alias bypassed the parent's stale-registration admission", status, err, targetRequests.Load()-before)
	}
	alive.Store(true)
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(second.Close)
	replaced := make(chan error, 1)
	go func() {
		replaced <- a.manager.Register(registration.RegistrationID, registration.Owner, second.URL, "")
	}()
	if err := restoredWorkerReceive(t, replaced, 2*time.Second); err != nil {
		t.Fatal("replacement lost cleanup failure", err)
	}
	nextRegistration := registration
	nextRegistration.Target = second.URL
	next := restoredAliasPublication(t, a, f, nextRegistration, captured).config
	restoredWorkerService(t, a, "web", func(s publisherapp.Service) bool { return s.Routable && s.Target == second.URL })
	if a.manager.CurrentRegistration("web", registration.RegistrationID, target.URL) ||
		!errors.Is(old.AdmitRequest(request), publisherapp.ErrRegistrationStale) || !errors.Is(old.Ready(), publisherapp.ErrRegistrationStale) {
		t.Error("old registration/run callbacks crossed actual listener replacement")
	}
	if err := next.AdmitRequest(request); err != nil {
		t.Fatal("new production admission was not current", err)
	}
	registration.Target = second.URL
	restoredUnregister(t, a, registration)
	if a.manager.CurrentRegistration("web", registration.RegistrationID, second.URL) ||
		!errors.Is(next.AdmitRequest(request), publisherapp.ErrRegistrationStale) || !errors.Is(next.Ready(), publisherapp.ErrRegistrationStale) {
		t.Error("actual unregister retained request or run callback authority")
	}
}

func TestConfiguredProbeRejectsHeldSameAddressTargetIdentity(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	var identity atomic.Value
	identity.Store("container-one")
	var armed atomic.Bool
	entered, release := make(chan struct{}, 8), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if armed.Load() {
			select {
			case entered <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	resolver := targetplan.TargetResolverFunc(func(context.Context, clientproject.Project, string) (string, string, error) {
		return target.Listener.Addr().String(), identity.Load().(string), nil
	})
	a, f, captured := restoredConfiguredWorkers(t, config.Services{"web": {Public: new(false),
		Target: &config.ServiceTarget{Type: "docker", Container: new("app"), Port: new(3000)}}}, nil, resolver)
	_, digest, err := a.project.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	registration, err := a.acquire(t.Context(), publisherprotocol.Lease{Service: "web", Owner: strings.Repeat("a", 32), Pid: os.Getpid(), ConfigurationDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	if registration.Target != target.URL {
		t.Fatal("container host:port did not pass through normal HTTP target conversion")
	}
	actual := restoredWorkerReceive(t, captured, 2*time.Second).config
	current := restoredWorkerService(t, a, "web", func(s publisherapp.Service) bool { return s.Routable })
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	snapshot, err := a.workers.Check(ctx, []string{"web"})
	cancel()
	if err != nil || !snapshot.Services[0].Ready {
		t.Fatal("initial actual target probe failed", err)
	}
	armed.Store(true)
	result := make(chan bool, 1)
	ctx, cancel = context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	go func() { result <- actual.Healthy(ctx) }()
	restoredWorkerReceive(t, entered, 250*time.Millisecond)
	identity.Store("container-two")
	address, capturedIdentity, err := actual.ResolveHTTPTarget(httptest.NewRequest(http.MethodGet, "https://service.example", nil))
	if err != nil || address != target.URL || capturedIdentity != "container-two" {
		t.Fatal("HTTP target did not follow same-address identity replacement", err)
	}
	changed := a.manager.Snapshot().Services[0]
	if changed.Ready || changed.RunNumber != current.RunNumber || !changed.Routable || f.Runs.Load() != 1 {
		t.Fatal("HTTP identity change restarted the run or retained readiness")
	}
	unblock()
	if restoredWorkerReceive(t, result, 250*time.Millisecond) {
		t.Error("held real target probe accepted the old same-address identity")
	}
	armed.Store(false)
	ctx, cancel = context.WithTimeout(t.Context(), 250*time.Millisecond)
	snapshot, err = a.workers.Check(ctx, []string{"web"})
	cancel()
	if err != nil || !snapshot.Services[0].Ready || snapshot.Services[0].RunNumber != current.RunNumber {
		t.Error("fresh explicit target check did not restore readiness on the same run", err)
	}
	restoredUnregister(t, a, registration)
}

func TestConfiguredPublicReplacementGetsFreshAutomaticReadinessProof(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	var identity atomic.Value
	identity.Store("container-one")
	var requests atomic.Int32
	oldEntered, newEntered := make(chan struct{}), make(chan struct{})
	extraRequest := make(chan struct{}, 1)
	oldRelease, newRelease := make(chan struct{}), make(chan struct{})
	releaseOld := sync.OnceFunc(func() { close(oldRelease) })
	releaseNew := sync.OnceFunc(func() { close(newRelease) })
	defer releaseOld()
	defer releaseNew()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(publisherapp.ProbeHeader) != "" {
			t.Error("private readiness proof reached the target")
		}
		// publication heartbeats have their own local target check. count only
		// public-host GETs carried through the real visitor TLS/proof boundary.
		if strings.HasPrefix(r.Host, "127.0.0.1:") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var release <-chan struct{}
		switch requests.Add(1) {
		case 1:
		case 2:
			close(oldEntered)
			release = oldRelease
		case 3:
			close(newEntered)
			release = newRelease
		default:
			select {
			case extraRequest <- struct{}{}:
			default:
			}
		}
		if release != nil {
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	resolver := targetplan.TargetResolverFunc(func(context.Context, clientproject.Project, string) (string, string, error) {
		return target.Listener.Addr().String(), identity.Load().(string), nil
	})
	a, f, captured := restoredConfiguredWorkers(t, config.Services{"web": {Public: new(true),
		Target: &config.ServiceTarget{Type: "docker", Container: new("app"), Port: new(3000)}}}, nil, resolver)
	a.workers.AutomaticReadiness = true
	proofs := make(chan *httpaccess.ReadinessProof, 1)
	attach := a.AttachPublication
	a.AttachPublication = func(ctx context.Context, service publisherapp.Service, cfg *publisherservice.RunConfig) error {
		if err := attach(ctx, service, cfg); err != nil {
			return err
		}
		prepareProof := cfg.ReadinessProof
		cfg.ReadinessProof = func(run httpaccess.ReadinessRun) *httpaccess.ReadinessProof {
			proof := prepareProof(run)
			proofs <- proof
			return proof
		}
		return nil
	}
	_, digest, err := a.project.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	registration, err := a.acquire(t.Context(), publisherprotocol.Lease{Service: "web", Owner: strings.Repeat("a", 32), Pid: os.Getpid(), ConfigurationDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	actual := restoredWorkerReceive(t, captured, 2*time.Second).config
	proof := restoredWorkerReceive(t, proofs, 2*time.Second)
	current := restoredWorkerService(t, a, "web", func(s publisherapp.Service) bool { return s.Ready })
	if requests.Load() != 1 || proof == nil || proof.HeaderValue() != "" {
		t.Fatal("startup did not perform one proved public GET")
	}
	// hold a real success from the old identity while a visitor's target capture
	// detects its replacement at the exact same listener address.
	result := make(chan publisherapp.Snapshot, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	go func() {
		snapshot, err := a.workers.Check(ctx, []string{"web"})
		if err != nil {
			t.Error(err)
		}
		result <- snapshot
	}()
	restoredWorkerReceive(t, oldEntered, 2*time.Second)
	if proof.HeaderValue() != "" {
		t.Fatal("old public GET did not consume its renewed proof")
	}
	identity.Store("container-two")
	address, selected, err := actual.ResolveHTTPTarget(httptest.NewRequest(http.MethodGet, current.PublicURL, nil))
	if err != nil || address != target.URL || selected != "container-two" {
		t.Fatal("visitor did not detect same-address replacement", err)
	}
	if changed := a.manager.Snapshot().Services[0]; changed.Ready || !changed.Routable || changed.RunNumber != current.RunNumber {
		t.Fatal("replacement retained saved readiness or replaced its publication")
	}
	releaseOld()
	stale := restoredWorkerReceive(t, result, 2*time.Second)
	if stale.Services[0].Ready {
		t.Fatal("held success restored readiness for the old target identity")
	}
	restoredWorkerReceive(t, newEntered, 2*time.Second)
	if proof.HeaderValue() != "" || requests.Load() != 3 {
		t.Fatal("replacement did not consume a fresh proof in its new public GET")
	}
	if a.manager.Snapshot().Services[0].Ready {
		t.Fatal("replacement became ready before its new public response")
	}
	releaseNew()
	ready := restoredWorkerService(t, a, "web", func(s publisherapp.Service) bool { return s.Ready })
	if ready.RunNumber != current.RunNumber || f.Runs.Load() != 1 || ready.Observation == nil || ready.Observation.Status != http.StatusNoContent {
		t.Fatal("fresh proved response did not restore readiness on the current run")
	}
	select {
	case <-extraRequest:
		t.Fatal("automatic readiness continued polling after replacement success")
	case <-time.After(100 * time.Millisecond):
	}
	restoredUnregister(t, a, registration)
}

func TestConfiguredProjectFixtureRejectsScopeAndCredentialChanges(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, f, _ := restoredConfiguredWorkers(t, config.Services{"web": {Public: new(true)}}, nil, nil)
	owner, err := f.Owner()
	if err != nil {
		t.Fatal(err)
	}
	facts, err := owner.Discovery(t.Context())
	if err != nil || len(facts.Authentication.Methods) != 1 || facts.Authentication.Methods[0] != controlv1.Oidc ||
		facts.Authentication.Oidc == nil || facts.Authentication.Oidc.Issuer != f.URL || facts.Authentication.Oidc.LoginFlow != controlv1.DeviceCode {
		t.Fatal("configured fixture discovery omitted its advertised authentication facts", err)
	}
	source := a.project.LocalPublicationIdentity()
	body := controlv1.RealizeLocalProjectServiceRequest{TeamId: "tm_0000000000000000000001", SourceFingerprint: source.Fingerprint,
		WorktreeKey: a.project.LocalWorktreeKey(), Configuration: controlv1.ProjectServiceConfiguration{
			Name: new("web"), Protocol: new(controlv1.ServiceProtocolHTTP), Target: "app", Public: new(true)}}
	for _, test := range []struct {
		name   string
		change func(*controlv1.RealizeLocalProjectServiceRequest)
	}{
		{"team", func(r *controlv1.RealizeLocalProjectServiceRequest) { r.TeamId = "another-team" }},
		{"source", func(r *controlv1.RealizeLocalProjectServiceRequest) { r.SourceFingerprint = strings.Repeat("0", 64) }},
		{"worktree", func(r *controlv1.RealizeLocalProjectServiceRequest) { r.WorktreeKey = strings.Repeat("0", 64) }},
		{"label", func(r *controlv1.RealizeLocalProjectServiceRequest) { r.WorktreeLabel = new("another-checkout") }},
		{"declaration", func(r *controlv1.RealizeLocalProjectServiceRequest) { r.Configuration.Target = "another-target" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := body
			test.change(&changed)
			if _, err := owner.RealizeLocalProjectService(t.Context(), source.Key, "web", changed); err == nil {
				t.Fatal("fixture accepted another " + test.name)
			}
		})
	}
	if _, err := owner.RealizeLocalProjectService(t.Context(), source.Key+"-other", "web", body); err == nil {
		t.Fatal("fixture accepted another project")
	}
	if _, err := owner.RealizeLocalProjectService(t.Context(), source.Key, "other", body); err == nil {
		t.Fatal("fixture accepted another service")
	}
	if _, found := f.LocalService(t.Context(), "web"); found {
		t.Fatal("rejected realization created a saved service")
	}
	selected, err := owner.RealizeLocalProjectService(t.Context(), source.Key, "web", body)
	if err != nil {
		t.Fatal(err)
	}
	again, err := owner.RealizeLocalProjectService(t.Context(), source.Key, "web", body)
	if err != nil || again.ServiceId != selected.ServiceId {
		t.Fatal("exact realization was not idempotent", err)
	}
	saved, err := owner.GetService(t.Context(), selected.ServiceId)
	if err != nil || selected.Metadata == nil || selected.Metadata.Endpoint == nil || selected.Metadata.Endpoint.Hostname != saved.Endpoint.Hostname || selected.WorktreeKey != body.WorktreeKey {
		t.Fatal("realization was not backed by the actual saved service", err)
	}
	params := controlv1.GetLocalProjectServiceParams{TeamId: body.TeamId, SourceFingerprint: body.SourceFingerprint, WorktreeKey: body.WorktreeKey}
	if read, err := owner.GetLocalProjectService(t.Context(), source.Key, "web", params); err != nil || read.ServiceId != saved.Id {
		t.Fatal("exact management read changed its service", err)
	}
	for _, change := range []func(*controlv1.GetLocalProjectServiceParams){
		func(p *controlv1.GetLocalProjectServiceParams) { p.TeamId = "other" },
		func(p *controlv1.GetLocalProjectServiceParams) { p.SourceFingerprint = "other" },
		func(p *controlv1.GetLocalProjectServiceParams) { p.WorktreeKey = "other" },
	} {
		changed := params
		change(&changed)
		if _, err := owner.GetLocalProjectService(t.Context(), source.Key, "web", changed); err == nil {
			t.Fatal("fixture read another management scope")
		}
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.URL+"/v1/projects/"+source.Key+"/local-services/web?team_id="+body.TeamId+"&source_fingerprint="+body.SourceFingerprint+"&worktree_key="+body.WorktreeKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer not-the-management-credential")
	response, err := f.HTTP.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("fixture allowed a local read without its management credential")
	}
	if _, err := owner.CreatePreview(t.Context(), body.TeamId, "wrong-project-key"); err == nil {
		t.Fatal("fixture associated another project's preview")
	}
	salt, err := a.state.WorktreeHashSalt(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	hash := hmac.New(sha256.New, salt[:])
	_, _ = hash.Write([]byte(f.URL + "\x00" + body.TeamId + "\x00" + a.project.LocalWorktreeKey()))
	preview, err := owner.CreatePreview(t.Context(), body.TeamId, hex.EncodeToString(hash.Sum(nil)))
	if err != nil {
		t.Fatal(err)
	}
	outside, err := f.SavedService(t.Context(), "outside", controlv1.ProjectServiceConfiguration{Public: new(true)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.AddPreviewService(t.Context(), preview.Id, outside.Id); err == nil {
		t.Fatal("fixture included an unrealized service in the exact local preview")
	}
	included, err := owner.AddPreviewService(t.Context(), preview.Id, saved.Id)
	if err != nil || len(included.ServiceIds) != 1 || included.ServiceIds[0] != saved.Id {
		t.Fatal("fixture did not associate the actual local saved service", err)
	}
	if f.Enrollments.Load() != 0 || f.Runs.Load() != 0 {
		t.Fatal("management fixture manufactured publisher authorization or a run")
	}
}

func TestConfiguredTargetProbeCancellationKeepsPublicationAndJoins(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	var armed atomic.Bool
	entered, canceled, release := make(chan struct{}, 8), make(chan struct{}, 8), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if armed.Load() {
			select {
			case entered <- struct{}{}:
			default:
			}
			select {
			case <-r.Context().Done():
				select {
				case canceled <- struct{}{}:
				default:
				}
				return
			case <-release:
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	resolver := targetplan.TargetResolverFunc(func(context.Context, clientproject.Project, string) (string, string, error) {
		return target.Listener.Addr().String(), "container", nil
	})
	a, f, captured := restoredConfiguredWorkers(t, config.Services{"web": {Public: new(false), Target: &config.ServiceTarget{Type: "docker", Container: new("app"), Port: new(3000)}}}, nil, resolver)
	_, digest, err := a.project.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	registration, err := a.acquire(t.Context(), publisherprotocol.Lease{Service: "web", Owner: strings.Repeat("a", 32), Pid: os.Getpid(), ConfigurationDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	if registration.Target != target.URL {
		t.Fatal("container host:port did not pass through normal HTTP target conversion")
	}
	actual := restoredWorkerReceive(t, captured, 2*time.Second).config
	current := restoredWorkerService(t, a, "web", func(s publisherapp.Service) bool { return s.Routable })
	armed.Store(true)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan bool, 1)
	go func() { result <- actual.Healthy(ctx) }()
	restoredWorkerReceive(t, entered, 2*time.Second)
	cancel()
	restoredWorkerReceive(t, canceled, 2*time.Second)
	if restoredWorkerReceive(t, result, 2*time.Second) {
		t.Error("canceled real target probe reported healthy")
	}
	if after := a.manager.Snapshot().Services[0]; after.RunNumber != current.RunNumber || !after.Routable || after.Ready || f.Runs.Load() != 1 {
		t.Error("probe cancellation stopped or restarted the actual publication")
	}
	unblock()
	restoredUnregister(t, a, registration)
}
