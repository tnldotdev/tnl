package tnl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/localapi"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

type applicationJournalObservation struct {
	path, after string
	status      *publisherapp.Snapshot
	events      []publisherapp.Event
}

// the real manager, scoped API, and SQLite journal own lifecycle state. this
// fixture substitutes only source acceptance and the worker's event gates.
type applicationJournal struct {
	manager      *publisherapp.Manager
	database     *clientstate.Database
	project      string
	capabilities *publisherprotocol.Capabilities
	observed     chan applicationJournalObservation
	published    chan publisherprotocol.AcceptedPublication
	unregistered chan publisherprotocol.Registration
	mu           sync.Mutex
	initial      string
}

func newApplicationJournal(t *testing.T, run publisherapp.Run, cleanup func() error) *applicationJournal {
	t.Helper()
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	manager, err := publisherapp.New(t.Context(), project, database, nil, run)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	f := &applicationJournal{manager: manager, database: database, project: project,
		observed: make(chan applicationJournalObservation, 64), published: make(chan publisherprotocol.AcceptedPublication, 1), unregistered: make(chan publisherprotocol.Registration, 1)}
	server := httptest.NewUnstartedServer(nil)
	f.capabilities, err = publisherprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	api := &localapi.Server{Manager: manager, Database: database, Project: project, Capabilities: f.capabilities}
	api.PublishApplication = func(ctx context.Context, request publisherprotocol.ApplicationPublication) (publisherprotocol.AcceptedPublication, error) {
		f.mu.Lock()
		captured := f.initial != ""
		f.mu.Unlock()
		if !captured {
			return publisherprotocol.AcceptedPublication{}, errors.New("publication preceded the journal cursor read")
		}
		if err := manager.AddService(publisherapp.Service{Name: request.InvocationId, Directory: "."}); err != nil {
			return publisherprotocol.AcceptedPublication{}, err
		}
		hostname := strings.Repeat("a", 26) + ".apps.example"
		id, err := manager.Reserve(request.InvocationId, request.Owner, request.Pid, "https://"+hostname)
		if err != nil {
			return publisherprotocol.AcceptedPublication{}, err
		}
		if err := manager.SetCleanup(id, request.Owner, cleanup); err != nil {
			return publisherprotocol.AcceptedPublication{}, err
		}
		if err := manager.RegisterContext(ctx, id, request.Owner, request.Target, ""); err != nil {
			return publisherprotocol.AcceptedPublication{}, err
		}
		accepted := publisherprotocol.AcceptedPublication{}
		accepted.Registration = publisherprotocol.Registration{Version: 1, RegistrationID: id, Owner: request.Owner, Target: request.Target}
		accepted.PublicUrlId, accepted.Hostname, accepted.PublicUrl = "url_0123456789ABCDEFGHIJKL", hostname, "https://"+hostname
		f.published <- accepted
		return accepted, nil
	}
	api.UnregisterApplication = func(_ context.Context, _ string, registration publisherprotocol.Registration) error {
		select {
		case f.unregistered <- registration:
		default:
		}
		return manager.UnregisterTarget(registration.RegistrationID, registration.Owner, registration.Target)
	}
	handler := api.Handler()
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/status" && r.URL.Path != "/v1/events" {
			handler.ServeHTTP(w, r)
			return
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		observation := applicationJournalObservation{path: r.URL.Path, after: r.URL.Query().Get("after")}
		if response.Code == http.StatusOK {
			if r.URL.Path == "/v1/status" {
				if err := json.Unmarshal(response.Body.Bytes(), &observation.status); err != nil {
					t.Error(err)
				}
				f.mu.Lock()
				if f.initial == "" {
					f.initial = observation.status.Cursor
				}
				f.mu.Unlock()
			} else if err := json.Unmarshal(response.Body.Bytes(), &observation.events); err != nil {
				t.Error(err)
			}
		}
		select {
		case f.observed <- observation:
		case <-r.Context().Done():
		}
		for name, values := range response.Header() {
			w.Header()[name] = values
		}
		w.WriteHeader(response.Code)
		_, _ = io.Copy(w, response.Body)
	})
	server.Start()
	t.Cleanup(server.Close)
	return f
}

func (f *applicationJournal) runtime(_ context.Context, _ Options, invocation string) (publisherprotocol.Endpoint, error) {
	return f.capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &invocation})
}

// a subsequent event request proves the observer processed the held snapshot;
// a negative select immediately after the HTTP response alone would race it.
func (f *applicationJournal) throughBlankStage(t *testing.T, ctx context.Context, stopped <-chan struct{}) {
	t.Helper()
	seen := false
	for {
		select {
		case observation := <-f.observed:
			if seen && observation.path == "/v1/events" {
				return
			}
			if observation.status != nil {
				for _, service := range observation.status.Services {
					if service.Registered && !service.Routable && service.RunNumber > 0 && service.ProvisioningStage == "" {
						seen = true
					}
				}
			}
		case <-stopped:
			t.Fatal("SDK treated an intermediate blank-stage snapshot as terminal")
		case <-ctx.Done():
			t.Fatal("observer did not process the held blank-stage snapshot", context.Cause(ctx))
		}
	}
}

func assertApplicationListener(t *testing.T, target string, open bool) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get(target)
	if err == nil {
		_ = response.Body.Close()
	}
	if open && (err != nil || response.StatusCode != 204) || !open && err == nil {
		t.Fatalf("SDK listener open=%v: response=%v err=%v", open, response, err)
	}
}

func TestOpenInitialBlankStageWaitsForReadinessOrCancellation(t *testing.T) {
	for _, cancelBeforeReady := range []bool{false, true} {
		t.Run(map[bool]string{false: "ready", true: "cancel"}[cancelBeforeReady], func(t *testing.T) {
			ctx, stop := context.WithTimeout(t.Context(), 10*time.Second)
			defer stop()
			ctx, cancel := context.WithCancelCause(ctx)
			defer cancel(nil)
			ready, joined := make(chan struct{}), make(chan struct{})
			var cleaned atomic.Int32
			var once sync.Once
			f := newApplicationJournal(t, func(ctx context.Context, _ publisherapp.Service, observe func(uint64, bool) error) error {
				defer close(joined)
				if err := observe(1, false); err != nil {
					return err
				}
				select {
				case <-ready:
					if err := observe(1, true); err != nil {
						return err
					}
				case <-ctx.Done():
					return context.Cause(ctx)
				}
				<-ctx.Done()
				return context.Cause(ctx)
			}, func() error {
				select {
				case <-joined:
				default:
					t.Error("native cleanup preceded worker completion")
				}
				once.Do(func() { cleaned.Add(1) })
				return nil
			})
			var tunnel *Tunnel
			var openErr error
			opened := make(chan struct{})
			go func() {
				tunnel, openErr = openApplication(ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), sdkOptions(), f.runtime)
				close(opened)
			}()
			f.throughBlankStage(t, ctx, opened)
			accepted := <-f.published
			assertApplicationListener(t, accepted.Registration.Target, true)
			cause := errors.New("application owner stopped before readiness")
			if cancelBeforeReady {
				cancel(cause)
			} else {
				close(ready)
			}
			select {
			case <-opened:
			case <-ctx.Done():
				if !cancelBeforeReady {
					t.Fatal("Open did not observe readiness", context.Cause(ctx))
				}
				<-opened
			}
			if cancelBeforeReady {
				if tunnel != nil || !errors.Is(openErr, cause) {
					t.Fatal("canceled Open lost its exact cause", openErr)
				}
			} else {
				if openErr != nil || tunnel == nil {
					t.Fatal("Open did not wait for the actual ready observation", openErr)
				}
				if err := tunnel.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if cleaned.Load() != 1 || <-f.unregistered != accepted.Registration {
				t.Fatal("SDK changed its accepted registration or skipped joined cleanup")
			}
			assertApplicationListener(t, accepted.Registration.Target, false)
		})
	}
}

func TestOpenDrainingBlankStageWaitsForExplicitStoppedEventAndCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	drain, finish, cleanupStarted, cleanupRelease := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	var cleaned atomic.Int32
	f := newApplicationJournal(t, func(ctx context.Context, _ publisherapp.Service, observe func(uint64, bool) error) error {
		if err := observe(1, true); err != nil {
			return err
		}
		select {
		case <-drain:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
		if err := observe(1, false); err != nil {
			return err
		}
		select {
		case <-finish:
			return nil
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}, func() error {
		once.Do(func() {
			close(cleanupStarted)
			select {
			case <-cleanupRelease:
			case <-ctx.Done():
			}
			cleaned.Add(1)
		})
		return nil
	})
	tunnel, err := openApplication(ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), sdkOptions(), f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	accepted := <-f.published
	close(drain)
	f.throughBlankStage(t, ctx, tunnel.done)
	assertApplicationListener(t, accepted.Registration.Target, true)
	close(finish)
	select {
	case <-cleanupStarted:
	case <-ctx.Done():
		t.Fatal("native worker did not enter cleanup")
	}
	select {
	case <-tunnel.done:
		t.Fatal("SDK finished before native terminal cleanup")
	default:
	}
	assertApplicationListener(t, accepted.Registration.Target, true)
	close(cleanupRelease)
	select {
	case <-tunnel.done:
	case <-ctx.Done():
		t.Fatal("SDK missed the exact stopped event", context.Cause(ctx))
	}
	if err := tunnel.Wait(); err != nil {
		t.Fatal("explicit graceful stop became an SDK failure", err)
	}
	if cleaned.Load() != 1 || <-f.unregistered != accepted.Registration {
		t.Fatal("graceful stop replaced the registration or its cleanup")
	}
	assertApplicationListener(t, accepted.Registration.Target, false)
}

func TestOpenConsumesStoppedBeforeAcknowledgmentAndPreservesCleanupFailure(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "cleanup-failure"}[cleanupFails], func(t *testing.T) {
			f := newSDKNative(t, false)
			f.failCleanup = cleanupFails
			f.publicationEvents = func(service publisherapp.Service) []publisherapp.Event {
				return []publisherapp.Event{{Cursor: "sdk_terminal_cursor", Type: "service.stopped", Service: &service}}
			}
			tunnel, err := openApplication(t.Context(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), sdkOptions(), f.runtime)
			if tunnel != nil || !errors.Is(err, errApplicationStoppedBeforeReady) {
				t.Fatal("early explicit stop was not an Open failure", err)
			}
			var response *publisherprotocol.ResponseError
			if cleanupFails && (!errors.As(err, &response) || response.Code != "runtime.cleanup_failed") {
				t.Fatal("terminal observation hid the independent cleanup failure", err)
			}
			f.mu.Lock()
			reads, closes, requests, target := f.statusReads, f.closes, f.requests, f.request.Target
			f.mu.Unlock()
			if reads != 1 || closes != 1 || requests != 1 || <-f.eventsRead != "sdk_fixture_cursor" {
				t.Fatal("observer captured its cursor after publication, skipped an early stop, or replaced the invocation")
			}
			assertApplicationListener(t, target, false)
		})
	}
}

func TestOpenIgnoresOtherRegistrationTerminalEventsAndAdvancesEveryCursor(t *testing.T) {
	f := newSDKNative(t, true)
	f.publicationEvents = func(service publisherapp.Service) []publisherapp.Event {
		mutations := []func(*publisherapp.Service){
			func(s *publisherapp.Service) { s.Name = "ivk_another" },
			func(s *publisherapp.Service) { s.RegistrationID = "reg_another" },
			func(s *publisherapp.Service) { s.Target = "http://127.0.0.1:1" },
			func(s *publisherapp.Service) { s.PublicURL = "https://another.example" },
		}
		var events []publisherapp.Event
		for index, mutate := range mutations {
			other := service
			mutate(&other)
			events = append(events, publisherapp.Event{Cursor: fmt.Sprintf("sdk_cursor_%d", index), Type: "service.stopped", Service: &other})
		}
		return append(events, publisherapp.Event{Cursor: "sdk_cursor_unrelated", Type: "cursor"})
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	tunnel, err := openApplication(ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), sdkOptions(), f.runtime)
	if err != nil {
		t.Fatal("another registration's stop terminated this publication", err)
	}
	defer tunnel.Close()
	for _, expected := range []string{"sdk_fixture_cursor", "sdk_cursor_unrelated"} {
		select {
		case actual := <-f.eventsRead:
			if actual != expected {
				t.Fatalf("exclusive event cursor=%q, want %q", actual, expected)
			}
		case <-tunnel.done:
			t.Fatal("unrelated terminal event stopped SDK", tunnel.Wait())
		case <-ctx.Done():
			t.Fatal("observer did not advance all scoped cursors", context.Cause(ctx))
		}
	}
	if err := tunnel.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenExpiredEventCursorFailsWithoutGuessingOrResettingHistory(t *testing.T) {
	f := newSDKNative(t, false)
	f.eventsExpired = true
	tunnel, err := openApplication(t.Context(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), sdkOptions(), f.runtime)
	var response *publisherprotocol.ResponseError
	if tunnel != nil || !errors.As(err, &response) || response.Status != 410 || response.Code != "runtime.cursor_expired" {
		t.Fatal("lost journal history was inferred as a graceful stop or silently reset", err)
	}
	f.mu.Lock()
	reads, closes, requests, target := f.statusReads, f.closes, f.requests, f.request.Target
	f.mu.Unlock()
	if reads != 1 || closes != 1 || requests != 1 {
		t.Fatal("expired cursor reset status, reallocated, or skipped original cleanup")
	}
	assertApplicationListener(t, target, false)
}

func TestOpenStoppedEventJoinsSourceFailureAndRetainsFailedCleanup(t *testing.T) {
	f := newSDKNative(t, true)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	entered, joined := make(chan struct{}), make(chan struct{})
	independent := errors.New("independent source completion failed")
	var acquisitions atomic.Int32
	options := sdkOptions()
	options.OIDCSource.Assertion = func(ctx context.Context) (OIDCAssertion, error) {
		if acquisitions.Add(1) == 1 {
			return OIDCAssertion{Token: "private-proof", ExpiresAt: time.Now().Add(6 * time.Second)}, nil
		}
		close(entered)
		<-ctx.Done()
		close(joined)
		return OIDCAssertion{}, errors.Join(context.Cause(ctx), independent)
	}
	tunnel, err := openApplication(ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), options, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("source refresh did not start", context.Cause(ctx))
	}
	f.mu.Lock()
	service := publisherapp.Service{Name: f.request.InvocationId, RegistrationID: f.accepted.Registration.RegistrationID, Target: f.request.Target, PublicURL: f.accepted.PublicUrl}
	f.events = []publisherapp.Event{{Cursor: "sdk_stopped_cursor", Type: "service.stopped", Service: &service}}
	f.failCleanup = true
	target := f.request.Target
	f.mu.Unlock()
	select {
	case <-tunnel.done:
	case <-ctx.Done():
		t.Fatal("terminal event did not cancel and join source acquisition", context.Cause(ctx))
	}
	err = tunnel.Wait()
	var response *publisherprotocol.ResponseError
	if !errors.Is(err, independent) || !errors.As(err, &response) || response.Code != "runtime.cleanup_failed" {
		t.Fatal("terminal stop hid independent source or cleanup failure", err)
	}
	select {
	case <-joined:
	default:
		t.Fatal("Wait returned before the source worker joined")
	}
	assertApplicationListener(t, target, false)
	err = tunnel.Close()
	response = nil
	if !errors.Is(err, independent) || errors.As(err, &response) || acquisitions.Load() != 2 {
		t.Fatal("cleanup retry replaced source authority or discarded the operation failure", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed || f.closes != 2 {
		t.Fatal("failed original cleanup obligation was not retained")
	}
}
