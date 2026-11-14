package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPrivateHTTPRunChecksActualTargetAndFencesReplacement(t *testing.T) {
	w, _ := testWorkers(t)
	started := make(chan uint64, 4)
	callbacks := make(chan func(uint64, bool) error, 4)
	var number atomic.Uint64
	number.Store(16)
	w.Configure = func(_ context.Context, service Service) (Configuration, error) {
		return Configuration{Service: &ServicePublication{
			Options: clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: "https://control.example",
				Project: w.Manager.Snapshot().Project, Service: service.Name, Target: service.Target, ServiceProtocol: controlv1.ServiceProtocolHTTP},
			Run: func(ctx context.Context, observe func(uint64, bool) error, _ inspection.Observer) error {
				run := number.Add(1)
				if err := observe(run, false); err != nil {
					return err
				}
				if err := observe(run, true); err != nil {
					return err
				}
				callbacks <- observe
				started <- run
				<-ctx.Done()
				return ctx.Err()
			}, Check: func(ctx context.Context, service Service) Observation {
				return ProbeServiceTarget(ctx, service, targettransport.Transport{Protocol: config.ProtocolHTTP})
			},
		}}, nil
	}
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer second.Close()
	var replace atomic.Bool
	id := ""
	first := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/health" || request.Header.Get(ProbeHeader) != "" || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Error("private check used a public proof, app credentials or the wrong target path")
		}
		if replace.Load() {
			if err := w.Manager.Register(id, "owner", second.URL, "node"); err != nil {
				t.Error(err)
			}
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Error("replacement private run did not start")
			}
		}
		response.WriteHeader(http.StatusOK)
	}))
	defer first.Close()
	var err error
	id, err = w.Manager.Reserve("web", "owner", 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Manager.Register(id, "owner", first.URL, "node"); err != nil {
		t.Fatal(err)
	}
	select {
	case run := <-started:
		if run != 17 {
			t.Fatalf("private run=%d", run)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("private run did not start")
	}
	firstObserve := receiveServicePublication(t, callbacks)
	initial := w.Manager.Snapshot()
	if len(initial.Publications) != 1 || initial.Services[0].TunnelID == "" || initial.Services[0].TunnelID != initial.Publications[0].ID {
		t.Fatalf("private run has no bound local publication: %+v", initial)
	}
	snapshot, err := w.Check(t.Context(), []string{"web"})
	if err != nil || !snapshot.Services[0].Ready || snapshot.Services[0].PublicURL != "" || snapshot.Services[0].RunNumber != 17 {
		t.Fatalf("private readiness: %+v: %v", snapshot.Services, err)
	}
	replace.Store(true)
	snapshot, err = w.Check(t.Context(), []string{"web"})
	if err != nil || snapshot.Services[0].Ready || snapshot.Services[0].RunNumber != 18 || !snapshot.Services[0].Routable {
		t.Fatalf("stale private check crossed replacement: %+v: %v", snapshot.Services, err)
	}
	snapshot, err = w.Check(t.Context(), []string{"web"})
	if err != nil || !snapshot.Services[0].Ready || snapshot.Services[0].Observation.Status != http.StatusNoContent {
		t.Fatalf("replacement private check: %+v: %v", snapshot.Services, err)
	}
	if len(snapshot.Publications) != 1 || snapshot.Services[0].TunnelID == initial.Services[0].TunnelID || snapshot.Publications[0].ID != snapshot.Services[0].TunnelID {
		t.Fatalf("replacement retained the previous publication: %+v", snapshot)
	}
	if err := firstObserve(99, true); !errors.Is(err, ErrRegistrationStale) {
		t.Fatalf("stopped operation updated a replacement: %v", err)
	}
	if after := assertServicePublication(t, w, controlv1.ServiceProtocolHTTP, second.URL, clientstate.TunnelStateReady, 18, ""); snapshot.Cursor != after.Cursor || !reflect.DeepEqual(snapshot.Services, after.Services) {
		t.Fatalf("stale operation changed publication or readiness: before=%+v after=%+v", snapshot, after)
	}
}

func TestServicePublicationJournalsProvisioningBeforeManagerObservations(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol controlv1.ServiceProtocol
		target   string
		url      string
		prepared string
	}{
		{"public_http", controlv1.ServiceProtocolHTTP, "http://127.0.0.1:3000", "https://public.example", ""},
		{"prepared_http", controlv1.ServiceProtocolHTTP, "http://127.0.0.1:3000", "https://public.example", "https://public.example"},
		{"changed_endpoint", controlv1.ServiceProtocolHTTP, "http://127.0.0.1:3000", "https://public.example", "https://previous.example"},
		{"connector_http", controlv1.ServiceProtocolHTTP, "http://127.0.0.1:3000", "", ""},
		{"connector_tcp", controlv1.Tcp, "127.0.0.1:15432", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _ := testWorkers(t)
			if err := w.Manager.Configure([]Service{{Name: "web", ServiceProtocol: string(tc.protocol)}}); err != nil {
				t.Fatal(err)
			}
			provisioned, ready := make(chan error, 1), make(chan error, 1)
			promote := make(chan struct{})
			w.Configure = func(_ context.Context, service Service) (Configuration, error) {
				return Configuration{Service: &ServicePublication{
					Options: servicePublicationOptions(w, service), URL: tc.url,
					Run: func(ctx context.Context, observe func(uint64, bool) error, _ inspection.Observer) error {
						err := observe(7, false)
						provisioned <- err
						if err != nil {
							return err
						}
						select {
						case <-promote:
						case <-ctx.Done():
							return ctx.Err()
						}
						err = observe(7, true)
						ready <- err
						if err != nil {
							return err
						}
						<-ctx.Done()
						return ctx.Err()
					},
					Check: func(context.Context, Service) Observation { return Observation{} },
				}}, nil
			}
			cursor := w.Manager.Snapshot().Cursor
			id := registerServicePublication(t, w, tc.target, tc.prepared)
			if err := receiveServicePublication(t, provisioned); err != nil {
				t.Fatal(err)
			}
			starting := assertServicePublication(t, w, tc.protocol, tc.target, clientstate.TunnelStateProvisioning, 7, "")
			if starting.Services[0].Routable || starting.Services[0].Ready || starting.Services[0].PublicURL != tc.prepared {
				t.Fatal("provisioning was reported as routable or checked", starting)
			}
			close(promote)
			if err := receiveServicePublication(t, ready); err != nil {
				t.Fatal(err)
			}
			routable := assertServicePublication(t, w, tc.protocol, tc.target, clientstate.TunnelStateReady, 7, tc.url)
			if routable.Services[0].TunnelID != starting.Services[0].TunnelID || !routable.Services[0].Routable || routable.Services[0].Ready || routable.Services[0].PublicURL != tc.url {
				t.Fatal("ready publication lost its identity or invented readiness", routable)
			}
			events, err := EventsAfterFrom(t.Context(), w.Database, routable.Project, cursor)
			if err != nil {
				t.Fatal(err)
			}
			var transitions []string
			for _, event := range events {
				if publication := event.Publication; publication != nil && publication.ID == starting.Services[0].TunnelID && publication.PublishRunNumber == 7 {
					transitions = append(transitions, "publication."+string(publication.State))
					if publication.ServiceProtocol != tc.protocol || publication.PublicURLID != "" || tc.url == "" && (publication.PublicURL != "" || publication.Hostname != "") {
						t.Fatal("publication event lost its protocol or invented an endpoint", publication)
					}
				}
				if event.Type == "service.publication" && event.Service != nil {
					if event.Service.TunnelID != starting.Services[0].TunnelID || event.Service.RunNumber != 7 {
						t.Fatal("manager event lost the local publication identity", event)
					}
					state := "provisioning"
					if event.Service.Routable {
						state = "ready"
						if event.Service.PublicURL != tc.url {
							t.Fatal("ready observation omitted the realized endpoint", event)
						}
					} else if event.Service.PublicURL != tc.prepared {
						t.Fatal("provisioning changed the preparation endpoint", event)
					}
					transitions = append(transitions, "service."+state)
				}
			}
			want := []string{"publication.provisioning", "service.provisioning", "publication.ready", "service.ready"}
			if !reflect.DeepEqual(transitions, want) {
				t.Fatalf("journal must commit before manager observation: got=%v want=%v", transitions, want)
			}
			if err := w.Manager.UnregisterTarget(id, "owner", tc.target); err != nil {
				t.Fatal(err)
			}
			assertNoServicePublications(t, w)
		})
	}
}

func TestServicePublicationEndpointUsesBoundTargetAndRun(t *testing.T) {
	for _, tc := range []struct {
		name        string
		target      string
		run         uint64
		wrongTunnel bool
	}{
		{"current", "http://127.0.0.1:3000", 7, false},
		{"other_target", "http://127.0.0.1:4000", 7, false},
		{"other_run", "http://127.0.0.1:3000", 6, false},
		{"other_tunnel", "http://127.0.0.1:3000", 7, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _ := testWorkers(t)
			callbacks := make(chan func(PublicationUpdate) error, 1)
			w.Manager.run = func(ctx context.Context, _ Service, observe func(PublicationUpdate) error) error {
				callbacks <- observe
				<-ctx.Done()
				return ctx.Err()
			}
			target := "http://127.0.0.1:3000"
			id := registerServicePublication(t, w, target, "https://prepared.example")
			observe := receiveServicePublication(t, callbacks)
			bound, err := w.Database.BeginTunnel(t.Context(), servicePublicationOptions(w, Service{Name: "web", Target: target}))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := bound.Finish(t.Context(), nil); err != nil {
					t.Error(err)
				}
			}()
			if err := w.Manager.BindTunnel("web", id, target, bound.ID()); err != nil {
				t.Fatal(err)
			}
			if err := bound.SetProvisioning(t.Context(), 7); err != nil {
				t.Fatal(err)
			}
			if err := observe(PublicationUpdate{RunNumber: 7, TunnelID: bound.ID(), Target: target}); err != nil {
				t.Fatal(err)
			}
			if err := bound.SetReady(t.Context(), "https://current.example", 7); err != nil {
				t.Fatal(err)
			}
			sibling, err := w.Database.BeginTunnel(t.Context(), servicePublicationOptions(w, Service{Name: "other", Target: target}))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := sibling.Finish(t.Context(), nil); err != nil {
					t.Error(err)
				}
			}()
			if err := sibling.SetReady(t.Context(), "https://sibling.example", 7); err != nil {
				t.Fatal(err)
			}
			before := w.Manager.Snapshot()
			update := PublicationUpdate{RunNumber: tc.run, Routable: true, TunnelID: bound.ID(), Target: tc.target, PublicURL: "https://current.example"}
			if tc.wrongTunnel {
				update.TunnelID, update.PublicURL = sibling.ID(), "https://sibling.example"
			}
			stale := tc.target != target || tc.run != 7 || tc.wrongTunnel
			if err := observe(update); stale && !errors.Is(err, ErrRegistrationStale) || !stale && err != nil {
				t.Fatal("publication accepted mismatched completed facts", err)
			}
			after := w.Manager.Snapshot()
			want := "https://current.example"
			if stale {
				want = "https://prepared.example"
				if after.Cursor != before.Cursor || !reflect.DeepEqual(after.Services, before.Services) {
					t.Fatal("rejected publication changed the journal", after)
				}
			}
			if service := after.Services[0]; service.PublicURL != want || service.Routable == stale || service.Ready {
				t.Fatal("publication adopted another endpoint or conflated readiness", service)
			}
			before = after
			update.RunNumber = 6
			if err := observe(update); !errors.Is(err, ErrRegistrationStale) {
				t.Fatal("older run replaced the endpoint", err)
			}
			if after := w.Manager.Snapshot(); after.Cursor != before.Cursor || !reflect.DeepEqual(after.Services, before.Services) {
				t.Fatal("older run changed the endpoint observation", after)
			}
			if err := w.Manager.UnregisterTarget(id, "owner", target); err != nil {
				t.Fatal(err)
			}
			update.RunNumber = 9
			if err := observe(update); !errors.Is(err, ErrRegistrationStale) {
				t.Fatal("released registration accepted an endpoint", err)
			}
		})
	}
}

func TestServicePublicationUnregisterJoinsOperationBeforeDrainingInspection(t *testing.T) {
	for _, mode := range []inspection.Mode{inspection.SummaryMode, inspection.None} {
		t.Run(string(mode), func(t *testing.T) {
			w, _ := testWorkers(t)
			project := w.Manager.Snapshot().Project
			primary, shared := t.TempDir(), t.TempDir()
			started, canceled, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			type cleanupResult struct {
				records []clientstate.InspectionRecord
				err     error
			}
			cleaned := make(chan cleanupResult, 1)
			w.Configure = func(_ context.Context, service Service) (Configuration, error) {
				return Configuration{
					PrimaryRoot: primary, SharedRoot: shared,
					Inspection: inspection.Policy{Mode: mode, Retention: time.Hour, MaxBytes: 1 << 20},
					Cleanup: func() error {
						records, err := w.Database.ListInspections(context.Background(), clientstate.InspectionFilter{Project: project, SharedProject: shared, Limit: 10})
						cleaned <- cleanupResult{records, err}
						return err
					},
					Service: &ServicePublication{
						Options: servicePublicationOptions(w, service),
						Run: func(ctx context.Context, observe func(uint64, bool) error, summary inspection.Observer) error {
							if err := observe(11, false); err != nil {
								return err
							}
							if err := observe(11, true); err != nil {
								return err
							}
							now := time.Now().UTC()
							summary(inspection.Summary{Protocol: inspection.HTTP, ReceivedAt: now, Method: "GET", Path: "/initial", Status: 200, Result: inspection.ResultOK, Origin: "local_service"})
							close(started)
							<-ctx.Done()
							close(canceled)
							<-release
							summary(inspection.Summary{Protocol: inspection.HTTP, ReceivedAt: now.Add(time.Millisecond), Method: "GET", Path: "/shutdown", Status: 200, Result: inspection.ResultError, Origin: "local_service", Duration: 3 * time.Millisecond})
							close(joined)
							return ctx.Err()
						},
						Check: func(context.Context, Service) Observation { return Observation{} },
					},
				}, nil
			}
			target := "http://127.0.0.1:3000"
			id := registerServicePublication(t, w, target, "")
			receiveServicePublication(t, started)
			before := assertServicePublication(t, w, controlv1.ServiceProtocolHTTP, target, clientstate.TunnelStateReady, 11, "")
			unregistered := make(chan error, 1)
			go func() { unregistered <- w.Manager.UnregisterTarget(id, "owner", target) }()
			receiveServicePublication(t, canceled)
			select {
			case err := <-unregistered:
				t.Fatalf("unregister returned before the operation joined: %v", err)
			case <-cleaned:
				t.Fatal("configuration cleanup ran before the operation joined")
			default:
			}
			active, err := w.Database.SnapshotProject(t.Context(), project)
			if err != nil || len(active.Tunnels) != 1 || active.Tunnels[0].ID != before.Services[0].TunnelID {
				t.Fatalf("journal ended before the operation joined: %+v, %v", active, err)
			}
			releaseOnce.Do(func() { close(release) })
			if err := receiveServicePublication(t, unregistered); err != nil {
				t.Fatal(err)
			}
			select {
			case <-joined:
			default:
				t.Fatal("unregister did not join the operation")
			}
			cleanup := receiveServicePublication(t, cleaned)
			if cleanup.err != nil {
				t.Fatal(cleanup.err)
			}
			wantRecords := 2
			if mode == inspection.None {
				wantRecords = 0
			}
			if len(cleanup.records) != wantRecords {
				t.Fatalf("cleanup saw %d records, want %d: %+v", len(cleanup.records), wantRecords, cleanup.records)
			}
			for index, record := range cleanup.records {
				if record.TunnelID != before.Services[0].TunnelID || record.Project != project || record.PrimaryCheckoutRoot != primary || record.SharedProjectRoot != shared || record.Service != "web" || record.Protocol != inspection.HTTP {
					t.Fatal("inspection record lost its publication scope", record)
				}
				if index == 0 && (record.Path != "/shutdown" || record.Status != http.StatusOK || record.Result != inspection.ResultError || record.DurationMS != 3) ||
					index == 1 && (record.Path != "/initial" || record.Result != inspection.ResultOK) {
					t.Fatal("operation completion summary was lost or changed", record)
				}
			}
			assertNoServicePublications(t, w)
			if service := w.Manager.Snapshot().Services[0]; service.Registered || service.RegistrationID != "" || service.TunnelID != "" || service.RunNumber != 0 || service.Routable || service.Ready {
				t.Fatal("unregister retained live publication facts", service)
			}
			w.mu.Lock()
			proofs := len(w.proofs)
			w.mu.Unlock()
			if proofs != 0 {
				t.Fatal("unregister retained readiness state", proofs)
			}
		})
	}
}

func TestServicePublicationFailedStartupFinishesJournalAndInspection(t *testing.T) {
	w, _ := testWorkers(t)
	project := w.Manager.Snapshot().Project
	startup := failure.Wrap("start service run", failure.ServerUnavailable, errors.New("operation failed"))
	operationContext := make(chan context.Context, 1)
	w.Configure = func(_ context.Context, service Service) (Configuration, error) {
		return Configuration{
			Inspection: inspection.Policy{Mode: inspection.SummaryMode, Retention: time.Hour, MaxBytes: 1 << 20},
			Service: &ServicePublication{
				Options: servicePublicationOptions(w, service),
				Run: func(ctx context.Context, observe func(uint64, bool) error, summary inspection.Observer) error {
					operationContext <- ctx
					if err := observe(3, false); err != nil {
						return err
					}
					summary(inspection.Summary{Protocol: inspection.HTTP, ReceivedAt: time.Now().UTC(), Method: "GET", Path: "/startup", Status: 503, Result: inspection.ResultError, Origin: "tnl"})
					return startup
				},
				Check: func(context.Context, Service) Observation { return Observation{} },
			},
		}, nil
	}
	cursor := w.Manager.Snapshot().Cursor
	id := registerServicePublication(t, w, "http://127.0.0.1:3000", "")
	w.Manager.mu.Lock()
	done := w.Manager.registrations["web"].done
	w.Manager.mu.Unlock()
	receiveServicePublication(t, done)
	ctx := receiveServicePublication(t, operationContext)
	if ctx.Err() == nil {
		t.Fatal("failed startup left the journal lease context running")
	}
	assertNoServicePublications(t, w)
	service := w.Manager.Snapshot().Services[0]
	if service.TunnelID == "" || service.Routable || service.Ready || service.Failure != string(failure.ServerUnavailable) {
		t.Fatal("failed startup lost its publication identity or failure", service)
	}
	assertServicePublicationTerminal(t, w, cursor, service.TunnelID, clientstate.TunnelStateFailed, string(failure.ServerUnavailable))
	records, err := w.Database.ListInspections(t.Context(), clientstate.InspectionFilter{Project: project, SharedProject: project, Limit: 10})
	if err != nil || len(records) != 1 || records[0].TunnelID != service.TunnelID || records[0].Path != "/startup" {
		t.Fatalf("failed startup did not drain inspection: %+v, %v", records, err)
	}
	if err := w.Manager.Unregister(id, "owner"); !errors.Is(err, startup) || !errors.Is(err, ErrRegistrationStopped) {
		t.Fatal("failed startup was classified as a clean stop", err)
	}
}

func TestServicePublicationFailedBindingClosesUnboundJournal(t *testing.T) {
	cleanupCause := errors.New("binding cleanup failed")
	for _, tc := range []struct {
		name           string
		cleanupFailure error
		code           string
	}{
		{"cleanup_succeeds", nil, string(failure.Unexpected)},
		{"cleanup_fails", failure.Wrap("clean up failed binding", failure.ServerUnavailable, cleanupCause), string(failure.ServerUnavailable)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _ := testWorkers(t)
			operationCalled := false
			cleanupCalls := 0
			w.Configure = func(_ context.Context, service Service) (Configuration, error) {
				return Configuration{
					Cleanup: func() error {
						cleanupCalls++
						return tc.cleanupFailure
					},
					Service: &ServicePublication{
						Options: servicePublicationOptions(w, service),
						Run: func(context.Context, func(uint64, bool) error, inspection.Observer) error {
							operationCalled = true
							return nil
						},
						Check: func(context.Context, Service) Observation { return Observation{} },
					},
				}, nil
			}
			cursor := w.Manager.Snapshot().Cursor
			err := w.Run(t.Context(), Service{Name: "web", ServiceProtocol: "http", RegistrationID: "stale", Target: "http://127.0.0.1:3000"}, func(PublicationUpdate) error { return nil })
			if !errors.Is(err, ErrRegistrationStale) || operationCalled || cleanupCalls != 1 {
				t.Fatalf("failed binding ran the operation or skipped cleanup: err=%v operation=%v cleanup calls=%d", err, operationCalled, cleanupCalls)
			}
			if tc.cleanupFailure != nil && (!errors.Is(err, tc.cleanupFailure) || !errors.Is(err, cleanupCause)) {
				t.Fatal("failed binding lost the independent configuration cleanup failure", err)
			}
			assertNoServicePublications(t, w)
			events, err := EventsAfterFrom(t.Context(), w.Database, w.Manager.Snapshot().Project, cursor)
			if err != nil {
				t.Fatal(err)
			}
			var states []clientstate.TunnelState
			var tunnelID string
			for _, event := range events {
				if event.Publication != nil {
					if tunnelID != "" && event.Publication.ID != tunnelID {
						t.Fatal("failed binding created multiple publications", events)
					}
					tunnelID = event.Publication.ID
					states = append(states, event.Publication.State)
				}
			}
			if tunnelID == "" || !reflect.DeepEqual(states, []clientstate.TunnelState{clientstate.TunnelStateStarting, clientstate.TunnelStateFailed}) {
				t.Fatalf("failed binding did not finish its local journal: %v", states)
			}
			assertServicePublicationTerminal(t, w, cursor, tunnelID, clientstate.TunnelStateFailed, tc.code)
		})
	}
}

func TestServicePublicationCancellationRetainsOperationAndCleanupFailures(t *testing.T) {
	for _, tc := range []struct {
		name             string
		operationFailure error
		code             string
	}{
		{"cleanup_only", nil, string(failure.Unexpected)},
		{"operation_and_cleanup", failure.Wrap("stop service run", failure.ServerUnavailable, errors.New("operation failed")), string(failure.ServerUnavailable)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _ := testWorkers(t)
			cleanupFailure := errors.New("cleanup failed")
			var cleanupCalls atomic.Int32
			started := make(chan struct{})
			w.Configure = func(_ context.Context, service Service) (Configuration, error) {
				return Configuration{
					Cleanup: func() error {
						cleanupCalls.Add(1)
						return errors.Join(context.Canceled, cleanupFailure)
					},
					Service: &ServicePublication{
						Options: servicePublicationOptions(w, service),
						Run: func(ctx context.Context, observe func(uint64, bool) error, _ inspection.Observer) error {
							if err := observe(5, true); err != nil {
								return err
							}
							close(started)
							<-ctx.Done()
							if tc.operationFailure == nil {
								return ctx.Err()
							}
							return errors.Join(ctx.Err(), tc.operationFailure)
						},
						Check: func(context.Context, Service) Observation { return Observation{} },
					},
				}, nil
			}
			cursor := w.Manager.Snapshot().Cursor
			target := "http://127.0.0.1:3000"
			id := registerServicePublication(t, w, target, "")
			receiveServicePublication(t, started)
			tunnelID := w.Manager.Snapshot().Services[0].TunnelID
			err := w.Manager.UnregisterTarget(id, "owner", target)
			causes := []error{cleanupFailure}
			if tc.operationFailure != nil {
				causes = append(causes, tc.operationFailure)
			}
			for _, cause := range append(causes, ErrRegistrationStopped) {
				if !errors.Is(err, cause) {
					t.Fatalf("unregister lost %v from joined failure: %v", cause, err)
				}
			}
			for _, cause := range causes {
				if !errors.Is(w.Manager.RetirementError(), cause) {
					t.Fatalf("retirement lost %v: %v", cause, w.Manager.RetirementError())
				}
			}
			if cleanupCalls.Load() != 1 {
				t.Fatalf("configuration cleanup ran %d times, want once", cleanupCalls.Load())
			}
			assertNoServicePublications(t, w)
			assertServicePublicationTerminal(t, w, cursor, tunnelID, clientstate.TunnelStateFailed, tc.code)
		})
	}
}

func TestServicePublicationRejectsOlderRunBeforeJournalMutation(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		name := "sequential"
		if concurrent {
			name = "concurrent"
		}
		t.Run(name, func(t *testing.T) {
			w, _ := testWorkers(t)
			callbacks := make(chan func(uint64, bool) error, 1)
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			if concurrent {
				w.Manager.run = func(ctx context.Context, service Service, observe func(PublicationUpdate) error) error {
					return w.Run(ctx, service, func(update PublicationUpdate) error {
						err := observe(update)
						if update.RunNumber == 2 && !update.Routable {
							close(entered)
							<-release
						}
						return err
					})
				}
			}
			w.Configure = func(_ context.Context, service Service) (Configuration, error) {
				return Configuration{Service: &ServicePublication{
					Options: servicePublicationOptions(w, service),
					Run: func(ctx context.Context, observe func(uint64, bool) error, _ inspection.Observer) error {
						callbacks <- observe
						<-ctx.Done()
						return ctx.Err()
					},
					Check: func(context.Context, Service) Observation { return Observation{} },
				}}, nil
			}
			target := "http://127.0.0.1:3000"
			id := registerServicePublication(t, w, target, "")
			observe := receiveServicePublication(t, callbacks)
			if concurrent {
				current, stale := make(chan error, 1), make(chan error, 1)
				go func() { current <- observe(2, false) }()
				receiveServicePublication(t, entered)
				cursor := w.Manager.Snapshot().Cursor
				attempted := make(chan struct{})
				go func() {
					close(attempted)
					stale <- observe(1, true)
				}()
				receiveServicePublication(t, attempted)
				releaseOnce.Do(func() { close(release) })
				if err := receiveServicePublication(t, current); err != nil {
					t.Fatal(err)
				}
				if err := receiveServicePublication(t, stale); !errors.Is(err, ErrRegistrationStale) {
					t.Fatal("concurrent older run was accepted", err)
				}
				if after := w.Manager.Snapshot(); after.Cursor != cursor {
					t.Fatalf("concurrent older run changed the journal cursor: before=%s after=%s", cursor, after.Cursor)
				}
			} else if err := observe(2, false); err != nil {
				t.Fatal(err)
			}
			assertServicePublication(t, w, controlv1.ServiceProtocolHTTP, target, clientstate.TunnelStateProvisioning, 2, "")
			if err := observe(2, true); err != nil {
				t.Fatal(err)
			}
			before := assertServicePublication(t, w, controlv1.ServiceProtocolHTTP, target, clientstate.TunnelStateReady, 2, "")
			for _, ready := range []bool{false, true} {
				if err := observe(1, ready); !errors.Is(err, ErrRegistrationStale) {
					t.Fatalf("older run callback ready=%v was accepted: %v", ready, err)
				}
				after := assertServicePublication(t, w, controlv1.ServiceProtocolHTTP, target, clientstate.TunnelStateReady, 2, "")
				if before.Cursor != after.Cursor || !reflect.DeepEqual(before.Services, after.Services) {
					t.Fatalf("rejected older run changed the journal: before=%+v after=%+v", before, after)
				}
			}
			if err := w.Manager.UnregisterTarget(id, "owner", target); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func servicePublicationOptions(w *Workers, service Service) clientstate.BeginTunnelOptions {
	return clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: "https://control.example",
		Project: w.Manager.Snapshot().Project, Service: service.Name, Target: service.Target,
		ServiceProtocol: controlv1.ServiceProtocol(service.ServiceProtocol),
	}
}

func registerServicePublication(t *testing.T, w *Workers, target, url string) string {
	t.Helper()
	id, err := w.Manager.Reserve("web", "owner", 1, url)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Manager.Register(id, "owner", target, "node"); err != nil {
		t.Fatal(err)
	}
	return id
}

func receiveServicePublication[T any](t *testing.T, values <-chan T) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("service publication did not reach the expected lifecycle boundary")
		var zero T
		return zero
	}
}

func assertServicePublication(t *testing.T, w *Workers, protocol controlv1.ServiceProtocol, target string, state clientstate.TunnelState, run uint64, url string) Snapshot {
	t.Helper()
	snapshot := w.Manager.Snapshot()
	if len(snapshot.Publications) != 1 || len(snapshot.Services) != 1 {
		t.Fatalf("service publication is missing from the project journal: %+v", snapshot)
	}
	publication, service := snapshot.Publications[0], snapshot.Services[0]
	if service.TunnelID == "" || publication.ID != service.TunnelID || service.RunNumber != run ||
		publication.ServiceProtocol != protocol || publication.State != state || publication.PublishRunNumber != run ||
		publication.Target != target || publication.Project != snapshot.Project || publication.Service != service.Name ||
		publication.PublicURL != url || publication.PublicURLID != "" || url == "" && publication.Hostname != "" {
		t.Fatalf("service and local publication disagree: service=%+v publication=%+v", service, publication)
	}
	local, err := w.Database.SnapshotProject(t.Context(), snapshot.Project)
	if err != nil || len(local.Tunnels) != 1 {
		t.Fatalf("local publication row is not shared with the project journal: %+v, %v", local, err)
	}
	// lease maintenance can advance between these two independent reads.
	publication.HeartbeatAt, publication.LeaseExpiresAt = local.Tunnels[0].HeartbeatAt, local.Tunnels[0].LeaseExpiresAt
	if !reflect.DeepEqual(local.Tunnels[0], publication) {
		t.Fatalf("local publication row is not shared with the project journal: %+v, %v", local, err)
	}
	return snapshot
}

func assertNoServicePublications(t *testing.T, w *Workers) {
	t.Helper()
	snapshot := w.Manager.Snapshot()
	local, err := w.Database.SnapshotProject(t.Context(), snapshot.Project)
	if err != nil || len(local.Tunnels) != 0 || local.Summary.Total != 0 || len(snapshot.Publications) != 0 {
		t.Fatalf("stopped operation retained an active publication: runtime=%+v local=%+v err=%v", snapshot.Publications, local, err)
	}
}

func assertServicePublicationTerminal(t *testing.T, w *Workers, cursor, tunnelID string, state clientstate.TunnelState, failureCode string) {
	t.Helper()
	events, err := EventsAfterFrom(t.Context(), w.Database, w.Manager.Snapshot().Project, cursor)
	if err != nil {
		t.Fatal(err)
	}
	var last *clientstate.TunnelInfo
	for _, event := range events {
		if event.Publication != nil && event.Publication.ID == tunnelID {
			last = event.Publication
		}
	}
	if last == nil || last.State != state || last.Failure != failureCode {
		t.Fatalf("terminal publication lost its outcome: %+v", last)
	}
}

func TestPrivateReadinessKeepsHTTPAuthorityIndependentOfTLSTrust(t *testing.T) {
	var authority atomic.Value
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { authority.Store(r.Host); w.WriteHeader(http.StatusOK) }))
	defer target.Close()
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	transport := targettransport.Transport{Protocol: config.ProtocolHTTP, TLS: &tls.Config{RootCAs: roots, ServerName: target.Certificate().DNSNames[0]}}
	observation := ProbeServiceTarget(t.Context(), Service{Target: target.URL, ServiceProtocol: "http", Readiness: Readiness{Path: "/"}}, transport)
	if !observation.Ready || authority.Load() != strings.TrimPrefix(target.URL, "https://") {
		t.Fatal("TLS certificate identity changed HTTP target authority", observation, authority.Load())
	}
}
