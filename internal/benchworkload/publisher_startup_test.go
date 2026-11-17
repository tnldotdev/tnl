package benchworkload

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publisherStartupTestControl struct {
	publisherservice.RunControl
	get       func(context.Context, string, string) (controlv1.Service, error)
	heartbeat func(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error)
	close     func(context.Context, string, string, credentials.ServiceRunToken) error
}

func (c *publisherStartupTestControl) GetPublisherService(ctx context.Context, service, access string) (controlv1.Service, error) {
	return c.get(ctx, service, access)
}

func (c *publisherStartupTestControl) HeartbeatServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken, health controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	return c.heartbeat(ctx, service, run, token, health)
}

func (c *publisherStartupTestControl) CloseServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken) error {
	return c.close(ctx, service, run, token)
}

func decodePublisherStartupTrace(t *testing.T, trace *publisherStartupTrace) publisherStartupSnapshot {
	t.Helper()
	var snapshot publisherStartupSnapshot
	if err := json.Unmarshal(trace.failureJSON(), &snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestPublisherStartupTraceDelegatesAndRedacts(t *testing.T) {
	const serviceID, runID = "svc_0123456789ABCDEFGHIJKL", "srun_0123456789ABCDEFGHIJKL"
	const access, token, connectionCredential, pem = "access-secret", "run-token-secret", "connection-secret", "pem-secret"
	problem := errors.New("control-error-secret")
	service := controlv1.Service{
		Id: serviceID, EndpointRevision: 7, TrustRevision: 3,
		Endpoint:  &controlv1.ServiceEndpoint{Hostname: "web.example.test", Port: 443, Public: true},
		TargetTls: &controlv1.ServiceTargetTLS{Pem: new(pem)},
	}
	state := controlv1.ServiceRunState{
		ServiceId: serviceID, ServiceRunId: runID, RunNumber: 4, State: "ready",
		EndpointRevision: 8, PublicEndpointReady: false, Healthy: new(false), PublisherExpiresAt: time.Now().Add(time.Minute),
		PublisherConnections: []controlv1.ConnectionAssignment{{PublisherConnectionCredential: connectionCredential}},
	}
	health := controlv1.ServiceRunHeartbeat{Healthy: true, StreamCapacity: 64, ActiveStreams: 3}
	gets, heartbeats, closes, accesses := 0, 0, 0, 0
	var gotAt, heartbeatAt time.Time
	control := &publisherStartupTestControl{
		get: func(ctx context.Context, selected, suppliedAccess string) (controlv1.Service, error) {
			gets++
			gotAt = time.Now()
			if ctx != t.Context() || selected != serviceID || suppliedAccess != access {
				t.Error("startup observation changed the original publisher lookup")
			}
			return service, nil
		},
		heartbeat: func(ctx context.Context, selected, run string, suppliedToken credentials.ServiceRunToken, suppliedHealth controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
			heartbeats++
			heartbeatAt = time.Now()
			if ctx != t.Context() || selected != serviceID || run != runID || suppliedToken != credentials.ServiceRunToken(token) || suppliedHealth != health {
				t.Error("startup observation changed the original authenticated heartbeat")
			}
			return state, problem
		},
		close: func(ctx context.Context, selected, run string, suppliedToken credentials.ServiceRunToken) error {
			closes++
			if ctx != t.Context() || selected != serviceID || run != runID || suppliedToken != credentials.ServiceRunToken(token) {
				t.Error("startup observation changed promoted control delegation")
			}
			return problem
		},
	}
	trace := &publisherStartupTrace{}
	cfg := observePublisherStartup(publisherservice.RunConfig{
		Control: control, HeartbeatInterval: 10 * time.Second, DrainTime: time.Second,
		Access: func(ctx context.Context) (string, error) {
			accesses++
			if ctx != t.Context() {
				t.Error("startup observation changed access context")
			}
			return access, problem
		},
	}, trace)
	if got, err := cfg.Access(t.Context()); got != access || err != problem || cfg.HeartbeatInterval != 10*time.Second || cfg.DrainTime != time.Second {
		t.Fatal("startup observation changed access, heartbeat cadence, or drain time")
	}
	if got, err := cfg.Control.GetPublisherService(t.Context(), serviceID, access); err != nil || !reflect.DeepEqual(got, service) {
		t.Fatal("startup observation changed the approved service result", err)
	}
	if got, err := cfg.Control.HeartbeatServiceRun(t.Context(), serviceID, runID, credentials.ServiceRunToken(token), health); err != problem || !reflect.DeepEqual(got, state) {
		t.Fatal("startup observation changed the heartbeat result or error", err)
	}
	if err := cfg.Control.CloseServiceRun(t.Context(), serviceID, runID, credentials.ServiceRunToken(token)); err != problem {
		t.Fatal("startup observation changed a promoted operation's result", err)
	}
	*state.Healthy = true
	snapshot := decodePublisherStartupTrace(t, trace)
	approval := snapshot.Approval
	if approval == nil || !approval.Completed || approval.Error || approval.RequestedServiceID != serviceID || approval.ServiceID != serviceID ||
		approval.EndpointRevision != 7 || approval.Hostname != "web.example.test" || !approval.Public ||
		approval.StartedAt.After(gotAt) || approval.FinishedAt.Before(gotAt) {
		t.Fatal("startup observation lost captured approval or request/response timing", approval)
	}
	if gets != 1 || heartbeats != 1 || closes != 1 || accesses != 1 || snapshot.HeartbeatCalls != 1 || len(snapshot.Heartbeats) != 1 {
		t.Fatal("startup observation added control calls or lost the original heartbeat")
	}
	heartbeat := snapshot.Heartbeats[0]
	if !heartbeat.Completed || !heartbeat.Error || heartbeat.StartedAt.After(heartbeatAt) || heartbeat.FinishedAt.Before(heartbeatAt) ||
		heartbeat.ServiceID != serviceID || heartbeat.RunID != runID ||
		heartbeat.Request != (publisherStartupHealth{Healthy: true, StreamCapacity: 64, ActiveStreams: 3}) ||
		heartbeat.Response.State != "ready" || heartbeat.Response.ServiceID != serviceID || heartbeat.Response.RunID != runID || heartbeat.Response.RunNumber != 4 ||
		heartbeat.Response.EndpointRevision != 8 || heartbeat.Response.PublicEndpointReady || !heartbeat.Response.HealthyPresent || heartbeat.Response.Healthy ||
		!heartbeat.Response.PublisherExpiresAt.Equal(state.PublisherExpiresAt) {
		t.Fatal("startup observation lost selected request/response facts", heartbeat)
	}
	encoded := string(trace.failureJSON())
	for _, secret := range []string{access, token, connectionCredential, pem, problem.Error(), "publisher_connections"} {
		if strings.Contains(encoded, secret) {
			t.Fatalf("startup observation retained secret or whole response field %q", secret)
		}
	}
}

func TestPublisherStartupTraceBoundsHistoryAndStopsAfterReady(t *testing.T) {
	trace := &publisherStartupTrace{}
	gets, calls, observations, notifications := 0, 0, 0, 0
	status := publisherservice.RunStatus{
		Ready: false, TargetHealthy: true, ConfigurationCurrent: true,
		LastCheck: time.Now(), LastSuccess: time.Now().Add(-time.Second), LeaseExpiresAt: time.Now().Add(time.Minute),
		Connected: [2]bool{true, true}, Transports: [2]tunnel.Transport{tunnel.TransportQUIC, tunnel.TransportWSS},
	}
	control := &publisherStartupTestControl{
		get: func(context.Context, string, string) (controlv1.Service, error) {
			gets++
			return controlv1.Service{EndpointRevision: int64(gets)}, nil
		},
		heartbeat: func(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
			calls++
			return controlv1.ServiceRunState{State: "ready", EndpointRevision: int64(calls)}, nil
		},
	}
	cfg := observePublisherStartup(publisherservice.RunConfig{
		Control: control,
		ObserveReadiness: func(got publisherservice.RunStatus) {
			observations++
			if got != status {
				t.Error("startup observation changed the original readiness callback")
			}
		},
		Ready: func() error { notifications++; return nil },
	}, trace)
	if _, err := cfg.Control.GetPublisherService(t.Context(), "service", "secret"); err != nil {
		t.Fatal(err)
	}
	for index := range 20 {
		status.LastCheck = status.LastCheck.Add(time.Duration(index) * time.Millisecond)
		if _, err := cfg.Control.HeartbeatServiceRun(t.Context(), "service", "run", "secret", controlv1.ServiceRunHeartbeat{}); err != nil {
			t.Fatal(err)
		}
		cfg.ObserveReadiness(status)
	}
	if err := cfg.Ready(); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Control.GetPublisherService(t.Context(), "service", "secret"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := cfg.Control.HeartbeatServiceRun(t.Context(), "service", "run", "secret", controlv1.ServiceRunHeartbeat{}); err != nil {
			t.Fatal(err)
		}
		cfg.ObserveReadiness(status)
	}
	snapshot := decodePublisherStartupTrace(t, trace)
	if gets != 2 || calls != 23 || observations != 23 || notifications != 1 ||
		snapshot.Approval == nil || snapshot.Approval.EndpointRevision != 1 ||
		snapshot.HeartbeatCalls != 20 || snapshot.ReadinessChecks != 20 ||
		len(snapshot.Heartbeats) != publisherStartupHistoryLimit || len(snapshot.Readiness) != publisherStartupHistoryLimit {
		t.Fatal("startup observation changed callbacks or retained unbounded/post-ready history")
	}
	for index, heartbeat := range snapshot.Heartbeats {
		if heartbeat.Sequence != uint64(index+13) || heartbeat.Response.EndpointRevision != int64(index+13) || !heartbeat.Completed || heartbeat.Error || heartbeat.Response.HealthyPresent {
			t.Fatal("startup history did not retain the most recent complete selected responses", heartbeat)
		}
	}
	last := snapshot.Readiness[len(snapshot.Readiness)-1]
	if last.Ready != status.Ready || last.TargetHealthy != status.TargetHealthy || last.ConfigurationCurrent != status.ConfigurationCurrent ||
		!last.LastCheck.Equal(status.LastCheck) || !last.LastSuccess.Equal(status.LastSuccess) || !last.LeaseExpiresAt.Equal(status.LeaseExpiresAt) ||
		last.Connected != status.Connected || last.Transports != status.Transports || last.Draining != status.Draining || last.ObservedAt.IsZero() {
		t.Fatal("startup observation lost the last local readiness facts", last)
	}
}

func TestPublisherStartupTraceFreezesInFlightHeartbeatAtFailure(t *testing.T) {
	trace := &publisherStartupTrace{}
	entered, finish, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(finish) })
	control := &publisherStartupTestControl{heartbeat: func(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
		close(entered)
		<-finish
		return controlv1.ServiceRunState{State: "ready", EndpointRevision: 9, PublicEndpointReady: true}, nil
	}}
	cfg := observePublisherStartup(publisherservice.RunConfig{Control: control}, trace)
	go func() {
		defer close(joined)
		if _, err := cfg.Control.HeartbeatServiceRun(t.Context(), "service", "run", "secret", controlv1.ServiceRunHeartbeat{Healthy: true}); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(func() { release(); <-joined })
	<-entered
	before := decodePublisherStartupTrace(t, trace)
	if len(before.Heartbeats) != 1 || before.Heartbeats[0].StartedAt.IsZero() || before.Heartbeats[0].Completed || !before.Heartbeats[0].FinishedAt.IsZero() {
		t.Fatal("startup observation hid an in-flight heartbeat")
	}
	release()
	<-joined
	after := decodePublisherStartupTrace(t, trace)
	if !reflect.DeepEqual(before.Heartbeats, after.Heartbeats) || after.HeartbeatCalls != 1 {
		t.Fatal("a late response rewrote the pre-cancellation failure snapshot")
	}
}

func TestPublisherStartupTracePreservesReadyFailure(t *testing.T) {
	trace := &publisherStartupTrace{}
	problem := errors.New("ready callback failed")
	cfg := observePublisherStartup(publisherservice.RunConfig{Ready: func() error { return problem }}, trace)
	if err := cfg.Ready(); err != problem {
		t.Fatal("startup observation changed the ready callback error", err)
	}
	cfg.ObserveReadiness(publisherservice.RunStatus{TargetHealthy: true})
	if snapshot := decodePublisherStartupTrace(t, trace); snapshot.ReadinessChecks != 1 {
		t.Fatal("failed readiness notification stopped activation observations")
	}
}

func TestPublisherStartupTraceOptInKeepsActivationDeadline(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "diagnostic"}[enabled], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				gets, heartbeats, observations := 0, 0, 0
				control := &publisherStartupTestControl{
					get: func(context.Context, string, string) (controlv1.Service, error) {
						gets++
						return controlv1.Service{EndpointRevision: 7}, nil
					},
					heartbeat: func(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
						heartbeats++
						return controlv1.ServiceRunState{State: "ready", EndpointRevision: 7, PublicEndpointReady: false}, nil
					},
				}
				group := &Publishers{
					ctx: ctx, cancel: cancel, prepare: benchmarkTestPreparation, failures: make(chan error, 1),
					config: PublisherConfig{Parallel: 1, ReadyTimeout: 30 * time.Second, StopTimeout: 10 * time.Second, TraceStartup: enabled},
					base:   publisherservice.RunConfig{Control: control, ObserveReadiness: func(publisherservice.RunStatus) { observations++ }},
				}
				group.run = func(runCtx context.Context, cfg publisherservice.RunConfig) error {
					if !enabled && cfg.Control != control {
						t.Error("default startup installed a diagnostic control wrapper")
					}
					_, _ = cfg.Control.GetPublisherService(runCtx, cfg.ServiceID, "secret")
					_, _ = cfg.Control.HeartbeatServiceRun(runCtx, cfg.ServiceID, "run", "secret", controlv1.ServiceRunHeartbeat{Healthy: true})
					cfg.ObserveReadiness(publisherservice.RunStatus{TargetHealthy: true})
					<-runCtx.Done()
					return runCtx.Err()
				}
				started := time.Now()
				_, err := group.Start(t.Context(), []int{0})
				if err == nil || !strings.HasPrefix(err.Error(), "publisher 0 readiness exceeded 30s") || time.Since(started) != 30*time.Second {
					t.Fatal("startup observation changed the original timeout or error prefix", err)
				}
				if gets != 1 || heartbeats != 1 || observations != 1 || strings.Contains(err.Error(), "startup_observation=") != enabled {
					t.Fatal("startup observation was not opt-in or changed calls", err)
				}
				if enabled {
					_, encoded, found := strings.Cut(err.Error(), "; startup_observation=")
					var snapshot publisherStartupSnapshot
					if !found || json.Unmarshal([]byte(encoded), &snapshot) != nil || snapshot.Approval == nil ||
						snapshot.Approval.EndpointRevision != 7 || len(snapshot.Heartbeats) != 1 || len(snapshot.Readiness) != 1 {
						t.Fatal("activation failure did not include bounded selected startup facts", err)
					}
				}
				if _, err := group.Stop(t.Context(), []int{0}); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}
