package installed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/failure"
	publisherdeployment "github.com/tnldotdev/tnl/internal/publisher/deployment"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// use the real supervisor, deployment loop and HTTP client error adapter. a synthetic
// error returned directly by Engine.Deployment would not test the retry boundary.
func TestInstalledDeploymentRuntimeConflictBlocksWithoutReclaim(t *testing.T) {
	options := testOptions(t)
	options.User = true
	r, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	job, _, key := kindFixture(t, KindDeployment)
	member := *job.DeploymentMember
	var replaced atomic.Bool
	var mu sync.Mutex
	var requests []controlv1.PublisherRuntimeRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/publisher/runtimes/" + member.PublisherIdentityId + "/inspect", "/v1/publisher/runtimes/" + member.PublisherIdentityId + "/start", "/v1/publisher/runtimes/" + member.PublisherIdentityId + "/renew", "/v1/publisher/runtimes/" + member.PublisherIdentityId + "/stop":
			var body controlv1.PublisherRuntimeRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			mu.Lock()
			requests = append(requests, body)
			mu.Unlock()
			if replaced.Load() {
				serverhttp.WriteProblem(w, http.StatusConflict, "conflict", "publisher runtime has been replaced or stopped", "")
				return
			}
			if body.Action == controlv1.RuntimeInspect {
				_ = json.NewEncoder(w).Encode(controlv1.PublisherRuntimeResponse{Epoch: 0})
				return
			}
			until := time.Now().Add(100 * time.Millisecond)
			_ = json.NewEncoder(w).Encode(controlv1.PublisherRuntimeResponse{Epoch: 1, LeaseExpiresAt: &until, DeploymentLease: &controlv1.DeploymentPublisherLease{AccessToken: "dpl_lease_fixture", ExpiresAt: until}})
		case "/v1/publisher/deployments/assignments":
			_ = json.NewEncoder(w).Encode(controlv1.DeploymentPublisherAssignments{Member: member, Revision: 1, ConfigurationHash: strings.Repeat("a", 64), Services: []controlv1.DeploymentPublisherServiceAssignment{}})
		case "/v1/publisher/deployments/configuration-acknowledgements":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s", request.URL.Path)
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	job.Server = server.URL
	if err := r.InstallDeployment(t.Context(), job, member, key); err != nil {
		t.Fatal(err)
	}
	client, err := publisherdeployment.NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int64
	engine := Engine{Registry: r, PollInterval: 5 * time.Millisecond, RetryMin: 5 * time.Millisecond, RetryMax: 10 * time.Millisecond, Deployment: func(ctx context.Context, job Job, _ *clienttelemetry.Collector, observe func(int64, bool) error) error {
		attempts.Add(1)
		current, private, _, err := r.DeploymentIdentity(ctx, job)
		if err != nil {
			return err
		}
		return (publisherdeployment.Runtime{Control: client, Member: current, Private: private, Observe: observe, PollInterval: 5 * time.Millisecond, Publish: func(context.Context, controlv1.DeploymentPublisherServiceAssignment, func(bool)) error {
			t.Error("empty deployment published a service")
			return ErrScope
		}}).Serve(ctx)
	}}
	cancel, done := startEngine(t, engine)
	defer joinEngine(t, cancel, done)
	status := func() Status {
		t.Helper()
		jobs, err := r.List(t.Context())
		if err != nil || len(jobs) != 1 {
			t.Fatal("read installed deployment", err)
		}
		return jobs[0].Status
	}
	await(t, func() bool { return status().State == "ready" })
	replaced.Store(true)
	await(t, func() bool { return status().State == "blocked" })
	if s := status(); s.Failure != string(failure.ServerConflict) || s.Attempts != 1 {
		t.Fatalf("conflict classification: %+v", s)
	}
	// allow many supervisor polls and minimum-backoff windows after blocking.
	time.Sleep(100 * time.Millisecond)
	if attempts.Load() != 1 {
		t.Fatal("supervisor restarted a fenced deployment")
	}
	mu.Lock()
	defer mu.Unlock()
	inspects, starts := 0, 0
	run := ""
	for _, request := range requests {
		if request.Action == controlv1.RuntimeInspect {
			inspects++
		}
		if request.Action == controlv1.RuntimeStart {
			starts++
		}
		if run == "" {
			run = request.ProcessRunId
		}
		if request.ProcessRunId != run {
			t.Fatal("automatic retry replaced runtime owner")
		}
	}
	if inspects != 1 || starts != 1 {
		t.Fatalf("fenced process reclaimed epoch: inspect=%d start=%d", inspects, starts)
	}
}
