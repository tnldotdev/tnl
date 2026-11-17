package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	"github.com/tnldotdev/tnl/internal/publisher/local"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestWaitUsesActualOwnerAndFreshPublicTargetProbe(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
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
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := projectConfiguration{Project: clientproject.Project{Root: root,
		Selection: clientproject.Selection{Path: filepath.Join(root, "tnl.json")},
		Config: config.TNL{Server: &f.URL, Services: config.Services{
			"web": {Public: new(true), HTTP: &config.HTTPService{Readiness: &config.Readiness{Path: "/ready"}}},
		}}}}
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Error(err)
		}
	})
	salt, err := state.WorktreeHashSalt(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	hash := hmac.New(sha256.New, salt[:])
	_, _ = hash.Write([]byte(f.URL + "\x00tm_0000000000000000000001\x00" + root))
	source := project.LocalPublicationIdentity()
	if err := f.ConfigureLocal(publishingtest.LocalProject{Key: source.Key, Fingerprint: source.Fingerprint,
		Worktree: project.LocalWorktreeKey(), Label: project.Worktree.Label.FullLabel, PreviewKey: hex.EncodeToString(hash.Sum(nil)),
		Services: map[string]controlv1.ProjectServiceConfiguration{
			"web": {Name: new("web"), Protocol: new(controlv1.ServiceProtocolHTTP), Target: "app", Public: new(true),
				Http: &controlv1.ProjectServiceHTTP{Readiness: &struct {
					Path string `json:"path"`
				}{Path: "/ready"}}},
		}}); err != nil {
		t.Fatal(err)
	}
	var publicRequests atomic.Int32
	var holdPublic atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(publisherapp.ProbeHeader) != "" {
			t.Error("owner proof reached the application target")
		}
		if !strings.HasPrefix(r.Host, "127.0.0.1:") {
			if r.Method != http.MethodGet || r.URL.Path != "/ready" {
				t.Errorf("public readiness reached the wrong target path: %s %s", r.Method, r.URL)
			}
			publicRequests.Add(1)
			if holdPublic.CompareAndSwap(true, false) {
				close(entered)
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	t.Cleanup(unblock)
	snapshot, _, err := project.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	path, err := publisherprotocol.DescriptorPath(state.Root(), root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- local.Serve(ctx, local.Options{Directory: root, StateDir: state.Root(), Snapshot: bytes.NewReader(snapshot)})
	}()
	stop := sync.OnceValue(func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			return errors.New("local publisher cleanup did not join within 5s")
		}
	})
	t.Cleanup(func() {
		unblock()
		if err := stop(); err != nil {
			t.Error("owner cleanup", err)
		}
	})
	bound, finish := context.WithTimeout(t.Context(), 5*time.Second)
	defer finish()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	var endpoint publisherprotocol.Endpoint
	for {
		if current, err := publisherprotocol.ReadEndpoint(path); err == nil && local.Available(bound, current) {
			endpoint = current
			break
		}
		select {
		case err := <-done:
			done <- err
			t.Fatal("owner exited before publishing its descriptor", err)
		case <-bound.Done():
			t.Fatal("owner did not publish its descriptor", bound.Err())
		case <-tick.C:
		}
	}
	var appEndpoint publisherprotocol.Endpoint
	if err := publisherprotocol.Call(bound, endpoint, "POST", "/v1/capabilities",
		publisherprotocol.CapabilityRequest{Scope: "app", Service: new("web")}, &appEndpoint); err != nil {
		t.Fatal(err)
	}
	owner := strings.Repeat("a", 32)
	var assignment publisherprotocol.Assignment
	if err := publisherprotocol.Call(bound, appEndpoint, "POST", "/v1/prepare", publisherprotocol.Prepare{
		Version: 1, Directory: root, Service: "web", Owner: owner, PID: os.Getpid(), Framework: publisherprotocol.FrameworkNode}, &assignment); err != nil {
		t.Fatal(err)
	}
	registration := publisherprotocol.Registration{Version: 1, RegistrationID: assignment.RegistrationID, Owner: owner, Target: target.URL}
	if err := publisherprotocol.Call(bound, appEndpoint, "POST", "/v1/register", registration, nil); err != nil {
		t.Fatal(err)
	}
	var before publisherapp.Snapshot
	for {
		if err := publisherprotocol.Call(bound, endpoint, "GET", "/v1/status", nil, &before); err != nil {
			read, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			durable, readErr := publisherapp.ReadSnapshotFrom(read, state, root)
			cancel()
			t.Fatalf("owner status failed: %v; target public GETs=%d; journal=%+v; journal error=%v", err, publicRequests.Load(), durable.Services, readErr)
		}
		if len(before.Services) == 1 && before.Services[0].Ready {
			break
		}
		select {
		case <-bound.Done():
			t.Fatal("real publication never became ready", before, bound.Err())
		case <-tick.C:
		}
	}
	if publicRequests.Load() != 1 || before.Services[0].Observation == nil {
		t.Fatal("startup did not establish one actual public readiness observation", before)
	}
	type waitResult struct {
		output bytes.Buffer
		err    error
	}
	result := make(chan waitResult, 1)
	holdPublic.Store(true)
	start := time.Now()
	go func() {
		var value waitResult
		value.err = runAppWait(t.Context(), project, state.Root(), waitCommand{Service: []string{"web"}, Timeout: 3 * time.Second, Output: "json"}, &value.output)
		result <- value
	}()
	select {
	case <-entered:
	case value := <-result:
		t.Fatalf("wait returned without a fresh public target response: %v %s", value.err, &value.output)
	case <-time.After(3 * time.Second):
		t.Fatal("owner /v1/check did not reach the actual public target")
	}
	select {
	case value := <-result:
		t.Fatalf("saved Ready bypassed the held fresh target response: %v %s", value.err, &value.output)
	default:
	}
	unblock()
	var value waitResult
	select {
	case value = <-result:
	case <-time.After(3 * time.Second):
		t.Fatal("wait did not join after the fresh target response")
	}
	if value.err != nil {
		t.Fatalf("actual owner wait failed: %v %s", value.err, &value.output)
	}
	var got struct {
		publisherapp.Snapshot
		State     string `json:"state"`
		CheckedBy string `json:"checked_by"`
	}
	if err := json.Unmarshal(value.output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.State != "ready" || got.CheckedBy != "selected local publisher process (fresh public-path check)" || len(got.Services) != 1 {
		t.Fatalf("wait result lost its actual owner: %s", &value.output)
	}
	service := got.Services[0]
	if !service.Registered || !service.Routable || !service.Ready || service.RegistrationID != assignment.RegistrationID ||
		service.Target != target.URL || service.PublicURL != assignment.PublicURL || service.RunNumber != before.Services[0].RunNumber ||
		service.Observation == nil || !service.Observation.Ready || service.Observation.Status != http.StatusNoContent ||
		service.Observation.Readiness.Path != "/ready" || service.Observation.CheckedAt.Before(start) ||
		!service.Observation.CheckedAt.After(before.Services[0].Observation.CheckedAt) || publicRequests.Load() != 2 ||
		f.Runs.Load() != 1 || f.Enrollments.Load() != 1 || f.Allocations.Load() != 0 {
		t.Fatalf("wait did not use the current registered target/run and a fresh public proof: %s", &value.output)
	}
	cleanup, finishCleanup := context.WithTimeout(context.Background(), 3*time.Second)
	defer finishCleanup()
	if err := publisherprotocol.Call(cleanup, appEndpoint, "POST", "/v1/unregister", registration, nil); err != nil {
		t.Error("publication cleanup", err)
	}
	if err := stop(); err != nil {
		t.Error("owner cleanup", err)
	}
	t.Log("proved actual local owner API and fresh public GET through visitor TLS/yamux to the registered target; control and ingress dialing are fixtures, not deployed PostgreSQL/DNS")
}
