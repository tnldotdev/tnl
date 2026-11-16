package localapi

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

func TestNativeUnregisterEnforcesWireDeadlineAndReplaysJoinedTimeout(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	started, joined := make(chan struct{}), make(chan struct{})
	deadlines := make(chan time.Time, 1)
	var runs atomic.Int32
	var manager *publisherapp.Manager
	manager, err = publisherapp.New(t.Context(), root, database, []publisherapp.Service{{Name: "web"}}, func(ctx context.Context, service publisherapp.Service, _ func(publisherapp.PublicationUpdate) error) error {
		runs.Add(1)
		close(started)
		<-ctx.Done()
		until := manager.PublicationShutdownDeadline(service.RegistrationID)
		deadlines <- until
		finish, cancel := context.WithDeadline(context.WithoutCancel(ctx), until)
		defer cancel()
		<-finish.Done()
		close(joined)
		return errors.Join(ctx.Err(), finish.Err())
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	const owner, target = "0123456789abcdef0123456789abcdef", "http://127.0.0.1:3000"
	id, err := manager.Reserve("web", owner, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(id, owner, target, "node"); err != nil {
		t.Fatal(err)
	}
	<-started
	server := httptest.NewUnstartedServer(nil)
	caps, err := publisherprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	name := "web"
	endpoint, err := caps.Issue(publisherprotocol.CapabilityRequest{Scope: "app", Service: &name})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = (&Server{Capabilities: caps, Manager: manager}).Handler()
	server.Start()
	defer server.Close()
	until := time.Now().UTC().Add(80 * time.Millisecond)
	request := publisherprotocol.Registration{Version: 1, RegistrationID: id, Owner: owner, Target: target, ShutdownDeadline: &until}
	for range 2 {
		err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", request, nil)
		var response *publisherprotocol.ResponseError
		if !errors.As(err, &response) || response.Code != "runtime.publication_cleanup_failed" {
			t.Fatal("native timeout was not an exact stopped cleanup failure", err)
		}
		select {
		case <-joined:
		default:
			t.Fatal("native returned before its publication worker joined")
		}
	}
	if got := <-deadlines; !got.Equal(until) || runs.Load() != 1 {
		t.Fatal("native unregister replaced the wire budget or restarted work", got, until, runs.Load())
	}
	if !errors.Is(manager.RetirementError(), context.DeadlineExceeded) {
		t.Fatal("native retirement hid the expired cleanup budget", manager.RetirementError())
	}
}
