package main

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/localapi"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

// command observation tests use the real manager, journal and API without
// reaching into the process constructor's private worker state.
func observationFixture(t *testing.T, defaultProtection bool) (projectConfiguration, *clientstate.Database, *publisherapp.Manager, publisherprotocol.Endpoint) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	options := clientstate.OpenOptions{Protection: clientstate.ProtectionFile}
	if defaultProtection {
		options.Protection = ""
	}
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	project := projectConfiguration{Project: clientproject.Project{Root: root, Config: config.TNL{Services: config.Services{"web": {}, "api": {}}}}}
	manager, err := publisherapp.New(t.Context(), root, state, publisherapp.ConfiguredServices(project.Project), func(ctx context.Context, _ publisherapp.Service, observe func(uint64, bool) error) error {
		if err := observe(1, true); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	server := httptest.NewUnstartedServer(nil)
	capabilities, err := publisherprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = (&localapi.Server{Manager: manager, Database: state, Project: root, Capabilities: capabilities}).Handler()
	server.Start()
	t.Cleanup(server.Close)
	return project, state, manager, capabilities.Owner()
}

func waitObservationFixture(t *testing.T, manager *publisherapp.Manager, predicate func(publisherapp.Snapshot) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if snapshot := manager.Snapshot(); predicate(snapshot) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("observation fixture did not reach its expected state")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
