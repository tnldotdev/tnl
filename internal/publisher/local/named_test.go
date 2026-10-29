package local

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

func TestNamedLeasePinsConfigurationDigestAtOwnerBoundary(t *testing.T) {
	a, endpoint := testAppRuntime(t)
	selectedServer, selectedTeam := "https://selected.example.test", "selected"
	configuredServer, configuredTeam := "https://configured.example.test", "configured"
	address := config.Target("127.0.0.1:4100")
	transferred := a.project
	transferred.Selection = clientproject.Selection{Path: filepath.Join(transferred.Root, "development.json")}
	transferred.Config = config.TNL{Server: &selectedServer, Team: &selectedTeam, Services: config.Services{"api": {Target: &config.ServiceTarget{Type: "address", Address: &address}}}}
	snapshot, digest, err := transferred.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	transferred, err = clientproject.ReadSnapshot(strings.NewReader(string(snapshot)))
	if err != nil {
		t.Fatal(err)
	}
	a.project = transferred
	request := publisherprotocol.Lease{Service: "api", Owner: strings.Repeat("a", 32), Pid: os.Getpid(), ConfigurationDigest: digest}
	request.TelemetryDisabled = new(bool)
	*request.TelemetryDisabled = true
	var registration publisherprotocol.Registration
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/leases", request, &registration); err != nil || registration.Target != "http://127.0.0.1:4100" {
		t.Fatalf("resolved lease = %+v, %v", registration, err)
	}
	defer a.manager.Unregister(registration.RegistrationID, request.Owner)
	a.mu.Lock()
	disabled := a.prepared[registration.RegistrationID].telemetryDisabled
	a.mu.Unlock()
	if !disabled {
		t.Fatal("named lease lost its invocation-specific telemetry choice")
	}
	for _, change := range []func(*clientproject.Project){
		func(p *clientproject.Project) { p.Config.Server = &configuredServer },
		func(p *clientproject.Project) { p.Config.Team = &configuredTeam },
		func(p *clientproject.Project) { p.Selection.Path = filepath.Join(p.Root, "tnl.json") },
	} {
		other := transferred
		change(&other)
		_, request.ConfigurationDigest, err = other.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.acquire(context.Background(), request); !errors.Is(err, publisherapp.ErrOwnerConflict) {
			t.Fatalf("different invocation acquired current owner: %v", err)
		}
	}
}
