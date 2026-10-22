package local

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	clientruntime "github.com/tnldotdev/tnl/internal/publisher/app"
	privateprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

func TestNamedLeasePinsConfigurationDigestAtOwnerBoundary(t *testing.T) {
	a, endpoint := testAppRuntime(t)
	selectedServer, selectedTeam := "https://selected.example.test", "selected"
	configuredServer, configuredTeam := "https://configured.example.test", "configured"
	address := config.Target("127.0.0.1:4100")
	transferred := a.project
	transferred.Selection = projectconfig.Selection{Path: filepath.Join(transferred.Root, "development.json")}
	transferred.Config = config.TNL{Server: &selectedServer, Team: &selectedTeam, Services: config.Services{"api": {Target: &config.ServiceTarget{Type: "address", Address: &address}}}}
	snapshot, digest, err := transferred.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	transferred, err = projectconfig.ReadSnapshot(strings.NewReader(string(snapshot)))
	if err != nil {
		t.Fatal(err)
	}
	a.project = transferred
	request := privateprotocol.Lease{Service: "api", Owner: strings.Repeat("a", 32), Pid: os.Getpid(), ConfigurationDigest: digest}
	var registration privateprotocol.Registration
	if err := privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/leases", request, &registration); err != nil || registration.Target != "http://127.0.0.1:4100" {
		t.Fatalf("resolved lease = %+v, %v", registration, err)
	}
	defer a.manager.Unregister(registration.RegistrationID, request.Owner)
	for _, change := range []func(*projectconfig.Project){
		func(p *projectconfig.Project) { p.Config.Server = &configuredServer },
		func(p *projectconfig.Project) { p.Config.Team = &configuredTeam },
		func(p *projectconfig.Project) { p.Selection.Path = filepath.Join(p.Root, "tnl.json") },
	} {
		other := transferred
		change(&other)
		_, request.ConfigurationDigest, err = other.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.acquire(context.Background(), request); !errors.Is(err, clientruntime.ErrOwnerConflict) {
			t.Fatalf("different invocation acquired current owner: %v", err)
		}
	}
}
