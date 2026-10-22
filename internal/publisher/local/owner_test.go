package local

import (
	"os"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	privateprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

func TestAppWorkflowRejectsStaleOwnerAfterOneAppRestart(t *testing.T) {
	a, endpoint := testAppRuntime(t)
	a.project.Config.Services = config.Services{"web": {Tunnel: &config.Tunnel{}}, "api": {Tunnel: &config.Tunnel{Access: &config.Access{Mode: "anonymous"}}}}
	for _, name := range []string{"web", "api"} {
		id, err := a.manager.Reserve(name, name, os.Getpid(), "")
		if err != nil {
			t.Fatal(err)
		}
		if err := a.manager.Register(id, name, "http://127.0.0.1:3000", "node"); err != nil {
			t.Fatal(err)
		}
		if name == "web" {
			t.Cleanup(func() { _ = a.manager.Unregister(id, name) })
		}
		if name == "api" {
			if err := a.manager.Unregister(id, name); err != nil {
				t.Fatal(err)
			}
		}
	}
	path, err := privateprotocol.DescriptorPath(a.state.Root(), a.project.Root)
	if err != nil {
		t.Fatal(err)
	}
	if err := privateprotocol.WriteEndpoint(path, endpoint); err != nil {
		t.Fatal(err)
	}
	changed := a.project
	changed.Config.Services = config.Services{"web": {Tunnel: &config.Tunnel{}}, "api": {Tunnel: &config.Tunnel{Access: &config.Access{Mode: "restricted"}}}}
	if _, err := EnsureOwner(t.Context(), changed, a.state.Root()); err == nil {
		t.Fatal("restarted app silently reused the old owner's policy")
	}
}
