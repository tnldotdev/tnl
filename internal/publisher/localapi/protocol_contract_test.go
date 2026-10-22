package localpublisher

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clientruntime "github.com/tnldotdev/tnl/internal/publisher/app"
	privateprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/pkg/api/localpublisherv1"
)

func TestStatusProtocolsMatchContract(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	protocols := []string{"http", "tcp", "mysql", "postgres", "kubernetes"}
	services := make([]clientruntime.Service, 0, len(protocols))
	for _, protocol := range protocols {
		services = append(services, clientruntime.Service{Name: protocol, ServiceProtocol: protocol})
	}
	manager, err := clientruntime.New(t.Context(), root, database, services, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	server := httptest.NewUnstartedServer(nil)
	caps, err := privateprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = (&Server{Capabilities: caps, Manager: manager, Database: database, Project: root}).Handler()
	server.Start()
	defer server.Close()
	var snapshot localpublisherv1.Snapshot
	if err := privateprotocol.Call(t.Context(), caps.Owner(), "GET", "/v1/status", nil, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Services) != len(protocols) {
		t.Fatalf("status services: %+v", snapshot.Services)
	}
	for _, service := range snapshot.Services {
		if service.ServiceProtocol == nil || !service.ServiceProtocol.Valid() || string(*service.ServiceProtocol) != service.Service {
			t.Errorf("generated contract rejects or changes emitted protocol for %q: %v", service.Service, service.ServiceProtocol)
		}
	}
}
