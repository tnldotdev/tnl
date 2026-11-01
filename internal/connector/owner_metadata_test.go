package connector

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestWorkloadInventoryProjectsExactServiceFactsAndRejectsDuplicates(t *testing.T) {
	var inventory controlv1.WorkloadServices
	if err := json.Unmarshal([]byte(`{"services":[{"id":"svc_0123456789ABCDEFGHIJKL","service":"api","protocol":"http","endpoint":{"hostname":"api.example.test","port":25443,"public":true}}]}`), &inventory); err != nil {
		t.Fatal(err)
	}
	services, err := workloadInventoryServices(inventory, "team")
	if err != nil || len(services) != 1 {
		t.Fatal(services, err)
	}
	service := services["api"]
	if service.Id != inventory.Services[0].Id || service.Name != "api" || service.TeamId != "team" || !service.Enabled || service.Protocol != "http" || service.Endpoint == nil || *service.Endpoint != inventory.Services[0].Endpoint {
		t.Fatal("inventory projection changed approved service facts")
	}
	inventory.Services = append(inventory.Services, inventory.Services[0])
	if _, err := workloadInventoryServices(inventory, "team"); !errors.Is(err, connectorruntime.ErrInvalid) {
		t.Fatal("duplicate service name silently replaced an approved record", err)
	}
}

func TestConnectionMetadataProjectsOnlyRequestedValidProtocolsInScopeOrder(t *testing.T) {
	service := controlv1.Service{Id: "svc_0123456789ABCDEFGHIJKL", Enabled: true, Protocol: "http", Endpoint: &controlv1.ServiceEndpoint{Hostname: "api.example.test", Port: 25443, Public: true}}
	database := service
	database.Protocol = "postgres"
	database.Endpoint = &controlv1.ServiceEndpoint{Hostname: "db.example.test", Port: 25444}
	invalid := service
	invalid.Endpoint = nil
	inventory := map[string]controlv1.Service{"api": service, "db": database, "wrong-protocol": database, "invalid": invalid, "unrequested": service}
	configuration := config.TNL{Services: config.Services{"api": {}, "db": {Protocol: new("postgres")}, "wrong-protocol": {}, "invalid": {}}}
	services, metadata, err := projectConnectionMetadata(configuration, []string{"missing", "db", "api", "wrong-protocol", "invalid"}, inventory)
	if err != nil || len(services) != 2 || len(metadata.Services) != 2 || metadata.Namespace != "db.example.test" {
		t.Fatal("projection included an invalid or unrequested service", services, metadata, err)
	}
	if metadata.Services["api"].Hostname != service.Endpoint.Hostname || !metadata.Services["api"].Public || metadata.Services["api"].URL != "https://api.example.test:25443" || metadata.Services["db"].Public {
		t.Fatal("metadata changed managed TLS identity or reachability", metadata)
	}
	if len(inventory) != 5 {
		t.Fatal("projection mutated the caller's inventory")
	}
	if _, err := connectionServiceMetadata(database, "http"); !errors.Is(err, connectorruntime.ErrInvalid) {
		t.Fatal("single-service refresh accepted another protocol", err)
	}
}
