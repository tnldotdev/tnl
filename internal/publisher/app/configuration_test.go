package app

import (
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestConfiguredServicesOnlyIncludesExplicitLocalTargets(t *testing.T) {
	project := clientproject.Project{Config: config.TNL{Services: config.Services{"web": {}, "orders": {Protocol: new("postgres")}, "remote": {Protocol: new("mysql")}}, Environments: map[string]config.Environment{
		"local":   {Targets: map[string]config.EnvironmentTarget{"web": {}, "orders": {Address: new(config.Target("127.0.0.1:5432"))}}},
		"staging": {Targets: map[string]config.EnvironmentTarget{"remote": {Address: new(config.Target("db.internal:3306"))}, "web": {Address: new(config.Target("web.internal:8080"))}}},
	}}}
	services := ConfiguredServices(project)
	if len(services) != 2 || services[0].Name != "orders" || services[0].ServiceProtocol != "postgres" || services[1].Name != "web" {
		t.Fatalf("local inventory included remote-only shape or lost a local target: %+v", services)
	}
	delete(project.Config.Environments, "local")
	if services := ConfiguredServices(project); len(services) != 0 {
		t.Fatalf("remote environment targets fell back into local inventory: %+v", services)
	}
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), ConfiguredServices(project), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if services := manager.Snapshot().Services; len(services) != 0 {
		t.Fatalf("native observations reported remote-only registrations: %+v", services)
	}
}

func TestConfiguredServicesKeepsImplicitLocalWithoutEnvironments(t *testing.T) {
	project := clientproject.Project{Config: config.TNL{Services: config.Services{"web": {}, "orders": {Protocol: new("postgres")}}}}
	services := ConfiguredServices(project)
	if len(services) != 2 || services[0].Name != "orders" || services[1].Name != "web" {
		t.Fatalf("implicit local services changed without environment declarations: %+v", services)
	}
}
