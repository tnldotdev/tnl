package resolve

import (
	"encoding/json"
	"strings"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestLocalDeclarationOmitsPublisherConfiguration(t *testing.T) {
	project := clientproject.Project{Config: config.TNL{
		OAuth:    true,
		Webhooks: map[string]config.Webhook{"payments": {Service: "web", Path: "/private-hook", Provider: "custom"}},
		Services: config.Services{
			"web": {Public: new(true), Target: &config.ServiceTarget{Type: "address", Address: new(config.Target("http://private.internal:3000"))},
				HTTP: &config.HTTPService{Open: new(true), Readiness: &config.Readiness{Path: "/private-health"}, Paths: map[string]config.PathMount{"/private-mount": {Service: "api"}},
					Access: &config.Access{Mode: "anonymous"}, Limits: &config.WorkLimits{Concurrency: new(4)}}},
			"api": {Target: &config.ServiceTarget{Type: "docker", Container: new("private-container"), Port: new(3001)}},
		},
	}}
	value, err := Declaration(t.Context(), project, appliedTestContext(), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private.internal", "private-container", "/private-hook", "/private-health", "/private-mount"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("local declaration exposed publisher configuration", secret)
		}
	}
	web := value.Services["web"]
	if value.Oauth || len(value.Webhooks) != 0 || web.Http == nil || *web.Http.Access.Mode != "anonymous" || *web.Http.Limits.Concurrency != 4 {
		t.Fatal("local minimization lost shared visitor policy")
	}
	if !project.Config.OAuth || len(project.Config.Webhooks) != 1 || project.Config.Services["web"].HTTP.Readiness == nil {
		t.Fatal("declaration changed local runtime configuration")
	}
}
