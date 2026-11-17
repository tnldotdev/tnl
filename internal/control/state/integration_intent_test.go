package state

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestIntegrationTargetRequiresExplicitAnonymousHandlerIntent(t *testing.T) {
	for _, target := range []string{"integration:oauth", "integration:webhooks"} {
		t.Run(target, func(t *testing.T) {
			declaration := ProjectServiceConfiguration{
				Target: target, Public: new(true),
				HTTP: &config.HTTPService{Access: &config.Access{Mode: "anonymous"}},
			}
			if err := normalizeAppliedProjectService("integration", &declaration, true); err != nil {
				t.Fatal("explicit anonymous integration handler was rejected", err)
			}
			for _, mutate := range []func(*ProjectServiceConfiguration){
				func(d *ProjectServiceConfiguration) { d.HTTP = nil },
				func(d *ProjectServiceConfiguration) { d.HTTP.Access.Mode = "" },
				func(d *ProjectServiceConfiguration) { d.HTTP.Access.Mode = "restricted" },
				func(d *ProjectServiceConfiguration) { d.Protocol = "tcp" },
				func(d *ProjectServiceConfiguration) { d.Ephemeral = true },
				func(d *ProjectServiceConfiguration) { d.TargetTLS = &ProjectTargetTLS{Hostname: "target.example"} },
				func(d *ProjectServiceConfiguration) { d.Target = "integration:unknown" },
			} {
				invalid := ProjectServiceConfiguration{Target: target, Public: new(true),
					HTTP: &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}}
				mutate(&invalid)
				if err := normalizeAppliedProjectService("integration", &invalid, true); err == nil {
					t.Error("integration accepted an implicit, incompatible, or unknown handler declaration", invalid)
				}
			}
		})
	}
}
