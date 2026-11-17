package invocation

import (
	"bytes"
	"encoding/json"
	"testing"

	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var integrationIntentCases = []struct {
	hostname string
	intent   targetsyntax.IntegrationTarget
}{
	{"oauth.member.example", targetsyntax.OAuthIntegration},
	{"hooks.member.example", targetsyntax.WebhookIntegration},
}

func TestIntegrationPreparationDoesNotConvertOrdinaryApp(t *testing.T) {
	for _, test := range integrationIntentCases {
		hostname, intent := test.hostname, test.intent
		for _, mode := range []controlv1.VisitorAccessMode{controlv1.Restricted, controlv1.Anonymous} {
			t.Run(hostname+"/"+string(mode), func(t *testing.T) {
				f := newServiceSetupFixture(t, hostname)
				saved, err := reserveConfiguredService(t.Context(), f.services, controlv1.ProjectServiceConfiguration{
					Target: "app", Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: &mode}},
				})
				if err != nil {
					t.Fatal(err)
				}
				before, err := json.Marshal(f.declaration)
				if err != nil {
					t.Fatal(err)
				}
				updates, changes := f.updates, f.changes
				cfg, adopted, err := nativeIntegrationConfig(t.Context(), f.services, hostname, intent, nil)
				if err == nil || cfg.Control != nil || cfg.Access != nil || cfg.ServiceID != "" || adopted.Id != "" {
					t.Error("ordinary app was silently converted to an anonymous integration", err)
				}
				after, err := json.Marshal(f.declaration)
				if err != nil || !bytes.Equal(before, after) || f.saved.Id != saved.Id ||
					f.updates != updates || f.changes != changes || f.enrollments != 0 || f.redemptions != 0 || f.runs != 0 {
					t.Error("refused conversion mutated the app or minted integration authority", err)
				}
			})
		}
	}
}

func TestIntegrationPreparationAcceptsOnlyTheExplicitConvertedIntent(t *testing.T) {
	for _, test := range integrationIntentCases {
		t.Run(test.hostname, func(t *testing.T) {
			f := newServiceSetupFixture(t, test.hostname)
			saved, err := reserveConfiguredService(t.Context(), f.services, controlv1.ProjectServiceConfiguration{
				Target: "app", Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: new(controlv1.Restricted)}},
			})
			if err != nil {
				t.Fatal(err)
			}
			declaration, digest, err := f.services.routes.GetServiceConfiguration(t.Context(), saved.Id)
			if err != nil || declaration == nil {
				t.Fatal(err)
			}
			declaration.Target = string(test.intent)
			declaration.Http.Access.Mode = new(controlv1.Anonymous)
			_, err = f.services.routes.ConfigureService(t.Context(), saved.Id, controlv1.UpdateServiceRequest{
				Protocol: saved.Protocol, ExpectedTrustRevision: saved.TrustRevision,
				ExpectedConfigurationDigest: &digest, Configuration: declaration,
				ExpectedPublisherPool: new(saved.PublisherPool), PublisherPool: saved.PublisherPool,
			})
			if err != nil {
				t.Fatal("explicit conversion failed", err)
			}
			other := targetsyntax.OAuthIntegration
			if test.intent == other {
				other = targetsyntax.WebhookIntegration
			}
			if _, _, err := nativeIntegrationConfig(t.Context(), f.services, test.hostname, other, nil); err == nil || f.enrollments != 0 {
				t.Fatal("one integration intent silently became another", err)
			}
			cfg, adopted, err := nativeIntegrationConfig(t.Context(), f.services, test.hostname, test.intent, nil)
			if err != nil || cfg.ServiceID != saved.Id || adopted.Id != saved.Id || f.creates != 1 || f.enrollments != 1 {
				t.Fatal("explicit converted declaration did not retain the one service and exact publisher grant", err)
			}
		})
	}
}
