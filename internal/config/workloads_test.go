package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkloadProviderDeclarationsAndLegacyRejection(t *testing.T) {
	services := Services{"inventory": {PublisherGroup: new("production"), Target: &ServiceTarget{Type: "address", Address: new(Target("localhost:3000"))}}, "models": {PublisherGroup: new("production"), Protocol: new("postgres"), Target: &ServiceTarget{Type: "address", Address: new(Target("localhost:5432"))}}}
	for _, p := range []Workload{
		{Provider: "vercel", TeamID: "team_one", ProjectID: "prj_store", Environment: "production", Services: []string{"inventory", "models"}},
		{Provider: "fly", Org: "acme", OrgID: "123", App: "store", AppID: "456", Services: []string{"inventory"}},
		{Provider: "oidc", Issuer: "https://issuer.example", JWKSURL: "https://issuer.example/.well-known/jwks", Audience: "store", Claims: map[string]string{"sub": "store"}, Services: []string{"models"}},
	} {
		t.Run(p.Provider, func(t *testing.T) {
			configuration := TNL{PublisherGroups: map[string]PublisherGroup{"production": {}}, Services: services, Workloads: map[string]Workload{"storefront": p}}
			if err := ValidateTNL(configuration); err != nil {
				t.Fatal("valid provider rejected", err)
			}
			bad := p
			bad.Provider = "unknown"
			configuration.Workloads["storefront"] = bad
			if err := ValidateTNL(configuration); err == nil {
				t.Fatal("unknown provider accepted")
			}
			bad = p
			bad.GitHub = &WorkloadGitHub{}
			configuration.Workloads["storefront"] = bad
			if err := ValidateTNL(configuration); err == nil {
				t.Fatal("mixed provider policy accepted")
			}
			bad = p
			bad.Services = []string{"missing"}
			configuration.Workloads["storefront"] = bad
			if err := ValidateTNL(configuration); err == nil {
				t.Fatal("unknown service accepted")
			}
			configuration.Workloads["storefront"] = p
			document := Document{Version: new(1), TNL: &configuration}
			b, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "tnl.json")
			if err = os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = LoadDocument(path); err != nil {
				t.Fatal("static workload rejected", err)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "tnl.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"tnl":{"ci":{}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDocument(path); err == nil {
		t.Fatal("legacy ci alias accepted")
	}
}
