package config

import (
	"strings"
	"testing"
)

func TestVercelProjectNameValidation(t *testing.T) {
	for _, name := range []string{
		"a", "0", "store-front", "store_front", "store.front", "store--front", "prj_store",
		strings.Repeat("a", 64), strings.Repeat("a", 100),
	} {
		t.Run(name, func(t *testing.T) {
			if !ValidVercelProjectName(name) {
				t.Fatal("valid Vercel project name rejected")
			}
			configuration := TNL{Deployment: "production", Services: Services{"db": {}}, Workloads: map[string]Workload{"web": {Vercel: &WorkloadVercel{Project: name, Team: "acme", Environment: "production"}, Services: []string{"db"}}}}
			if err := ValidateWorkloads(configuration.Services, configuration.Workloads); err != nil {
				t.Fatal("valid Vercel project declaration rejected", err)
			}
		})
	}
	for _, name := range []string{
		"", strings.Repeat("a", 101), "Store_front", "store---front", "store front", "store/front",
		"store\\front", "store\n", "store\x00", "store?front", "störé", "store:front",
	} {
		t.Run(name, func(t *testing.T) {
			if ValidVercelProjectName(name) {
				t.Fatal("invalid Vercel project name accepted")
			}
		})
	}
}

func TestVercelWorkloadTeamRemainsDNSLabel(t *testing.T) {
	configuration := TNL{Deployment: "production", Services: Services{"db": {}}, Workloads: map[string]Workload{"web": {Vercel: &WorkloadVercel{Project: "store_front", Team: "acme_inc", Environment: "production"}, Services: []string{"db"}}}}
	if err := ValidateWorkloads(configuration.Services, configuration.Workloads); err == nil {
		t.Fatal("Vercel project-name rules were applied to the team slug")
	}
}
