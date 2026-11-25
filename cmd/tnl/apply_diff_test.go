package main

import (
	"bytes"
	"strings"
	"testing"

	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	api "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestApplyDiffReviewsPublicAccessAndWorkloadRemoval(t *testing.T) {
	old := api.AppliedProjectConfiguration{Revision: 12, Configuration: api.ProjectConfiguration{
		Services:  map[string]api.ProjectServiceConfiguration{"orders": {Target: "db:5432"}},
		Workloads: &map[string]api.ProjectWorkload{"migration": {Services: []string{"orders"}}},
	}}
	next := api.ProjectConfiguration{Services: map[string]api.ProjectServiceConfiguration{"orders": {Target: "db:5432", Public: new(true)}}}
	d, err := compareApply(authorityv1.Team{Id: "team"}, "production", old, next, nil)
	if err != nil || d.Base != 12 {
		t.Fatal(d, err)
	}
	var out bytes.Buffer
	if err := d.write(&out, statusOutputHuman, "studio"); err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(out.String()), " ")
	if !strings.HasPrefix(text, "Proposed changes to production (team studio): RESOURCE FIELD BEFORE AFTER") || !strings.Contains(text, "binding orders reachability connector-only public endpoint requested") ||
		!strings.Contains(text, `workload migration allowed services ["orders"] (absent)`) {
		t.Fatal(out.String())
	}
	var removal bool
	for _, c := range d.Changes {
		if c.Resource == "workload" && c.Field == "services" && c.After == nil && string(c.Before) == `["orders"]` {
			removal = true
		}
	}
	if !removal {
		t.Fatal(d)
	}
}

func TestApplyDiffUsesCapturedDomainForInheritedBindings(t *testing.T) {
	const name = "production"
	team := authorityv1.Team{Id: "team", DefaultDomainId: "new-default"}
	old := api.AppliedProjectConfiguration{
		Revision: 2, Deployments: &[]api.AppliedDeployment{{Name: name, DomainId: "captured"}},
		Configuration: api.ProjectConfiguration{
			Settings: &api.DeploymentSettings{DomainId: new("captured")},
			Services: map[string]api.ProjectServiceConfiguration{"orders": {Target: "app", DomainId: new("captured")}},
		},
	}
	next := api.ProjectConfiguration{Settings: &api.DeploymentSettings{}, Services: map[string]api.ProjectServiceConfiguration{"orders": {Target: "app"}}}
	diff, err := compareApply(team, name, old, next, nil)
	if err != nil || len(diff.Changes) != 0 {
		t.Fatalf("omitted domain changed the deployment: %+v (%v)", diff, err)
	}
	binding := next.Services["orders"]
	binding.DomainId = new("selected")
	next.Services["orders"] = binding
	diff, err = compareApply(team, name, old, next, nil)
	if err != nil || len(diff.Changes) != 1 || diff.Changes[0].Resource != "binding" || string(diff.Changes[0].After) != `"selected"` {
		t.Fatalf("missing explicit domain change: %+v (%v)", diff, err)
	}
}
