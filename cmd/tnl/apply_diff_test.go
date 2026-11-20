package main

import (
	"bytes"
	"strings"
	"testing"

	api "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestApplyDiffReviewsPublicAccessAndWorkloadRemoval(t *testing.T) {
	old := api.AppliedProjectConfiguration{Revision: 12, Configuration: api.ProjectConfiguration{
		Services:  map[string]api.ProjectServiceConfiguration{"orders": {Target: "db:5432"}},
		Workloads: &map[string]api.ProjectWorkload{"migration": {Services: []string{"orders"}}},
	}}
	next := api.ProjectConfiguration{Services: map[string]api.ProjectServiceConfiguration{"orders": {Target: "db:5432", Public: new(true)}}}
	d, err := compareApply("team", "production", old, next, nil)
	if err != nil || d.Base != 12 {
		t.Fatal(d, err)
	}
	var out bytes.Buffer
	if err := d.write(&out, statusOutputHuman); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "connector-only -> public endpoint requested") || !strings.Contains(out.String(), "workload migration") {
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
