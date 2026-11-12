package resolve

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestEnvironmentSelectorsNarrowOnlyAuthorizedProjectInventory(t *testing.T) {
	environments := []controlv1.Environment{{Id: "production-id", Name: "production", TeamId: "team", ProjectKey: "project"}, {Id: "staging-id", Name: "staging", TeamId: "team", ProjectKey: "project"}}
	for _, selector := range []string{"production", "production-id"} {
		selected, err := SelectEnvironments(environments, "team", "project", selector)
		if err != nil || len(selected) != 1 || selected[0].Id != "production-id" {
			t.Fatalf("environment selector=%s: %+v, %v", selector, selected, err)
		}
	}
	if _, err := SelectEnvironments(environments, "team", "project", "missing"); err == nil {
		t.Fatal("unknown environment selected a fallback")
	}
	for _, field := range []string{"team", "project", "duplicate", "ambiguous"} {
		copy := append([]controlv1.Environment{}, environments...)
		switch field {
		case "team":
			copy[0].TeamId = "other"
		case "project":
			copy[0].ProjectKey = "other"
		case "duplicate":
			copy[0].Id = copy[1].Id
		case "ambiguous":
			copy[1].Name = copy[0].Id
		}
		_, err := SelectEnvironments(copy, "team", "project", "production-id")
		if err == nil {
			t.Fatalf("accepted wrong or ambiguous %s inventory", field)
		}
		if field != "ambiguous" {
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid {
				t.Fatalf("wrong inventory error: %v", err)
			}
		}
	}
}
