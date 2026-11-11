package config

import "testing"

func TestPublisherGroupBoundTargetRequiresTemplateWithoutFixedTarget(t *testing.T) {
	for _, test := range []struct {
		name     string
		template bool
		target   *ServiceTarget
		binding  string
		valid    bool
	}{
		{name: "bound", template: true, binding: "group", valid: true},
		{name: "direct group", binding: "group"},
		{name: "mixed", template: true, binding: "group", target: &ServiceTarget{Type: "address", Address: new(Target("db.internal:5432"))}},
		{name: "fixed", template: true, binding: "fixed", target: &ServiceTarget{Type: "address", Address: new(Target("db.internal:5432"))}, valid: true},
		{name: "missing fixed", template: true, binding: "fixed"},
		{name: "unknown", template: true, binding: "runtime"},
	} {
		t.Run(test.name, func(t *testing.T) {
			configuration := TNL{PublisherGroups: map[string]PublisherGroup{"customer": {Template: test.template}}, Services: Services{"db": {PublisherGroup: new("customer"), Protocol: new("postgres"), TargetBinding: test.binding, Target: test.target}}}
			err := ValidateTNL(configuration)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v want=%v: %v", err == nil, test.valid, err)
			}
		})
	}
}
