package visitorscope

import (
	"strings"
	"testing"
)

func TestScopeRequiresServiceIdentity(t *testing.T) {
	serviceID := "svc_" + strings.Repeat("A", 22)
	for _, test := range []struct {
		name  string
		scope Scope
		valid bool
	}{
		{"service", Scope{Kind: Service, ID: serviceID}, true},
		{"empty", Scope{}, false},
		{"missing ID", Scope{Kind: Service}, false},
		{"short ID", Scope{Kind: Service, ID: "svc_A"}, false},
		{"unknown kind", Scope{Kind: "unknown", ID: serviceID}, false},
		{"retired kind", Scope{Kind: "public_url", ID: "url_" + strings.Repeat("A", 22)}, false},
		{"retired kind with service ID", Scope{Kind: "public_url", ID: serviceID}, false},
		{"service with retired ID", Scope{Kind: Service, ID: "url_" + strings.Repeat("A", 22)}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.scope.Valid(); got != test.valid {
				t.Fatalf("scope validity = %t, want %t", got, test.valid)
			}
		})
	}
}
