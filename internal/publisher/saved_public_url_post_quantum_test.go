package publisher

import (
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestSavedPublicURLPostQuantumRequirement(t *testing.T) {
	control := &publisherControlStub{allowed: []string{"lookup", "create", "update"}}
	cfg := Config{Control: control, Management: control, TeamID: "team", DomainID: "domain", PublicURLScope: controlv1.Shared,
		Purpose: controlv1.App, Hostname: "app.example", Target: "http://127.0.0.1:3000", RequirePostQuantum: new(true)}
	u, created, err := createOrLoadPublicURL(t.Context(), cfg)
	if err != nil || !created || !u.RequirePostQuantum {
		t.Fatalf("create: %+v, %v", u, err)
	}
	cfg.RequirePostQuantum = nil
	u, created, err = createOrLoadPublicURL(t.Context(), cfg)
	if err != nil || created || !u.RequirePostQuantum || control.updated != nil {
		t.Fatalf("restart cleared saved requirement: %+v, %v", u, err)
	}
	cfg.RequirePostQuantum = new(false)
	u, _, err = createOrLoadPublicURL(t.Context(), cfg)
	if err != nil || u.RequirePostQuantum || control.updated == nil || control.updated.RequirePostQuantum == nil || *control.updated.RequirePostQuantum {
		t.Fatalf("explicit false: %+v, %v", u, err)
	}
	cfg.RequirePostQuantum = new(true)
	u, _, err = createOrLoadPublicURL(t.Context(), cfg)
	if err != nil || !u.RequirePostQuantum {
		t.Fatalf("strict policy was not restored: %+v, %v", u, err)
	}
}
