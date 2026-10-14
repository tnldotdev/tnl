package main

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestAdminBrowserSelectionNeedsOwnedHTTPApp(t *testing.T) {
	id := "url_0123456789abcdefghijkl"
	inventory := []controlv1.AvailablePublicURL{{Id: id, CanonicalHostname: "web.example.test", ServiceProtocol: controlv1.Http,
		Purpose: controlv1.App, VisitorAccess: "owner"}}
	for _, selector := range []string{id, "web.example.test", "https://web.example.test"} {
		selected, err := selectAdminBrowserURL(selector, inventory)
		if err != nil || selected.Id != id {
			t.Fatalf("admin URL %q = %+v, %v", selector, selected, err)
		}
	}
	for _, selector := range []string{"http://web.example.test", "https://web.example.test/path", "web.example.test:443"} {
		if _, err := selectAdminBrowserURL(selector, inventory); err == nil {
			t.Fatalf("unsafe admin browser URL %q accepted", selector)
		}
	}
	for _, access := range []controlv1.AvailablePublicURLVisitorAccess{"inventory", "team", "invite"} {
		inventory[0].VisitorAccess = access
		if _, err := selectAdminBrowserURL(id, inventory); err == nil {
			t.Fatalf("%q visitor obtained owner browser access", access)
		}
	}
	if _, err := selectAdminBrowserURL("missing.example.test", inventory); !errors.Is(err, controlclient.ErrNotFound) {
		t.Fatalf("missing admin URL = %v", err)
	}
}
