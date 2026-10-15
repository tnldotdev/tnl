package clientstate

import (
	"path/filepath"
	"testing"
)

func TestIntegrationURLHostnameIsSavedPerProjectServerNamespaceAndPurpose(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	const server = "https://control.example.test"
	origin, err := state.IntegrationURLHostname(t.Context(), server, "/projects/shop", "member.example.test", "oauth", "oauth-shop-ab1234.member.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	got, err := state.IntegrationURLHostname(t.Context(), server, "/projects/shop", "member.example.test", "oauth", "oauth-renamed-abcdef.member.example.test")
	if err != nil || got != origin {
		t.Fatalf("saved origin changed: %q, %v", got, err)
	}
	for _, other := range []struct{ server, project, namespace, purpose, proposed string }{
		{server, "/projects/shop", "other.example.test", "oauth", "oauth-shop-ab1234.other.example.test"},
		{server, "/projects/other", "member.example.test", "oauth", "oauth-other-abcdef.member.example.test"},
		{"https://other.example.test", "/projects/shop", "member.example.test", "oauth", "oauth-other-abcdef.member.example.test"},
		{server, "/projects/shop", "member.example.test", "other", "other-shop-ab1234.member.example.test"},
	} {
		got, err := state.IntegrationURLHostname(t.Context(), other.server, other.project, other.namespace, other.purpose, other.proposed)
		if err != nil || got != other.proposed {
			t.Fatalf("context reused another origin: %q, %v", got, err)
		}
	}
	if _, err := state.IntegrationURLHostname(t.Context(), server, "/projects/shop", "member.example.test", "oauth", "nested.oauth.member.example.test"); err == nil {
		t.Fatal("nested callback hostname was accepted")
	}
}
