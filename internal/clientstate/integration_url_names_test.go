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

func TestIntegrationURLHostnameReplacesOldOAuthAndWebhookLabelsOnce(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	const server, project, namespace = "https://control.example.test", "/projects/shop", "member.example.test"
	if _, err := state.Server(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ purpose, old, proposed string }{
		{"oauth", "oauth-shop-ab1234.member.example.test", "oauth-shop-k4m2pv.member.example.test"},
		{"hooks", "hooks-shop-ab1234.member.example.test", "hooks-shop-k4m2pv5d7g2aq.member.example.test"},
	} {
		if _, err := state.db.ExecContext(t.Context(), `INSERT INTO integration_url_hostnames
			(server_origin, project_key, namespace, purpose, hostname) VALUES (?, ?, ?, ?, ?)`, server, project, namespace, test.purpose, test.old); err != nil {
			t.Fatal(err)
		}
		got, err := state.IntegrationURLHostname(t.Context(), server, project, namespace, test.purpose, test.proposed)
		if err != nil || got != test.proposed {
			t.Fatalf("%s migration = %q, %v", test.purpose, got, err)
		}
		got, err = state.IntegrationURLHostname(t.Context(), server, project, namespace, test.purpose, test.old)
		if err != nil || got != test.proposed {
			t.Fatalf("%s migrated name was replaced again: %q, %v", test.purpose, got, err)
		}
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	got, err := state.IntegrationURLHostname(t.Context(), server, project, namespace, "hooks", "hooks-other-aaaaaaaaaaaaa.member.example.test")
	if err != nil || got != "hooks-shop-k4m2pv5d7g2aq.member.example.test" {
		t.Fatalf("saved webhook URL after restart = %q, %v", got, err)
	}
}
