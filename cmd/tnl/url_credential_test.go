package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestCredentialCreationOutputKeepsSecretOutsideTheDiagram(t *testing.T) {
	secret, _, _, err := credentials.NewPublicURLPublishCredential()
	if err != nil {
		t.Fatal(err)
	}
	result := publicURLCredentialCreateResult{
		SchemaVersion: 1, PublicURL: "https://app.alex.example.test", PublicURLID: "url_test",
		Target: "http://app:3000", CredentialID: "upc_test", Credential: secret.String(),
		ExpiresAt: time.Date(2027, 1, 7, 12, 0, 0, 0, time.UTC),
	}
	var stdout, stderr bytes.Buffer
	if err := writeCredentialCreateResult(credentialOutputHuman, result, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != secret.String()+"\n" || strings.Contains(stderr.String(), secret.String()) ||
		!strings.Contains(stderr.String(), result.PublicURL) || !strings.Contains(stderr.String(), result.CredentialID) {
		t.Fatalf("human output leaked or lost a value: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if err := writeCredentialCreateResult(credentialOutputJSON, result, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var encoded publicURLCredentialCreateResult
	if err := json.Unmarshal(stdout.Bytes(), &encoded); err != nil || encoded != result || stderr.Len() != 0 {
		t.Fatalf("JSON output = %#v, stderr = %q, err = %v", encoded, stderr.String(), err)
	}
	result.Target = ""
	stdout.Reset()
	stderr.Reset()
	if err := writeCredentialCreateResult(credentialOutputHuman, result, &stdout, &stderr); err != nil ||
		strings.Contains(stderr.String(), "target") || stdout.String() != secret.String()+"\n" {
		t.Fatalf("targetless credential output = %q, %q, %v", stdout.String(), stderr.String(), err)
	}
}

func TestCredentialLifetimeAcceptsPositiveDurationsUpToNinetyDays(t *testing.T) {
	for _, value := range []string{"1s", "24h", "7d", "90d"} {
		if got, err := parseCredentialLifetime(value); err != nil || got <= 0 || got > 90*24*time.Hour {
			t.Fatalf("lifetime %q = %s, %v", value, got, err)
		}
	}
	for _, value := range []string{"0s", "100ms", "1.5s", "-1s", "91d", "1w", "999999999999999999999d"} {
		if _, err := parseCredentialLifetime(value); err == nil {
			t.Fatalf("invalid lifetime %q was accepted", value)
		}
	}
}

func TestCredentialCreationUsesProjectServiceOnlyWhenSelected(t *testing.T) {
	target := config.Target("http://app:3000")
	root := t.TempDir()
	worktree, err := projectconfig.ResolveWorktree(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	worktree = projectconfig.ApplyWorktreeHashSalt(worktree, root, [32]byte{1})
	project := projectConfiguration{Project: projectconfig.Project{
		Selection: projectconfig.Selection{Path: root + "/tnl.yml"}, Root: root, Worktree: worktree,
		Config: config.TNL{Services: config.Services{"api": {Publish: &config.Publish{Target: &target}}}},
	}}
	selected, err := resolveCredentialCreateConfig(publicURLCredentialCreateCommand{Selector: "api"}, project)
	if err != nil || selected.Target != "" || selected.Name != projectconfig.ServiceWorktreeLabel("api", worktree) {
		t.Fatalf("configured service = %#v, %v", selected, err)
	}
	adHoc, err := resolveCredentialCreateConfig(publicURLCredentialCreateCommand{Target: "http://app:3000"}, project)
	if err != nil || adHoc.Name != "" || adHoc.Target != string(target) {
		t.Fatalf("ad hoc URL inherited project identity = %#v, %v", adHoc, err)
	}
	implicit, err := resolveCredentialCreateConfig(publicURLCredentialCreateCommand{}, project)
	if err != nil || implicit.Name != selected.Name || implicit.Target != "" {
		t.Fatalf("single project service = %#v, %v", implicit, err)
	}
	exact, err := resolveCredentialCreateConfig(publicURLCredentialCreateCommand{PublicURL: "https://app.example.test"}, project)
	if err != nil || exact.Target != "" || exact.Name != "" || exact.PublicURL != "https://app.example.test" {
		t.Fatalf("targetless exact URL = %#v, %v", exact, err)
	}
}

func TestCredentialManagementOutputShowsMetadataWithoutSecrets(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	result := publicURLCredentialListResult{SchemaVersion: 1, Credentials: []publicURLCredentialListEntry{
		{CredentialID: "upc_current", PublicURLID: "url_app", PublicURL: "https://app.example.test", CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
		{CredentialID: "upc_old", PublicURLID: "url_app", PublicURL: "https://app.example.test", CreatedAt: now.Add(-time.Hour), ExpiresAt: now, RevokedAt: &now},
	}}
	var output bytes.Buffer
	if err := writeCredentialListResult(credentialOutputHuman, result, now, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "upc_current") || !strings.Contains(output.String(), "upc_old") ||
		!strings.Contains(output.String(), "https://app.example.test") || strings.Contains(output.String(), "tnl_publish_") {
		t.Fatalf("list output = %q", output.String())
	}
	output.Reset()
	if err := writeCredentialListResult(credentialOutputJSON, result, now, &output); err != nil {
		t.Fatal(err)
	}
	var decoded publicURLCredentialListResult
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil || decoded.SchemaVersion != 1 || len(decoded.Credentials) != 2 || strings.Contains(output.String(), "tnl_publish_") {
		t.Fatalf("JSON list output = %q, %v", output.String(), err)
	}
	output.Reset()
	urlID := controlv1.PublicURLID("url_app")
	publicURL := "https://app.example.test"
	revoked := controlv1.PublicURLPublishCredential{Id: "upc_old", Kind: controlv1.PublicURLPublishCredentialKindSavedUrl,
		PublicUrlId: &urlID, PublicUrl: &publicURL, RevokedAt: &now}
	if err := writeCredentialRevokeResult(credentialOutputJSON, revoked, &output); err != nil {
		t.Fatal(err)
	}
	var response struct {
		SchemaVersion int       `json:"schema_version"`
		CredentialID  string    `json:"credential_id"`
		RevokedAt     time.Time `json:"revoked_at"`
	}
	if err := json.Unmarshal(output.Bytes(), &response); err != nil || response.SchemaVersion != 1 || response.CredentialID != revoked.Id || !response.RevokedAt.Equal(now) {
		t.Fatalf("JSON revoke output = %q, %v", output.String(), err)
	}
}
