package cli_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationCLITeamSelectionAndApplyPreview(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	const (
		personal = "tm_0000000000000000000001"
		org      = "tm_0000000000000000000002"
		origin   = "https://example.test/studio/app.git"
	)
	memberships := []authorityv1.Membership{
		{TeamId: personal, TeamDisplayName: "personal", Role: authorityv1.TeamRoleOwner},
		{TeamId: org, TeamDisplayName: "studio", Role: authorityv1.TeamRoleAdmin},
	}
	source, err := (naming.GitProjectSource{GitOrigin: origin, ConfigurationPath: "tnl.json"}).Identity()
	if err != nil {
		t.Fatal(err)
	}
	token, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet || (r.URL.Path != "/v1/discovery" && r.Header.Get("Authorization") != "Bearer "+token.String()) {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var response any
		switch r.URL.Path {
		case "/v1/discovery":
			response = controlv1.ControlDiscovery{
				ManagedDomain: "example.test", ManagedUrlMode: controlv1.Simple,
				Authentication: controlv1.AuthenticationFacts{
					Methods: []controlv1.AuthenticationFactsMethods{controlv1.Oidc},
					Oidc:    &controlv1.OIDCAuthenticationFacts{Issuer: "https://issuer.example.test", LoginFlow: controlv1.DeviceCode},
				},
			}
		case "/v1/identity":
			response = authorityv1.IdentityContext{PersonalTeamId: personal, DefaultTeamId: new(org), Memberships: memberships}
		case "/v1/teams/" + personal:
			response = authorityv1.Team{Id: personal, DisplayName: "personal", Kind: authorityv1.Personal, DefaultDomainId: "domain"}
		case "/v1/teams/" + org:
			response = authorityv1.Team{Id: org, DisplayName: "studio", Kind: authorityv1.Organization, DefaultDomainId: "domain"}
		case "/v1/teams/" + personal + "/domains", "/v1/teams/" + org + "/domains":
			response = authorityv1.DomainPage{Domains: []authorityv1.Domain{
				{Id: "domain", CanonicalDomain: "example.test", Kind: authorityv1.Managed, State: authorityv1.DomainStateReady},
			}}
		case "/v1/projects/" + source.Key + "/configuration":
			if r.URL.Query().Get("deployment") != "local" || r.URL.Query().Get("team_id") != org {
				t.Errorf("preview addressed the wrong scope: %s", r.URL)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			response = controlv1.AppliedProjectConfiguration{
				TeamId: org, Deployment: "local", ProjectKey: source.Key, SourceFingerprint: source.Fingerprint, Revision: 7,
			}
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	var env []string
	if keychain := testutil.UseClientKeychain(t); keychain != "" {
		env = append(env, "TNL_STATE_KEYCHAIN="+keychain)
	}
	dir := t.TempDir()
	env = append(env, "PATH="+os.Getenv("PATH"), "TNL_ACCESS_TOKEN="+token.String())
	for _, args := range [][]string{{"init", "--quiet"}, {"remote", "add", "origin", origin}} {
		cmd := exec.CommandContext(t.Context(), "git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture Git setup: %v %s", err, out)
		}
	}
	state := filepath.Join(dir, "state")
	db, err := clientstate.Open(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := db.Server(t.Context(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		t.Helper()
		got := runBuiltCLI(t, dir, env, append(args, "--server", server.URL, "--state-dir", state)...)
		if got.exit != 0 || got.stderr != "" {
			t.Fatalf("%v failed: %+v", args, got)
		}
		return got.stdout
	}
	wantCurrent := func(wantID, wantName, wantRole, wantSource string, args ...string) {
		t.Helper()
		raw := run(append([]string{"team", "current", "--output", "json"}, args...)...)
		var got struct {
			SchemaVersion int    `json:"schema_version"`
			TeamID        string `json:"team_id"`
			TeamName      string `json:"team_name"`
			Role          string `json:"role"`
			Source        string `json:"source"`
		}
		if err := json.Unmarshal([]byte(raw), &got); err != nil || got.SchemaVersion != 1 ||
			got.TeamID != wantID || got.TeamName != wantName || got.Role != wantRole || got.Source != wantSource {
			t.Fatalf("team current %v: %s (%v)", args, raw, err)
		}
	}
	wantSaved := func(want string) {
		t.Helper()
		id, found, err := store.SelectedTeam(t.Context())
		if err != nil || found != (want != "") || id != want {
			t.Fatalf("saved team = %q, %t, %v; want %q", id, found, err, want)
		}
	}

	if got := run("--no-config", "team", "list"); !strings.Contains(got, "studio") {
		t.Fatalf("organization is missing from team list: %s", got)
	}
	wantCurrent(org, "studio", "admin", "initial", "--no-config")
	wantSaved("")
	const projectConfig = `{
		"version":1,"tnl":{"team":"personal","services":{"web":{}},"deployments":{"local":{"targets":{"web":{}}}}}
	}`
	config := filepath.Join(dir, "tnl.json")
	if err := os.WriteFile(config, []byte(projectConfig), 0600); err != nil {
		t.Fatal(err)
	}
	wantCurrent(personal, "personal", "owner", "project")
	wantCurrent(org, "studio", "admin", "flag", "--team", "studio")
	args := []string{"apply", "--team", "studio", "--output", "json"}
	rawPreview := run(append(args, "--dry-run")...)
	if diff := run(append(args, "--diff")...); diff != rawPreview {
		t.Fatalf("preview aliases differ:\n--dry-run: %s\n--diff: %s", rawPreview, diff)
	}
	var preview struct {
		TeamID   string            `json:"team_id"`
		Revision string            `json:"base_revision"`
		Changes  []json.RawMessage `json:"changes"`
	}
	if err := json.Unmarshal([]byte(rawPreview), &preview); err != nil ||
		preview.TeamID != org || preview.Revision != "7" || len(preview.Changes) == 0 {
		t.Fatalf("preview lost scope, revision, or changes: %s (%v)", rawPreview, err)
	}
	if err := os.WriteFile(config, []byte(strings.Replace(projectConfig, `"team":"personal",`, "", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if initialPreview := run("apply", "--dry-run", "--output", "json"); initialPreview != rawPreview {
		t.Fatalf("preview did not use the initial organization team: %s", initialPreview)
	}
	wantSaved("")
	run("team", "use", "personal")
	wantCurrent(personal, "personal", "owner", "saved", "--no-config")
}
