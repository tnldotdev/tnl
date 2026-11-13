package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/zalando/go-keyring"
)

func TestShareCheckoutCommandParsing(t *testing.T) {
	for _, test := range []struct {
		args    []string
		command string
		service string
	}{
		{[]string{"share"}, "share", ""},
		{[]string{"share", "--service", "web", "--expires-in", "7d"}, "share", "web"},
		{[]string{"share", "create", "--service", "web"}, "share", "web"},
		{[]string{"share", "link", "create", "web.example.test"}, "share link create <url>", ""},
		{[]string{"share", "link", "create", "web.example.test", "--preview"}, "share link create <url>", ""},
		{[]string{"share", "token", "create", "web.example.test", "--name", "ci"}, "share token create <url>", ""},
		{[]string{"share", "list"}, "share list <url>", ""},
		{[]string{"share", "revoke", "shr_example"}, "share revoke <share-id>", ""},
		{[]string{"share", "team", "create"}, "share team create <url>", ""},
		{[]string{"share", "service", "list", "database"}, "share service list <name>", ""},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			var flags cli
			parser, err := kong.New(&flags)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := parser.Parse(test.args)
			if err != nil {
				t.Fatal(err)
			}
			command := canonicalParsedCommand(parsed.Command())
			if command != test.command || flags.Share.Create.Service != test.service || !projectSensitiveCommand(command) {
				t.Fatalf("command=%q service=%q", command, flags.Share.Create.Service)
			}
			if command == "share" && (flags.Share.Create.ExpiresIn != "24h" && flags.Share.Create.ExpiresIn != "7d" || flags.Share.Create.Output != statusOutputHuman) {
				t.Fatalf("share defaults = %+v", flags.Share.Create)
			}
		})
	}
	for _, args := range [][]string{
		{"share", "--preview"},
		{"share", "list", "--service", "web"},
		{"share", "link", "create", "--service", "web"},
	} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse(args); err == nil {
			t.Fatalf("unexpected share flags accepted: %v", args)
		}
	}
}

func TestShareCheckoutEntryIsDeterministic(t *testing.T) {
	services := map[string]shareServiceResult{
		"api": {PublicURLID: "url_api"}, "docs": {PublicURLID: "url_docs"},
		"web": {PublicURLID: "url_web"}, "app": {PublicURLID: "url_app"},
	}
	for _, test := range []struct{ remove, service, want string }{
		{"", "", "url_app"},
		{"app", "", "url_web"},
		{"web", "", "url_api"},
		{"", "docs", "url_docs"},
	} {
		delete(services, test.remove)
		got, err := checkoutShareEntry(test.service, services)
		if err != nil || got != test.want {
			t.Fatalf("entry service %q = %q, %v; want %q", test.service, got, err, test.want)
		}
	}
	for _, services := range []map[string]shareServiceResult{nil, {}} {
		if _, err := checkoutShareEntry("", services); err == nil {
			t.Fatal("empty checkout selected an entry")
		} else if reason, ok := failure.ReasonOf(err); !ok || reason != failure.PreviewNotSaved {
			t.Fatalf("empty checkout failure = %v", err)
		}
	}
	if _, err := checkoutShareEntry("missing", services); err == nil {
		t.Fatal("missing service fell back to another URL")
	}
}

func TestShareCheckoutHelpDescribesScopeAndLifetime(t *testing.T) {
	var flags cli
	var output bytes.Buffer
	parser, err := kong.New(&flags, kong.Name("tnl"), kong.Writers(&output, io.Discard), kong.Exit(func(int) {}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse([]string{"share", "--help"}); err != nil && output.Len() == 0 {
		t.Fatal(err)
	}
	for _, want := range []string{"--service", "--expires-in", "checkout", "link", "revoke"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("share help missing %q:\n%s", want, output.String())
		}
	}
}

func TestShareCheckoutValidatesBeforeAuthentication(t *testing.T) {
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{
		Services: config.Services{"web": {Tunnel: &config.Tunnel{}}, "private": {}},
	}}}
	for _, service := range []string{"missing", "private"} {
		err := runShareCheckout(t.Context(), shareCheckoutCommand{Service: service}, project, io.Discard, io.Discard)
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ShareInputInvalid {
			t.Fatalf("service %q failure = %v", service, err)
		}
	}
	for _, args := range [][]string{
		{"share", "--expires-in=0d"},
		{"share", "--name=" + strings.Repeat("x", 129)},
		{"share"},
	} {
		args = append([]string{"--no-config", "--no-telemetry"}, args...)
		args = append(args, "--state-dir", filepath.Join(t.TempDir(), "state"))
		err := run(t.Context(), args, io.Discard, io.Discard)
		reason, ok := failure.ReasonOf(err)
		if !ok || reason != failure.ShareInputInvalid && reason != failure.PreviewNotSaved {
			t.Fatalf("checkout share %v failure = %v", args, err)
		}
	}
}

func TestShareCheckoutUsesProjectServerAndTeam(t *testing.T) {
	server, team := "https://project.example.test", "shop"
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Server: &server, Team: &team}}}
	var flags cli
	if err := applyProjectCommandContext("share", project, &flags); err != nil || flags.Share.Create.ServerURL != server || flags.Share.Create.ProjectTeam != team {
		t.Fatal("share did not inherit project scope", err)
	}
	flags.Share.Create.ServerURL = "https://other.example.test"
	if err := applyProjectCommandContext("share", project, &flags); err != nil || flags.Share.Create.ProjectTeam != "" {
		t.Fatal("share retained another server's project team", err)
	}
}

func TestShareCheckoutCreatesCapturedScopeAndKeepsExactURLCommandsNarrow(t *testing.T) {
	keyring.MockInit()
	const teamID = "tm_0123456789abcdefghijkl"
	const previewID = "pv_0123456789abcdefghijkl"
	const webID = "url_0123456789abcdefghijkl"
	const apiID = "url_abcdefghijkl0123456789"
	const otherID = "url_othercheckout123456789"
	const shareID = "shr_0123456789abcdefghijkl"
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	urls := []controlv1.PublicURL{
		{Id: webID, TeamId: teamID, CanonicalHostname: "web.example.test", ServiceProtocol: controlv1.Http, LifecycleState: controlv1.Enabled},
		{Id: apiID, TeamId: teamID, CanonicalHostname: "api.example.test", ServiceProtocol: controlv1.Http, LifecycleState: controlv1.Enabled},
		{Id: otherID, TeamId: teamID, CanonicalHostname: "other.example.test", ServiceProtocol: controlv1.Http, LifecycleState: controlv1.Enabled},
	}
	type creation struct {
		path string
		body controlv1.CreateShareRequest
	}
	created := make(chan creation, 1)
	lookups := make(chan string, 8)
	var widenResponse atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		write := func(value any) { t.Helper(); _ = json.NewEncoder(w).Encode(value) }
		if r.URL.Path != "/v1/discovery" && r.Header.Get("Authorization") != "Bearer "+access.String() {
			t.Error("share management did not use its control session")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/discovery":
			write(controlv1.ControlDiscovery{ManagedDomain: "example.test", ManagedUrlMode: "generated",
				Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{"oidc"}, Oidc: &controlv1.OIDCAuthenticationFacts{Issuer: "https://issuer.example.test", LoginFlow: "device_code"}}})
		case "GET /v1/identity":
			write(authorityv1.IdentityContext{PersonalTeamId: teamID, Memberships: []authorityv1.Membership{
				{TeamId: teamID, Role: "owner", MemberSlug: "member", ManagedLabel: "member"},
			}})
		case "GET /v1/teams/" + teamID:
			write(authorityv1.Team{Id: teamID, DefaultDomainId: "dom_fixture", Kind: "organization", DisplayName: "shop"})
		case "GET /v1/teams/" + teamID + "/domains":
			write(authorityv1.DomainPage{Domains: []authorityv1.Domain{{Id: "dom_fixture", CanonicalDomain: "example.test", Kind: "custom", State: "ready"}}})
		case "GET /v1/previews/" + previewID:
			write(controlv1.Preview{Id: previewID, TeamId: teamID, PublicUrlIds: []string{webID, apiID}})
		case "GET /v1/public-urls":
			lookups <- r.URL.Query().Get("canonical_hostname")
			page := controlv1.PublicURLPage{PublicUrls: []controlv1.PublicURL{}}
			for _, publicURL := range urls {
				if hostname := r.URL.Query().Get("canonical_hostname"); hostname == "" || hostname == publicURL.CanonicalHostname {
					page.PublicUrls = append(page.PublicUrls, publicURL)
				}
			}
			write(page)
		case "POST /v1/previews/" + previewID + "/shares", "POST /v1/shares":
			var body controlv1.CreateShareRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if !opaqueid.Valid(r.Header.Get("Idempotency-Key"), opaqueid.IdempotencyPrefix) {
				t.Error("share creation omitted its idempotency key")
			}
			created <- creation{r.URL.Path, body}
			share := controlv1.Share{Id: shareID, TeamId: teamID, PublicUrlIds: body.PublicUrlIds, ExpiresAt: body.ExpiresAt}
			if widenResponse.Load() {
				share.PublicUrlIds = append(slices.Clone(share.PublicUrlIds), otherID)
			}
			if strings.HasPrefix(r.URL.Path, "/v1/previews/") {
				id := previewID
				share.PreviewId = &id
			}
			entry := ""
			for _, publicURL := range urls {
				if publicURL.Id == body.EntryPublicUrlId {
					entry = "https://" + publicURL.CanonicalHostname + "/__tnl/share/" + shareID + "." + strings.Repeat("A", 43)
				}
			}
			w.WriteHeader(http.StatusCreated)
			write(controlv1.ShareCreation{Share: share, Link: entry, TokenSource: controlv1.VisitorTokenShareSource{Kind: controlv1.VisitorTokenShare, ShareId: shareID, Secret: strings.Repeat("A", 43)}})
		default:
			t.Errorf("unexpected share request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original })
	root := t.TempDir()
	configPath := filepath.Join(root, "tnl.yml")
	source := "version: 1\ntnl:\n  server: " + server.URL + "\n  team: " + teamID + "\n  publisher_groups:\n    remote: {}\n  services:\n    web:\n      public_url: {hostname: web.example.test}\n    api:\n      public_url: {hostname: api.example.test}\n    private: {}\n    database:\n      publisher_group: remote\n      protocol: postgres\n      target: {type: address, address: database.internal:5432}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(t.TempDir(), "state")
	db, err := clientstate.Open(t.Context(), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := db.Server(t.Context(), server.URL)
	if err == nil {
		err = store.SavePreviewID(t.Context(), teamID, root, previewID)
	}
	closeErr := db.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("save preview: %v; close: %v", err, closeErr)
	}
	for _, test := range []struct {
		name    string
		args    []string
		ids     []string
		entry   string
		preview bool
		json    bool
	}{
		{"checkout", []string{"share", "--expires-in=7d"}, []string{webID, apiID}, webID, true, false},
		{"checkout JSON", []string{"share", "--output=json"}, []string{webID, apiID}, webID, true, true},
		{"one service", []string{"share", "--service=web"}, []string{webID}, webID, false, false},
		{"API service", []string{"share", "--service=api", "--output=json"}, []string{apiID}, apiID, false, true},
		{"exact URL", []string{"share", "link", "create", "web.example.test"}, []string{webID}, webID, false, false},
		{"explicit preview", []string{"share", "link", "create", "api.example.test", "--preview"}, []string{webID, apiID}, apiID, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"--no-telemetry", "--config", configPath}, test.args...)
			args = append(args, "--server", server.URL, "--access-token", access.String(), "--team", teamID, "--state-dir", stateDir)
			var output, diagnostics bytes.Buffer
			before := time.Now()
			if err := run(t.Context(), args, &output, &diagnostics); err != nil {
				t.Fatal(err)
			}
			var got creation
			select {
			case got = <-created:
			default:
				t.Fatal("share command did not create a share")
			}
			wantIDs := slices.Clone(test.ids)
			slices.Sort(wantIDs)
			wantPath := "/v1/shares"
			if test.preview {
				wantPath = "/v1/previews/" + previewID + "/shares"
			}
			if got.path != wantPath || !slices.Equal(got.body.PublicUrlIds, wantIDs) || got.body.EntryPublicUrlId != test.entry {
				t.Fatalf("share path=%q scope=%+v; want path=%q IDs=%v entry=%q", got.path, got.body, wantPath, wantIDs, test.entry)
			}
			var queried []string
			for len(lookups) != 0 {
				queried = append(queried, <-lookups)
			}
			if strings.HasPrefix(test.name, "one service") || test.name == "API service" {
				wantHostname := "web.example.test"
				if test.entry == apiID {
					wantHostname = "api.example.test"
				}
				if !slices.Equal(queried, []string{wantHostname}) {
					t.Fatalf("single-service share queried other URLs: %v", queried)
				}
			}
			lifetime := 24 * time.Hour
			if test.name == "checkout" {
				lifetime = 7 * 24 * time.Hour
			}
			if got.body.ExpiresAt.Before(before.Add(lifetime)) || got.body.ExpiresAt.After(time.Now().Add(lifetime)) {
				t.Fatalf("unexpected share expiry: %s", got.body.ExpiresAt)
			}
			if diagnostics.Len() != 0 {
				t.Fatalf("unexpected diagnostics: %s", diagnostics.String())
			}
			if test.json {
				var result struct {
					SchemaVersion int                           `json:"schema_version"`
					PreviewID     *string                       `json:"preview_id"`
					PublicURLIDs  []string                      `json:"public_url_ids"`
					Services      map[string]shareServiceResult `json:"services"`
				}
				if err := json.Unmarshal(output.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if result.SchemaVersion != 1 || (result.PreviewID != nil) != test.preview || !slices.Equal(result.PublicURLIDs, wantIDs) ||
					test.preview && (len(result.Services) != 2 || result.Services["web"].PublicURLID != webID || result.Services["api"].PublicURLID != apiID) {
					t.Fatalf("share JSON lost its captured scope: %s", output.String())
				}
			} else if !strings.HasPrefix(output.String(), "https://") || strings.Count(output.String(), "\n") != 1 {
				t.Fatalf("share did not print one raw link: %q", output.String())
			}
		})
	}
	t.Run("reject widened server scope", func(t *testing.T) {
		widenResponse.Store(true)
		args := []string{"--no-telemetry", "--config", configPath, "share", "--service=web",
			"--server", server.URL, "--access-token", access.String(), "--team", teamID, "--state-dir", stateDir}
		var output, diagnostics bytes.Buffer
		err := run(t.Context(), args, &output, &diagnostics)
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid || output.Len() != 0 {
			t.Fatalf("widened share response was printed or misclassified: output=%q, error=%v", output.String(), err)
		}
	})
}
