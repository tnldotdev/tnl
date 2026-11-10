package workloadsetup

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"golang.org/x/sys/unix"
)

func TestVercelLinkedSelectionRejectsChangedIdentity(t *testing.T) {
	for _, test := range []struct {
		name    string
		project string
		owner   string
	}{
		{name: "project", project: "prj_other", owner: "team_one"},
		{name: "owner", project: "prj_store", owner: "team_other"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Mkdir(filepath.Join(directory, ".vercel"), 0700); err != nil {
				t.Fatal(err)
			}
			project, owner := "prj_store", "team_one"
			writeLink := func() {
				t.Helper()
				data, err := json.Marshal(map[string]string{"projectId": project, "orgId": owner})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, ".vercel", "project.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			writeLink()
			calls := 0
			r := fixtureResolver(t, func(request *http.Request) string {
				calls++
				if strings.HasPrefix(request.URL.Path, "/v9/projects/") {
					if request.URL.Path != "/v9/projects/"+project || request.URL.Query().Get("teamId") != owner {
						t.Fatal("linked Vercel selection lost", request.URL)
					}
					return `{"id":"` + project + `","name":"store","accountId":"` + owner + `","oidcTokenConfig":{"enabled":true,"issuerMode":"team"}}`
				}
				if request.URL.Path != "/v2/teams/"+owner {
					t.Fatal("wrong Vercel owner lookup", request.URL)
				}
				return `{"id":"` + owner + `","slug":"acme"}`
			})
			policy := config.Workload{Vercel: &config.WorkloadVercel{Environment: "production"}, Grants: config.ServiceVisitGrants("db")}
			o := Options{Directory: directory, Server: "https://control.example", Workloads: map[string]config.Workload{"web": policy}}
			first, err := r.resolve(t.Context(), o)
			if err != nil {
				t.Fatal("initial linked Vercel binding failed", err)
			}
			o.Previous = first
			r.getenv = func(string) string { return "" }
			if reused, err := r.resolve(t.Context(), o); err != nil || calls != 2 || !reflect.DeepEqual(first, reused) {
				t.Fatal("unchanged linked Vercel binding required authentication", err)
			}

			project, owner = test.project, test.owner
			writeLink()
			policy.Grants = config.ServiceVisitGrants("db", "cache")
			o.Workloads["web"] = policy
			r.getenv = func(string) string {
				t.Fatal("changed linked Vercel identity required provider authentication")
				return ""
			}
			rebound, err := r.resolve(t.Context(), o)
			if !errors.Is(err, ErrRebinding) {
				t.Fatalf("changed linked %s must require a new workload name; got error %v and binding %+v", test.name, err, rebound["web"])
			}
			encoded, marshalErr := json.Marshal(first["web"].Grants)
			var original config.WorkloadGrants
			if marshalErr != nil || json.Unmarshal(encoded, &original) != nil {
				t.Fatal("invalid saved grant", marshalErr)
			}
			if rebound != nil || calls != 2 || !reflect.DeepEqual(original, config.ServiceVisitGrants("db")) {
				t.Fatal("changed linked identity expanded the saved service grant", rebound, first)
			}
		})
	}
}

func TestVercelProjectNameAllowsUnderscore(t *testing.T) {
	for _, selection := range []string{"explicit", "linked"} {
		t.Run(selection, func(t *testing.T) {
			directory := t.TempDir()
			v := &config.WorkloadVercel{Team: "acme", Project: "store_front", Environment: "production"}
			project := v.Project
			if selection == "linked" {
				v.Project, v.Team, project = "", "", "prj_store"
				if err := os.Mkdir(filepath.Join(directory, ".vercel"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, ".vercel", "project.json"), []byte(`{"projectId":"prj_store","orgId":"team_one"}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			r := fixtureResolver(t, func(request *http.Request) string {
				calls++
				if strings.HasPrefix(request.URL.Path, "/v9/projects/") {
					if request.URL.Path != "/v9/projects/"+project {
						t.Fatal("wrong Vercel project lookup", request.URL)
					}
					return `{"id":"prj_store","name":"store_front","accountId":"team_one","oidcTokenConfig":{"enabled":true,"issuerMode":"team"}}`
				}
				if request.URL.Path != "/v2/teams/team_one" {
					t.Fatal("wrong Vercel team lookup", request.URL)
				}
				return `{"id":"team_one","slug":"acme"}`
			})
			o := Options{Directory: directory, Server: "https://control.example", Workloads: map[string]config.Workload{"web": {Vercel: v, Grants: config.ServiceVisitGrants("db")}}}
			bound, err := r.resolve(t.Context(), o)
			if err != nil {
				t.Fatal("valid Vercel project name store_front rejected", err)
			}
			trust := bound["web"].Trust
			if calls != 2 || trust.Claims["project"] != "store_front" || trust.Claims["project_id"] != "prj_store" || trust.Claims["owner_id"] != "team_one" {
				t.Fatal("Vercel project name or identity changed", trust)
			}
		})
	}
}

func TestFlyPersonalOrganizationUsesRawSlug(t *testing.T) {
	for _, org := range []string{"", "alice"} {
		name := "inferred"
		if org != "" {
			name = "explicit"
		}
		t.Run(name, func(t *testing.T) {
			query := ""
			r := fixtureResolver(t, func(request *http.Request) string {
				if request.Method != http.MethodPost || request.URL.String() != "https://api.fly.io/graphql" || request.Header.Get("Authorization") != "Bearer provider-secret" {
					t.Fatal("wrong Fly metadata request")
				}
				var body struct {
					Query     string            `json:"query"`
					Variables map[string]string `json:"variables"`
				}
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body.Variables["app"] != "worker" {
					t.Fatal("wrong Fly app selection", body.Variables)
				}
				query = body.Query
				return `{"data":{"app":{"name":"worker","internalNumericId":456,"organization":{"slug":"personal","rawSlug":"alice","internalNumericId":123}}}}`
			})
			o := Options{Server: "https://control.example", Workloads: map[string]config.Workload{"job": {Fly: &config.WorkloadFly{App: "worker", Org: org}, Grants: config.ServiceVisitGrants("db")}}}
			bound, err := r.resolve(t.Context(), o)
			if !strings.Contains(query, "rawSlug") {
				t.Error("Fly metadata query did not request organization.rawSlug")
			}
			if err != nil {
				t.Fatal("Fly personal organization raw slug alice rejected", err)
			}
			trust := bound["job"].Trust
			if trust.Issuer != "https://oidc.fly.io/alice" || trust.JwksUrl != "https://oidc.fly.io/alice/.well-known/jwks" || trust.Claims["org_name"] != "alice" || trust.Claims["org_id"] != "123" || trust.Claims["app_id"] != "456" {
				t.Fatal("Fly personal organization bound to display slug instead of raw slug", trust)
			}
		})
	}
}

func TestFlyLocalSelectionReusesSavedBindingWithoutAuthentication(t *testing.T) {
	for _, test := range []struct {
		name  string
		toml  string
		valid bool
	}{
		{name: "literal", toml: "app = 'worker' # local application\nprimary_region = 'ord'\n", valid: true},
		{name: "quoted key and nested app", toml: "# app = 'not-selected'\n\"app\" = \"wor\\u006ber\"\n[env]\napp = 'not-selected'\n", valid: true},
		{name: "malformed", toml: "app = 'worker'\n[invalid\n"},
		{name: "nested app only", toml: "[env]\napp = 'worker'\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.WriteFile(filepath.Join(directory, "fly.toml"), []byte(test.toml), 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			r := fixtureResolver(t, func(*http.Request) string {
				calls++
				if calls != 1 {
					t.Fatal("saved Fly binding contacted the provider")
				}
				return `{"data":{"app":{"name":"worker","internalNumericId":456,"organization":{"slug":"acme","rawSlug":"acme","internalNumericId":123}}}}`
			})
			f := &config.WorkloadFly{App: "worker"}
			o := Options{Directory: directory, Server: "https://control.example", Workloads: map[string]config.Workload{"job": {Fly: f, Grants: config.ServiceVisitGrants("db")}}}
			first, err := r.resolve(t.Context(), o)
			if err != nil {
				t.Fatal("initial Fly binding failed", err)
			}
			f.App, o.Previous = "", first
			lookups, commands := 0, 0
			r.getenv = func(string) string {
				lookups++
				return ""
			}
			r.run = func(context.Context, string, string, ...string) ([]byte, error) {
				commands++
				return nil, errors.New("flyctl requires authentication")
			}
			reused, err := r.resolve(t.Context(), o)
			if !test.valid {
				if err == nil || reused != nil || commands != 0 || lookups != 0 || calls != 1 {
					t.Fatal("invalid local Fly selection must be rejected before saved reuse or authentication", err, reused, commands, lookups, calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("local fly.toml selection must reuse saved trust without flyctl authentication: %v (commands=%d, credential lookups=%d)", err, commands, lookups)
			}
			if commands != 0 || lookups != 0 || calls != 1 || !reflect.DeepEqual(first, reused) {
				t.Fatal("unchanged local Fly selection required authentication or changed trust", commands, lookups, calls, reused)
			}
		})
	}
}

func TestVercelProjectNameWithIDPrefixStillUsesName(t *testing.T) {
	r := fixtureResolver(t, func(request *http.Request) string {
		switch request.URL.Path {
		case "/v9/projects/prj_store":
			return `{"id":"prj_identity","name":"prj_store","accountId":"team_one","oidcTokenConfig":{"enabled":true,"issuerMode":"team"}}`
		case "/v2/teams/team_one":
			return `{"id":"team_one","slug":"acme"}`
		default:
			t.Fatal("wrong Vercel metadata lookup", request.URL)
			return ""
		}
	})
	o := Options{Server: "https://control.example", Workloads: map[string]config.Workload{"web": {Vercel: &config.WorkloadVercel{Project: "prj_store", Team: "acme", Environment: "production"}, Grants: config.ServiceVisitGrants("db")}}}
	bound, err := r.resolve(t.Context(), o)
	if err != nil || bound["web"].Trust.Claims["project"] != "prj_store" || bound["web"].Trust.Claims["project_id"] != "prj_identity" {
		t.Fatal("explicit Vercel project name was treated as an immutable ID", err, bound)
	}
}

func TestFlyLocalSelectionRequiresBoundedRegularFile(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(string) error
	}{
		{name: "missing", setup: func(string) error { return nil }},
		{name: "directory", setup: func(path string) error { return os.Mkdir(path, 0700) }},
		{name: "fifo", setup: func(path string) error { return unix.Mkfifo(path, 0600) }},
		{name: "too large", setup: func(path string) error {
			return os.WriteFile(path, []byte("app = 'worker'\n#"+strings.Repeat("x", 2<<20)), 0600)
		}},
		{name: "nonstring app", setup: func(path string) error {
			return os.WriteFile(path, []byte("app = 123\n"), 0600)
		}},
		{name: "duplicate app", setup: func(path string) error {
			return os.WriteFile(path, []byte("app = 'worker'\napp = 'other'\n"), 0600)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			if err := test.setup(filepath.Join(directory, "fly.toml")); err != nil {
				t.Fatal(err)
			}
			r := fixtureResolver(t, func(*http.Request) string {
				t.Fatal("invalid local Fly selection contacted the provider")
				return ""
			})
			r.getenv = func(string) string {
				t.Fatal("invalid local Fly selection required provider authentication")
				return ""
			}
			o := Options{Directory: directory, Server: "https://control.example", Workloads: map[string]config.Workload{"job": {Fly: &config.WorkloadFly{}, Grants: config.ServiceVisitGrants("db")}}}
			if bound, err := r.resolve(t.Context(), o); !errors.Is(err, ErrBinding) || bound != nil {
				t.Fatal("invalid local Fly selection accepted", err, bound)
			}
		})
	}
}

func TestFlyLocalSelectionAcceptsFileAtSizeLimit(t *testing.T) {
	directory := t.TempDir()
	prefix := "app = 'worker'\n#"
	data := prefix + strings.Repeat("x", (2<<20)-len(prefix))
	if err := os.WriteFile(filepath.Join(directory, "fly.toml"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	r := fixtureResolver(t, func(*http.Request) string {
		return `{"data":{"app":{"name":"worker","internalNumericId":456,"organization":{"rawSlug":"acme","internalNumericId":123}}}}`
	})
	o := Options{Directory: directory, Server: "https://control.example", Workloads: map[string]config.Workload{"job": {Fly: &config.WorkloadFly{}, Grants: config.ServiceVisitGrants("db")}}}
	if bound, err := r.resolve(t.Context(), o); err != nil || bound["job"].Trust.Claims["app_name"] != "worker" {
		t.Fatal("local Fly file at the size limit rejected", err, bound)
	}
}
