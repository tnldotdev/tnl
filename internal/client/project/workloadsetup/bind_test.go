package workloadsetup

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/project/githubmetadata"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestGitHubBindingDefaultsReuseAndErrors(t *testing.T) {
	r := newResolver()
	calls := 0
	r.github = func(_ context.Context, repository string) (githubmetadata.Repository, error) {
		calls++
		if repository != "example/repository" {
			t.Fatal("wrong repository")
		}
		return githubmetadata.Repository{Repository: repository, RepositoryID: "12345", OwnerID: "6789", DefaultBranch: "trunk"}, nil
	}
	o := Options{Server: "https://control.example", Workloads: map[string]config.Workload{"test": {GitHub: &config.WorkloadGitHub{Workflow: ".github/workflows/test.yml"}, Services: []string{"cluster"}}}, Repository: func(context.Context) (string, error) { return "example/repository", nil }}
	first, err := r.resolve(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	g := first["test"].Github
	if calls != 1 || g.RepositoryId != "12345" || g.RepositoryOwnerId != "6789" || g.Ref != "refs/heads/trunk" || g.WorkflowRef != "example/repository/.github/workflows/test.yml@refs/heads/trunk" || !reflect.DeepEqual(g.Events, []string{"push"}) || first["test"].MaxDurationSeconds != 3600 {
		t.Fatal("incorrect initial binding", first)
	}
	o.Previous = first
	r.github = func(context.Context, string) (githubmetadata.Repository, error) {
		t.Fatal("unchanged apply required authentication")
		return githubmetadata.Repository{}, nil
	}
	second, err := r.resolve(t.Context(), o)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("saved binding changed", err)
	}
	cause := errors.New("private repository metadata unavailable")
	r.github = func(context.Context, string) (githubmetadata.Repository, error) {
		return githubmetadata.Repository{}, cause
	}
	o.Previous = nil
	if _, err = r.resolve(t.Context(), o); !errors.Is(err, cause) {
		t.Fatal("metadata cause lost", err)
	}
	if reason, known := failure.ReasonOf(err); !known || reason != failure.WorkloadRepositoryMetadataUnavailable {
		t.Fatal("metadata diagnostic changed", err)
	}
	for _, metadata := range []githubmetadata.Repository{
		{Repository: "example/renamed", RepositoryID: "12345", OwnerID: "6789", DefaultBranch: "main"},
		{Repository: "example/repository", RepositoryID: "99999", OwnerID: "6789", DefaultBranch: "main"},
	} {
		r.github = func(context.Context, string) (githubmetadata.Repository, error) { return metadata, nil }
		o.Previous = first
		p := o.Previous["test"]
		copy := *p.Github
		copy.Ref = "refs/tags/v1"
		copy.DefaultBranch = nil
		p.Github = &copy
		o.Previous = map[string]controlv1.ProjectWorkload{"test": p}
		if _, err := r.resolve(t.Context(), o); err == nil {
			t.Fatal("renamed or recreated repository silently rebound")
		}
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func fixtureResolver(t *testing.T, handler func(*http.Request) string) resolver {
	t.Helper()
	r := newResolver()
	r.getenv = func(string) string { return "provider-secret" }
	r.client.Transport = roundTrip(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(handler(request))), Request: request}, nil
	})
	r.run = func(context.Context, string, string, ...string) ([]byte, error) {
		t.Fatal("unexpected provider CLI")
		return nil, ErrBinding
	}
	return r
}

func TestVercelNameBindingAndReuse(t *testing.T) {
	calls := 0
	r := fixtureResolver(t, func(request *http.Request) string {
		calls++
		if request.URL.Host != "api.vercel.com" || request.Header.Get("Authorization") != "Bearer provider-secret" {
			t.Fatal("wrong metadata authority")
		}
		if strings.HasPrefix(request.URL.Path, "/v9/projects/") {
			if request.URL.Path != "/v9/projects/store" || request.URL.Query().Get("slug") != "acme" {
				t.Fatal("wrong Vercel selection")
			}
			return `{"id":"prj_store","name":"store","accountId":"team_one","oidcTokenConfig":{"enabled":true,"issuerMode":"team"}}`
		}
		if request.URL.Path != "/v2/teams/team_one" {
			t.Fatal("wrong team metadata")
		}
		return `{"id":"team_one","slug":"acme"}`
	})
	o := Options{Server: "https://control.example", Workloads: map[string]config.Workload{"web": {Vercel: &config.WorkloadVercel{Team: "acme", Project: "store", Environment: "production"}, Services: []string{"db"}}}}
	first, err := r.resolve(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	trust := first["web"].Trust
	if calls != 2 || trust.Issuer != "https://oidc.vercel.com/acme" || trust.Audience != "https://vercel.com/acme" || trust.Claims["project_id"] != "prj_store" || trust.Claims["owner_id"] != "team_one" {
		t.Fatal("wrong Vercel binding", trust)
	}
	o.Previous = first
	r.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		t.Fatal("unchanged apply called Vercel")
		return nil, ErrBinding
	})
	second, err := r.resolve(t.Context(), o)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("Vercel binding changed", err)
	}
	if first["web"].Trust.Claims["environment"] != "production" {
		t.Fatal("saved policy mutated")
	}
}

func TestFlyNumericBindingAndReuse(t *testing.T) {
	calls := 0
	r := fixtureResolver(t, func(request *http.Request) string {
		calls++
		if request.URL.String() != "https://api.fly.io/graphql" || request.Method != "POST" {
			t.Fatal("wrong Fly metadata authority")
		}
		return `{"data":{"app":{"name":"worker","internalNumericId":456,"organization":{"slug":"acme","internalNumericId":"123"}}}}`
	})
	o := Options{Server: "https://control.example", Workloads: map[string]config.Workload{"job": {Fly: &config.WorkloadFly{App: "worker"}, Services: []string{"db"}}}}
	first, err := r.resolve(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	trust := first["job"].Trust
	if calls != 1 || trust.Claims["app_id"] != "456" || trust.Claims["org_id"] != "123" || trust.Issuer != "https://oidc.fly.io/acme" || trust.Audience != o.Server {
		t.Fatal("wrong Fly binding", trust)
	}
	o.Previous = first
	r.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		t.Fatal("unchanged apply called Fly")
		return nil, ErrBinding
	})
	if _, err := r.resolve(t.Context(), o); err != nil {
		t.Fatal(err)
	}
}

func TestOIDCDiscoveryAndSavedKeys(t *testing.T) {
	calls := 0
	r := fixtureResolver(t, func(request *http.Request) string {
		calls++
		if request.URL.String() != "https://issuer.example/.well-known/openid-configuration" || request.Header.Get("Authorization") != "" {
			t.Fatal("incorrect discovery request")
		}
		return `{"issuer":"https://issuer.example","jwks_uri":"https://issuer.example/keys"}`
	})
	o := Options{Server: "https://control.example", Workloads: map[string]config.Workload{"job": {OIDC: &config.WorkloadOIDC{Issuer: "https://issuer.example", Claims: map[string]string{"sub": "worker"}}, Services: []string{"db"}}}}
	first, err := r.resolve(t.Context(), o)
	if err != nil || first["job"].Trust.Audience != o.Server || first["job"].Trust.JwksUrl != "https://issuer.example/keys" {
		t.Fatal("OIDC discovery failed", err)
	}
	o.Previous = first
	if _, err := r.resolve(t.Context(), o); err != nil || calls != 1 {
		t.Fatal("saved discovery was not reused", err)
	}
	for _, body := range []string{
		`{"issuer":"https://elsewhere.example","jwks_uri":"https://issuer.example/keys"}`,
		`{"issuer":"https://issuer.example","jwks_uri":"http://issuer.example/keys"}`,
		`{"issuer":"https://issuer.example","jwks_uri":"https://issuer.example/keys"} {}`,
	} {
		r.client.Transport = roundTrip(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: request}, nil
		})
		o.Previous = nil
		if _, err := r.resolve(t.Context(), o); err == nil {
			t.Fatal("untrusted discovery accepted")
		}
	}
}

func TestLinkedVercelProjectIsOnlyASelectionHint(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, ".vercel"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".vercel", "project.json"), []byte(`{"projectId":"prj_linked","orgId":"team_linked"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, projectID := range []string{"prj_linked", "prj_wrong"} {
		calls := 0
		r := fixtureResolver(t, func(request *http.Request) string {
			calls++
			if strings.HasPrefix(request.URL.Path, "/v9/projects/") {
				if request.URL.Path != "/v9/projects/prj_linked" || request.URL.Query().Get("teamId") != "team_linked" {
					t.Fatal("linked project hint lost")
				}
				return `{"id":"` + projectID + `","name":"linked","accountId":"team_linked","oidcTokenConfig":{"enabled":true,"issuerMode":"global"}}`
			}
			return `{"id":"team_linked","slug":"acme"}`
		})
		o := Options{Directory: directory, Server: "https://control.example", Workloads: map[string]config.Workload{"web": {Vercel: &config.WorkloadVercel{Environment: "preview"}, Services: []string{"db"}}}}
		bound, err := r.resolve(t.Context(), o)
		if projectID == "prj_linked" {
			if err != nil || calls != 2 || bound["web"].Trust.Issuer != "https://oidc.vercel.com" {
				t.Fatal("linked project did not bind", err)
			}
		} else if err == nil {
			t.Fatal("API response substituted a different linked project")
		}
	}
}

func TestFlyLocalSelectionAndNumericIDs(t *testing.T) {
	r := fixtureResolver(t, func(*http.Request) string {
		return `{"data":{"app":{"name":"worker","internalNumericId":456,"organization":{"slug":"acme","internalNumericId":123}}}}`
	})
	calls := 0
	r.run = func(_ context.Context, directory, name string, args ...string) ([]byte, error) {
		calls++
		if directory != "/project" || name != "flyctl" || !reflect.DeepEqual(args, []string{"config", "show", "--local"}) {
			t.Fatal("local Fly selection started a provider operation")
		}
		return []byte(`{"app":"worker"}`), nil
	}
	o := Options{Directory: "/project", Server: "https://control.example", Workloads: map[string]config.Workload{"job": {Fly: &config.WorkloadFly{}, Services: []string{"db"}}}}
	bound, err := r.resolve(t.Context(), o)
	if err != nil || calls != 1 || bound["job"].Trust.Claims["app_id"] != "456" {
		t.Fatal("local Fly defaults failed", err)
	}
}

func TestDiscoveryRejectsRedirectsAndBounds(t *testing.T) {
	for _, status := range []int{302, 401, 403, 500, 200} {
		r := newResolver()
		calls := 0
		r.client.Transport = roundTrip(func(request *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: status, Header: http.Header{"Location": {"https://elsewhere.example/private"}}, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", (2<<20)+1))), Request: request}, nil
		})
		o := Options{Server: "https://control.example", Workloads: map[string]config.Workload{"job": {OIDC: &config.WorkloadOIDC{Issuer: "https://issuer.example", Claims: map[string]string{"sub": "worker"}}, Services: []string{"db"}}}}
		if _, err := r.resolve(t.Context(), o); err == nil || calls != 1 {
			t.Fatal("redirect, denied response or oversized metadata accepted", status, err)
		}
	}
}
