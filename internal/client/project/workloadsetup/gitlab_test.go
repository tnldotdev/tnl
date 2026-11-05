package workloadsetup

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

const gitLabProjectJSON = `{"id":123,"path_with_namespace":"shop/storefront","default_branch":"trunk","namespace":{"id":456,"full_path":"shop"}}`

func TestGitLabTrustedSetupDefaultsReuseAndRebinding(t *testing.T) {
	r := newResolver()
	calls := 0
	r.run = func(_ context.Context, directory, name string, args ...string) ([]byte, error) {
		calls++
		if directory != "/project" {
			t.Fatal("wrong setup directory")
		}
		if name == "git" && reflect.DeepEqual(args, []string{"remote", "get-url", "origin"}) {
			return []byte("git@gitlab.com:shop/storefront.git\n"), nil
		}
		if name != "glab" || !reflect.DeepEqual(args, []string{"api", "--hostname", "gitlab.com", "projects/shop%2Fstorefront"}) {
			t.Fatal("unexpected provider lookup", name, args)
		}
		return []byte(gitLabProjectJSON), nil
	}
	o := Options{Directory: "/project", Server: "https://control.example", Workloads: map[string]config.Workload{"deploy": {GitLab: &config.WorkloadGitLab{}, Services: []string{"db"}}}}
	first, err := r.resolve(t.Context(), o)
	if err != nil || calls != 2 {
		t.Fatal("initial GitLab binding failed", err, calls)
	}
	p := first["deploy"]
	if p.Gitlab == nil || p.Gitlab.ProjectId != "123" || p.Gitlab.NamespaceId != "456" || p.Trust.Issuer != "https://gitlab.com" || p.Trust.JwksUrl != "https://gitlab.com/oauth/discovery/keys" || p.Trust.Audience != o.Server || p.Trust.Claims["ref_path"] != "refs/heads/trunk" || p.Trust.Claims["pipeline_source"] != "push" || p.MaxDurationSeconds != 0 {
		t.Fatal("GitLab defaults changed", p)
	}
	o.Previous = first
	r.run = func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
		if name != "git" {
			t.Fatal("unchanged apply required provider authentication", name, args)
		}
		return []byte("https://gitlab.com/shop/storefront.git"), nil
	}
	if next, err := r.resolve(t.Context(), o); err != nil || !reflect.DeepEqual(first, next) {
		t.Fatal("saved binding changed", err)
	}
	g := config.WorkloadGitLab{Project: "shop/renamed", Tag: new("v1.2.3"), Audience: "tnl-orders", PipelineSource: "web", Environment: "production"}
	policy := o.Workloads["deploy"]
	policy.GitLab = &g
	o.Workloads["deploy"] = policy
	for _, test := range []struct {
		name, metadata string
		allowed        bool
	}{
		{"same project renamed", strings.Replace(gitLabProjectJSON, "storefront", "renamed", 1), true},
		{"recreated project", strings.Replace(strings.Replace(gitLabProjectJSON, "storefront", "renamed", 1), `"id":123`, `"id":999`, 1), false},
		{"different namespace", strings.Replace(strings.Replace(gitLabProjectJSON, "storefront", "renamed", 1), `"id":456`, `"id":999`, 1), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			r.run = func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
				if name != "glab" {
					t.Fatal(name, args)
				}
				return []byte(test.metadata), nil
			}
			next, err := r.resolve(t.Context(), o)
			if test.allowed {
				if err != nil || next["deploy"].Trust.Claims["ref_path"] != "refs/tags/v1.2.3" || next["deploy"].Trust.Claims["environment"] != "production" || next["deploy"].Trust.Claims["pipeline_source"] != "web" || next["deploy"].Trust.Audience != "tnl-orders" {
					t.Fatal("explicit selectors changed", err)
				}
			} else if !errors.Is(err, ErrRebinding) {
				t.Fatal("different immutable identity silently rebound", err)
			}
		})
	}
}

func TestGitLabSetupRejectsWrongMetadataAndKeepsAuthenticationCause(t *testing.T) {
	r := newResolver()
	o := Options{Server: "https://control.example", Workloads: map[string]config.Workload{"deploy": {GitLab: &config.WorkloadGitLab{Project: "shop/storefront"}, Services: []string{"db"}}}}
	for _, metadata := range []string{`not-json`, strings.Replace(gitLabProjectJSON, "storefront", "another", 1), strings.Replace(gitLabProjectJSON, `"id":123`, `"id":0`, 1), strings.Replace(gitLabProjectJSON, `"full_path":"shop"`, `"full_path":"another"`, 1), strings.Replace(gitLabProjectJSON, `"id":123`, `"archived":true,"id":123`, 1)} {
		r.run = func(context.Context, string, string, ...string) ([]byte, error) { return []byte(metadata), nil }
		if _, err := r.resolve(t.Context(), o); !errors.Is(err, ErrBinding) {
			t.Fatal("wrong project metadata established authority", err)
		}
	}
	cause := errors.New("GitLab project authentication unavailable")
	r.run = func(context.Context, string, string, ...string) ([]byte, error) { return nil, cause }
	if _, err := r.resolve(t.Context(), o); !errors.Is(err, ErrGitLabAuthentication) || !errors.Is(err, cause) {
		t.Fatal("setup lost its failure classification or cause", err)
	}
}

func TestGitLabOriginProjectIsPinnedToSelectedServer(t *testing.T) {
	for _, remote := range []string{"git@gitlab.com:shop/subgroup/storefront.git", "https://gitlab.com/shop/subgroup/storefront.git", "ssh://git@gitlab.com/shop/subgroup/storefront.git"} {
		if project := gitLabOriginProject(remote, "https://gitlab.com"); project != "shop/subgroup/storefront" {
			t.Fatal("valid origin rejected", remote, project)
		}
	}
	for _, remote := range []string{"git@github.com:shop/storefront.git", "https://another.example/shop/storefront.git", "https://user:private@gitlab.com/shop/storefront.git", "file:///shop/storefront", "ssh://user@gitlab.com/shop/storefront.git"} {
		if project := gitLabOriginProject(remote, "https://gitlab.com"); project != "" {
			t.Fatal("origin crossed selected provider boundary", remote, project)
		}
	}
}

func TestGitLabSelfManagedSetupAndExplicitBranchWithoutDefault(t *testing.T) {
	r := newResolver()
	r.run = func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
		if name != "glab" || !reflect.DeepEqual(args, []string{"api", "--hostname", "gitlab.example", "projects/shop%2Fstorefront"}) {
			t.Fatal("lookup crossed selected instance", name, args)
		}
		return []byte(strings.Replace(gitLabProjectJSON, `"default_branch":"trunk"`, `"default_branch":null`, 1)), nil
	}
	o := Options{Server: "https://control.example", Workloads: map[string]config.Workload{"deploy": {GitLab: &config.WorkloadGitLab{Server: "https://gitlab.example", Project: "shop/storefront", Branch: new("release")}, Services: []string{"db"}}}}
	bound, err := r.resolve(t.Context(), o)
	if err != nil || bound["deploy"].Trust.Issuer != "https://gitlab.example" || bound["deploy"].Trust.JwksUrl != "https://gitlab.example/oauth/discovery/keys" || bound["deploy"].Trust.Claims["ref_path"] != "refs/heads/release" {
		t.Fatal("self-managed explicit branch binding failed", err)
	}
	policy := o.Workloads["deploy"]
	policy.GitLab.Branch = nil
	o.Workloads["deploy"] = policy
	if _, err := r.resolve(t.Context(), o); !errors.Is(err, ErrBinding) {
		t.Fatal("missing default branch silently selected a ref", err)
	}
	policy.GitLab.Branch, policy.GitLab.Server = new("release"), "https://another.example"
	o.Workloads["deploy"], o.Previous = policy, bound
	r.run = func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
		if name != "glab" || !reflect.DeepEqual(args, []string{"api", "--hostname", "another.example", "projects/shop%2Fstorefront"}) {
			t.Fatal("changed instance lookup used another host", name, args)
		}
		return []byte(gitLabProjectJSON), nil
	}
	if _, err := r.resolve(t.Context(), o); !errors.Is(err, ErrRebinding) {
		t.Fatal("same numeric IDs on another instance inherited the old grant", err)
	}
}
