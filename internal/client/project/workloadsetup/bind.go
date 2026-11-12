// package workloadsetup owns trusted workload setup and stable provider bindings.
// it depends on configuration, provider metadata and public control contracts;
// connector runtime acquisition never calls setup or provider account APIs.
package workloadsetup

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/githubmetadata"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/httpclient"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var ErrBinding = errors.New("workload setup could not bind the selected platform identity; check provider authentication and project selection")
var ErrRebinding = errors.New("the selected workload resolves to a different platform identity; review it before creating a new explicit approval intent")
var ErrVercelAuthentication = errors.New("Vercel workload approval needs VERCEL_TOKEN with read access to the selected project and team")
var ErrVercelProject = errors.New("select vercel.project or link this project with vercel link before approving")

type Options struct {
	Directory  string
	Server     string
	Workloads  map[string]config.Workload
	Previous   map[string]controlv1.ProjectWorkload
	Repository func(context.Context) (string, error)
}

type resolver struct {
	client *http.Client
	github func(context.Context, string) (githubmetadata.Repository, error)
	getenv func(string) string
	run    func(context.Context, string, string, ...string) ([]byte, error)
}

// resolve uses existing provider authentication only. explicit approval saves
// exact identities; receipt recovery never resolves provider names again.
func Resolve(ctx context.Context, options Options) (map[string]controlv1.ProjectWorkload, error) {
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return newResolver().resolve(bounded, options)
}

func newResolver() resolver {
	return resolver{client: httpclient.NoRedirects(&http.Client{Timeout: 10 * time.Second}), github: githubmetadata.Resolve, getenv: environment, run: commandOutput}
}

func (r resolver) resolve(ctx context.Context, o Options) (map[string]controlv1.ProjectWorkload, error) {
	if !config.WorkloadHTTPS(o.Server) {
		return nil, ErrBinding
	}
	services := config.Services{}
	for _, workload := range o.Workloads {
		for _, name := range workload.Services {
			services[name] = config.Service{}
		}
	}
	if err := config.ValidateWorkloads(services, o.Workloads); err != nil {
		return nil, errors.Join(ErrBinding, err)
	}
	result := make(map[string]controlv1.ProjectWorkload, len(o.Workloads))
	repositories := map[string]controlv1.ProjectWorkloadGitHub{}
	for _, previous := range o.Previous {
		if previous.Provider == controlv1.WorkloadGitHub && previous.Github != nil {
			repositories[previous.Github.Repository] = *previous.Github
		}
	}
	for name, p := range o.Workloads {
		previous := o.Previous[name]
		bound := controlv1.ProjectWorkload{Provider: controlv1.WorkloadProvider(p.Provider()), Services: slices.Clone(p.Services), MaxDurationSeconds: int(p.DurationLimit() / time.Second)}
		var err error
		if p.GitHub != nil && p.Provider() == "github" {
			bound.Github, err = r.bindGitHub(ctx, o, p.GitHub, previous, repositories)
		} else if p.Google != nil && p.Provider() == "google" {
			bound.Trust, bound.Google, err = r.google(ctx, o, p.Google, previous)
		} else if p.Kubernetes != nil && p.Provider() == "kubernetes" {
			bound.Trust, bound.Kubernetes, err = r.kubernetes(ctx, o, p.Kubernetes, previous)
		} else if p.GitLab != nil && p.Provider() == "gitlab" {
			bound.Trust, bound.Gitlab, err = r.gitlab(ctx, o, p.GitLab, previous)
		} else {
			bound.Trust, err = r.bindProvider(ctx, o, p, previous)
		}
		if err != nil {
			if _, known := failure.ReasonOf(err); known {
				return nil, err
			}
			return nil, failure.Wrap("bind workload provider", failure.ProjectConfigInvalid, err)
		}
		result[name] = bound
	}
	return result, nil
}
