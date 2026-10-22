package main

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/projectpublisher"
)

func (a *appRuntime) resolveRuntimeMounts(project projectConfiguration, service string) ([]localproxy.Mount, error) {
	return configuredProjectMounts(project, service, func(name string) string {
		for _, candidate := range a.manager.Snapshot().Services {
			if candidate.Name == name && a.manager.Current(name, candidate.RegistrationID, candidate.Target, 0) {
				return candidate.Target
			}
		}
		return ""
	})
}

func resolveProjectMounts(project projectConfiguration, service string) ([]localproxy.Mount, error) {
	return configuredProjectMounts(project, service, nil)
}

// one resolver owns mount trust and target selection for app, named and scoped
// publishers. only app targets use registrations; static addresses stay static.
func configuredProjectMounts(project projectConfiguration, service string, appTarget func(string) string) ([]localproxy.Mount, error) {
	if service == "" {
		return nil, nil
	}
	configuration := project.Config.Services[service]
	paths := config.ServicePaths(configuration)
	prefixes := make([]string, 0, len(paths))
	for prefix := range paths {
		prefixes = append(prefixes, prefix)
	}
	slices.Sort(prefixes)
	mounts := make([]localproxy.Mount, 0, len(prefixes))
	for _, prefix := range prefixes {
		mount := paths[prefix]
		definition := project.Config.Services[mount.Service]
		local := config.ServicePublish(definition)
		target := ""
		if local.Target != nil {
			target = string(*local.Target)
		}
		var resolve func() string
		switch config.TargetType(definition) {
		case "app":
			if appTarget != nil {
				resolve = func() string { return appTarget(mount.Service) }
			}
		case "address":
			resolved, err := project.ResolvePublish(mount.Service, "")
			if err != nil {
				return nil, err
			}
			target = string(*resolved.Target)
		default:
			binding := &projectpublisher.TargetBinding{Resolve: func(ctx context.Context) (projectpublisher.TargetSnapshot, error) {
				return projectpublisher.ResolveTargetSnapshot(ctx, project.Project, mount.Service, runtimeTargetResolver)
			}}
			resolve = func() string {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				selected, err := binding.Capture(ctx)
				if err != nil {
					return ""
				}
				return selected.Address
			}
		}
		if target == "" && resolve == nil {
			return nil, failure.Wrap("resolve path mounts", failure.MissingTarget, fmt.Errorf("service %q mount %q needs a discovered target for %q", service, prefix, mount.Service))
		}
		normalized := ""
		if target != "" {
			var err error
			normalized, err = targetsyntax.NormalizeTarget(target)
			if err != nil {
				return nil, fmt.Errorf("service %q mount %q: %w", service, prefix, err)
			}
		}
		caFile := ""
		if local.TargetCAFile != nil {
			caFile = *local.TargetCAFile
		}
		options, err := targetOptionsForCA(caFile, project.Root)
		if err != nil {
			return nil, fmt.Errorf("service %q mount %q: %w", service, prefix, err)
		}
		if local.TargetTLSName != nil {
			options.ServerName = *local.TargetTLSName
		}
		mounts = append(mounts, localproxy.Mount{Prefix: prefix, Target: normalized, StripPrefix: mount.StripPrefix, Options: options, ResolveTarget: resolve})
	}
	return mounts, nil
}
