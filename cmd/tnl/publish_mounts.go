package main

import (
	"fmt"
	"slices"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
)

func resolveProjectMounts(project projectConfiguration, service string) ([]localproxy.Mount, error) {
	if service == "" {
		return nil, nil
	}
	paths := config.ServicePaths(project.Config.Services[service])
	prefixes := make([]string, 0, len(paths))
	for prefix := range paths {
		prefixes = append(prefixes, prefix)
	}
	slices.Sort(prefixes)
	mounts := make([]localproxy.Mount, 0, len(prefixes))
	for _, prefix := range prefixes {
		mount := paths[prefix]
		effective, err := project.EffectiveService(mount.Service)
		if err != nil {
			return nil, err
		}
		target := ""
		if effective.Publish != nil && effective.Publish.Target != nil {
			target = string(*effective.Publish.Target)
		}
		if target == "" {
			return nil, failure.Wrap("resolve path mounts", failure.MissingTarget, fmt.Errorf("service %q mount %q needs an address target for %q", service, prefix, mount.Service))
		}
		normalized, err := localproxy.NormalizeTarget(target)
		if err != nil {
			return nil, fmt.Errorf("service %q mount %q: %w", service, prefix, err)
		}
		caFile := ""
		if effective.Publish != nil && effective.Publish.TargetCAFile != nil {
			caFile = *effective.Publish.TargetCAFile
		}
		options, err := targetOptionsForCA(caFile, project.Root)
		if err != nil {
			return nil, fmt.Errorf("service %q mount %q: %w", service, prefix, err)
		}
		mounts = append(mounts, localproxy.Mount{Prefix: prefix, Target: normalized, StripPrefix: mount.StripPrefix, Options: options})
	}
	return mounts, nil
}
