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
		if target == "" {
			return nil, failure.Wrap("resolve path mounts", failure.MissingTarget, fmt.Errorf("service %q mount %q needs a discovered target for %q", service, prefix, mount.Service))
		}
		normalized, err := localproxy.NormalizeTarget(target)
		if err != nil {
			return nil, fmt.Errorf("service %q mount %q: %w", service, prefix, err)
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
		mounts = append(mounts, localproxy.Mount{Prefix: prefix, Target: normalized, StripPrefix: mount.StripPrefix, Options: options})
	}
	return mounts, nil
}
