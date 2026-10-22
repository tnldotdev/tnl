package invocation

import (
	"context"
	"fmt"
	"slices"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	targetbinding "github.com/tnldotdev/tnl/internal/publisher/target"
)

// one resolver owns mount trust and target selection for app, named and scoped
// publishers. only app targets use registrations; static addresses stay static.
func ProjectMounts(project clientproject.Project, service string, appTarget func(string) string, resolver targetbinding.TargetResolver) ([]publisherproxy.Mount, error) {
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
	mounts := make([]publisherproxy.Mount, 0, len(prefixes))
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
			binding := &targetbinding.TargetBinding{Resolve: func(ctx context.Context) (targetbinding.TargetSnapshot, error) {
				return targetbinding.ResolveTargetSnapshot(ctx, project, mount.Service, resolver)
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
		options, err := publisherproxy.TargetOptionsForCA(caFile, project.Root)
		if err != nil {
			return nil, fmt.Errorf("service %q mount %q: %w", service, prefix, err)
		}
		if local.TargetTLSName != nil {
			options.ServerName = *local.TargetTLSName
		}
		mounts = append(mounts, publisherproxy.Mount{Prefix: prefix, Target: normalized, StripPrefix: mount.StripPrefix, Options: options, ResolveTarget: resolve})
	}
	return mounts, nil
}
