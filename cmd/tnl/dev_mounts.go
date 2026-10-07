package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
)

type devGroupTargets struct {
	mu      sync.Mutex
	ready   chan struct{}
	want    int
	targets map[string]string
}

func newDevGroupTargets(count int) *devGroupTargets {
	return &devGroupTargets{ready: make(chan struct{}), want: count, targets: make(map[string]string, count)}
}

func (g *devGroupTargets) wait(ctx context.Context, child *devProcess, name, target string) (map[string]string, error) {
	g.mu.Lock()
	g.targets[name] = target
	if len(g.targets) == g.want {
		close(g.ready)
	}
	g.mu.Unlock()
	select {
	case <-g.ready:
	case <-child.Done():
		if err := childResult(child.Err()); err != nil {
			return nil, err
		}
		return nil, failure.Wrap("wait for development services", failure.DevProcessFailed, errors.New("development server command stopped before other services were ready"))
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	copy := make(map[string]string, len(g.targets))
	for service, target := range g.targets {
		copy[service] = target
	}
	return copy, nil
}

func resolveProjectMounts(project projectConfiguration, service string, targets map[string]string) ([]localproxy.Mount, error) {
	if service == "" {
		return nil, nil
	}
	configuration := project.Config.Services[service]
	prefixes := make([]string, 0, len(configuration.Paths))
	for prefix := range configuration.Paths {
		prefixes = append(prefixes, prefix)
	}
	slices.Sort(prefixes)
	mounts := make([]localproxy.Mount, 0, len(prefixes))
	for _, prefix := range prefixes {
		mount := configuration.Paths[prefix]
		target := targets[mount.Service]
		if target == "" {
			effective, err := project.EffectiveService(mount.Service)
			if err != nil {
				return nil, err
			}
			if effective.Publish != nil && effective.Publish.Target != nil {
				target = string(*effective.Publish.Target)
			} else if effective.Dev != nil && effective.Dev.Port != nil {
				target = strconv.Itoa(*effective.Dev.Port)
			}
		}
		if target == "" {
			return nil, failure.Wrap("resolve development mounts", failure.MissingTarget, fmt.Errorf("service %q mount %q needs a target for %q; run tnl dev without a service or configure its publish.target", service, prefix, mount.Service))
		}
		normalized, err := localproxy.NormalizeTarget(target)
		if err != nil {
			return nil, fmt.Errorf("service %q mount %q: %w", service, prefix, err)
		}
		mounts = append(mounts, localproxy.Mount{Prefix: prefix, Target: normalized, StripPrefix: mount.StripPrefix})
	}
	return mounts, nil
}
