package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/dockertarget"
)

type dockerPublishResolver struct {
	mu       sync.Mutex
	ctx      context.Context
	selected dockerPublishTarget
	root     string
	http     bool
	checked  time.Time
	current  string
	lastErr  error
	lookup   func(context.Context, string, string, string, int) (string, error)
}

func newDockerPublishResolver(ctx context.Context, root string, selected dockerPublishTarget, http bool) *dockerPublishResolver {
	return &dockerPublishResolver{ctx: ctx, root: root, selected: selected, http: http, lookup: dockertarget.ComposePort}
}

func (r *dockerPublishResolver) initial() (string, error) {
	target := r.target()
	if target != "" {
		return target, nil
	}
	return "", diagnostic.WrapMessage(diagnostic.TargetUnavailable,
		fmt.Sprintf("Docker Compose service %q has no reachable published port; run docker compose -p %s up -d %s and publish private port %d", r.selected.service, r.selected.projectLabel, r.selected.service, r.selected.port), r.lastErr)
}

func (r *dockerPublishResolver) target() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.checked) < time.Second {
		return r.current
	}
	r.checked = time.Now()
	address, err := r.lookup(r.ctx, r.root, r.selected.projectLabel, r.selected.service, r.selected.port)
	r.lastErr = err
	if err != nil {
		r.current = ""
	} else if r.http {
		r.current = "http://" + address
	} else {
		r.current = address
	}
	return r.current
}
