package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDockerPublisherFollowsReboundPortAndRejectsMissingService(t *testing.T) {
	selected := dockerPublishTarget{service: "database", port: 5432, projectLabel: "shop-perf-k7n2p9"}
	resolver := newDockerPublishResolver(t.Context(), t.TempDir(), selected, false)
	port := "127.0.0.1:49153"
	var lookups int
	resolver.lookup = func(_ context.Context, root, project, service string, privatePort int) (string, error) {
		lookups++
		if root != resolver.root || project != selected.projectLabel || service != selected.service || privatePort != selected.port {
			t.Fatalf("discovery changed the selected worktree or private port")
		}
		if port == "" {
			return "", errors.New("container stopped")
		}
		return port, nil
	}
	if initial, err := resolver.initial(); err != nil || initial != port || resolver.target() != port || lookups != 1 {
		t.Fatalf("initial target = %q, %v; lookups = %d", initial, err, lookups)
	}
	port = ""
	resolver.mu.Lock()
	resolver.checked = time.Time{}
	resolver.mu.Unlock()
	if current := resolver.target(); current != "" {
		t.Fatalf("stopped container retained stale host port %q", current)
	}
	port = "127.0.0.1:49154"
	resolver.mu.Lock()
	resolver.checked = time.Time{}
	resolver.mu.Unlock()
	if current := resolver.target(); current != port || lookups != 3 {
		t.Fatalf("replacement target = %q; lookups = %d", current, lookups)
	}
	httpResolver := newDockerPublishResolver(t.Context(), resolver.root, selected, true)
	httpResolver.lookup = resolver.lookup
	if target, err := httpResolver.initial(); err != nil || target != "http://"+port {
		t.Fatalf("HTTP target = %q, %v", target, err)
	}
	port = ""
	failed := newDockerPublishResolver(t.Context(), resolver.root, selected, false)
	failed.lookup = resolver.lookup
	if _, err := failed.initial(); err == nil || !strings.Contains(err.Error(), "docker compose -p shop-perf-k7n2p9 up -d database") {
		t.Fatalf("missing service diagnostic = %v", err)
	}
}
