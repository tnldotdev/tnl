package localpublisher

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestDockerPublisherFollowsReboundPortAndRejectsMissingService(t *testing.T) {
	privatePort := 5432
	selected := dockerPublishTarget{selection: config.DockerSelection{Compose: &config.ComposeSelection{File: "compose.yaml", Project: "shop-perf-k7n2p9", Service: "database"}, ContainerPort: &privatePort}, projectLabel: "shop-perf-k7n2p9"}
	resolver := newDockerPublishResolver(t.Context(), t.TempDir(), selected, false)
	port := "127.0.0.1:49153"
	var lookups int
	resolver.lookup = func(_ context.Context, root, project string, selector config.DockerSelection) (string, error) {
		lookups++
		if root != resolver.root || project != selected.projectLabel || selector.Compose.Service != selected.selection.Compose.Service || *selector.ContainerPort != *selected.selection.ContainerPort {
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
	if _, err := failed.initial(); err == nil || !strings.Contains(err.Error(), "selected Docker container has no reachable published port") {
		t.Fatalf("missing service diagnostic = %v", err)
	}
}
