package invocation

import (
	"context"
	"errors"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

type canceledMountResolver struct{}

func (canceledMountResolver) ResolveTarget(ctx context.Context, _ clientproject.Project, _ string) (string, error) {
	return "", context.Cause(ctx)
}
func (canceledMountResolver) ResolveTargetIdentity(ctx context.Context, _ clientproject.Project, _ string) (string, string, error) {
	return "", "", context.Cause(ctx)
}

func TestDiscoveredMountPreservesRequestCancellation(t *testing.T) {
	project := clientproject.Project{Config: config.TNL{Services: config.Services{
		"web": {Tunnel: &config.Tunnel{}, HTTP: &config.HTTPService{Paths: map[string]config.PathMount{"/api": {Service: "api"}}}},
		"api": {Target: &config.ServiceTarget{Type: "docker", Container: new("api"), Port: new(3000)}},
	}}}
	mounts, err := ProjectMounts(t.Context(), project, "web", nil, canceledMountResolver{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	cause := errors.New("visitor disconnected")
	cancel(cause)
	_, _, err = mounts[0].ResolveTarget(ctx)
	if !errors.Is(err, cause) {
		t.Fatalf("mount lost request cancellation: %v", err)
	}
}
