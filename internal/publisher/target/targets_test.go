package target

import (
	"context"
	"errors"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestTargetSnapshotRequiresContainerIdentity(t *testing.T) {
	protocol, container, port := "tcp", "database", 5432
	project := clientproject.Project{Root: "/project", Config: config.TNL{Services: config.Services{
		"db": {Protocol: &protocol, Target: &config.ServiceTarget{Type: "docker", Container: &container, Port: &port}},
	}}}
	if _, err := ResolveTargetSnapshot(t.Context(), project, "db", nil); err == nil {
		t.Fatal("container accepted without an identity-bearing resolver")
	}
	identity := ""
	resolver := TargetResolverFunc(func(context.Context, clientproject.Project, string) (string, string, error) {
		return "127.0.0.1:15432", identity, nil
	})
	if _, err := ResolveTargetSnapshot(t.Context(), project, "db", resolver); err == nil {
		t.Fatal("container accepted without immutable identity")
	}
	identity = "container-a"
	if snapshot, err := ResolveTargetSnapshot(t.Context(), project, "db", resolver); err != nil || snapshot.Address != "127.0.0.1:15432" || snapshot.Identity != identity {
		t.Fatalf("container snapshot lost its explicit identity: %+v, %v", snapshot, err)
	}
}

func TestTargetBindingFencesSameAddressReplacementAndLostTargets(t *testing.T) {
	identity := "container-a"
	unavailable := false
	changed := 0
	binding := TargetBinding{Resolve: func(context.Context) (TargetSnapshot, error) {
		if unavailable {
			return TargetSnapshot{}, errors.New("container stopped")
		}
		return TargetSnapshot{Address: "127.0.0.1:49152", Identity: identity}, nil
	}, Changed: func() { changed++ }}
	captured, err := binding.Capture(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	identity = "container-b"
	if binding.Current(t.Context(), captured) || changed != 1 {
		t.Fatal("same-address replacement accepted an old readiness observation")
	}
	next, err := binding.Capture(t.Context())
	if err != nil || next.Address != captured.Address || next.Identity == captured.Identity {
		t.Fatalf("next=%+v err=%v", next, err)
	}
	if captured.Identity != "container-a" {
		t.Fatal("an already admitted stream lost its immutable target")
	}
	unavailable = true
	if binding.Current(t.Context(), next) || changed != 2 {
		t.Fatal("lost target retained readiness")
	}
	unavailable = false
	if binding.Current(t.Context(), next) {
		t.Fatal("recovery accepted a check captured before the availability gap")
	}
}
