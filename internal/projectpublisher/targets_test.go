package projectpublisher

import (
	"context"
	"errors"
	"testing"
)

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
