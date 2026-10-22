package target

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceTargetTrustMismatchFailsBeforeResolutionOrPublication(t *testing.T) {
	trust, err := targettrust.NewCache(nil).Capture(t.Context(), t.TempDir(), "target.internal:5432", config.TrustSource{CA: "system"})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	err = PublishPrivate(t.Context(), TargetPlan{Protocol: config.ProtocolPostgres, Target: "127.0.0.1:1", Trust: &trust},
		publisherservice.RunConfig{Metadata: controlv1.ServiceMetadata{Protocol: controlv1.Postgres}},
		TargetHooks{Capture: func(TargetSnapshot) error { called = true; return nil }})
	if !errors.Is(err, ErrScope) || called {
		t.Fatalf("contradictory trust reached target resolution or publication: %v called=%t", err, called)
	}
}
