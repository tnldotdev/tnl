package publisherjob

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/privatepublisher"
	"github.com/tnldotdev/tnl/internal/privatetrust"
	"github.com/tnldotdev/tnl/internal/projectpublisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestPrivateTargetTrustMismatchFailsBeforeResolutionOrPublication(t *testing.T) {
	trust, err := privatetrust.NewCache(nil).Capture(t.Context(), t.TempDir(), "target.internal:5432", config.TrustSource{CA: "system"})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	err = PublishPrivate(t.Context(), Job{Kind: KindPrivateService, Protocol: config.ProtocolPostgres, Target: "127.0.0.1:1", Trust: &trust},
		privatepublisher.RunConfig{Metadata: controlv1.PrivateServiceMetadata{Protocol: controlv1.Postgres}},
		PrivateTargetHooks{Capture: func(projectpublisher.TargetSnapshot) error { called = true; return nil }})
	if !errors.Is(err, ErrScope) || called {
		t.Fatalf("contradictory trust reached target resolution or publication: %v called=%t", err, called)
	}
}
