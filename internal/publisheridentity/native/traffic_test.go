package native

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type trafficControlStub struct {
	NativeControl
	url, retry, token, proof string
	selection                *trafficlimits.Selection
}

func (s *trafficControlStub) CreatePublisherRunWithTraffic(_ context.Context, id, retry, token, proof string, selection *trafficlimits.Selection) (controlv1.PublishRunSetup, error) {
	s.url, s.retry, s.token, s.proof, s.selection = id, retry, token, proof, selection
	return controlv1.PublishRunSetup{}, nil
}

func TestNativeTrafficSelectionKeepsSignedRunBoundary(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	control := &trafficControlStub{}
	n := &Native{NativeControl: control, authority: &lostEnrollmentResponse{}, private: private, route: controlv1.PublicURL{Id: "url"}}
	connections := 48
	selected, err := n.WithTraffic(&trafficlimits.Selection{Connections: &connections})
	if err != nil {
		t.Fatal(err)
	}
	connections = 24
	if _, err := selected.CreatePublishRun(t.Context(), "url", "retry"); err != nil {
		t.Fatal(err)
	}
	if control.url != "url" || control.retry != "retry" || control.token != "access" || control.selection == nil || *control.selection.Connections != 48 || n.traffic != nil {
		t.Fatal("traffic selection or scoped authentication changed")
	}
	if _, err := publisheridentity.VerifyRun(private.Public().(ed25519.PublicKey), control.proof, "url", "retry"); err != nil {
		t.Fatal(err)
	}
	if _, err := selected.CreatePublishRun(t.Context(), "other", "retry"); !errors.Is(err, ErrScope) {
		t.Fatalf("unscoped run: %v", err)
	}
	n.NativeControl = &unusedControl{}
	if _, err := n.WithTraffic(&trafficlimits.Selection{Connections: &connections}); !errors.Is(err, ErrTrafficUnsupported) {
		t.Fatalf("silently dropped selection: %v", err)
	}
}
