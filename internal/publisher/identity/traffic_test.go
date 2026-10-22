package identity

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type trafficControlStub struct {
	NativeControl
	url, retry, token, proof string
	selection                *trafficlimits.Selection
}

func TestNativeTrafficClonePreservesOptionalValues(t *testing.T) {
	selection := &trafficlimits.Selection{Connections: new(48), Rate: new(3), RatePer: new("1m"), Burst: new(4), UploadBytes: new(int64(1 << 20)), DownloadBytes: new(int64(2 << 20)), TotalConnections: new(int64(0)), TotalUploadBytes: new(int64(7)), TotalDownloadBytes: new(int64(8))}
	n := &Native{NativeControl: &trafficControlStub{}}
	selected, err := n.WithTraffic(selection)
	if err != nil || !reflect.DeepEqual(selection, selected.traffic) {
		t.Fatal("typed copy changed explicit traffic values", err)
	}
	*selection.Connections, *selection.Rate, *selection.RatePer, *selection.Burst = 1, 1, "1s", 1
	*selection.UploadBytes, *selection.DownloadBytes = 1, 1
	*selection.TotalConnections, *selection.TotalUploadBytes, *selection.TotalDownloadBytes = 1, 1, 1
	limits, err := selected.traffic.Resolve(trafficlimits.Default(), trafficlimits.Ceiling())
	if err != nil || limits.Connections != 48 || limits.Rate != 3 || limits.Period().String() != "1m0s" || limits.Burst != 4 || limits.UploadBytes != 1<<20 || limits.DownloadBytes != 2<<20 || limits.TotalConnections != 0 || limits.TotalUploadBytes != 7 || limits.TotalDownloadBytes != 8 {
		t.Fatal("input pointers changed worker traffic budgets", err)
	}
	if selected, err := n.WithTraffic(nil); err != nil || selected.traffic != nil || (*trafficlimits.Selection)(nil).Clone() != nil {
		t.Fatal("omitted selection became explicit traffic limits", err)
	}
}

func (s *trafficControlStub) CreatePublisherRunWithTraffic(_ context.Context, id, retry, token, proof string, selection *trafficlimits.Selection) (controlv1.PublishRunSetup, error) {
	s.url, s.retry, s.token, s.proof, s.selection = id, retry, token, proof, selection
	return controlv1.PublishRunSetup{}, nil
}

func TestNativeTrafficSelectionKeepsSignedRunBoundary(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	control := &trafficControlStub{}
	n := &Native{NativeControl: control, authority: &lostEnrollmentResponse{}, private: private, publicURL: controlv1.PublicURL{Id: "url"}}
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
	if _, err := publisherproof.VerifyRun(private.Public().(ed25519.PublicKey), control.proof, "url", "retry"); err != nil {
		t.Fatal(err)
	}
	*control.selection.Connections = 1
	if _, err := selected.CreatePublishRun(t.Context(), "url", "retry"); err != nil || *control.selection.Connections != 48 {
		t.Fatal("control mutated the worker's traffic selection", err)
	}
	if _, err := selected.CreatePublishRun(t.Context(), "other", "retry"); !errors.Is(err, ErrScope) {
		t.Fatalf("unscoped run: %v", err)
	}
	n.NativeControl = &unusedControl{}
	if _, err := n.WithTraffic(&trafficlimits.Selection{Connections: &connections}); !errors.Is(err, ErrTrafficUnsupported) {
		t.Fatalf("silently dropped selection: %v", err)
	}
}
