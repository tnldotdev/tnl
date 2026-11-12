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
	unusedControl
	url, retry, token, proof string
	selection                *trafficlimits.Selection
}

func TestNativeTrafficClonePreservesOptionalValues(t *testing.T) {
	selection := &trafficlimits.Selection{Connections: new(48), Rate: new(3), RatePer: new("1m"), Burst: new(4), UploadBytes: new(int64(1 << 20)), DownloadBytes: new(int64(2 << 20)), TotalConnections: new(int64(0)), TotalUploadBytes: new(int64(7)), TotalDownloadBytes: new(int64(8))}
	n := &Native{NativeControl: NativeControl{PublicURLControl: &trafficControlStub{}}}
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

func (s *trafficControlStub) CreatePublisherRun(_ context.Context, id, retry, token, proof string, selection *trafficlimits.Selection, _ ...string) (controlv1.PublishRunSetup, error) {
	s.url, s.retry, s.token, s.proof, s.selection = id, retry, token, proof, selection
	return controlv1.PublishRunSetup{}, nil
}

func TestNativeTrafficSelectionKeepsSignedRunBoundary(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	for _, test := range []struct {
		name      string
		selection *trafficlimits.Selection
	}{
		{name: "defaults"},
		{name: "explicit", selection: &trafficlimits.Selection{Connections: new(48)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			control := &trafficControlStub{}
			n := &Native{NativeControl: NativeControl{PublicURLControl: control}, authority: &lostEnrollmentResponse{}, private: private, publicURL: controlv1.PublicURL{Id: "url"}}
			selected, err := n.WithTraffic(test.selection)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if _, err := selected.CreatePublishRun(t.Context(), "url", "retry"); err != nil {
					t.Fatal(err)
				}
				if control.url != "url" || control.retry != "retry" || control.token != "access" || !reflect.DeepEqual(control.selection, test.selection) || n.traffic != nil {
					t.Fatal("traffic selection or scoped authentication changed")
				}
				public := private.Public().(ed25519.PublicKey)
				if _, err := publisherproof.VerifyRun(public, control.proof, "url", "retry"); err != nil {
					t.Fatal(err)
				}
				if _, err := publisherproof.VerifyRun(public, control.proof, "other", "retry"); err == nil {
					t.Fatal("proof authorized another public URL")
				}
				if _, err := publisherproof.VerifyRun(public, control.proof, "url", "other"); err == nil {
					t.Fatal("proof authorized another attempt")
				}
				if control.selection != nil {
					*control.selection.Connections = 1
				}
			}
			if _, err := selected.CreatePublishRun(t.Context(), "other", "retry"); !errors.Is(err, ErrScope) {
				t.Fatalf("unscoped run: %v", err)
			}
		})
	}
}

func TestNativeTrafficSelectionsAreIndependent(t *testing.T) {
	n := &Native{NativeControl: NativeControl{PublicURLControl: &unusedControl{}}}
	selection := &trafficlimits.Selection{Connections: new(48)}
	first, err := n.WithTraffic(selection)
	if err != nil {
		t.Fatal(err)
	}
	second, err := first.WithTraffic(selection)
	if err != nil {
		t.Fatal(err)
	}
	*selection.Connections = 24
	*first.traffic.Connections = 12
	if *second.traffic.Connections != 48 || n.traffic != nil {
		t.Fatal("one worker changed another worker's selection")
	}
	defaults, err := first.WithTraffic(nil)
	if err != nil || defaults.traffic != nil || *first.traffic.Connections != 12 {
		t.Fatal("selecting defaults changed the original worker", err)
	}
	if _, err := first.WithTraffic(&trafficlimits.Selection{Connections: new(0)}); err == nil || *first.traffic.Connections != 12 {
		t.Fatal("invalid selection changed the original worker")
	}
	if _, err := (*Native)(nil).WithTraffic(selection); !errors.Is(err, ErrScope) {
		t.Fatalf("nil adapter: %v", err)
	}
}
