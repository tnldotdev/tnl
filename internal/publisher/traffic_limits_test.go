package publisher

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestSelectedTrafficRequiresMatchingRunSetup(t *testing.T) {
	connections, period := 16, "2s"
	selected := trafficlimits.Selection{Connections: &connections, RatePer: &period}
	if err := verifyRunTraffic(selected, nil); err == nil {
		t.Fatal("control silently omitted selected traffic")
	}
	actual := &controlv1.PublishRunTrafficLimits{Connections: 16, RatePerNs: int64(2 * time.Second)}
	if err := verifyRunTraffic(selected, actual); err != nil {
		t.Fatal(err)
	}
	actual.RatePerNs = int64(time.Second)
	if err := verifyRunTraffic(selected, actual); err == nil {
		t.Fatal("control changed the selected rate period")
	}
}
