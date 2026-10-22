package state

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

func TestPublishRunTrafficDigestNormalizesSelections(t *testing.T) {
	base := sha256.Sum256([]byte("authorized publish run"))
	omitted, err := publishRunTrafficDigest(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := publishRunTrafficDigest(base, &trafficlimits.Selection{})
	if err != nil || omitted != empty {
		t.Fatal("empty selection changed idempotency")
	}
	first, second := "1000ms", "1s"
	a, _ := publishRunTrafficDigest(base, &trafficlimits.Selection{RatePer: &first})
	b, _ := publishRunTrafficDigest(base, &trafficlimits.Selection{RatePer: &second})
	if a != b {
		t.Fatal("equivalent rate periods changed idempotency")
	}
	rate := 20
	c, _ := publishRunTrafficDigest(base, &trafficlimits.Selection{Rate: &rate})
	if c == omitted {
		t.Fatal("explicit selection was not bound to idempotency")
	}
	invalid := 0
	if _, err := publishRunTrafficDigest(base, &trafficlimits.Selection{Connections: &invalid}); !errors.Is(err, ErrTrafficSelection) {
		t.Fatalf("invalid selection classification: %v", err)
	}
}

func TestPublishRunTrafficResolutionAndStoredBounds(t *testing.T) {
	rate, per, total := 40, "2s", int64(100)
	request := PublishRunRequest{TrafficSelection: &trafficlimits.Selection{Rate: &rate, RatePer: &per, TotalConnections: &total}}
	payload, err := resolvePublishRunTraffic(request)
	if err != nil {
		t.Fatal(err)
	}
	l, err := decodePublishRunTraffic(payload)
	if err != nil || l.Rate != 40 || l.RatePer != 2*time.Second || l.Connections != 32 || l.UploadBytes != 8<<20 || l.TotalConnections != total {
		t.Fatalf("resolved limits: %+v %v", l, err)
	}
	tooFast := "1ms"
	request.TrafficSelection.RatePer = &tooFast
	if _, err := resolvePublishRunTraffic(request); !errors.Is(err, ErrTrafficSelection) {
		t.Fatalf("ceiling: %v", err)
	}
	request.TrafficSelection = nil
	request.TrafficDefaults = trafficlimits.Default()
	request.TrafficDefaults.Burst = 201
	if _, err := resolvePublishRunTraffic(request); !errors.Is(err, ErrTrafficSelection) {
		t.Fatalf("unsafe defaults: %v", err)
	}
	for _, invalid := range []string{`{}`, `null`, string(payload) + `{}`, `{"connections":32,"rate":20,"burst":40,"upload_bytes":8388608,"download_bytes":16777216}`, `{"unexpected":1}`} {
		if _, err := decodePublishRunTraffic([]byte(invalid)); err == nil {
			t.Fatalf("accepted stored limits: %s", invalid)
		}
	}
}
