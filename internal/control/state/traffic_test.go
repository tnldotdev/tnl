package state

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

func TestServiceRunTrafficDigestNormalizesSelections(t *testing.T) {
	base := sha256.Sum256([]byte("authorized service run"))
	omitted, err := runTrafficDigest(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := runTrafficDigest(base, &trafficlimits.Selection{})
	if err != nil || omitted != empty {
		t.Fatal("empty selection changed idempotency")
	}
	first, second := "1000ms", "1s"
	a, _ := runTrafficDigest(base, &trafficlimits.Selection{RatePer: &first})
	b, _ := runTrafficDigest(base, &trafficlimits.Selection{RatePer: &second})
	if a != b {
		t.Fatal("equivalent rate periods changed idempotency")
	}
	rate := 20
	c, _ := runTrafficDigest(base, &trafficlimits.Selection{Rate: &rate})
	if c == omitted {
		t.Fatal("explicit selection was not bound to idempotency")
	}
	invalid := 0
	if _, err := runTrafficDigest(base, &trafficlimits.Selection{Connections: &invalid}); !errors.Is(err, ErrTrafficSelection) {
		t.Fatalf("invalid selection classification: %v", err)
	}
}

func TestServiceRunPreparationRequiresStoredTraffic(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte(`{}`), []byte(`null`)} {
		if _, err := serviceRunPreparation(controlstatedb.ControlServiceRun{TrafficLimits: payload}); err == nil {
			t.Fatal("missing stored approval received defaults")
		}
	}
	payload, err := resolveRunTraffic(nil, trafficlimits.Limits{}, trafficlimits.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := serviceRunPreparation(controlstatedb.ControlServiceRun{TrafficLimits: payload})
	if err != nil || prepared.Traffic != trafficlimits.Default() {
		t.Fatal("stored approval changed in preparation projection", prepared.Traffic, err)
	}
}

func TestServiceRunTrafficResolutionAndStoredBounds(t *testing.T) {
	rate, per, total := 40, "2s", int64(100)
	selection := &trafficlimits.Selection{Rate: &rate, RatePer: &per, TotalConnections: &total}
	payload, err := resolveRunTraffic(selection, trafficlimits.Limits{}, trafficlimits.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	l, err := decodeRunTraffic(payload)
	if err != nil || l.Rate != 40 || l.RatePer != 2*time.Second || l.Connections != 32 || l.UploadBytes != 8<<20 || l.TotalConnections != total {
		t.Fatalf("resolved limits: %+v %v", l, err)
	}
	tooFast := "1ms"
	selection.RatePer = &tooFast
	if _, err := resolveRunTraffic(selection, trafficlimits.Limits{}, trafficlimits.Limits{}); !errors.Is(err, ErrTrafficSelection) {
		t.Fatalf("ceiling: %v", err)
	}
	defaults := trafficlimits.Default()
	defaults.Burst = 201
	if _, err := resolveRunTraffic(nil, defaults, trafficlimits.Limits{}); !errors.Is(err, ErrTrafficSelection) {
		t.Fatalf("unsafe defaults: %v", err)
	}
	for _, invalid := range []string{`{}`, `null`, string(payload) + `{}`, `{"connections":32,"rate":20,"burst":40,"upload_bytes":8388608,"download_bytes":16777216}`, `{"unexpected":1}`} {
		if _, err := decodeRunTraffic([]byte(invalid)); err == nil {
			t.Fatalf("accepted stored limits: %s", invalid)
		}
	}
}
