package trafficlimits

import (
	"math"
	"testing"
	"time"
)

func TestSelectionPeriodsCeilingsAndTotals(t *testing.T) {
	minute := "1m"
	rate := 100
	burst := 2
	s := Selection{Rate: &rate, RatePer: &minute, Burst: &burst}
	l, err := s.Resolve(Default(), Ceiling())
	if err != nil || l.Period() != time.Minute || l.Rate != 100 {
		t.Fatalf("resolved: %+v, %v", l, err)
	}
	fast := "1ms"
	s.RatePer = &fast
	if _, err := s.Resolve(Default(), Ceiling()); err == nil {
		t.Fatal("fast equivalent rate exceeded ceiling")
	}
	ceiling := Ceiling()
	ceiling.TotalConnections = 10
	if Default().Within(ceiling) {
		t.Fatal("unlimited total exceeded bounded ceiling")
	}
	total := int64(5)
	if _, err := (Selection{TotalConnections: &total}).Resolve(func() Limits { d := Default(); d.TotalConnections = 10; return d }(), ceiling); err != nil {
		t.Fatal(err)
	}
	negative := int64(-1)
	if (Selection{TotalUploadBytes: &negative}).Validate() == nil {
		t.Fatal("negative total accepted")
	}
	overflow := Default()
	overflow.Rate = math.MaxInt
	if overflow.Within(Ceiling()) {
		t.Fatal("overflow accepted")
	}
}

func TestByteRateBounds(t *testing.T) {
	for _, value := range []string{"64KiB/s", "8MiB/s", "1024GiB/s"} {
		if _, err := ParseByteRate(value); err != nil {
			t.Fatal(value, err)
		}
	}
	for _, value := range []string{"63KiB/s", "0MiB/s", "1025GiB/s", "1MB/s", "99999999999999999999999GiB/s"} {
		if _, err := ParseByteRate(value); err == nil {
			t.Fatal(value)
		}
	}
}
