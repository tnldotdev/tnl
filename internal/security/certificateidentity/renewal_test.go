package certificateidentity

import (
	"testing"
	"time"
)

func TestRenewAtUsesCertificateValidityAndUTC(t *testing.T) {
	start := time.Date(2026, 11, 12, 10, 0, 0, 0, time.FixedZone("fixture", 3600))
	end := start.Add(90 * 24 * time.Hour)
	want := start.Add(60 * 24 * time.Hour)
	got := RenewAt(start, end)
	if !got.Equal(want) || got.Location() != time.UTC {
		t.Fatalf("renewal = %v, want %v in UTC", got, want)
	}
}
